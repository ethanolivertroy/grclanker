import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import {
  batch2All as all,
  batch2Any as any,
  batch2Checks,
  batch2ComparePaths as comparePaths,
  batch2Defined as defined,
  batch2Eq as eq,
  batch2Gt as gt,
  batch2Gte as gte,
  batch2Lte as lte,
  batch2Ne as ne,
  batch2Rule as rule,
  restSurface,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import { AZURE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

const DOCS = "https://learn.microsoft.com/en-us/graph/api/overview";
const ARM_DOCS = "https://learn.microsoft.com/en-us/rest/api/azure/";
export const AZURE_GUEST_ROLE_SAME_AS_MEMBER = "a0b1b346-4d3e-4e8b-98f8-753987be4970";
export const AZURE_GUEST_ROLE_LIMITED = "10dae51f-b6af-4016-8d66-8c2a99b929b3";
export const AZURE_GUEST_ROLE_RESTRICTED = "2af84b1e-32c8-42b7-82bc-daa82404023b";
export const AZURE_HIGH_PRIVILEGE_DELEGATED_SCOPES = [
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
] as const;
export const AZURE_ADMIN_PORTS = [22, 3389, 3306, 1433] as const;
export const AZURE_SECURE_SCORE_PASS_RATIO = 0.75;
export const AZURE_SECURE_SCORE_WARN_RATIO = 0.5;
export const AZURE_MIN_RETENTION_DAYS = 90;
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

interface AzureDecision {
  inputs: Readonly<Record<string, string>>;
  constants?: Readonly<Record<string, PortableValue>>;
  rules: readonly VerdictRule[];
}

const inputs = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(
  names.map((name) => [name, ({
    readable: "Boolean. True only when every Azure API response required by this finding was returned and its decision fields were present; false, null, or missing means manual.",
    complete: "Boolean. True only when every required Azure list exhausted its continuation links; false means counts are lower bounds and cannot support pass unless the documented parent-parity limitation says otherwise.",
    inventory_count: "Integer. Complete source-record count before any 25-item evidence presentation slice; zero retains the check-specific empty-inventory semantics.",
    guest_role_id: `Lowercase authorizationPolicy.guestUserRoleId GUID. ${AZURE_GUEST_ROLE_SAME_AS_MEMBER} means guests have member permissions, ${AZURE_GUEST_ROLE_LIMITED} is the default limited role, and ${AZURE_GUEST_ROLE_RESTRICTED} is the most restricted role; null means the raw field was absent.`,
    allow_invites_from: "Lowercase authorizationPolicy.allowInvitesFrom enum. `everyone` fails; `none` and `adminsandguestinviters` are restricted; null or an undocumented value cannot pass.",
    maximum_score: "Number from secureScores.maxScore. Zero, null, or missing means no scored record and requires manual review.",
    score_ratio: "Number computed as secureScores.currentScore divided by secureScores.maxScore only when maxScore is positive; null means the ratio is not computable.",
    exposed_rule_count: `Integer. Complete count, across every returned NSG and every security rule before evidence slicing, of enabled inbound Allow rules from any source whose TCP/all destination range contains one of ${AZURE_ADMIN_PORTS.join(", ")}.`,
  } as Record<string, string>)[name] ?? (
    name.endsWith("_count") || name.endsWith("_maximum")
      ? `Integer. Complete unsliced Azure collector value for ${name.replaceAll("_", " ")}; null or missing cannot support pass.`
      : name.endsWith("_ratio")
        ? `Number. Azure evidence-derived ratio for ${name.replaceAll("_", " ")}; null, missing, or a nonpositive denominator cannot support pass.`
        : `Primitive Azure vendor field or evidence-derived boolean for ${name.replaceAll("_", " ")}; null, missing, or undocumented values cannot support pass.`
  )]),
);
const ordered = (branches: {
  manual?: VerdictCondition;
  fail?: VerdictCondition;
  warn?: VerdictCondition;
  pass?: VerdictCondition;
  failFirst?: boolean;
}): readonly VerdictRule[] => [
  ...(branches.failFirst && branches.fail ? [rule("fail", branches.fail, "A proved violation precedes incomplete companion evidence.")] : []),
  ...(branches.manual ? [rule("manual", branches.manual)] : []),
  ...(!branches.failFirst && branches.fail ? [rule("fail", branches.fail)] : []),
  ...(branches.warn ? [rule("warn", branches.warn)] : []),
  ...(branches.pass ? [rule("pass", branches.pass)] : []),
  rule("manual", { op: "always" }, "Unknown, null, contradictory, or otherwise insufficient evidence requires manual review."),
];
const unreadable = ne("readable", true);
const incomplete = ne("complete", true);
const empty = eq("inventory_count", 0);
const countDecision = (
  names: string[],
  branches: Parameters<typeof ordered>[0],
  constants?: Readonly<Record<string, PortableValue>>,
): AzureDecision => ({ inputs: inputs("readable", "complete", "inventory_count", ...names), constants, rules: ordered(branches) });

const AZURE_DECISIONS: Readonly<Record<string, AzureDecision>> = {
  "AZURE-ID-01": {
    inputs: inputs("policy_readable", "complete", "policy_count", "mfa_policy_count", "security_defaults_readable", "security_defaults_enabled"),
    rules: ordered({
      manual: any(ne("policy_readable", true), all(eq("mfa_policy_count", 0), ne("security_defaults_readable", true))),
      fail: all(eq("mfa_policy_count", 0), eq("security_defaults_enabled", false)),
      warn: incomplete,
      pass: any(gt("mfa_policy_count", 0), eq("security_defaults_enabled", true)),
    }),
  },
  "AZURE-ID-02": {
    inputs: inputs("policy_readable", "complete", "legacy_block_policy_count", "security_defaults_readable", "security_defaults_enabled"),
    rules: ordered({
      manual: any(ne("policy_readable", true), all(eq("legacy_block_policy_count", 0), ne("security_defaults_readable", true))),
      fail: all(eq("legacy_block_policy_count", 0), eq("security_defaults_enabled", false)),
      warn: incomplete,
      pass: any(gt("legacy_block_policy_count", 0), eq("security_defaults_enabled", true)),
    }),
  },
  "AZURE-ID-03": countDecision(["without_mfa_count", "without_mfa_ratio"], {
    manual: any(unreadable, empty),
    fail: comparePaths("gt", "without_mfa_ratio", "warning_ratio_maximum"),
    warn: any(incomplete, gt("without_mfa_count", 0)),
    pass: eq("without_mfa_count", 0),
  }, { warning_ratio_maximum: 0.1 }),
  "AZURE-ID-04": countDecision(["global_admin_count", "privileged_assignment_count"], {
    manual: any(unreadable, eq("privileged_assignment_count", 0)),
    fail: any(gt("global_admin_count", 4), gt("privileged_assignment_count", 10)),
    warn: any(incomplete, gt("privileged_assignment_count", 5)),
    pass: lte("privileged_assignment_count", 5),
  }, { maximum_global_admins: 4, pass_maximum_assignments: 5, fail_above_assignments: 10 }),
  "AZURE-ID-05": countDecision(["expired_credential_count", "expiring_credential_count", "missing_expiry_count", "long_lived_credential_count"], {
    manual: any(unreadable, empty),
    fail: gt("expired_credential_count", 0),
    warn: any(incomplete, gt("expiring_credential_count", 0), gt("missing_expiry_count", 0), gt("long_lived_credential_count", 0)),
    pass: { op: "always" },
  }, { expiring_days: 30, long_lived_days: 730 }),
  "AZURE-ID-06": countDecision(["eligible_assignment_count", "permanent_privileged_count"], {
    manual: any(unreadable, all(eq("eligible_assignment_count", 0), eq("permanent_privileged_count", 0))),
    fail: gt("permanent_privileged_count", 2),
    warn: any(incomplete, gt("permanent_privileged_count", 0), eq("eligible_assignment_count", 0)),
    pass: { op: "always" },
  }, { maximum_permanent_privileged_assignments: 2 }),
  "AZURE-ID-07": {
    inputs: inputs("readable", "guest_role_id", "allow_invites_from"),
    constants: {
      guest_role_same_as_member_guid: AZURE_GUEST_ROLE_SAME_AS_MEMBER,
      guest_role_limited_guid: AZURE_GUEST_ROLE_LIMITED,
      guest_role_restricted_guid: AZURE_GUEST_ROLE_RESTRICTED,
    },
    rules: ordered({
      manual: any(unreadable, { op: "not", condition: defined("guest_role_id") }, { op: "not", condition: defined("allow_invites_from") }),
      fail: any(comparePaths("eq", "guest_role_id", "guest_role_same_as_member_guid"), eq("allow_invites_from", "everyone")),
      warn: any(
        { op: "not", condition: comparePaths("eq", "guest_role_id", "guest_role_restricted_guid") },
        all(ne("allow_invites_from", "none"), ne("allow_invites_from", "adminsandguestinviters")),
      ),
      pass: all(
        comparePaths("eq", "guest_role_id", "guest_role_restricted_guid"),
        any(eq("allow_invites_from", "none"), eq("allow_invites_from", "adminsandguestinviters")),
      ),
    }),
  },
  "AZURE-ID-08": countDecision(["stale_guest_count", "unknown_activity_count"], {
    manual: unreadable,
    fail: gt("stale_guest_count", 0),
    warn: any(incomplete, gt("unknown_activity_count", 0)),
    pass: { op: "always" },
  }, { stale_days: 90 }),
  "AZURE-ID-09": countDecision(["license_present", "enforcing_policy_count"], {
    manual: any(unreadable, ne("license_present", true)),
    fail: eq("enforcing_policy_count", 0),
    warn: incomplete,
    pass: gt("enforcing_policy_count", 0),
  }),
  "AZURE-ID-10": countDecision(["license_present", "enforcing_policy_count"], {
    manual: any(unreadable, ne("license_present", true)),
    fail: eq("enforcing_policy_count", 0),
    warn: incomplete,
    pass: gt("enforcing_policy_count", 0),
  }),
  "AZURE-ID-11": countDecision(["high_risk_user_count"], {
    manual: unreadable,
    fail: gt("high_risk_user_count", 0),
    warn: any(incomplete, gt("inventory_count", 0)),
    pass: eq("inventory_count", 0),
  }),
  "AZURE-ID-12": countDecision(["expired_credential_count", "expiring_credential_count", "missing_expiry_count", "long_lived_credential_count", "ownerless_application_count"], {
    manual: any(unreadable, empty),
    fail: gt("expired_credential_count", 0),
    warn: any(incomplete, gt("expiring_credential_count", 0), gt("missing_expiry_count", 0), gt("long_lived_credential_count", 0), gt("ownerless_application_count", 0)),
    pass: { op: "always" },
  }, { expiring_days: 30, long_lived_days: 730 }),
  "AZURE-ID-13": countDecision(["risky_grant_count"], {
    manual: any(unreadable, empty),
    fail: gt("risky_grant_count", 0),
    warn: incomplete,
    pass: eq("risky_grant_count", 0),
  }, { high_privilege_delegated_scopes: AZURE_HIGH_PRIVILEGE_DELEGATED_SCOPES }),
  "AZURE-MON-01": {
    inputs: inputs("readable", "maximum_score", "score_ratio"),
    constants: { pass_minimum_ratio: AZURE_SECURE_SCORE_PASS_RATIO, warn_minimum_ratio: AZURE_SECURE_SCORE_WARN_RATIO },
    rules: ordered({
      manual: any(unreadable, lte("maximum_score", 0)),
      fail: { op: "not", condition: comparePaths("gte", "score_ratio", "warn_minimum_ratio") },
      warn: all(comparePaths("gte", "score_ratio", "warn_minimum_ratio"), { op: "not", condition: comparePaths("gte", "score_ratio", "pass_minimum_ratio") }),
      pass: comparePaths("gte", "score_ratio", "pass_minimum_ratio"),
    }),
  },
  "AZURE-MON-02": countDecision([], { manual: unreadable, warn: any(incomplete, empty), pass: gt("inventory_count", 0) }),
  "AZURE-MON-03": countDecision([], { manual: unreadable, warn: any(incomplete, empty), pass: gt("inventory_count", 0) }),
  "AZURE-MON-04": countDecision(["standard_plan_count"], {
    manual: any(unreadable, empty),
    fail: eq("standard_plan_count", 0),
    warn: any(incomplete, { op: "not", condition: comparePaths("eq", "standard_plan_count", "inventory_count") }),
    pass: comparePaths("eq", "standard_plan_count", "inventory_count"),
  }),
  "AZURE-MON-05": countDecision(["effective_setting_count"], {
    manual: unreadable,
    fail: eq("effective_setting_count", 0),
    warn: incomplete,
    pass: gt("effective_setting_count", 0),
  }),
  "AZURE-MON-06": countDecision(["destination_workspace_count", "linked_workspace_count", "workspace_retention_at_least_minimum_count"], {
    manual: any(unreadable, all(gt("destination_workspace_count", 0), eq("linked_workspace_count", 0))),
    fail: any(eq("destination_workspace_count", 0), { op: "not", condition: comparePaths("eq", "workspace_retention_at_least_minimum_count", "linked_workspace_count") }),
    warn: incomplete,
    pass: comparePaths("eq", "workspace_retention_at_least_minimum_count", "linked_workspace_count"),
  }, { minimum_retention_days: AZURE_MIN_RETENTION_DAYS }),
  "AZURE-SUB-01": countDecision(["matching_assignment_count", "warn_maximum"], {
    manual: any(unreadable, empty),
    fail: comparePaths("gt", "matching_assignment_count", "warn_maximum"),
    warn: any(incomplete, gt("matching_assignment_count", 0)),
    pass: eq("matching_assignment_count", 0),
  }),
  "AZURE-SUB-02": countDecision(["matching_assignment_count", "warn_maximum"], {
    manual: any(unreadable, empty),
    fail: comparePaths("gt", "matching_assignment_count", "warn_maximum"),
    warn: any(incomplete, gt("matching_assignment_count", 0)),
    pass: eq("matching_assignment_count", 0),
  }),
  "AZURE-SUB-03": countDecision(["configured_contact_count"], {
    manual: unreadable,
    fail: eq("configured_contact_count", 0),
    pass: gt("configured_contact_count", 0),
  }),
  "AZURE-SUB-04": countDecision([], { manual: unreadable, warn: any(incomplete, empty), pass: gt("inventory_count", 0) }),
  "AZURE-SUB-05": countDecision(["privileged_service_principal_count"], {
    manual: any(unreadable, empty),
    fail: gt("privileged_service_principal_count", 0),
    warn: incomplete,
    pass: eq("privileged_service_principal_count", 0),
  }),
  "AZURE-DP-01": countDecision(["license_present", "device_count", "device_policy_with_required_settings_count", "noncompliant_device_count", "unknown_device_count"], {
    manual: any(unreadable, ne("license_present", true), all(gt("inventory_count", 0), eq("device_count", 0))),
    fail: any(eq("inventory_count", 0), eq("device_policy_with_required_settings_count", 0), gt("noncompliant_device_count", 0)),
    warn: any(incomplete, gt("unknown_device_count", 0)),
    pass: { op: "always" },
  }),
  "AZURE-DP-03": countDecision(["active_sensitivity_record_count"], {
    manual: unreadable,
    fail: eq("active_sensitivity_record_count", 0),
    warn: incomplete,
    pass: gt("active_sensitivity_record_count", 0),
  }),
  "AZURE-DP-04": countDecision(["missing_protection_count", "access_policy_vault_count", "open_network_count"], {
    manual: any(unreadable, empty),
    fail: gt("missing_protection_count", 0),
    warn: any(incomplete, gt("access_policy_vault_count", 0), gt("open_network_count", 0)),
    pass: { op: "always" },
  }),
  "AZURE-DP-05": countDecision(["http_allowed_count", "public_blob_count", "public_blob_unset_count", "weak_tls_count"], {
    manual: any(unreadable, empty),
    fail: any(gt("http_allowed_count", 0), gt("public_blob_count", 0)),
    warn: any(incomplete, gt("public_blob_unset_count", 0), gt("weak_tls_count", 0)),
    pass: { op: "always" },
  }),
  "AZURE-DP-06": countDecision(["mailbox_read_count", "mailbox_unreadable_count", "forwarding_rule_count"], {
    manual: any(unreadable, empty),
    fail: gt("forwarding_rule_count", 0),
    warn: any(incomplete, gt("mailbox_unreadable_count", 0)),
    pass: eq("forwarding_rule_count", 0),
  }, undefined),
  "AZURE-DP-08": {
    inputs: inputs("readable", "capability_present", "capability", "domain_allowlist", "external_resharing"),
    rules: ordered({
      manual: any(unreadable, ne("capability_present", true)),
      fail: all(ne("capability", "disabled"), ne("capability", "existingexternalusersharingonly"), ne("capability", "externalusersharingonly")),
      warn: any(eq("external_resharing", true), all(eq("capability", "externalusersharingonly"), ne("domain_allowlist", true))),
      pass: { op: "always" },
    }),
  },
  "AZURE-NP-01": countDecision(["exposed_rule_count"], {
    manual: any(unreadable, empty),
    fail: gt("exposed_rule_count", 0),
    warn: incomplete,
    pass: eq("exposed_rule_count", 0),
  }, { administrative_ports: AZURE_ADMIN_PORTS }),
  "AZURE-NP-02": countDecision(["assignment_not_do_not_enforce_count"], {
    manual: unreadable,
    fail: any(empty, eq("assignment_not_do_not_enforce_count", 0)),
    warn: any(incomplete, { op: "not", condition: comparePaths("eq", "assignment_not_do_not_enforce_count", "inventory_count") }),
    pass: comparePaths("eq", "assignment_not_do_not_enforce_count", "inventory_count"),
  }),
  "AZURE-NP-03": {
    inputs: inputs("readable", "resource_count_present", "policy_count_present", "noncompliant_policy_count"),
    rules: ordered({
      manual: any(unreadable, ne("resource_count_present", true), ne("policy_count_present", true)),
      warn: gt("noncompliant_policy_count", 0),
      pass: eq("noncompliant_policy_count", 0),
    }),
  },
  "AZURE-NP-04": countDecision(["covered_nsg_count", "uncovered_nsg_count"], {
    manual: any(unreadable, empty),
    fail: all(gt("uncovered_nsg_count", 0), eq("covered_nsg_count", 0)),
    warn: any(incomplete, gt("uncovered_nsg_count", 0)),
    pass: eq("uncovered_nsg_count", 0),
  }),
};

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
  decisionInputs: AZURE_DECISIONS[id]?.inputs,
  decisionRules: AZURE_DECISIONS[id]?.rules,
  constants: AZURE_DECISIONS[id]?.constants,
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
  knownGaps: [
    "Current-runtime limitation preserved for parity: AZURE-MON-06 caps pass only when the Log Analytics workspace inventory is truncated; truncation of diagnostic settings alone does not cap the finding. A runtime follow-up must make both dependencies completeness-gating.",
    "Certificate authentication, managed identity, several mailbox and device surfaces, alternate reporters, and standalone binaries are not shipped.",
  ],
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
