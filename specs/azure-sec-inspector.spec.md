---
slug: "azure-sec-inspector"
name: "Azure Security Inspector"
vendor: "Microsoft"
category: "cloud"
language: "language-neutral"
status: "generated"
version: "1.0.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# Azure Security Inspector

Portable contract for the shipped Microsoft Entra ID, Microsoft Graph, and Azure Resource Manager security assessments.

## Purpose

Give security and compliance teams a read-only, repeatable view of Microsoft Entra ID, Microsoft Graph, and Azure Resource Manager posture without treating denied, partial, or unavailable tenant evidence as compliance.

## Design guidance

Use a dedicated least-privilege audit application. Preserve cloud, subscription, license, API-version, permission, and pagination limits as evidence. Keep Exchange, Purview DLP, certificate-authentication, and Entra diagnostic-export gaps manual until the runtime ships decisive read surfaces.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- Microsoft Graph and Azure Resource Manager are collected independently; a token-request failure marks the dependent resource call not attempted.
- Certificate credentials, mailbox forwarding settings outside inbox rules, transport rules, and Entra diagnostic-export configuration are not implemented and remain explicit follow-ups.
- Every list verdict uses complete seen and total cardinalities; arrays retained in finding evidence are presentation samples only.
- Certificate authentication, managed identity, several mailbox and device surfaces, alternate reporters, and standalone binaries are not shipped.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `azure_check_access` | Validate read-only Azure audit access across Entra ID, Microsoft Graph security surfaces, and subscription-level ARM posture endpoints. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `azure_assess_identity` | Assess Entra ID posture: Conditional Access MFA and legacy auth, MFA registration, privileged roles and PIM, guest access, sign-in and user risk policies, risky users, app registration credentials, and tenant-wide consent grants. | `AZURE-ID-01`, `AZURE-ID-02`, `AZURE-ID-03`, `AZURE-ID-04`, `AZURE-ID-05`, `AZURE-ID-06`, `AZURE-ID-07`, `AZURE-ID-08`, `AZURE-ID-09`, `AZURE-ID-10`, `AZURE-ID-11`, `AZURE-ID-12`, `AZURE-ID-13` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `azure_assess_monitoring` | Assess Secure Score, directory audit and sign-in visibility, Defender for Cloud plan coverage, subscription diagnostic settings, and Log Analytics retention depth. | `AZURE-MON-01`, `AZURE-MON-02`, `AZURE-MON-03`, `AZURE-MON-04`, `AZURE-MON-05`, `AZURE-MON-06`, `AZURE-MON-07` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `azure_assess_subscription_guardrails` | Assess Azure subscription guardrails: Owner and Contributor sprawl at subscription scope, Defender for Cloud security contacts, Network Watcher presence, and service principals holding Owner or Contributor. | `AZURE-SUB-01`, `AZURE-SUB-02`, `AZURE-SUB-03`, `AZURE-SUB-04`, `AZURE-SUB-05` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `azure_assess_data_protection` | Assess Intune device compliance, DLP policy evidence, sensitivity labels (Graph beta), Key Vault soft delete, purge protection, RBAC and network ACLs, storage HTTPS-only, public blob access and TLS, inbox forwarding rules, and SharePoint external sharing. | `AZURE-DP-01`, `AZURE-DP-02`, `AZURE-DP-03`, `AZURE-DP-04`, `AZURE-DP-05`, `AZURE-DP-06`, `AZURE-DP-07`, `AZURE-DP-08` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `azure_assess_network_and_policy` | Assess NSG inbound rules exposing admin ports to any source, NSG flow log coverage per Network Watcher, Azure Policy assignment enforcement, and Azure Policy compliance state. | `AZURE-NP-01`, `AZURE-NP-02`, `AZURE-NP-03`, `AZURE-NP-04` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `azure_export_audit_bundle` | Export an Azure audit package with access checks, all five assessments, per-framework compliance reports, JSON analysis, an errors log on partial failure, and a zip archive. | `AZURE-ID-01`, `AZURE-ID-02`, `AZURE-ID-03`, `AZURE-ID-04`, `AZURE-ID-05`, `AZURE-ID-06`, `AZURE-ID-07`, `AZURE-ID-08`, `AZURE-ID-09`, `AZURE-ID-10`, `AZURE-ID-11`, `AZURE-ID-12`, `AZURE-ID-13`, `AZURE-MON-01`, `AZURE-MON-02`, `AZURE-MON-03`, `AZURE-MON-04`, `AZURE-MON-05`, `AZURE-MON-06`, `AZURE-MON-07`, `AZURE-SUB-01`, `AZURE-SUB-02`, `AZURE-SUB-03`, `AZURE-SUB-04`, `AZURE-SUB-05`, `AZURE-DP-01`, `AZURE-DP-02`, `AZURE-DP-03`, `AZURE-DP-04`, `AZURE-DP-05`, `AZURE-DP-06`, `AZURE-DP-07`, `AZURE-DP-08`, `AZURE-NP-01`, `AZURE-NP-02`, `AZURE-NP-03`, `AZURE-NP-04` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `azure_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `tenant_id` | string | no | Azure tenant ID. Defaults to AZURE_TENANT_ID or az account show. |
| `subscription_id` | string | no | Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID or az account show. |
| `graph_token` | string | no | Explicit Microsoft Graph bearer token. Defaults to AZURE_GRAPH_TOKEN, client credentials, or az account get-access-token. |
| `management_token` | string | no | Explicit ARM bearer token. Defaults to AZURE_MANAGEMENT_TOKEN, client credentials, or az account get-access-token. |
| `client_id` | string | no | App registration client ID for the OAuth 2.0 client credentials flow. Defaults to AZURE_CLIENT_ID. |
| `client_secret` | string | no | Client secret for the client credentials flow. Defaults to AZURE_CLIENT_SECRET. |
| `authority_host` | string | no | Authority host: login.microsoftonline.com (default), login.microsoftonline.us (US Government), login.chinacloudapi.cn or login.partner.microsoftonline.cn (China). Defaults to AZURE_AUTHORITY_HOST. |

#### `azure_assess_identity`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `tenant_id` | string | no | Azure tenant ID. Defaults to AZURE_TENANT_ID or az account show. |
| `subscription_id` | string | no | Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID or az account show. |
| `graph_token` | string | no | Explicit Microsoft Graph bearer token. Defaults to AZURE_GRAPH_TOKEN, client credentials, or az account get-access-token. |
| `management_token` | string | no | Explicit ARM bearer token. Defaults to AZURE_MANAGEMENT_TOKEN, client credentials, or az account get-access-token. |
| `client_id` | string | no | App registration client ID for the OAuth 2.0 client credentials flow. Defaults to AZURE_CLIENT_ID. |
| `client_secret` | string | no | Client secret for the client credentials flow. Defaults to AZURE_CLIENT_SECRET. |
| `authority_host` | string | no | Authority host: login.microsoftonline.com (default), login.microsoftonline.us (US Government), login.chinacloudapi.cn or login.partner.microsoftonline.cn (China). Defaults to AZURE_AUTHORITY_HOST. |

#### `azure_assess_monitoring`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `tenant_id` | string | no | Azure tenant ID. Defaults to AZURE_TENANT_ID or az account show. |
| `subscription_id` | string | no | Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID or az account show. |
| `graph_token` | string | no | Explicit Microsoft Graph bearer token. Defaults to AZURE_GRAPH_TOKEN, client credentials, or az account get-access-token. |
| `management_token` | string | no | Explicit ARM bearer token. Defaults to AZURE_MANAGEMENT_TOKEN, client credentials, or az account get-access-token. |
| `client_id` | string | no | App registration client ID for the OAuth 2.0 client credentials flow. Defaults to AZURE_CLIENT_ID. |
| `client_secret` | string | no | Client secret for the client credentials flow. Defaults to AZURE_CLIENT_SECRET. |
| `authority_host` | string | no | Authority host: login.microsoftonline.com (default), login.microsoftonline.us (US Government), login.chinacloudapi.cn or login.partner.microsoftonline.cn (China). Defaults to AZURE_AUTHORITY_HOST. |

#### `azure_assess_subscription_guardrails`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `tenant_id` | string | no | Azure tenant ID. Defaults to AZURE_TENANT_ID or az account show. |
| `subscription_id` | string | no | Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID or az account show. |
| `graph_token` | string | no | Explicit Microsoft Graph bearer token. Defaults to AZURE_GRAPH_TOKEN, client credentials, or az account get-access-token. |
| `management_token` | string | no | Explicit ARM bearer token. Defaults to AZURE_MANAGEMENT_TOKEN, client credentials, or az account get-access-token. |
| `client_id` | string | no | App registration client ID for the OAuth 2.0 client credentials flow. Defaults to AZURE_CLIENT_ID. |
| `client_secret` | string | no | Client secret for the client credentials flow. Defaults to AZURE_CLIENT_SECRET. |
| `authority_host` | string | no | Authority host: login.microsoftonline.com (default), login.microsoftonline.us (US Government), login.chinacloudapi.cn or login.partner.microsoftonline.cn (China). Defaults to AZURE_AUTHORITY_HOST. |
| `max_assignments` | number | no | Maximum ARM role assignments to sample. Defaults to 500. |

#### `azure_assess_data_protection`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `tenant_id` | string | no | Azure tenant ID. Defaults to AZURE_TENANT_ID or az account show. |
| `subscription_id` | string | no | Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID or az account show. |
| `graph_token` | string | no | Explicit Microsoft Graph bearer token. Defaults to AZURE_GRAPH_TOKEN, client credentials, or az account get-access-token. |
| `management_token` | string | no | Explicit ARM bearer token. Defaults to AZURE_MANAGEMENT_TOKEN, client credentials, or az account get-access-token. |
| `client_id` | string | no | App registration client ID for the OAuth 2.0 client credentials flow. Defaults to AZURE_CLIENT_ID. |
| `client_secret` | string | no | Client secret for the client credentials flow. Defaults to AZURE_CLIENT_SECRET. |
| `authority_host` | string | no | Authority host: login.microsoftonline.com (default), login.microsoftonline.us (US Government), login.chinacloudapi.cn or login.partner.microsoftonline.cn (China). Defaults to AZURE_AUTHORITY_HOST. |
| `max_mailboxes` | number | no | Maximum member mailboxes to inspect for inbox forwarding rules. Defaults to 100. |

#### `azure_assess_network_and_policy`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `tenant_id` | string | no | Azure tenant ID. Defaults to AZURE_TENANT_ID or az account show. |
| `subscription_id` | string | no | Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID or az account show. |
| `graph_token` | string | no | Explicit Microsoft Graph bearer token. Defaults to AZURE_GRAPH_TOKEN, client credentials, or az account get-access-token. |
| `management_token` | string | no | Explicit ARM bearer token. Defaults to AZURE_MANAGEMENT_TOKEN, client credentials, or az account get-access-token. |
| `client_id` | string | no | App registration client ID for the OAuth 2.0 client credentials flow. Defaults to AZURE_CLIENT_ID. |
| `client_secret` | string | no | Client secret for the client credentials flow. Defaults to AZURE_CLIENT_SECRET. |
| `authority_host` | string | no | Authority host: login.microsoftonline.com (default), login.microsoftonline.us (US Government), login.chinacloudapi.cn or login.partner.microsoftonline.cn (China). Defaults to AZURE_AUTHORITY_HOST. |

#### `azure_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `tenant_id` | string | no | Azure tenant ID. Defaults to AZURE_TENANT_ID or az account show. |
| `subscription_id` | string | no | Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID or az account show. |
| `graph_token` | string | no | Explicit Microsoft Graph bearer token. Defaults to AZURE_GRAPH_TOKEN, client credentials, or az account get-access-token. |
| `management_token` | string | no | Explicit ARM bearer token. Defaults to AZURE_MANAGEMENT_TOKEN, client credentials, or az account get-access-token. |
| `client_id` | string | no | App registration client ID for the OAuth 2.0 client credentials flow. Defaults to AZURE_CLIENT_ID. |
| `client_secret` | string | no | Client secret for the client credentials flow. Defaults to AZURE_CLIENT_SECRET. |
| `authority_host` | string | no | Authority host: login.microsoftonline.com (default), login.microsoftonline.us (US Government), login.chinacloudapi.cn or login.partner.microsoftonline.cn (China). Defaults to AZURE_AUTHORITY_HOST. |
| `output_dir` | string | no | Output root. Defaults to ./export/azure. |
| `max_assignments` | number | no | Maximum ARM role assignments to sample. Defaults to 500. |
| `max_mailboxes` | number | no | Maximum member mailboxes to inspect for inbox forwarding rules. Defaults to 100. |


## Authentication

Supported modes:

- Explicit Microsoft Graph and Azure Resource Manager bearer tokens
- Azure CLI token discovery
- OAuth client credentials

Credential precedence, highest first:

1. Explicit tool arguments
2. AZURE_* environment variables
3. Azure CLI
4. OAuth client credentials when a token is absent

Environment variables: `AZURE_AUTHORITY_HOST`, `AZURE_GRAPH_HOST`, `AZURE_MANAGEMENT_HOST`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_CLIENT_CERTIFICATE_PATH`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_GRAPH_TOKEN`, `AZURE_MANAGEMENT_TOKEN`, `AZURE_ACCESS_TOKEN`

Configuration locations: Azure CLI account context

Credential and deployment variants: Azure public cloud, Azure US Government, Azure China

Configuration fields: None

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

Credential refresh: POST /{tenant}/oauth2/v2.0/token using client_credentials independently for Microsoft Graph and Azure Resource Manager scopes.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| oauth-scope | `Documented Microsoft Graph application read permissions named by each failed surface` | `conditional-access`, `security-defaults`, `registration-details`, `directory-roles`, `directory-role-members`, `service-principals`, `pim-eligibilities`, `pim-assignments`, `authorization-policy`, `guest-users`, `subscribed-skus`, `risky-users`, `risk-detections`, `applications`, `permission-grants`, `secure-scores`, `directory-audits`, `sign-ins`, `compliance-policies`, `managed-devices`, `sensitivity-labels`, `member-users`, `message-rules`, `sharepoint-settings` |  |
| role | `Reader plus Security Reader and Monitoring Reader where required` | `defender-pricings`, `diagnostic-settings`, `log-workspaces`, `role-assignments`, `role-definitions`, `security-contacts`, `network-watchers`, `key-vaults`, `storage-accounts`, `network-security-groups`, `flow-logs`, `policy-assignments`, `policy-summary` |  |
| license | `Entra ID P1/P2 or Governance for reports, risk, and PIM surfaces` | `registration-details`, `risky-users`, `risk-detections`, `pim-eligibilities`, `pim-assignments` |  |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `conditional-access` | HTTP | `GET /v1.0/identity/conditionalAccess/policies` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `displayName`, `state`, `conditions`, `grantControls` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `security-defaults` | HTTP | `GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `isEnabled` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `registration-details` | HTTP | `GET /v1.0/reports/authenticationMethods/userRegistrationDetails` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `userPrincipalName`, `isMfaRegistered` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `directory-roles` | HTTP | `GET /v1.0/directoryRoles` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `displayName`, `roleTemplateId` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `directory-role-members` | HTTP | `GET /v1.0/directoryRoles/{id}/members` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `userPrincipalName`, `accountEnabled` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `service-principals` | HTTP | `GET /v1.0/servicePrincipals` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `displayName`, `passwordCredentials`, `keyCredentials` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `pim-eligibilities` | HTTP | `GET /v1.0/roleManagement/directory/roleEligibilitySchedules` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `principalId`, `roleDefinitionId`, `scheduleInfo` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `pim-assignments` | HTTP | `GET /v1.0/roleManagement/directory/roleAssignmentSchedules` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `principalId`, `roleDefinitionId`, `assignmentType`, `scheduleInfo` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `authorization-policy` | HTTP | `GET /v1.0/policies/authorizationPolicy` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `guestUserRoleId`, `allowInvitesFrom` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `guest-users` | HTTP | `GET /v1.0/users?$filter=userType eq 'Guest'` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `userPrincipalName`, `accountEnabled`, `signInActivity`, `externalUserState` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `subscribed-skus` | HTTP | `GET /v1.0/subscribedSkus` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `skuPartNumber`, `servicePlans` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `risky-users` | HTTP | `GET /v1.0/identityProtection/riskyUsers` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `riskLevel`, `riskState` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `risk-detections` | HTTP | `GET /v1.0/identityProtection/riskDetections` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `riskLevel`, `riskState`, `detectedDateTime` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `applications` | HTTP | `GET /v1.0/applications?$expand=owners` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `displayName`, `passwordCredentials`, `keyCredentials`, `owners` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `permission-grants` | HTTP | `GET /v1.0/oauth2PermissionGrants` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `clientId`, `consentType`, `scope` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `secure-scores` | HTTP | `GET /v1.0/security/secureScores` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `currentScore`, `maxScore` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `directory-audits` | HTTP | `GET /v1.0/auditLogs/directoryAudits` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `activityDateTime`, `activityDisplayName` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `sign-ins` | HTTP | `GET /v1.0/auditLogs/signIns` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `createdDateTime`, `status` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `defender-pricings` | HTTP | `GET /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `name`, `properties.pricingTier` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `diagnostic-settings` | HTTP | `GET /subscriptions/{subscriptionId}/providers/Microsoft.Insights/diagnosticSettings` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `properties.logs`, `properties.workspaceId`, `properties.storageAccountId`, `properties.eventHubAuthorizationRuleId` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `log-workspaces` | HTTP | `GET /subscriptions/{subscriptionId}/providers/Microsoft.OperationalInsights/workspaces` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `properties.retentionInDays` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `role-assignments` | HTTP | `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `properties.roleDefinitionId`, `properties.principalType` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `role-definitions` | HTTP | `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `properties.roleName` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `security-contacts` | HTTP | `GET /subscriptions/{subscriptionId}/providers/Microsoft.Security/securityContacts` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `properties.emails` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `network-watchers` | HTTP | `GET /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkWatchers` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `location` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `compliance-policies` | HTTP | `GET /beta/deviceManagement/deviceCompliancePolicies` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `displayName` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `managed-devices` | HTTP | `GET /v1.0/deviceManagement/managedDevices` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `deviceName`, `complianceState` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `sensitivity-labels` | HTTP | `GET /beta/security/informationProtection/sensitivityLabels` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `isActive`, `hasProtection` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `key-vaults` | HTTP | `GET /subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `name`, `properties.enableSoftDelete`, `properties.enablePurgeProtection`, `properties.enableRbacAuthorization`, `properties.networkAcls` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `storage-accounts` | HTTP | `GET /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `name`, `properties.supportsHttpsTrafficOnly`, `properties.allowBlobPublicAccess`, `properties.minimumTlsVersion`, `properties.encryption.keySource` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `member-users` | HTTP | `GET /v1.0/users?$filter=userType eq 'Member'` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `userPrincipalName`, `accountEnabled` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `message-rules` | HTTP | `GET /v1.0/users/{id}/mailFolders/inbox/messageRules` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `displayName`, `isEnabled`, `actions` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `sharepoint-settings` | HTTP | `GET /v1.0/admin/sharepoint/settings` | Microsoft Graph | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sharingCapability`, `sharingDomainRestrictionMode`, `isResharingByExternalUsersEnabled` | [Official documentation](https://learn.microsoft.com/en-us/graph/api/overview) |
| `network-security-groups` | HTTP | `GET /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `properties.securityRules` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `flow-logs` | HTTP | `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Network/networkWatchers/{watcher}/flowLogs` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `name`, `properties.enabled`, `properties.targetResourceId`, `properties.retentionPolicy` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `policy-assignments` | HTTP | `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `properties.policyDefinitionId`, `properties.enforcementMode` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |
| `policy-summary` | HTTP | `POST /subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize` | Azure Resource Manager | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `results.nonCompliantResources`, `results.nonCompliantPolicies` | [Official documentation](https://learn.microsoft.com/en-us/rest/api/azure/) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `conditional-access` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `conditional-access` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `conditional-access` | response | A JSON object or list containing only the documented id, displayName, state, conditions, grantControls members consumed by verdicts. | yes |
| `security-defaults` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `security-defaults` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `security-defaults` | response | A JSON object or list containing only the documented isEnabled members consumed by verdicts. | yes |
| `registration-details` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `registration-details` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `registration-details` | response | A JSON object or list containing only the documented id, userPrincipalName, isMfaRegistered members consumed by verdicts. | yes |
| `directory-roles` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `directory-roles` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `directory-roles` | response | A JSON object or list containing only the documented id, displayName, roleTemplateId members consumed by verdicts. | yes |
| `directory-role-members` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `directory-role-members` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `directory-role-members` | response | A JSON object or list containing only the documented id, userPrincipalName, accountEnabled members consumed by verdicts. | yes |
| `service-principals` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `service-principals` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `service-principals` | response | A JSON object or list containing only the documented id, displayName, passwordCredentials, keyCredentials members consumed by verdicts. | yes |
| `pim-eligibilities` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `pim-eligibilities` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `pim-eligibilities` | response | A JSON object or list containing only the documented principalId, roleDefinitionId, scheduleInfo members consumed by verdicts. | yes |
| `pim-assignments` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `pim-assignments` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `pim-assignments` | response | A JSON object or list containing only the documented principalId, roleDefinitionId, assignmentType, scheduleInfo members consumed by verdicts. | yes |
| `authorization-policy` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `authorization-policy` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `authorization-policy` | response | A JSON object or list containing only the documented guestUserRoleId, allowInvitesFrom members consumed by verdicts. | yes |
| `guest-users` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `guest-users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `guest-users` | response | A JSON object or list containing only the documented id, userPrincipalName, accountEnabled, signInActivity, externalUserState members consumed by verdicts. | yes |
| `subscribed-skus` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `subscribed-skus` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `subscribed-skus` | response | A JSON object or list containing only the documented skuPartNumber, servicePlans members consumed by verdicts. | yes |
| `risky-users` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `risky-users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `risky-users` | response | A JSON object or list containing only the documented id, riskLevel, riskState members consumed by verdicts. | yes |
| `risk-detections` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `risk-detections` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `risk-detections` | response | A JSON object or list containing only the documented id, riskLevel, riskState, detectedDateTime members consumed by verdicts. | yes |
| `applications` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `applications` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `applications` | response | A JSON object or list containing only the documented id, displayName, passwordCredentials, keyCredentials, owners members consumed by verdicts. | yes |
| `permission-grants` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `permission-grants` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `permission-grants` | response | A JSON object or list containing only the documented clientId, consentType, scope members consumed by verdicts. | yes |
| `secure-scores` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `secure-scores` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `secure-scores` | response | A JSON object or list containing only the documented currentScore, maxScore members consumed by verdicts. | yes |
| `directory-audits` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `directory-audits` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `directory-audits` | response | A JSON object or list containing only the documented id, activityDateTime, activityDisplayName members consumed by verdicts. | yes |
| `sign-ins` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `sign-ins` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `sign-ins` | response | A JSON object or list containing only the documented id, createdDateTime, status members consumed by verdicts. | yes |
| `defender-pricings` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `defender-pricings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `defender-pricings` | response | A JSON object or list containing only the documented name, properties.pricingTier members consumed by verdicts. | yes |
| `diagnostic-settings` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `diagnostic-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `diagnostic-settings` | response | A JSON object or list containing only the documented properties.logs, properties.workspaceId, properties.storageAccountId, properties.eventHubAuthorizationRuleId members consumed by verdicts. | yes |
| `log-workspaces` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `log-workspaces` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `log-workspaces` | response | A JSON object or list containing only the documented id, properties.retentionInDays members consumed by verdicts. | yes |
| `role-assignments` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `role-assignments` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `role-assignments` | response | A JSON object or list containing only the documented id, properties.roleDefinitionId, properties.principalType members consumed by verdicts. | yes |
| `role-definitions` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `role-definitions` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `role-definitions` | response | A JSON object or list containing only the documented id, properties.roleName members consumed by verdicts. | yes |
| `security-contacts` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `security-contacts` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `security-contacts` | response | A JSON object or list containing only the documented properties.emails members consumed by verdicts. | yes |
| `network-watchers` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `network-watchers` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `network-watchers` | response | A JSON object or list containing only the documented id, name, location members consumed by verdicts. | yes |
| `compliance-policies` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `compliance-policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `compliance-policies` | response | A JSON object or list containing only the documented id, displayName members consumed by verdicts. | yes |
| `managed-devices` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `managed-devices` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `managed-devices` | response | A JSON object or list containing only the documented id, deviceName, complianceState members consumed by verdicts. | yes |
| `sensitivity-labels` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `sensitivity-labels` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `sensitivity-labels` | response | A JSON object or list containing only the documented id, name, isActive, hasProtection members consumed by verdicts. | yes |
| `key-vaults` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `key-vaults` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `key-vaults` | response | A JSON object or list containing only the documented name, properties.enableSoftDelete, properties.enablePurgeProtection, properties.enableRbacAuthorization, properties.networkAcls members consumed by verdicts. | yes |
| `storage-accounts` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `storage-accounts` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `storage-accounts` | response | A JSON object or list containing only the documented name, properties.supportsHttpsTrafficOnly, properties.allowBlobPublicAccess, properties.minimumTlsVersion, properties.encryption.keySource members consumed by verdicts. | yes |
| `member-users` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `member-users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `member-users` | response | A JSON object or list containing only the documented id, userPrincipalName, accountEnabled members consumed by verdicts. | yes |
| `message-rules` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `message-rules` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `message-rules` | response | A JSON object or list containing only the documented id, displayName, isEnabled, actions members consumed by verdicts. | yes |
| `sharepoint-settings` | client | Use the configured Microsoft Graph origin; never follow a server link to a different origin. | yes |
| `sharepoint-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `sharepoint-settings` | response | A JSON object or list containing only the documented sharingCapability, sharingDomainRestrictionMode, isResharingByExternalUsersEnabled members consumed by verdicts. | yes |
| `network-security-groups` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `network-security-groups` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `network-security-groups` | response | A JSON object or list containing only the documented id, name, properties.securityRules members consumed by verdicts. | yes |
| `flow-logs` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `flow-logs` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `flow-logs` | response | A JSON object or list containing only the documented name, properties.enabled, properties.targetResourceId, properties.retentionPolicy members consumed by verdicts. | yes |
| `policy-assignments` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `policy-assignments` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `policy-assignments` | response | A JSON object or list containing only the documented id, properties.policyDefinitionId, properties.enforcementMode members consumed by verdicts. | yes |
| `policy-summary` | client | Use the configured Azure Resource Manager origin; never follow a server link to a different origin. | yes |
| `policy-summary` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `policy-summary` | response | A JSON object or list containing only the documented results.nonCompliantResources, results.nonCompliantPolicies members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `conditional-access`, `registration-details`, `directory-roles`, `directory-role-members`, `service-principals`, `pim-eligibilities`, `pim-assignments`, `guest-users`, `subscribed-skus`, `risky-users`, `risk-detections`, `applications`, `permission-grants`, `secure-scores`, `directory-audits`, `sign-ins`, `defender-pricings`, `diagnostic-settings`, `log-workspaces`, `role-assignments`, `role-definitions`, `security-contacts`, `network-watchers`, `compliance-policies`, `managed-devices`, `sensitivity-labels`, `key-vaults`, `storage-accounts`, `member-users`, `message-rules`, `network-security-groups`, `flow-logs`, `policy-assignments` | `@odata.nextLink`, `nextLink`, `next_page_link`, `totalCount` | service default | caller limit | 100 | Completion requires cursor exhaustion or reaching a declared total; a rejected next link, repeated cursor, empty page with a cursor, page cap, item cap, or missing total is partial. | Cursor exhausted; Declared total reached; Repeated cursor; Empty page with cursor; Cross-origin or user-information next link; Page or item cap |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Azure Security Inspector | Service and endpoint specific | `Retry-After`, `x-ms-ratelimit-remaining-*` | 429, 500, 502, 503, 504 | Honor bounded Retry-After and use bounded exponential retry; exhausted reads remain unreadable. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | Conditional Access MFA baseline | AZURE-ID-01 | Evaluate the ordered first-match rules for AZURE-ID-01 below. |
| 2 | MFA registration coverage | AZURE-ID-03 | Evaluate the ordered first-match rules for AZURE-ID-03 below. |
| 3 | Secure Score posture | AZURE-MON-01 | Evaluate the ordered first-match rules for AZURE-MON-01 below. |
| 4 | Legacy authentication blocking | AZURE-ID-02 | Evaluate the ordered first-match rules for AZURE-ID-02 below. |
| 5 | Privileged Identity Management eligibility | AZURE-ID-04, AZURE-ID-06 | Evaluate the ordered first-match rules for AZURE-ID-04, AZURE-ID-06 below. |
| 6 | Guest account hygiene | AZURE-ID-07, AZURE-ID-08 | Evaluate the ordered first-match rules for AZURE-ID-07, AZURE-ID-08 below. |
| 7 | Risky users and detections | AZURE-ID-09, AZURE-ID-11 | Evaluate the ordered first-match rules for AZURE-ID-09, AZURE-ID-11 below. |
| 8 | User risk policy | AZURE-ID-10 | Evaluate the ordered first-match rules for AZURE-ID-10 below. |
| 9 | Device compliance enforcement | AZURE-DP-01 | Evaluate the ordered first-match rules for AZURE-DP-01 below. |
| 10 | Data Loss Prevention policies | AZURE-DP-02 | Evaluate the ordered first-match rules for AZURE-DP-02 below. |
| 11 | Sensitivity labels published | AZURE-DP-03 | Evaluate the ordered first-match rules for AZURE-DP-03 below. |
| 12 | Unrestricted inbound admin ports | AZURE-NP-01 | Evaluate the ordered first-match rules for AZURE-NP-01 below. |
| 13 | Key Vault protection settings | AZURE-DP-04 | Evaluate the ordered first-match rules for AZURE-DP-04 below. |
| 14 | Storage account transport and access settings | AZURE-DP-05 | Evaluate the ordered first-match rules for AZURE-DP-05 below. |
| 15 | Subscription diagnostic settings | AZURE-MON-05 | Evaluate the ordered first-match rules for AZURE-MON-05 below. |
| 16 | Defender for Cloud plan coverage | AZURE-MON-04 | Evaluate the ordered first-match rules for AZURE-MON-04 below. |
| 17 | Contributor assignments at subscription scope | AZURE-SUB-01, AZURE-SUB-02 | Evaluate the ordered first-match rules for AZURE-SUB-01, AZURE-SUB-02 below. |
| 18 | Security contacts configured | AZURE-SUB-03 | Evaluate the ordered first-match rules for AZURE-SUB-03 below. |
| 19 | Entra ID audit log export | AZURE-MON-02, AZURE-MON-03, AZURE-MON-06, AZURE-MON-07 | Evaluate the ordered first-match rules for AZURE-MON-02, AZURE-MON-03, AZURE-MON-06, AZURE-MON-07 below. |
| 20 | Mailbox-level forwarding and transport rules | AZURE-DP-06, AZURE-DP-07 | Evaluate the ordered first-match rules for AZURE-DP-06, AZURE-DP-07 below. |
| 21 | SharePoint external sharing | AZURE-DP-08 | Evaluate the ordered first-match rules for AZURE-DP-08 below. |
| 22 | Tenant-wide delegated permission grants | AZURE-ID-12, AZURE-ID-13 | Evaluate the ordered first-match rules for AZURE-ID-12, AZURE-ID-13 below. |
| 23 | Privileged service principals at subscription scope | AZURE-ID-05, AZURE-SUB-05 | Evaluate the ordered first-match rules for AZURE-ID-05, AZURE-SUB-05 below. |
| 24 | NSG flow logs enabled | AZURE-SUB-04, AZURE-NP-04 | Evaluate the ordered first-match rules for AZURE-SUB-04, AZURE-NP-04 below. |
| 25 | Azure Policy compliance state | AZURE-NP-02, AZURE-NP-03 | Evaluate the ordered first-match rules for AZURE-NP-02, AZURE-NP-03 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `AZURE-ID-01` | high | `azure_assess_identity` | `conditional-access`, `security-defaults` | `policy_readable`, `complete`, `policy_count`, `mfa_policy_count`, `security_defaults_readable`, `security_defaults_enabled` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Conditional Access MFA baseline from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Conditional Access MFA baseline from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Conditional Access MFA baseline from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Conditional Access MFA baseline is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-02` | high | `azure_assess_identity` | `conditional-access`, `security-defaults` | `policy_readable`, `complete`, `legacy_block_policy_count`, `security_defaults_readable`, `security_defaults_enabled` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Legacy authentication blocking from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Legacy authentication blocking from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Legacy authentication blocking from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Legacy authentication blocking is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-03` | high | `azure_assess_identity` | `registration-details` | `readable`, `complete`, `inventory_count`, `without_mfa_count`, `without_mfa_ratio` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate MFA registration coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate MFA registration coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate MFA registration coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for MFA registration coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-04` | high | `azure_assess_identity` | `directory-roles`, `directory-role-members` | `readable`, `complete`, `inventory_count`, `global_admin_count`, `privileged_assignment_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Privileged directory role sprawl from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Privileged directory role sprawl from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Privileged directory role sprawl from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Privileged directory role sprawl is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-05` | medium | `azure_assess_identity` | `service-principals` | `readable`, `complete`, `inventory_count`, `expired_credential_count`, `expiring_credential_count`, `missing_expiry_count`, `long_lived_credential_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Service principal credential hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Service principal credential hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Service principal credential hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Service principal credential hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-06` | high | `azure_assess_identity` | `pim-eligibilities`, `pim-assignments` | `readable`, `complete`, `inventory_count`, `eligible_assignment_count`, `permanent_privileged_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Privileged Identity Management eligibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Privileged Identity Management eligibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Privileged Identity Management eligibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Privileged Identity Management eligibility is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-07` | medium | `azure_assess_identity` | `authorization-policy` | `readable`, `guest_role_present`, `guest_role_restricted`, `guest_role_same_as_member`, `invites_restricted`, `invites_from_everyone` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Guest access restrictions from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Guest access restrictions from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Guest access restrictions from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Guest access restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-08` | medium | `azure_assess_identity` | `guest-users` | `readable`, `complete`, `inventory_count`, `stale_guest_count`, `unknown_activity_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Guest account hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Guest account hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Guest account hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Guest account hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-09` | high | `azure_assess_identity` | `conditional-access`, `subscribed-skus` | `readable`, `complete`, `inventory_count`, `license_present`, `enforcing_policy_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Sign-in risk policy from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Sign-in risk policy from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Sign-in risk policy from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Sign-in risk policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-10` | high | `azure_assess_identity` | `conditional-access`, `subscribed-skus` | `readable`, `complete`, `inventory_count`, `license_present`, `enforcing_policy_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate User risk policy from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate User risk policy from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate User risk policy from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for User risk policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-11` | high | `azure_assess_identity` | `risky-users`, `risk-detections` | `readable`, `complete`, `inventory_count`, `high_risk_user_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Risky users and detections from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Risky users and detections from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Risky users and detections from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Risky users and detections is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-12` | medium | `azure_assess_identity` | `applications` | `readable`, `complete`, `inventory_count`, `expired_credential_count`, `expiring_credential_count`, `missing_expiry_count`, `long_lived_credential_count`, `ownerless_application_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate App registration credential and owner hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate App registration credential and owner hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate App registration credential and owner hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for App registration credential and owner hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-ID-13` | high | `azure_assess_identity` | `permission-grants` | `readable`, `complete`, `inventory_count`, `risky_grant_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Tenant-wide delegated permission grants from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Tenant-wide delegated permission grants from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Tenant-wide delegated permission grants from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Tenant-wide delegated permission grants is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-MON-01` | medium | `azure_assess_monitoring` | `secure-scores` | `readable`, `maximum_score`, `score_ratio` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Secure Score posture from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Secure Score posture from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Secure Score posture from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Secure Score posture is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-MON-02` | medium | `azure_assess_monitoring` | `directory-audits` | `readable`, `complete`, `inventory_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Directory audit visibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Directory audit visibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Directory audit visibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Directory audit visibility is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-MON-03` | medium | `azure_assess_monitoring` | `sign-ins` | `readable`, `complete`, `inventory_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Sign-in telemetry visibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Sign-in telemetry visibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Sign-in telemetry visibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Sign-in telemetry visibility is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-MON-04` | high | `azure_assess_monitoring` | `defender-pricings` | `readable`, `complete`, `inventory_count`, `standard_plan_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Defender for Cloud plan coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Defender for Cloud plan coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Defender for Cloud plan coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Defender for Cloud plan coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-MON-05` | high | `azure_assess_monitoring` | `diagnostic-settings` | `readable`, `complete`, `inventory_count`, `effective_setting_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Subscription diagnostic settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Subscription diagnostic settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Subscription diagnostic settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Subscription diagnostic settings is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-MON-06` | high | `azure_assess_monitoring` | `diagnostic-settings`, `log-workspaces` | `readable`, `complete`, `inventory_count`, `destination_workspace_count`, `linked_workspace_count`, `workspace_retention_at_least_minimum_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Activity log retention depth from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Activity log retention depth from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Activity log retention depth from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Activity log retention depth is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-MON-07` | medium | `azure_assess_monitoring` | None | None | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Entra ID audit log export from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Entra ID audit log export from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Entra ID audit log export from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Entra ID audit log export is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-SUB-01` | high | `azure_assess_subscription_guardrails` | `role-assignments`, `role-definitions` | `readable`, `complete`, `inventory_count`, `matching_assignment_count`, `warn_maximum` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Owner assignments at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Owner assignments at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Owner assignments at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Owner assignments at subscription scope is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-SUB-02` | medium | `azure_assess_subscription_guardrails` | `role-assignments`, `role-definitions` | `readable`, `complete`, `inventory_count`, `matching_assignment_count`, `warn_maximum` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Contributor assignments at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Contributor assignments at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Contributor assignments at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Contributor assignments at subscription scope is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-SUB-03` | medium | `azure_assess_subscription_guardrails` | `security-contacts` | `readable`, `complete`, `inventory_count`, `configured_contact_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Security contacts configured from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Security contacts configured from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Security contacts configured from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Security contacts configured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-SUB-04` | medium | `azure_assess_subscription_guardrails` | `network-watchers` | `readable`, `complete`, `inventory_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Network Watcher coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Network Watcher coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Network Watcher coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Network Watcher coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-SUB-05` | high | `azure_assess_subscription_guardrails` | `role-assignments`, `role-definitions` | `readable`, `complete`, `inventory_count`, `privileged_service_principal_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Privileged service principals at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Privileged service principals at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Privileged service principals at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Privileged service principals at subscription scope is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-DP-01` | high | `azure_assess_data_protection` | `subscribed-skus`, `compliance-policies`, `managed-devices`, `conditional-access` | `readable`, `complete`, `inventory_count`, `license_present`, `device_count`, `device_policy_with_required_settings_count`, `noncompliant_device_count`, `unknown_device_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Device compliance enforcement from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Device compliance enforcement from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Device compliance enforcement from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Device compliance enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-DP-02` | medium | `azure_assess_data_protection` | None | None | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Data Loss Prevention policies from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Data Loss Prevention policies from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Data Loss Prevention policies from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Data Loss Prevention policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-DP-03` | medium | `azure_assess_data_protection` | `sensitivity-labels` | `readable`, `complete`, `inventory_count`, `active_sensitivity_record_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Sensitivity labels published from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Sensitivity labels published from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Sensitivity labels published from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Sensitivity labels published is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-DP-04` | high | `azure_assess_data_protection` | `key-vaults` | `readable`, `complete`, `inventory_count`, `missing_protection_count`, `access_policy_vault_count`, `open_network_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Key Vault protection settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Key Vault protection settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Key Vault protection settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Key Vault protection settings is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-DP-05` | high | `azure_assess_data_protection` | `storage-accounts` | `readable`, `complete`, `inventory_count`, `http_allowed_count`, `public_blob_count`, `public_blob_unset_count`, `weak_tls_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Storage account transport and access settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Storage account transport and access settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Storage account transport and access settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Storage account transport and access settings is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-DP-06` | high | `azure_assess_data_protection` | `member-users`, `message-rules` | `readable`, `complete`, `inventory_count`, `mailbox_read_count`, `mailbox_unreadable_count`, `forwarding_rule_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Inbox forwarding rules from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Inbox forwarding rules from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Inbox forwarding rules from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Inbox forwarding rules is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-DP-07` | high | `azure_assess_data_protection` | None | None | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Mailbox-level forwarding and transport rules from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Mailbox-level forwarding and transport rules from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Mailbox-level forwarding and transport rules from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Mailbox-level forwarding and transport rules is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-DP-08` | medium | `azure_assess_data_protection` | `sharepoint-settings` | `readable`, `capability_present`, `capability`, `domain_allowlist`, `external_resharing` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate SharePoint external sharing from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate SharePoint external sharing from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate SharePoint external sharing from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for SharePoint external sharing is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-NP-01` | critical | `azure_assess_network_and_policy` | `network-security-groups` | `readable`, `complete`, `inventory_count`, `exposed_rule_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Unrestricted inbound admin ports from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Unrestricted inbound admin ports from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Unrestricted inbound admin ports from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Unrestricted inbound admin ports is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-NP-02` | medium | `azure_assess_network_and_policy` | `policy-assignments` | `readable`, `complete`, `inventory_count`, `assignment_not_do_not_enforce_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Azure Policy assignments enforced from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Azure Policy assignments enforced from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Azure Policy assignments enforced from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Azure Policy assignments enforced is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-NP-03` | medium | `azure_assess_network_and_policy` | `policy-summary` | `readable`, `resource_count_present`, `policy_count_present`, `noncompliant_policy_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Azure Policy compliance state from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Azure Policy compliance state from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Azure Policy compliance state from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for Azure Policy compliance state is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `AZURE-NP-04` | medium | `azure_assess_network_and_policy` | `network-security-groups`, `network-watchers`, `flow-logs` | `readable`, `complete`, `inventory_count`, `covered_nsg_count`, `uncovered_nsg_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate NSG flow logs enabled from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate NSG flow logs enabled from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate NSG flow logs enabled from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | The required evidence for NSG flow logs enabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `AZURE-ID-01` | 1 | manual | `azure_id_01_branch_01_matches` equals true |  |
| `AZURE-ID-01` | 2 | fail | `azure_id_01_branch_02_matches` equals true |  |
| `AZURE-ID-01` | 3 | warn | `azure_id_01_branch_03_matches` equals true |  |
| `AZURE-ID-01` | 4 | pass | `azure_id_01_branch_04_matches` equals true |  |
| `AZURE-ID-01` | 5 | manual | `azure_id_01_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-ID-02` | 1 | manual | `azure_id_02_branch_01_matches` equals true |  |
| `AZURE-ID-02` | 2 | fail | `azure_id_02_branch_02_matches` equals true |  |
| `AZURE-ID-02` | 3 | warn | `azure_id_02_branch_03_matches` equals true |  |
| `AZURE-ID-02` | 4 | pass | `azure_id_02_branch_04_matches` equals true |  |
| `AZURE-ID-02` | 5 | manual | `azure_id_02_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-ID-03` | 1 | manual | `azure_id_03_branch_01_matches` equals true |  |
| `AZURE-ID-03` | 2 | fail | `azure_id_03_branch_02_matches` equals true |  |
| `AZURE-ID-03` | 3 | warn | `azure_id_03_branch_03_matches` equals true |  |
| `AZURE-ID-03` | 4 | pass | `azure_id_03_branch_04_matches` equals true |  |
| `AZURE-ID-03` | 5 | manual | `azure_id_03_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-ID-04` | 1 | manual | `azure_id_04_branch_01_matches` equals true |  |
| `AZURE-ID-04` | 2 | fail | `azure_id_04_branch_02_matches` equals true |  |
| `AZURE-ID-04` | 3 | warn | `azure_id_04_branch_03_matches` equals true |  |
| `AZURE-ID-04` | 4 | pass | `azure_id_04_branch_04_matches` equals true |  |
| `AZURE-ID-04` | 5 | manual | `azure_id_04_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-ID-05` | 1 | manual | `azure_id_05_branch_01_matches` equals true |  |
| `AZURE-ID-05` | 2 | fail | `azure_id_05_branch_02_matches` equals true |  |
| `AZURE-ID-05` | 3 | warn | `azure_id_05_branch_03_matches` equals true |  |
| `AZURE-ID-05` | 4 | pass | `azure_id_05_branch_04_matches` equals true |  |
| `AZURE-ID-06` | 1 | manual | `azure_id_06_branch_01_matches` equals true |  |
| `AZURE-ID-06` | 2 | fail | `azure_id_06_branch_02_matches` equals true |  |
| `AZURE-ID-06` | 3 | warn | `azure_id_06_branch_03_matches` equals true |  |
| `AZURE-ID-06` | 4 | pass | `azure_id_06_branch_04_matches` equals true |  |
| `AZURE-ID-07` | 1 | manual | `azure_id_07_branch_01_matches` equals true |  |
| `AZURE-ID-07` | 2 | fail | `azure_id_07_branch_02_matches` equals true |  |
| `AZURE-ID-07` | 3 | warn | `azure_id_07_branch_03_matches` equals true |  |
| `AZURE-ID-07` | 4 | pass | `azure_id_07_branch_04_matches` equals true |  |
| `AZURE-ID-07` | 5 | manual | `azure_id_07_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-ID-08` | 1 | manual | `azure_id_08_branch_01_matches` equals true |  |
| `AZURE-ID-08` | 2 | fail | `azure_id_08_branch_02_matches` equals true |  |
| `AZURE-ID-08` | 3 | warn | `azure_id_08_branch_03_matches` equals true |  |
| `AZURE-ID-08` | 4 | pass | `azure_id_08_branch_04_matches` equals true |  |
| `AZURE-ID-09` | 1 | manual | `azure_id_09_branch_01_matches` equals true |  |
| `AZURE-ID-09` | 2 | fail | `azure_id_09_branch_02_matches` equals true |  |
| `AZURE-ID-09` | 3 | warn | `azure_id_09_branch_03_matches` equals true |  |
| `AZURE-ID-09` | 4 | pass | `azure_id_09_branch_04_matches` equals true |  |
| `AZURE-ID-09` | 5 | manual | `azure_id_09_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-ID-10` | 1 | manual | `azure_id_10_branch_01_matches` equals true |  |
| `AZURE-ID-10` | 2 | fail | `azure_id_10_branch_02_matches` equals true |  |
| `AZURE-ID-10` | 3 | warn | `azure_id_10_branch_03_matches` equals true |  |
| `AZURE-ID-10` | 4 | pass | `azure_id_10_branch_04_matches` equals true |  |
| `AZURE-ID-10` | 5 | manual | `azure_id_10_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-ID-11` | 1 | manual | `azure_id_11_branch_01_matches` equals true |  |
| `AZURE-ID-11` | 2 | fail | `azure_id_11_branch_02_matches` equals true |  |
| `AZURE-ID-11` | 3 | warn | `azure_id_11_branch_03_matches` equals true |  |
| `AZURE-ID-11` | 4 | pass | `azure_id_11_branch_04_matches` equals true |  |
| `AZURE-ID-11` | 5 | manual | `azure_id_11_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-ID-12` | 1 | manual | `azure_id_12_branch_01_matches` equals true |  |
| `AZURE-ID-12` | 2 | fail | `azure_id_12_branch_02_matches` equals true |  |
| `AZURE-ID-12` | 3 | warn | `azure_id_12_branch_03_matches` equals true |  |
| `AZURE-ID-12` | 4 | pass | `azure_id_12_branch_04_matches` equals true |  |
| `AZURE-ID-13` | 1 | manual | `azure_id_13_branch_01_matches` equals true |  |
| `AZURE-ID-13` | 2 | fail | `azure_id_13_branch_02_matches` equals true |  |
| `AZURE-ID-13` | 3 | warn | `azure_id_13_branch_03_matches` equals true |  |
| `AZURE-ID-13` | 4 | pass | `azure_id_13_branch_04_matches` equals true |  |
| `AZURE-ID-13` | 5 | manual | `azure_id_13_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-MON-01` | 1 | manual | `azure_mon_01_branch_01_matches` equals true |  |
| `AZURE-MON-01` | 2 | fail | `azure_mon_01_branch_02_matches` equals true |  |
| `AZURE-MON-01` | 3 | warn | `azure_mon_01_branch_03_matches` equals true |  |
| `AZURE-MON-01` | 4 | pass | `azure_mon_01_branch_04_matches` equals true |  |
| `AZURE-MON-01` | 5 | manual | `azure_mon_01_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-MON-02` | 1 | manual | `azure_mon_02_branch_01_matches` equals true |  |
| `AZURE-MON-02` | 2 | warn | `azure_mon_02_branch_02_matches` equals true |  |
| `AZURE-MON-02` | 3 | pass | `azure_mon_02_branch_03_matches` equals true |  |
| `AZURE-MON-02` | 4 | manual | `azure_mon_02_branch_04_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-MON-03` | 1 | manual | `azure_mon_03_branch_01_matches` equals true |  |
| `AZURE-MON-03` | 2 | warn | `azure_mon_03_branch_02_matches` equals true |  |
| `AZURE-MON-03` | 3 | pass | `azure_mon_03_branch_03_matches` equals true |  |
| `AZURE-MON-03` | 4 | manual | `azure_mon_03_branch_04_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-MON-04` | 1 | manual | `azure_mon_04_branch_01_matches` equals true |  |
| `AZURE-MON-04` | 2 | fail | `azure_mon_04_branch_02_matches` equals true |  |
| `AZURE-MON-04` | 3 | warn | `azure_mon_04_branch_03_matches` equals true |  |
| `AZURE-MON-04` | 4 | pass | `azure_mon_04_branch_04_matches` equals true |  |
| `AZURE-MON-04` | 5 | manual | `azure_mon_04_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-MON-05` | 1 | manual | `azure_mon_05_branch_01_matches` equals true |  |
| `AZURE-MON-05` | 2 | fail | `azure_mon_05_branch_02_matches` equals true |  |
| `AZURE-MON-05` | 3 | warn | `azure_mon_05_branch_03_matches` equals true |  |
| `AZURE-MON-05` | 4 | pass | `azure_mon_05_branch_04_matches` equals true |  |
| `AZURE-MON-05` | 5 | manual | `azure_mon_05_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-MON-06` | 1 | manual | `azure_mon_06_branch_01_matches` equals true |  |
| `AZURE-MON-06` | 2 | fail | `azure_mon_06_branch_02_matches` equals true |  |
| `AZURE-MON-06` | 3 | warn | `azure_mon_06_branch_03_matches` equals true |  |
| `AZURE-MON-06` | 4 | pass | `azure_mon_06_branch_04_matches` equals true |  |
| `AZURE-MON-06` | 5 | manual | `azure_mon_06_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-MON-07` | 1 | manual | `azure_mon_07_branch_01_matches` equals true | The shipped runtime has no decisive read surface for this check. |
| `AZURE-SUB-01` | 1 | manual | `azure_sub_01_branch_01_matches` equals true |  |
| `AZURE-SUB-01` | 2 | fail | `azure_sub_01_branch_02_matches` equals true |  |
| `AZURE-SUB-01` | 3 | warn | `azure_sub_01_branch_03_matches` equals true |  |
| `AZURE-SUB-01` | 4 | pass | `azure_sub_01_branch_04_matches` equals true |  |
| `AZURE-SUB-01` | 5 | manual | `azure_sub_01_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-SUB-02` | 1 | manual | `azure_sub_02_branch_01_matches` equals true |  |
| `AZURE-SUB-02` | 2 | fail | `azure_sub_02_branch_02_matches` equals true |  |
| `AZURE-SUB-02` | 3 | warn | `azure_sub_02_branch_03_matches` equals true |  |
| `AZURE-SUB-02` | 4 | pass | `azure_sub_02_branch_04_matches` equals true |  |
| `AZURE-SUB-02` | 5 | manual | `azure_sub_02_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-SUB-03` | 1 | manual | `azure_sub_03_branch_01_matches` equals true |  |
| `AZURE-SUB-03` | 2 | fail | `azure_sub_03_branch_02_matches` equals true |  |
| `AZURE-SUB-03` | 3 | pass | `azure_sub_03_branch_03_matches` equals true |  |
| `AZURE-SUB-03` | 4 | manual | `azure_sub_03_branch_04_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-SUB-04` | 1 | manual | `azure_sub_04_branch_01_matches` equals true |  |
| `AZURE-SUB-04` | 2 | warn | `azure_sub_04_branch_02_matches` equals true |  |
| `AZURE-SUB-04` | 3 | pass | `azure_sub_04_branch_03_matches` equals true |  |
| `AZURE-SUB-04` | 4 | manual | `azure_sub_04_branch_04_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-SUB-05` | 1 | manual | `azure_sub_05_branch_01_matches` equals true |  |
| `AZURE-SUB-05` | 2 | fail | `azure_sub_05_branch_02_matches` equals true |  |
| `AZURE-SUB-05` | 3 | warn | `azure_sub_05_branch_03_matches` equals true |  |
| `AZURE-SUB-05` | 4 | pass | `azure_sub_05_branch_04_matches` equals true |  |
| `AZURE-SUB-05` | 5 | manual | `azure_sub_05_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-DP-01` | 1 | manual | `azure_dp_01_branch_01_matches` equals true |  |
| `AZURE-DP-01` | 2 | fail | `azure_dp_01_branch_02_matches` equals true |  |
| `AZURE-DP-01` | 3 | warn | `azure_dp_01_branch_03_matches` equals true |  |
| `AZURE-DP-01` | 4 | pass | `azure_dp_01_branch_04_matches` equals true |  |
| `AZURE-DP-02` | 1 | manual | `azure_dp_02_branch_01_matches` equals true | The shipped runtime has no decisive read surface for this check. |
| `AZURE-DP-03` | 1 | manual | `azure_dp_03_branch_01_matches` equals true |  |
| `AZURE-DP-03` | 2 | fail | `azure_dp_03_branch_02_matches` equals true |  |
| `AZURE-DP-03` | 3 | warn | `azure_dp_03_branch_03_matches` equals true |  |
| `AZURE-DP-03` | 4 | pass | `azure_dp_03_branch_04_matches` equals true |  |
| `AZURE-DP-03` | 5 | manual | `azure_dp_03_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-DP-04` | 1 | manual | `azure_dp_04_branch_01_matches` equals true |  |
| `AZURE-DP-04` | 2 | fail | `azure_dp_04_branch_02_matches` equals true |  |
| `AZURE-DP-04` | 3 | warn | `azure_dp_04_branch_03_matches` equals true |  |
| `AZURE-DP-04` | 4 | pass | `azure_dp_04_branch_04_matches` equals true |  |
| `AZURE-DP-05` | 1 | manual | `azure_dp_05_branch_01_matches` equals true |  |
| `AZURE-DP-05` | 2 | fail | `azure_dp_05_branch_02_matches` equals true |  |
| `AZURE-DP-05` | 3 | warn | `azure_dp_05_branch_03_matches` equals true |  |
| `AZURE-DP-05` | 4 | pass | `azure_dp_05_branch_04_matches` equals true |  |
| `AZURE-DP-06` | 1 | manual | `azure_dp_06_branch_01_matches` equals true |  |
| `AZURE-DP-06` | 2 | fail | `azure_dp_06_branch_02_matches` equals true |  |
| `AZURE-DP-06` | 3 | warn | `azure_dp_06_branch_03_matches` equals true |  |
| `AZURE-DP-06` | 4 | pass | `azure_dp_06_branch_04_matches` equals true |  |
| `AZURE-DP-06` | 5 | manual | `azure_dp_06_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-DP-07` | 1 | manual | `azure_dp_07_branch_01_matches` equals true | The shipped runtime has no decisive read surface for this check. |
| `AZURE-DP-08` | 1 | manual | `azure_dp_08_branch_01_matches` equals true |  |
| `AZURE-DP-08` | 2 | fail | `azure_dp_08_branch_02_matches` equals true |  |
| `AZURE-DP-08` | 3 | warn | `azure_dp_08_branch_03_matches` equals true |  |
| `AZURE-DP-08` | 4 | pass | `azure_dp_08_branch_04_matches` equals true |  |
| `AZURE-NP-01` | 1 | manual | `azure_np_01_branch_01_matches` equals true |  |
| `AZURE-NP-01` | 2 | fail | `azure_np_01_branch_02_matches` equals true |  |
| `AZURE-NP-01` | 3 | warn | `azure_np_01_branch_03_matches` equals true |  |
| `AZURE-NP-01` | 4 | pass | `azure_np_01_branch_04_matches` equals true |  |
| `AZURE-NP-01` | 5 | manual | `azure_np_01_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-NP-02` | 1 | manual | `azure_np_02_branch_01_matches` equals true |  |
| `AZURE-NP-02` | 2 | fail | `azure_np_02_branch_02_matches` equals true |  |
| `AZURE-NP-02` | 3 | warn | `azure_np_02_branch_03_matches` equals true |  |
| `AZURE-NP-02` | 4 | pass | `azure_np_02_branch_04_matches` equals true |  |
| `AZURE-NP-02` | 5 | manual | `azure_np_02_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-NP-03` | 1 | manual | `azure_np_03_branch_01_matches` equals true |  |
| `AZURE-NP-03` | 2 | warn | `azure_np_03_branch_02_matches` equals true |  |
| `AZURE-NP-03` | 3 | pass | `azure_np_03_branch_03_matches` equals true |  |
| `AZURE-NP-03` | 4 | manual | `azure_np_03_branch_04_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |
| `AZURE-NP-04` | 1 | manual | `azure_np_04_branch_01_matches` equals true |  |
| `AZURE-NP-04` | 2 | fail | `azure_np_04_branch_02_matches` equals true |  |
| `AZURE-NP-04` | 3 | warn | `azure_np_04_branch_03_matches` equals true |  |
| `AZURE-NP-04` | 4 | pass | `azure_np_04_branch_04_matches` equals true |  |
| `AZURE-NP-04` | 5 | manual | `azure_np_04_branch_05_matches` equals true | Unknown, null, contradictory, or otherwise insufficient evidence requires manual review. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `AZURE-ID-01` | `azure_id_01_branch_01_matches` | AZURE-ID-01 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`policy_readable` does not equal true; all of (`mfa_policy_count` equals 0; `security_defaults_readable` does not equal true)). |
| `AZURE-ID-01` | `azure_id_01_branch_02_matches` | AZURE-ID-01 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: all of (`mfa_policy_count` equals 0; `security_defaults_enabled` equals false). |
| `AZURE-ID-01` | `azure_id_01_branch_03_matches` | AZURE-ID-01 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: `complete` does not equal true. |
| `AZURE-ID-01` | `azure_id_01_branch_04_matches` | AZURE-ID-01 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: any of (`mfa_policy_count` is greater than 0; `security_defaults_enabled` equals true). |
| `AZURE-ID-01` | `azure_id_01_branch_05_matches` | AZURE-ID-01 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-02` | `azure_id_02_branch_01_matches` | AZURE-ID-02 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`policy_readable` does not equal true; all of (`legacy_block_policy_count` equals 0; `security_defaults_readable` does not equal true)). |
| `AZURE-ID-02` | `azure_id_02_branch_02_matches` | AZURE-ID-02 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: all of (`legacy_block_policy_count` equals 0; `security_defaults_enabled` equals false). |
| `AZURE-ID-02` | `azure_id_02_branch_03_matches` | AZURE-ID-02 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: `complete` does not equal true. |
| `AZURE-ID-02` | `azure_id_02_branch_04_matches` | AZURE-ID-02 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: any of (`legacy_block_policy_count` is greater than 0; `security_defaults_enabled` equals true). |
| `AZURE-ID-02` | `azure_id_02_branch_05_matches` | AZURE-ID-02 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-03` | `azure_id_03_branch_01_matches` | AZURE-ID-03 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-ID-03` | `azure_id_03_branch_02_matches` | AZURE-ID-03 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `without_mfa_ratio` is greater than 0.1. |
| `AZURE-ID-03` | `azure_id_03_branch_03_matches` | AZURE-ID-03 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `without_mfa_count` is greater than 0). |
| `AZURE-ID-03` | `azure_id_03_branch_04_matches` | AZURE-ID-03 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `without_mfa_count` equals 0. |
| `AZURE-ID-03` | `azure_id_03_branch_05_matches` | AZURE-ID-03 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-04` | `azure_id_04_branch_01_matches` | AZURE-ID-04 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `privileged_assignment_count` equals 0). |
| `AZURE-ID-04` | `azure_id_04_branch_02_matches` | AZURE-ID-04 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: any of (`global_admin_count` is greater than 4; `privileged_assignment_count` is greater than 10). |
| `AZURE-ID-04` | `azure_id_04_branch_03_matches` | AZURE-ID-04 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `privileged_assignment_count` is greater than 5). |
| `AZURE-ID-04` | `azure_id_04_branch_04_matches` | AZURE-ID-04 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `privileged_assignment_count` is at most 5. |
| `AZURE-ID-04` | `azure_id_04_branch_05_matches` | AZURE-ID-04 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-05` | `azure_id_05_branch_01_matches` | AZURE-ID-05 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-ID-05` | `azure_id_05_branch_02_matches` | AZURE-ID-05 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `expired_credential_count` is greater than 0. |
| `AZURE-ID-05` | `azure_id_05_branch_03_matches` | AZURE-ID-05 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `expiring_credential_count` is greater than 0; `missing_expiry_count` is greater than 0; `long_lived_credential_count` is greater than 0). |
| `AZURE-ID-05` | `azure_id_05_branch_04_matches` | AZURE-ID-05 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-06` | `azure_id_06_branch_01_matches` | AZURE-ID-06 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; all of (`eligible_assignment_count` equals 0; `permanent_privileged_count` equals 0)). |
| `AZURE-ID-06` | `azure_id_06_branch_02_matches` | AZURE-ID-06 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `permanent_privileged_count` is greater than 2. |
| `AZURE-ID-06` | `azure_id_06_branch_03_matches` | AZURE-ID-06 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `permanent_privileged_count` is greater than 0; `eligible_assignment_count` equals 0). |
| `AZURE-ID-06` | `azure_id_06_branch_04_matches` | AZURE-ID-06 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-07` | `azure_id_07_branch_01_matches` | AZURE-ID-07 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `guest_role_present` does not equal true). |
| `AZURE-ID-07` | `azure_id_07_branch_02_matches` | AZURE-ID-07 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: any of (`guest_role_same_as_member` equals true; `invites_from_everyone` equals true). |
| `AZURE-ID-07` | `azure_id_07_branch_03_matches` | AZURE-ID-07 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`guest_role_restricted` does not equal true; `invites_restricted` does not equal true). |
| `AZURE-ID-07` | `azure_id_07_branch_04_matches` | AZURE-ID-07 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`guest_role_restricted` equals true; `invites_restricted` equals true). |
| `AZURE-ID-07` | `azure_id_07_branch_05_matches` | AZURE-ID-07 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-08` | `azure_id_08_branch_01_matches` | AZURE-ID-08 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: `readable` does not equal true. |
| `AZURE-ID-08` | `azure_id_08_branch_02_matches` | AZURE-ID-08 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `stale_guest_count` is greater than 0. |
| `AZURE-ID-08` | `azure_id_08_branch_03_matches` | AZURE-ID-08 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `unknown_activity_count` is greater than 0). |
| `AZURE-ID-08` | `azure_id_08_branch_04_matches` | AZURE-ID-08 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-09` | `azure_id_09_branch_01_matches` | AZURE-ID-09 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `license_present` does not equal true). |
| `AZURE-ID-09` | `azure_id_09_branch_02_matches` | AZURE-ID-09 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `enforcing_policy_count` equals 0. |
| `AZURE-ID-09` | `azure_id_09_branch_03_matches` | AZURE-ID-09 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: `complete` does not equal true. |
| `AZURE-ID-09` | `azure_id_09_branch_04_matches` | AZURE-ID-09 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `enforcing_policy_count` is greater than 0. |
| `AZURE-ID-09` | `azure_id_09_branch_05_matches` | AZURE-ID-09 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-10` | `azure_id_10_branch_01_matches` | AZURE-ID-10 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `license_present` does not equal true). |
| `AZURE-ID-10` | `azure_id_10_branch_02_matches` | AZURE-ID-10 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `enforcing_policy_count` equals 0. |
| `AZURE-ID-10` | `azure_id_10_branch_03_matches` | AZURE-ID-10 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: `complete` does not equal true. |
| `AZURE-ID-10` | `azure_id_10_branch_04_matches` | AZURE-ID-10 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `enforcing_policy_count` is greater than 0. |
| `AZURE-ID-10` | `azure_id_10_branch_05_matches` | AZURE-ID-10 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-11` | `azure_id_11_branch_01_matches` | AZURE-ID-11 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: `readable` does not equal true. |
| `AZURE-ID-11` | `azure_id_11_branch_02_matches` | AZURE-ID-11 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `high_risk_user_count` is greater than 0. |
| `AZURE-ID-11` | `azure_id_11_branch_03_matches` | AZURE-ID-11 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `inventory_count` is greater than 0). |
| `AZURE-ID-11` | `azure_id_11_branch_04_matches` | AZURE-ID-11 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `AZURE-ID-11` | `azure_id_11_branch_05_matches` | AZURE-ID-11 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-12` | `azure_id_12_branch_01_matches` | AZURE-ID-12 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-ID-12` | `azure_id_12_branch_02_matches` | AZURE-ID-12 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `expired_credential_count` is greater than 0. |
| `AZURE-ID-12` | `azure_id_12_branch_03_matches` | AZURE-ID-12 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `expiring_credential_count` is greater than 0; `missing_expiry_count` is greater than 0; `long_lived_credential_count` is greater than 0; `ownerless_application_count` is greater than 0). |
| `AZURE-ID-12` | `azure_id_12_branch_04_matches` | AZURE-ID-12 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-ID-13` | `azure_id_13_branch_01_matches` | AZURE-ID-13 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-ID-13` | `azure_id_13_branch_02_matches` | AZURE-ID-13 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `risky_grant_count` is greater than 0. |
| `AZURE-ID-13` | `azure_id_13_branch_03_matches` | AZURE-ID-13 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: `complete` does not equal true. |
| `AZURE-ID-13` | `azure_id_13_branch_04_matches` | AZURE-ID-13 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `risky_grant_count` equals 0. |
| `AZURE-ID-13` | `azure_id_13_branch_05_matches` | AZURE-ID-13 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-MON-01` | `azure_mon_01_branch_01_matches` | AZURE-MON-01 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `maximum_score` is at most 0). |
| `AZURE-MON-01` | `azure_mon_01_branch_02_matches` | AZURE-MON-01 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: not (`score_ratio` is at least 0.5). |
| `AZURE-MON-01` | `azure_mon_01_branch_03_matches` | AZURE-MON-01 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: all of (`score_ratio` is at least 0.5; not (`score_ratio` is at least 0.75)). |
| `AZURE-MON-01` | `azure_mon_01_branch_04_matches` | AZURE-MON-01 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `score_ratio` is at least 0.75. |
| `AZURE-MON-01` | `azure_mon_01_branch_05_matches` | AZURE-MON-01 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-MON-02` | `azure_mon_02_branch_01_matches` | AZURE-MON-02 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: `readable` does not equal true. |
| `AZURE-MON-02` | `azure_mon_02_branch_02_matches` | AZURE-MON-02 ordered branch 2 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `inventory_count` equals 0). |
| `AZURE-MON-02` | `azure_mon_02_branch_03_matches` | AZURE-MON-02 ordered branch 3 (pass) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` is greater than 0. |
| `AZURE-MON-02` | `azure_mon_02_branch_04_matches` | AZURE-MON-02 ordered branch 4 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-MON-03` | `azure_mon_03_branch_01_matches` | AZURE-MON-03 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: `readable` does not equal true. |
| `AZURE-MON-03` | `azure_mon_03_branch_02_matches` | AZURE-MON-03 ordered branch 2 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `inventory_count` equals 0). |
| `AZURE-MON-03` | `azure_mon_03_branch_03_matches` | AZURE-MON-03 ordered branch 3 (pass) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` is greater than 0. |
| `AZURE-MON-03` | `azure_mon_03_branch_04_matches` | AZURE-MON-03 ordered branch 4 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-MON-04` | `azure_mon_04_branch_01_matches` | AZURE-MON-04 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-MON-04` | `azure_mon_04_branch_02_matches` | AZURE-MON-04 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `standard_plan_count` equals 0. |
| `AZURE-MON-04` | `azure_mon_04_branch_03_matches` | AZURE-MON-04 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; not (`standard_plan_count` equals `inventory_count`)). |
| `AZURE-MON-04` | `azure_mon_04_branch_04_matches` | AZURE-MON-04 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `standard_plan_count` equals `inventory_count`. |
| `AZURE-MON-04` | `azure_mon_04_branch_05_matches` | AZURE-MON-04 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-MON-05` | `azure_mon_05_branch_01_matches` | AZURE-MON-05 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: `readable` does not equal true. |
| `AZURE-MON-05` | `azure_mon_05_branch_02_matches` | AZURE-MON-05 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `effective_setting_count` equals 0. |
| `AZURE-MON-05` | `azure_mon_05_branch_03_matches` | AZURE-MON-05 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: `complete` does not equal true. |
| `AZURE-MON-05` | `azure_mon_05_branch_04_matches` | AZURE-MON-05 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `effective_setting_count` is greater than 0. |
| `AZURE-MON-05` | `azure_mon_05_branch_05_matches` | AZURE-MON-05 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-MON-06` | `azure_mon_06_branch_01_matches` | AZURE-MON-06 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; all of (`destination_workspace_count` is greater than 0; `linked_workspace_count` equals 0)). |
| `AZURE-MON-06` | `azure_mon_06_branch_02_matches` | AZURE-MON-06 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: any of (`destination_workspace_count` equals 0; not (`workspace_retention_at_least_minimum_count` equals `linked_workspace_count`)). |
| `AZURE-MON-06` | `azure_mon_06_branch_03_matches` | AZURE-MON-06 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: `complete` does not equal true. |
| `AZURE-MON-06` | `azure_mon_06_branch_04_matches` | AZURE-MON-06 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `workspace_retention_at_least_minimum_count` equals `linked_workspace_count`. |
| `AZURE-MON-06` | `azure_mon_06_branch_05_matches` | AZURE-MON-06 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-MON-07` | `azure_mon_07_branch_01_matches` | AZURE-MON-07 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-SUB-01` | `azure_sub_01_branch_01_matches` | AZURE-SUB-01 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-SUB-01` | `azure_sub_01_branch_02_matches` | AZURE-SUB-01 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `matching_assignment_count` is greater than `warn_maximum`. |
| `AZURE-SUB-01` | `azure_sub_01_branch_03_matches` | AZURE-SUB-01 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `matching_assignment_count` is greater than 0). |
| `AZURE-SUB-01` | `azure_sub_01_branch_04_matches` | AZURE-SUB-01 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `matching_assignment_count` equals 0. |
| `AZURE-SUB-01` | `azure_sub_01_branch_05_matches` | AZURE-SUB-01 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-SUB-02` | `azure_sub_02_branch_01_matches` | AZURE-SUB-02 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-SUB-02` | `azure_sub_02_branch_02_matches` | AZURE-SUB-02 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `matching_assignment_count` is greater than `warn_maximum`. |
| `AZURE-SUB-02` | `azure_sub_02_branch_03_matches` | AZURE-SUB-02 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `matching_assignment_count` is greater than 0). |
| `AZURE-SUB-02` | `azure_sub_02_branch_04_matches` | AZURE-SUB-02 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `matching_assignment_count` equals 0. |
| `AZURE-SUB-02` | `azure_sub_02_branch_05_matches` | AZURE-SUB-02 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-SUB-03` | `azure_sub_03_branch_01_matches` | AZURE-SUB-03 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: `readable` does not equal true. |
| `AZURE-SUB-03` | `azure_sub_03_branch_02_matches` | AZURE-SUB-03 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `configured_contact_count` equals 0. |
| `AZURE-SUB-03` | `azure_sub_03_branch_03_matches` | AZURE-SUB-03 ordered branch 3 (pass) is true exactly when its portable evidence condition matches. Computed as: `configured_contact_count` is greater than 0. |
| `AZURE-SUB-03` | `azure_sub_03_branch_04_matches` | AZURE-SUB-03 ordered branch 4 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-SUB-04` | `azure_sub_04_branch_01_matches` | AZURE-SUB-04 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: `readable` does not equal true. |
| `AZURE-SUB-04` | `azure_sub_04_branch_02_matches` | AZURE-SUB-04 ordered branch 2 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `inventory_count` equals 0). |
| `AZURE-SUB-04` | `azure_sub_04_branch_03_matches` | AZURE-SUB-04 ordered branch 3 (pass) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` is greater than 0. |
| `AZURE-SUB-04` | `azure_sub_04_branch_04_matches` | AZURE-SUB-04 ordered branch 4 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-SUB-05` | `azure_sub_05_branch_01_matches` | AZURE-SUB-05 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-SUB-05` | `azure_sub_05_branch_02_matches` | AZURE-SUB-05 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `privileged_service_principal_count` is greater than 0. |
| `AZURE-SUB-05` | `azure_sub_05_branch_03_matches` | AZURE-SUB-05 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: `complete` does not equal true. |
| `AZURE-SUB-05` | `azure_sub_05_branch_04_matches` | AZURE-SUB-05 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `privileged_service_principal_count` equals 0. |
| `AZURE-SUB-05` | `azure_sub_05_branch_05_matches` | AZURE-SUB-05 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-DP-01` | `azure_dp_01_branch_01_matches` | AZURE-DP-01 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `license_present` does not equal true; all of (`inventory_count` is greater than 0; `device_count` equals 0)). |
| `AZURE-DP-01` | `azure_dp_01_branch_02_matches` | AZURE-DP-01 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: any of (`inventory_count` equals 0; `device_policy_with_required_settings_count` equals 0; `noncompliant_device_count` is greater than 0). |
| `AZURE-DP-01` | `azure_dp_01_branch_03_matches` | AZURE-DP-01 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `unknown_device_count` is greater than 0). |
| `AZURE-DP-01` | `azure_dp_01_branch_04_matches` | AZURE-DP-01 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-DP-02` | `azure_dp_02_branch_01_matches` | AZURE-DP-02 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-DP-03` | `azure_dp_03_branch_01_matches` | AZURE-DP-03 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: `readable` does not equal true. |
| `AZURE-DP-03` | `azure_dp_03_branch_02_matches` | AZURE-DP-03 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `active_sensitivity_record_count` equals 0. |
| `AZURE-DP-03` | `azure_dp_03_branch_03_matches` | AZURE-DP-03 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: `complete` does not equal true. |
| `AZURE-DP-03` | `azure_dp_03_branch_04_matches` | AZURE-DP-03 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `active_sensitivity_record_count` is greater than 0. |
| `AZURE-DP-03` | `azure_dp_03_branch_05_matches` | AZURE-DP-03 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-DP-04` | `azure_dp_04_branch_01_matches` | AZURE-DP-04 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-DP-04` | `azure_dp_04_branch_02_matches` | AZURE-DP-04 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `missing_protection_count` is greater than 0. |
| `AZURE-DP-04` | `azure_dp_04_branch_03_matches` | AZURE-DP-04 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `access_policy_vault_count` is greater than 0; `open_network_count` is greater than 0). |
| `AZURE-DP-04` | `azure_dp_04_branch_04_matches` | AZURE-DP-04 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-DP-05` | `azure_dp_05_branch_01_matches` | AZURE-DP-05 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-DP-05` | `azure_dp_05_branch_02_matches` | AZURE-DP-05 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: any of (`http_allowed_count` is greater than 0; `public_blob_count` is greater than 0). |
| `AZURE-DP-05` | `azure_dp_05_branch_03_matches` | AZURE-DP-05 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `public_blob_unset_count` is greater than 0; `weak_tls_count` is greater than 0). |
| `AZURE-DP-05` | `azure_dp_05_branch_04_matches` | AZURE-DP-05 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-DP-06` | `azure_dp_06_branch_01_matches` | AZURE-DP-06 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-DP-06` | `azure_dp_06_branch_02_matches` | AZURE-DP-06 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `forwarding_rule_count` is greater than 0. |
| `AZURE-DP-06` | `azure_dp_06_branch_03_matches` | AZURE-DP-06 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `mailbox_unreadable_count` is greater than 0). |
| `AZURE-DP-06` | `azure_dp_06_branch_04_matches` | AZURE-DP-06 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `forwarding_rule_count` equals 0. |
| `AZURE-DP-06` | `azure_dp_06_branch_05_matches` | AZURE-DP-06 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-DP-07` | `azure_dp_07_branch_01_matches` | AZURE-DP-07 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-DP-08` | `azure_dp_08_branch_01_matches` | AZURE-DP-08 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `capability_present` does not equal true). |
| `AZURE-DP-08` | `azure_dp_08_branch_02_matches` | AZURE-DP-08 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: all of (`capability` does not equal "disabled"; `capability` does not equal "existingexternalusersharingonly"; `capability` does not equal "externalusersharingonly"). |
| `AZURE-DP-08` | `azure_dp_08_branch_03_matches` | AZURE-DP-08 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`external_resharing` equals true; all of (`capability` equals "externalusersharingonly"; `domain_allowlist` does not equal true)). |
| `AZURE-DP-08` | `azure_dp_08_branch_04_matches` | AZURE-DP-08 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-NP-01` | `azure_np_01_branch_01_matches` | AZURE-NP-01 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-NP-01` | `azure_np_01_branch_02_matches` | AZURE-NP-01 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `exposed_rule_count` is greater than 0. |
| `AZURE-NP-01` | `azure_np_01_branch_03_matches` | AZURE-NP-01 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: `complete` does not equal true. |
| `AZURE-NP-01` | `azure_np_01_branch_04_matches` | AZURE-NP-01 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `exposed_rule_count` equals 0. |
| `AZURE-NP-01` | `azure_np_01_branch_05_matches` | AZURE-NP-01 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-NP-02` | `azure_np_02_branch_01_matches` | AZURE-NP-02 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: `readable` does not equal true. |
| `AZURE-NP-02` | `azure_np_02_branch_02_matches` | AZURE-NP-02 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: any of (`inventory_count` equals 0; `assignment_not_do_not_enforce_count` equals 0). |
| `AZURE-NP-02` | `azure_np_02_branch_03_matches` | AZURE-NP-02 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; not (`assignment_not_do_not_enforce_count` equals `inventory_count`)). |
| `AZURE-NP-02` | `azure_np_02_branch_04_matches` | AZURE-NP-02 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `assignment_not_do_not_enforce_count` equals `inventory_count`. |
| `AZURE-NP-02` | `azure_np_02_branch_05_matches` | AZURE-NP-02 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-NP-03` | `azure_np_03_branch_01_matches` | AZURE-NP-03 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `resource_count_present` does not equal true; `policy_count_present` does not equal true). |
| `AZURE-NP-03` | `azure_np_03_branch_02_matches` | AZURE-NP-03 ordered branch 2 (warn) is true exactly when its portable evidence condition matches. Computed as: `noncompliant_policy_count` is greater than 0. |
| `AZURE-NP-03` | `azure_np_03_branch_03_matches` | AZURE-NP-03 ordered branch 3 (pass) is true exactly when its portable evidence condition matches. Computed as: `noncompliant_policy_count` equals 0. |
| `AZURE-NP-03` | `azure_np_03_branch_04_matches` | AZURE-NP-03 ordered branch 4 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `AZURE-NP-04` | `azure_np_04_branch_01_matches` | AZURE-NP-04 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`readable` does not equal true; `inventory_count` equals 0). |
| `AZURE-NP-04` | `azure_np_04_branch_02_matches` | AZURE-NP-04 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: all of (`uncovered_nsg_count` is greater than 0; `covered_nsg_count` equals 0). |
| `AZURE-NP-04` | `azure_np_04_branch_03_matches` | AZURE-NP-04 ordered branch 3 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`complete` does not equal true; `uncovered_nsg_count` is greater than 0). |
| `AZURE-NP-04` | `azure_np_04_branch_04_matches` | AZURE-NP-04 ordered branch 4 (pass) is true exactly when its portable evidence condition matches. Computed as: `uncovered_nsg_count` equals 0. |
| `AZURE-NP-04` | `azure_np_04_branch_05_matches` | AZURE-NP-04 ordered branch 5 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `AZURE-ID-01` | `requiredEvidenceReadable` | true |
| `AZURE-ID-01` | `requiredEvidenceComplete` | true |
| `AZURE-ID-02` | `requiredEvidenceReadable` | true |
| `AZURE-ID-02` | `requiredEvidenceComplete` | true |
| `AZURE-ID-03` | `warning_ratio_maximum` | 0.1 |
| `AZURE-ID-04` | `maximum_global_admins` | 4 |
| `AZURE-ID-04` | `pass_maximum_assignments` | 5 |
| `AZURE-ID-04` | `fail_above_assignments` | 10 |
| `AZURE-ID-05` | `expiring_days` | 30 |
| `AZURE-ID-05` | `long_lived_days` | 730 |
| `AZURE-ID-06` | `maximum_permanent_privileged_assignments` | 2 |
| `AZURE-ID-07` | `requiredEvidenceReadable` | true |
| `AZURE-ID-07` | `requiredEvidenceComplete` | true |
| `AZURE-ID-08` | `stale_days` | 90 |
| `AZURE-ID-09` | `requiredEvidenceReadable` | true |
| `AZURE-ID-09` | `requiredEvidenceComplete` | true |
| `AZURE-ID-10` | `requiredEvidenceReadable` | true |
| `AZURE-ID-10` | `requiredEvidenceComplete` | true |
| `AZURE-ID-11` | `requiredEvidenceReadable` | true |
| `AZURE-ID-11` | `requiredEvidenceComplete` | true |
| `AZURE-ID-12` | `expiring_days` | 30 |
| `AZURE-ID-12` | `long_lived_days` | 730 |
| `AZURE-ID-13` | `requiredEvidenceReadable` | true |
| `AZURE-ID-13` | `requiredEvidenceComplete` | true |
| `AZURE-MON-01` | `pass_minimum_ratio` | 0.75 |
| `AZURE-MON-01` | `warn_minimum_ratio` | 0.5 |
| `AZURE-MON-02` | `requiredEvidenceReadable` | true |
| `AZURE-MON-02` | `requiredEvidenceComplete` | true |
| `AZURE-MON-03` | `requiredEvidenceReadable` | true |
| `AZURE-MON-03` | `requiredEvidenceComplete` | true |
| `AZURE-MON-04` | `requiredEvidenceReadable` | true |
| `AZURE-MON-04` | `requiredEvidenceComplete` | true |
| `AZURE-MON-05` | `requiredEvidenceReadable` | true |
| `AZURE-MON-05` | `requiredEvidenceComplete` | true |
| `AZURE-MON-06` | `minimum_retention_days` | 90 |
| `AZURE-MON-07` | `requiredEvidenceReadable` | true |
| `AZURE-MON-07` | `requiredEvidenceComplete` | true |
| `AZURE-SUB-01` | `requiredEvidenceReadable` | true |
| `AZURE-SUB-01` | `requiredEvidenceComplete` | true |
| `AZURE-SUB-02` | `requiredEvidenceReadable` | true |
| `AZURE-SUB-02` | `requiredEvidenceComplete` | true |
| `AZURE-SUB-03` | `requiredEvidenceReadable` | true |
| `AZURE-SUB-03` | `requiredEvidenceComplete` | true |
| `AZURE-SUB-04` | `requiredEvidenceReadable` | true |
| `AZURE-SUB-04` | `requiredEvidenceComplete` | true |
| `AZURE-SUB-05` | `requiredEvidenceReadable` | true |
| `AZURE-SUB-05` | `requiredEvidenceComplete` | true |
| `AZURE-DP-01` | `requiredEvidenceReadable` | true |
| `AZURE-DP-01` | `requiredEvidenceComplete` | true |
| `AZURE-DP-02` | `requiredEvidenceReadable` | true |
| `AZURE-DP-02` | `requiredEvidenceComplete` | true |
| `AZURE-DP-03` | `requiredEvidenceReadable` | true |
| `AZURE-DP-03` | `requiredEvidenceComplete` | true |
| `AZURE-DP-04` | `requiredEvidenceReadable` | true |
| `AZURE-DP-04` | `requiredEvidenceComplete` | true |
| `AZURE-DP-05` | `requiredEvidenceReadable` | true |
| `AZURE-DP-05` | `requiredEvidenceComplete` | true |
| `AZURE-DP-06` | `requiredEvidenceReadable` | true |
| `AZURE-DP-06` | `requiredEvidenceComplete` | true |
| `AZURE-DP-07` | `requiredEvidenceReadable` | true |
| `AZURE-DP-07` | `requiredEvidenceComplete` | true |
| `AZURE-DP-08` | `requiredEvidenceReadable` | true |
| `AZURE-DP-08` | `requiredEvidenceComplete` | true |
| `AZURE-NP-01` | `requiredEvidenceReadable` | true |
| `AZURE-NP-01` | `requiredEvidenceComplete` | true |
| `AZURE-NP-02` | `requiredEvidenceReadable` | true |
| `AZURE-NP-02` | `requiredEvidenceComplete` | true |
| `AZURE-NP-03` | `requiredEvidenceReadable` | true |
| `AZURE-NP-03` | `requiredEvidenceComplete` | true |
| `AZURE-NP-04` | `requiredEvidenceReadable` | true |
| `AZURE-NP-04` | `requiredEvidenceComplete` | true |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `AZURE-ID-01` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Conditional Access MFA baseline from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Conditional Access MFA baseline from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-02` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Legacy authentication blocking from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Legacy authentication blocking from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-03` | compliant | All required source reads are complete and this derivation returns pass: Evaluate MFA registration coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate MFA registration coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-04` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Privileged directory role sprawl from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Privileged directory role sprawl from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-05` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Service principal credential hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Service principal credential hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-06` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Privileged Identity Management eligibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Privileged Identity Management eligibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-07` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Guest access restrictions from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Guest access restrictions from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-08` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Guest account hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-08` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Guest account hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-09` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Sign-in risk policy from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-09` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Sign-in risk policy from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-09` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-09` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-10` | compliant | All required source reads are complete and this derivation returns pass: Evaluate User risk policy from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-10` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate User risk policy from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-10` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-10` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-11` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Risky users and detections from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-11` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Risky users and detections from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-11` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-11` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-12` | compliant | All required source reads are complete and this derivation returns pass: Evaluate App registration credential and owner hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-12` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate App registration credential and owner hygiene from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-12` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-12` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-ID-13` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Tenant-wide delegated permission grants from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-ID-13` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Tenant-wide delegated permission grants from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-ID-13` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-ID-13` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-MON-01` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Secure Score posture from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-MON-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Secure Score posture from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-MON-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-MON-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-MON-02` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Directory audit visibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-MON-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Directory audit visibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-MON-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-MON-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-MON-03` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Sign-in telemetry visibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-MON-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Sign-in telemetry visibility from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-MON-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-MON-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-MON-04` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Defender for Cloud plan coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-MON-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Defender for Cloud plan coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-MON-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-MON-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-MON-05` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Subscription diagnostic settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-MON-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Subscription diagnostic settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-MON-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-MON-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-MON-06` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Activity log retention depth from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-MON-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Activity log retention depth from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-MON-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-MON-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-MON-07` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Entra ID audit log export from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-MON-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Entra ID audit log export from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-MON-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-MON-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-SUB-01` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Owner assignments at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-SUB-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Owner assignments at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-SUB-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-SUB-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-SUB-02` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Contributor assignments at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-SUB-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Contributor assignments at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-SUB-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-SUB-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-SUB-03` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Security contacts configured from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-SUB-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Security contacts configured from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-SUB-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-SUB-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-SUB-04` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Network Watcher coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-SUB-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Network Watcher coverage from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-SUB-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-SUB-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-SUB-05` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Privileged service principals at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-SUB-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Privileged service principals at subscription scope from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-SUB-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-SUB-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-DP-01` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Device compliance enforcement from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-DP-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Device compliance enforcement from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-DP-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-DP-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-DP-02` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Data Loss Prevention policies from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-DP-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Data Loss Prevention policies from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-DP-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-DP-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-DP-03` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Sensitivity labels published from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-DP-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Sensitivity labels published from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-DP-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-DP-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-DP-04` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Key Vault protection settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-DP-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Key Vault protection settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-DP-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-DP-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-DP-05` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Storage account transport and access settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-DP-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Storage account transport and access settings from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-DP-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-DP-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-DP-06` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Inbox forwarding rules from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-DP-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Inbox forwarding rules from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-DP-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-DP-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-DP-07` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Mailbox-level forwarding and transport rules from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-DP-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Mailbox-level forwarding and transport rules from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-DP-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-DP-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-DP-08` | compliant | All required source reads are complete and this derivation returns pass: Evaluate SharePoint external sharing from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-DP-08` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate SharePoint external sharing from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-DP-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-DP-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-NP-01` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Unrestricted inbound admin ports from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-NP-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Unrestricted inbound admin ports from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-NP-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-NP-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-NP-02` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Azure Policy assignments enforced from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-NP-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Azure Policy assignments enforced from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-NP-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-NP-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-NP-03` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Azure Policy compliance state from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-NP-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Azure Policy compliance state from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-NP-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-NP-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `AZURE-NP-04` | compliant | All required source reads are complete and this derivation returns pass: Evaluate NSG flow logs enabled from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `AZURE-NP-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate NSG flow logs enabled from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `AZURE-NP-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `AZURE-NP-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Conditional Access MFA baseline | AC-2, AC-3, AC-7 | AC.L2-3.1.1 | CC6.1, CC6.6 | 1.2.1, 1.2.2 | 7.2.1 | SRG-APP-000033 | ISM-1401 | 7.1.1 |
| 2 | MFA registration coverage | IA-2(1), IA-2(2) | IA.L2-3.5.3 | CC6.1 | 1.1.1, 1.1.2, 1.1.3 | 8.4.2 | SRG-APP-000149 | ISM-1401 | 7.2.1 |
| 3 | Secure Score posture | CA-7, SI-4 | CA.L2-3.12.3 | CC7.1 | - | 11.5.1 | SRG-APP-000516 | ISM-1228 | 8.2.1 |
| 4 | Legacy authentication blocking | AC-17, IA-2(6) | AC.L2-3.1.12 | CC6.1, CC6.7 | 1.2.6 | 8.2.1 | SRG-APP-000295 | ISM-1557 | 7.2.2 |
| 5 | Privileged Identity Management eligibility | AC-6(1), AC-6(5) | AC.L2-3.1.5 | CC6.1, CC6.3 | 1.1.4, 1.23 | 7.2.2 | SRG-APP-000340 | ISM-1507 | 7.1.2 |
| 6 | Guest account hygiene | AC-2, AC-3 | AC.L2-3.1.1 | CC6.1, CC6.2 | 1.14 | 7.2.5 | SRG-APP-000033 | ISM-1380 | 7.1.3 |
| 7 | Risky users and detections | IA-5(13), SI-4 | IA.L2-3.5.2 | CC6.1, CC6.8 | 1.2.3 | 8.3.1 | SRG-APP-000516 | ISM-0120 | 7.2.3 |
| 8 | User risk policy | IA-5(13), SI-4 | IA.L2-3.5.2 | CC6.1, CC6.8 | 1.2.4 | 8.3.1 | SRG-APP-000516 | ISM-0120 | 7.2.4 |
| 9 | Device compliance enforcement | CM-2, CM-6 | CM.L2-3.4.1 | CC6.1, CC6.8 | - | 6.3.1 | SRG-APP-000383 | ISM-1490 | 6.3.1 |
| 10 | Data Loss Prevention policies | MP-4, SC-28 | SC.L2-3.13.16 | CC6.1, CC6.7 | - | 3.4.1 | SRG-APP-000231 | ISM-0264 | 6.2.1 |
| 11 | Sensitivity labels published | MP-4, SC-16 | SC.L2-3.13.16 | CC6.1, CC6.5 | - | 3.4.1 | SRG-APP-000231 | ISM-0264 | 6.2.2 |
| 12 | Unrestricted inbound admin ports | AC-4, SC-7 | SC.L2-3.13.1 | CC6.1, CC6.6 | 6.1, 6.2 | 1.3.1 | SRG-APP-000142 | ISM-1416 | 6.1.1 |
| 13 | Key Vault protection settings | SC-12, SC-28 | SC.L2-3.13.10 | CC6.1, CC6.7 | 8.1, 8.2, 8.5 | 3.6.4 | SRG-APP-000231 | ISM-0457 | 6.2.3 |
| 14 | Storage account transport and access settings | SC-8, SC-28 | SC.L2-3.13.8 | CC6.1, CC6.7 | 3.1, 3.7 | 3.4.1, 4.1.1 | SRG-APP-000014 | ISM-0457 | 6.2.4 |
| 15 | Subscription diagnostic settings | AU-2, AU-3, AU-6 | AU.L2-3.3.1 | CC7.2, CC7.3 | 5.1.1, 5.1.2 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 8.1.1 |
| 16 | Defender for Cloud plan coverage | SI-4, IR-4 | SI.L2-3.14.6 | CC7.2, CC7.3 | 2.1.1 through 2.1.15 | 11.5.1 | SRG-APP-000516 | ISM-1228 | 8.2.2 |
| 17 | Contributor assignments at subscription scope | AC-6, AC-6(1) | AC.L2-3.1.5 | CC6.1, CC6.3 | 1.23 | 7.2.2 | SRG-APP-000342 | ISM-1380 | 7.1.4 |
| 18 | Security contacts configured | IR-6, PM-2 | IR.L2-3.6.2 | CC7.4 | 2.1.19, 2.1.20 | 12.10.5 | SRG-APP-000516 | ISM-0072 | 9.1.1 |
| 19 | Entra ID audit log export | AU-9, AU-11 | AU.L2-3.3.8 | CC7.2 | 5.1.3, 5.2.6 | 10.7.1 | SRG-APP-000125 | ISM-0859 | 8.1.2 |
| 20 | Mailbox-level forwarding and transport rules | AC-4, SC-7 | SC.L2-3.13.1 | CC6.1 | - | 1.3.4 | SRG-APP-000142 | ISM-1416 | 6.1.2 |
| 21 | SharePoint external sharing | AC-3, AC-4 | AC.L2-3.1.3 | CC6.1, CC6.6 | - | 7.2.5 | SRG-APP-000033 | ISM-0263 | 6.1.3 |
| 22 | Tenant-wide delegated permission grants | CM-7, IA-5 | CM.L2-3.4.8 | CC6.1, CC6.2 | 1.11 | 8.6.3 | SRG-APP-000175 | ISM-1590 | 7.2.5 |
| 23 | Privileged service principals at subscription scope | AC-6, IA-4 | AC.L2-3.1.5 | CC6.1, CC6.3 | - | 8.6.3 | SRG-APP-000340 | ISM-1507 | 7.2.6 |
| 24 | NSG flow logs enabled | AU-12, SI-4 | AU.L2-3.3.1 | CC7.2 | 6.4, 6.5 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 8.1.3 |
| 25 | Azure Policy compliance state | CM-2, CM-6 | CM.L2-3.4.2 | CC6.1, CC8.1 | - | 6.3.1 | SRG-APP-000383 | ISM-1490 | 6.3.2 |

## Collection states

| State | Required rendering |
|---|---|
| complete | complete: proven API exhaustion or a successful single-object read. |
| truncated | truncated: preserve seen and total when available plus the exact stop reason. |
| unreadable | unreadable: render data and counts as null and retain a scrubbed error envelope. |
| denied | denied: render null evidence with the endpoint and HTTP status, never an empty inventory. |
| not requested | not_requested: identify the unreadable parent dependency and do not invent an HTTP status. |
| not configured | not_configured: identify the absent optional feature or credential without treating it as compliant. |

## Integration-specific scrubbing

Shared contract version: 1.1.

Projection stage: Project records to verdict-consumed fields, scrub configured and discovered credentials, then scrub again at every report and archive write sink.

Sensitive fields and values: client_secret, graph_token, management_token, access_token, authorization, cookie

Credential formats: Microsoft OAuth bearer tokens, OAuth client secrets, Azure CLI token output

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `conditional-access` | `id`, `displayName`, `state`, `conditions`, `grantControls` |
| `security-defaults` | `isEnabled` |
| `registration-details` | `id`, `userPrincipalName`, `isMfaRegistered` |
| `directory-roles` | `id`, `displayName`, `roleTemplateId` |
| `directory-role-members` | `id`, `userPrincipalName`, `accountEnabled` |
| `service-principals` | `id`, `displayName`, `passwordCredentials`, `keyCredentials` |
| `pim-eligibilities` | `principalId`, `roleDefinitionId`, `scheduleInfo` |
| `pim-assignments` | `principalId`, `roleDefinitionId`, `assignmentType`, `scheduleInfo` |
| `authorization-policy` | `guestUserRoleId`, `allowInvitesFrom` |
| `guest-users` | `id`, `userPrincipalName`, `accountEnabled`, `signInActivity`, `externalUserState` |
| `subscribed-skus` | `skuPartNumber`, `servicePlans` |
| `risky-users` | `id`, `riskLevel`, `riskState` |
| `risk-detections` | `id`, `riskLevel`, `riskState`, `detectedDateTime` |
| `applications` | `id`, `displayName`, `passwordCredentials`, `keyCredentials`, `owners` |
| `permission-grants` | `clientId`, `consentType`, `scope` |
| `secure-scores` | `currentScore`, `maxScore` |
| `directory-audits` | `id`, `activityDateTime`, `activityDisplayName` |
| `sign-ins` | `id`, `createdDateTime`, `status` |
| `defender-pricings` | `name`, `properties.pricingTier` |
| `diagnostic-settings` | `properties.logs`, `properties.workspaceId`, `properties.storageAccountId`, `properties.eventHubAuthorizationRuleId` |
| `log-workspaces` | `id`, `properties.retentionInDays` |
| `role-assignments` | `id`, `properties.roleDefinitionId`, `properties.principalType` |
| `role-definitions` | `id`, `properties.roleName` |
| `security-contacts` | `properties.emails` |
| `network-watchers` | `id`, `name`, `location` |
| `compliance-policies` | `id`, `displayName` |
| `managed-devices` | `id`, `deviceName`, `complianceState` |
| `sensitivity-labels` | `id`, `name`, `isActive`, `hasProtection` |
| `key-vaults` | `name`, `properties.enableSoftDelete`, `properties.enablePurgeProtection`, `properties.enableRbacAuthorization`, `properties.networkAcls` |
| `storage-accounts` | `name`, `properties.supportsHttpsTrafficOnly`, `properties.allowBlobPublicAccess`, `properties.minimumTlsVersion`, `properties.encryption.keySource` |
| `member-users` | `id`, `userPrincipalName`, `accountEnabled` |
| `message-rules` | `id`, `displayName`, `isEnabled`, `actions` |
| `sharepoint-settings` | `sharingCapability`, `sharingDomainRestrictionMode`, `isResharingByExternalUsersEnabled` |
| `network-security-groups` | `id`, `name`, `properties.securityRules` |
| `flow-logs` | `name`, `properties.enabled`, `properties.targetResourceId`, `properties.retentionPolicy` |
| `policy-assignments` | `id`, `properties.policyDefinitionId`, `properties.enforcementMode` |
| `policy-summary` | `results.nonCompliantResources`, `results.nonCompliantPolicies` |

## Export layout

Required paths:

- `QUICK_REFERENCE.md`
- `core_data/metadata.json`
- `core_data/access.json`
- `analysis/findings.json`
- `analysis/identity.json`
- `analysis/monitoring.json`
- `analysis/subscription-guardrails.json`
- `analysis/data-protection.json`
- `analysis/network-and-policy.json`
- `compliance/executive_summary.md`
- `compliance/unified_compliance_matrix.md`
- `compliance/fedramp.md`
- `compliance/cmmc.md`
- `compliance/soc2.md`
- `compliance/cis_azure.md`
- `compliance/pci_dss.md`
- `compliance/disa_stig.md`
- `compliance/irap.md`
- `compliance/ismap.md`

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `QUICK_REFERENCE.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `core_data/metadata.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/access.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/findings.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/identity.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/monitoring.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/subscription-guardrails.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/data-protection.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/network-and-policy.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `compliance/executive_summary.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/unified_compliance_matrix.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/fedramp.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cmmc.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/soc2.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cis_azure.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/pci_dss.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/disa_stig.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/irap.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/ismap.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `_errors.log` | text | Only under the runtime condition stated for this conditional file. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |

### Record schemas

#### finding

- `id`
- `title`
- `severity`
- `status`
- `summary`
- `evidence`
- `framework mappings`

#### collection_marker

- `collected`
- `status`
- `endpoint`
- `error`

#### bundle_result

- `outputDir`
- `zipPath`
- `fileCount`
- `findingCount`
- `errorCount`

#### assessment

- `title or category`
- `summary`
- `findings`
- `errors when collection was partial`

#### pagination_state

- `items or rows seen`
- `reported total when available`
- `pages`
- `truncated`
- `stop reason`

JSON formatting: UTF-8 JSON with two-space indentation and a trailing newline.

Overwrite policy: Allocate a new azure-audit-<UTC timestamp> directory and numeric suffix when either directory or paired archive exists.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Create <allocated-directory>.zip beside the allocated Azure audit directory.
