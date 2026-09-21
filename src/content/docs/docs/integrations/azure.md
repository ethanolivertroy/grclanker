---
title: Azure
description: Read-only Azure and Microsoft 365 security inspector covering Entra ID, Intune, Purview labels, Defender for Cloud, Key Vault, storage, networking, and Azure Policy.
---

The Azure integration audits an Entra ID tenant and one Azure subscription against the 25 controls in `specs/azure-sec-inspector.spec.md`. It calls Microsoft Graph v1.0 and Azure Resource Manager REST endpoints directly (no SDKs), never writes, and renders a `manual` verdict whenever an endpoint errors, a license is missing, or the API does not expose the control.

## What it inspects

- Entra ID: Conditional Access (MFA, legacy auth, sign-in risk, user risk, compliant device), MFA registration, privileged roles and PIM schedules, guest settings and guest hygiene, risky users, app registration credentials and owners, tenant-wide delegated consent.
- Monitoring: Secure Score, directory audit and sign-in visibility, Defender for Cloud plan tiers, subscription diagnostic settings, Log Analytics retention.
- Subscription guardrails: Owner and Contributor sprawl, privileged service principals, security contacts, Network Watcher presence.
- Data and endpoint protection: Intune compliance policies and device state, sensitivity labels, Key Vault soft delete, purge protection, RBAC and network ACLs, storage HTTPS-only, public blob access and TLS, inbox forwarding rules, SharePoint external sharing.
- Network and policy: NSG inbound Allow rules exposing 22, 3389, 3306, or 1433 to any source, Azure Policy assignment enforcement, Azure Policy compliance state.

## Setup and authentication

The tools resolve configuration in this order: explicit tool arguments, environment variables, then the `az` CLI (`az account show`, `az account get-access-token`). When `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` are present the CLI is not consulted and tokens are acquired with the OAuth 2.0 client credentials grant (`POST {authority}/{tenant}/oauth2/v2.0/token`, `grant_type=client_credentials`, `scope={resource}/.default`).

| Variable | Purpose |
|----------|---------|
| `AZURE_TENANT_ID` | Entra ID tenant (or `az account show`) |
| `AZURE_SUBSCRIPTION_ID` | Subscription to audit (or `az account show`) |
| `AZURE_GRAPH_TOKEN`, `AZURE_MANAGEMENT_TOKEN` | Pre-acquired bearer tokens |
| `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | App registration for the client credentials flow |
| `AZURE_AUTHORITY_HOST` | `login.microsoftonline.com` (default), `login.microsoftonline.us` (US Government: Graph `graph.microsoft.us`, ARM `management.usgovcloudapi.net`), `login.chinacloudapi.cn` |
| `AZURE_GRAPH_HOST`, `AZURE_MANAGEMENT_HOST` | Optional host overrides (for example DoD Graph `dod-graph.microsoft.us`) |

`AZURE_CLIENT_CERTIFICATE_PATH` is recognised but certificate credentials and managed identity are not implemented; the tools fail fast with an explanatory error rather than guessing. Use a client secret or pass tokens.

### Required Microsoft Graph application permissions

`Policy.Read.All`, `Directory.Read.All` (or `RoleManagement.Read.Directory`), `User.Read.All`, `AuditLog.Read.All`, `Reports.Read.All`, `Application.Read.All`, `Organization.Read.All`, `SecurityEvents.Read.All`, `SecurityAlert.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `RoleEligibilitySchedule.Read.Directory`, `RoleAssignmentSchedule.Read.Directory`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, `InformationProtectionPolicy.Read.All`, `MailboxSettings.Read`, `SharePointTenantSettings.Read.All`.

### Required Azure RBAC

`Reader` on the subscription plus `Security Reader` for Defender for Cloud pricings and security contacts.

## Tools

| Tool | Findings |
|------|----------|
| `azure_check_access` | Probes eight Graph and ARM surfaces and reports which are readable |
| `azure_assess_identity` | AZURE-ID-01 to AZURE-ID-13 |
| `azure_assess_monitoring` | AZURE-MON-01 to AZURE-MON-07 |
| `azure_assess_subscription_guardrails` | AZURE-SUB-01 to AZURE-SUB-05 (`max_assignments`, default 500), AZURE-NP-01 to AZURE-NP-03, and AZURE-DP-01 to AZURE-DP-08 (`max_mailboxes`, default 100); the data-protection and network/policy assessments are exported as `assessAzureDataProtection` and `assessAzureNetworkAndPolicy` and run inside this tool |
| `azure_export_audit_bundle` | All of the above into `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log` on partial failure, and a zip named after the allocated directory (reruns allocate `-2`, `-3`, never overwrite) |

## Status semantics

- `pass`: evidence collected and compliant.
- `warn`: compliant with caveats, a partial inventory (seen and total counts are reported), or items missing dates.
- `fail`: evidence collected and non-compliant, including empty inventories where emptiness fails by intent (no Conditional Access policies, no diagnostic settings, no security contacts, no labels, no compliance policies, no policy assignments).
- `manual`: the endpoint returned 401/403 or errored (the finding names the endpoint, the missing permission or role, and the evidence to collect), a license or service is absent (Entra ID P2, Intune, Purview), or the API does not expose the control.

Empty inventories that pass by intent are stated in the finding text: no guests (AZURE-ID-08), no risky users (AZURE-ID-11), no risky tenant-wide grants (AZURE-ID-13). Zero Key Vaults, storage accounts, NSGs, users, service principals, app registrations, role assignments, Defender plans, or managed devices render `manual` because emptiness usually means a read problem.

## Control coverage

| # | Spec control | Tool | Finding | Status semantics |
|---|--------------|------|---------|------------------|
| 1 | Conditional Access | identity | AZURE-ID-01 | pass with enabled MFA policy or security defaults; report-only never counts |
| 2 | MFA Enforcement | identity | AZURE-ID-03 | fail above 10% unregistered; zero users manual |
| 3 | Secure Score | monitoring | AZURE-MON-01 | pass at 75%+; no score manual |
| 4 | Legacy Auth Blocked | identity | AZURE-ID-02 | pass only with an enabled block policy on exchangeActiveSync/other or security defaults |
| 5 | Privileged Roles | identity | AZURE-ID-04, AZURE-ID-06 | fail above 4 Global Admins or 2 permanent privileged PIM assignments; P2 required for ID-06 |
| 6 | Guest User Access | identity | AZURE-ID-07, AZURE-ID-08 | pass with restricted guestUserRoleId and admin-only invites; stale guests fail, unknown last sign-in warns |
| 7 | Sign-In Risk | identity | AZURE-ID-09, AZURE-ID-11 | enabled CA on medium/high signInRiskLevels with mfa or block; P2 required |
| 8 | User Risk | identity | AZURE-ID-10 | enabled CA on medium/high userRiskLevels with passwordChange or block; P2 required |
| 9 | Device Compliance | subscription_guardrails (data protection) | AZURE-DP-01 | policies exist, no noncompliant devices, CA requires compliantDevice; Intune required |
| 10 | DLP Policies | subscription_guardrails (data protection) | AZURE-DP-02 | always manual (not exposed by Graph v1.0) |
| 11 | Sensitivity Labels | subscription_guardrails (data protection) | AZURE-DP-03 | pass with at least one isActive label |
| 12 | NSG Rules | subscription_guardrails (network and policy) | AZURE-NP-01 | fail on inbound Allow from any source to 22/3389/3306/1433 |
| 13 | Key Vault Access | subscription_guardrails (data protection) | AZURE-DP-04 | fail without enableSoftDelete and enablePurgeProtection; access policies or open network warn |
| 14 | Storage Encryption | subscription_guardrails (data protection) | AZURE-DP-05 | fail without supportsHttpsTrafficOnly or with allowBlobPublicAccess true; TLS below 1.2 warns |
| 15 | Diagnostic Logging | monitoring | AZURE-MON-05 | pass with an enabled log category and destination |
| 16 | Defender Enabled | monitoring | AZURE-MON-04 | pass when every plan is Standard |
| 17 | RBAC Least Privilege | subscription_guardrails | AZURE-SUB-01, AZURE-SUB-02 | Owner above 2 or Contributor above 5 fails |
| 18 | Security Contacts | subscription_guardrails | AZURE-SUB-03 | pass with an emails value |
| 19 | Audit Log Retention | monitoring | AZURE-MON-02, AZURE-MON-03, AZURE-MON-06, AZURE-MON-07 | Log Analytics retentionInDays 90+; Entra export is manual |
| 20 | Mail Forwarding | subscription_guardrails (data protection) | AZURE-DP-06, AZURE-DP-07 | inbox rules automated; mailbox forwarding and transport rules manual |
| 21 | External Sharing | subscription_guardrails (data protection) | AZURE-DP-08 | pass with disabled or existing-guest sharing; anonymous links fail |
| 22 | App Registrations | identity | AZURE-ID-12, AZURE-ID-13 | expired credentials fail; missing dates, long-lived secrets, or no owners warn; risky AllPrincipals grants fail |
| 23 | Service Principals | identity, subscription_guardrails | AZURE-ID-05, AZURE-SUB-05 | expired credentials or Owner/Contributor service principals fail |
| 24 | Network Watcher | subscription_guardrails | AZURE-SUB-04 | presence only; flow logs manual |
| 25 | Azure Policy | subscription_guardrails (network and policy) | AZURE-NP-02, AZURE-NP-03 | assignments must use enforcementMode Default; non-compliant policies warn |

## Framework mappings

Every finding carries the spec control number, and the bundle's `compliance/` folder renders one report per framework from section 5 of the spec: FedRAMP (NIST 800-53), CMMC 2.0, SOC 2, CIS Azure v2.1, PCI-DSS v4.0, DISA STIG, IRAP, and ISMAP, plus `executive_summary.md` and `unified_compliance_matrix.md`.

## Live smoke

```bash
npm --prefix cli run test:azure:live
```

Skips with exit 0 unless `AZURE_TENANT_ID` and `AZURE_SUBSCRIPTION_ID` are set together with either tokens or client credentials. Otherwise it runs `azure_check_access` and the identity assessment.

## Limitations and manual controls

- DLP policies (control 10), transport rules and mailbox-level forwarding (20), Teams guest access (21), NSG flow logs (24), and Entra log export (19) are not exposed through the Graph v1.0 or ARM endpoints used here and always render `manual` with the exact evidence to collect.
- Identity Protection, PIM, and risk-based Conditional Access require Entra ID P2; Intune and Purview require their licenses. Missing licenses render `manual`, never `pass`.
- Inbox rule inspection is capped by `max_mailboxes`; a capped or partially readable sample is reported as `warn` with seen and total counts.
- One subscription per run. Certificate credentials and managed identity are documented but not implemented.

## Official documentation

Endpoints, API versions, and fields are cited next to each request constant in `cli/extensions/grc-tools/azure.ts` (`AZURE_ENDPOINT_DOCS`, `AZURE_ARM_API_VERSIONS`). Key pages:

- [OAuth 2.0 client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [Microsoft Graph national cloud deployments](https://learn.microsoft.com/en-us/graph/deployments) and [Azure Government endpoints](https://learn.microsoft.com/en-us/azure/azure-government/compare-azure-government-global-azure)
- [conditionalAccessPolicy](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0), [conditionalAccessConditionSet](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0), [conditionalAccessGrantControls](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0)
- [authorizationPolicy](https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0), [List users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0), [signInActivity](https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0)
- [List riskyUsers](https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0), [List riskDetections](https://learn.microsoft.com/en-us/graph/api/riskdetection-list?view=graph-rest-1.0)
- [List roleEligibilitySchedules](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityschedules?view=graph-rest-1.0), [List roleAssignmentSchedules](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignmentschedules?view=graph-rest-1.0), [Entra role template IDs](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [List deviceCompliancePolicies](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0), [List managedDevices](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0), [complianceState](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-compliancestate?view=graph-rest-1.0)
- [List sensitivityLabels](https://learn.microsoft.com/en-us/graph/api/security-informationprotection-list-sensitivitylabels?view=graph-rest-1.0), [Get-DlpCompliancePolicy](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpcompliancepolicy)
- [List messageRules](https://learn.microsoft.com/en-us/graph/api/mailfolder-list-messagerules?view=graph-rest-1.0), [messageRuleActions](https://learn.microsoft.com/en-us/graph/api/resources/messageruleactions?view=graph-rest-1.0), [mailboxSettings](https://learn.microsoft.com/en-us/graph/api/resources/mailboxsettings?view=graph-rest-1.0), [Set-Mailbox](https://learn.microsoft.com/en-us/powershell/module/exchange/set-mailbox), [Get-TransportRule](https://learn.microsoft.com/en-us/powershell/module/exchange/get-transportrule)
- [sharepointSettings](https://learn.microsoft.com/en-us/graph/api/resources/sharepointsettings?view=graph-rest-1.0), [List applications](https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0), [List oauth2PermissionGrants](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0), [List subscribedSkus](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0)
- [Pricings - List](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list), [Security Contacts - List](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list), [Diagnostic Settings - List](https://learn.microsoft.com/en-us/rest/api/monitor/diagnostic-settings/list), [Workspaces - List](https://learn.microsoft.com/en-us/rest/api/loganalytics/workspaces/list), [Entra log retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)
- [Role Assignments - List For Subscription](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-subscription), [Network Security Groups - List All](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-security-groups/list-all), [Network Watchers - List All](https://learn.microsoft.com/en-us/rest/api/network-watcher/network-watchers/list-all)
- [Vaults - List By Subscription](https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/list-by-subscription), [Storage Accounts - List](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list)
- [Policy Assignments - List](https://learn.microsoft.com/en-us/rest/api/policy-authorization/policy-assignments/list), [Policy States - Summarize For Subscription](https://learn.microsoft.com/en-us/rest/api/policyinsights/policy-states/summarize-for-subscription), [Built-in policy definitions](https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies)
