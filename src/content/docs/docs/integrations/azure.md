---
title: Azure
description: Read-only Azure and Microsoft 365 security inspector covering Entra ID, Intune, Purview labels, Defender for Cloud, Key Vault, storage, networking, and Azure Policy.
---

The Azure integration audits an Entra ID tenant and one Azure subscription against the 25 controls in `specs/azure-sec-inspector.spec.md`. It calls Microsoft Graph v1.0 and Azure Resource Manager REST endpoints directly (no SDKs), never writes, and renders a `manual` verdict whenever an endpoint errors, a license is missing, or the API does not expose the control.

## What it inspects

- Entra ID: Conditional Access (MFA, legacy auth, sign-in risk, user risk, compliant device), MFA registration, privileged roles and PIM schedules, guest settings and guest hygiene, risky users, app registration credentials and owners, tenant-wide delegated consent.
- Monitoring: Secure Score, directory audit and sign-in visibility, Defender for Cloud plan tiers, subscription diagnostic settings, Log Analytics retention.
- Subscription guardrails: Owner and Contributor sprawl, privileged service principals, security contacts, Network Watcher presence.
- Data and endpoint protection: Intune compliance policies and device state, sensitivity labels (Graph beta), Key Vault soft delete, purge protection, RBAC and network ACLs, storage HTTPS-only, public blob access and TLS, inbox forwarding rules, SharePoint external sharing.
- Network and policy: NSG inbound Allow rules exposing 22, 3389, 3306, or 1433 to any source, NSG flow log coverage read from every Network Watcher, Azure Policy assignment enforcement, Azure Policy compliance state.

## Setup and authentication

The tools resolve configuration in this order: explicit tool arguments, environment variables, then the `az` CLI (`az account show`, `az account get-access-token`). When `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` are present the CLI is not consulted and tokens are acquired with the OAuth 2.0 client credentials grant (`POST {authority}/{tenant}/oauth2/v2.0/token`, `grant_type=client_credentials`, `scope={resource}/.default`).

| Variable | Purpose |
|----------|---------|
| `AZURE_TENANT_ID` | Entra ID tenant (or `az account show`) |
| `AZURE_SUBSCRIPTION_ID` | Subscription to audit (or `az account show`) |
| `AZURE_GRAPH_TOKEN`, `AZURE_MANAGEMENT_TOKEN` | Pre-acquired bearer tokens |
| `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | App registration for the client credentials flow |
| `AZURE_AUTHORITY_HOST` | `login.microsoftonline.com` (default), `login.microsoftonline.us` (US Government: Graph `graph.microsoft.us`, ARM `management.usgovcloudapi.net`), `login.chinacloudapi.cn` or `login.partner.microsoftonline.cn` (China operated by 21Vianet: Graph `microsoftgraph.chinacloudapi.cn`, ARM `management.chinacloudapi.cn`; both hosts are documented and accepted) |
| `AZURE_GRAPH_HOST`, `AZURE_MANAGEMENT_HOST` | Optional host overrides (for example DoD Graph `dod-graph.microsoft.us`) |

`AZURE_CLIENT_CERTIFICATE_PATH` is recognised but certificate credentials and managed identity are not implemented; the tools fail fast with an explanatory error rather than guessing. Use a client secret or pass tokens.

### Required Microsoft Graph application permissions

`Policy.Read.All`, `Directory.Read.All` (or `RoleManagement.Read.Directory`), `User.Read.All`, `AuditLog.Read.All`, `Reports.Read.All`, `Application.Read.All`, `Organization.Read.All`, `SecurityEvents.Read.All`, `SecurityAlert.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `RoleEligibilitySchedule.Read.Directory`, `RoleAssignmentSchedule.Read.Directory`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, `InformationProtectionPolicy.Read.All`, `MailboxSettings.Read`, `SharePointTenantSettings.Read.All`.

### Required Azure RBAC

`Reader` on the subscription plus `Security Reader` for Defender for Cloud pricings and security contacts.

## Tools

| Tool | Findings |
|------|----------|
| `azure_check_access` | Probes eight Graph and ARM surfaces and reports which are readable; a probe that stopped at its page cap carries `truncated: true` and its count is a floor |
| `azure_assess_identity` | AZURE-ID-01 to AZURE-ID-13 |
| `azure_assess_monitoring` | AZURE-MON-01 to AZURE-MON-07 |
| `azure_assess_subscription_guardrails` | AZURE-SUB-01 to AZURE-SUB-05 (`max_assignments`, default 500) |
| `azure_assess_data_protection` | AZURE-DP-01 to AZURE-DP-08 (`max_mailboxes`, default 100); AZURE-DP-03 reads the Graph beta sensitivity label endpoint |
| `azure_assess_network_and_policy` | AZURE-NP-01 to AZURE-NP-04 |
| `azure_export_audit_bundle` | All five assessments into `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log` on partial failure, and a zip named after the allocated directory (reruns allocate `-2`, `-3`, never overwrite) |

## Status semantics

- `pass`: evidence collected and compliant.
- `warn`: compliant with caveats, a partial inventory (seen and total counts are reported), or items missing dates.
- `fail`: evidence collected and non-compliant, including empty inventories where emptiness fails by intent (no Conditional Access policies, no diagnostic settings, no security contacts, no labels, no compliance policies, no policy assignments).
- `manual`: the endpoint returned 401/403 or errored (the finding names the endpoint, the missing permission or role, and the evidence to collect), a license or service is absent (Entra ID P2, Intune, Purview), or the API does not expose the control. When the failure was the token request itself, the finding names that request (taken from the observed request URL, not from the finding's endpoint constant) and states that no resource request was made: `POST /<tenant>/oauth2/v2.0/token returned 403 Forbidden, so no Microsoft Graph request was made for this finding. Fix the app registration's client credentials (tenant id, client id, client secret) so a token is issued; the read then needs Policy.Read.All. Or collect ... manually.`, never `GET /v1.0/... returned 403 Forbidden. Grant Policy.Read.All`. Its evidence carries `endpoint: "POST /<tenant>/oauth2/v2.0/token"`, `request_url` pointing at the token endpoint, and `resource_request: "not attempted: the token request failed, so no Microsoft Graph request was made"` (or `Azure Resource Manager` for ARM findings). The same attribution appears in the `errors` array and `_errors.log` (`AZURE-ID-01 POST /<tenant>/oauth2/v2.0/token: 403 Forbidden; no Microsoft Graph request was made`), in the AZURE-ID-01 and AZURE-ID-02 security-defaults note, and in `azure_check_access`, whose notes add `POST /<tenant>/oauth2/v2.0/token returned 403 Forbidden; no resource request was made for organization, conditional_access, ...` beside the `not_readable` surfaces whose `request_url` is the token endpoint. The same attribution holds when the token request was rejected before any response arrived (a DNS, TLS, connection, or timeout failure): the rejection is wrapped with the token URL, so the finding reads `POST /<tenant>/oauth2/v2.0/token received no response (TypeError: fetch failed (ENOTFOUND)), so no Microsoft Graph request was made for this finding. Restore network access to login.microsoftonline.com (DNS, TLS, proxy) so the token request receives a response; the read then needs Policy.Read.All. Or collect ... manually.`, its `http_status` is `null`, `request_url` is the token endpoint, `resource_request` carries the not-attempted marker, and no Graph or ARM endpoint or HTTP status is named anywhere in the findings, the `errors` array, `_errors.log`, or `azure_check_access`, whose note reads `POST /<tenant>/oauth2/v2.0/token received no response (...); no resource request was made for ...` and whose next step names the network path rather than the client credentials. The transport message is scrubbed like any other error string and only the error's name, its scrubbed message, and the cause's network code (`ENOTFOUND`, `ECONNREFUSED`) are kept. A Graph or ARM request rejected before any response keeps its own endpoint and observed `request_url`, records `http_status: null`, and reads `GET /v1.0/identity/conditionalAccess/policies received no response (...). Restore network access to graph.microsoft.com (DNS, TLS, proxy) and re-run; the read needs Policy.Read.All.` instead of recommending a permission grant for a request that was never answered.

Empty inventories that pass by intent are stated in the finding text: no guests (AZURE-ID-08) and no risky users (AZURE-ID-11). Zero Key Vaults, storage accounts, NSGs, users, service principals, app registrations, oauth2PermissionGrants, role assignments, Defender plans, or managed devices render `manual` because emptiness usually means a read problem.

### Verdict safety rules

- Secondary reads never pass silently. Every finding that combines two or more inventories (role members per role, PIM eligibility and assignment schedules, licenses plus Conditional Access, diagnostic settings plus workspaces, role assignments plus role definitions, users plus inbox rules, Network Watchers plus flow logs) renders `manual` naming the failed endpoint and the permission to grant when a secondary read is denied while the primary is readable. The test suite denies each secondary one at a time against a fully compliant fixture and asserts that no unrelated finding moves.
- AZURE-ID-01 and AZURE-ID-02 treat security defaults as a secondary read: an enabled MFA or legacy-auth block policy satisfies the control on its own and the finding notes when the defaults read failed; with no such policy the verdict rests on the unreadable read and renders `manual` naming `GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy`, never "security defaults are off".
- AZURE-DP-06 counts denied mailboxes (401/403) separately from mailboxes that errored without a permission failure (typically users without an Exchange mailbox), names `MailboxSettings.Read (application)` for the denied subset, and caps at `warn`; every mailbox denied renders `manual`.
- Every pagination walk reports `truncated: true` on each early exit: the item cap, a next link that repeats the page just fetched, and an empty page that still advertises a next link. Truncated pages cap `pass` at `warn` with seen and total counts (AZURE-MON-04 and AZURE-MON-05 included), and `azure_check_access` keeps the flag next to a capped probe count so `core_data/access.json` never presents a page cap as an inventory size.
- Failed reads named inside a non-manual finding (security defaults, security alerts, a denied mailbox subset) are also recorded in the assessment `errors` array and therefore in `_errors.log`.
- Every endpoint and status named in output is one the run requested and observed. A `manual` finding names the request that failed: the resource endpoint when that request was answered 401/403, or the token request (`POST /<tenant>/oauth2/v2.0/token`) when no resource request was made because no token was issued, whether the token endpoint refused the request or never answered it. The request-matching tests record every request the fixture served, including a denied token request and a token request rejected before any response (DNS, TLS, timeout), and assert that every path and status mentioned in any finding, evidence field, access-check surface, or error line appears in that log; for the pre-response rejection that means the token request is the only endpoint named and no HTTP status is named at all.
- Every fixed-text message the integration emits (the parse and non-JSON notes, the token-failure and `not attempted` wordings, the unread and partial-inventory prose, every `AzureApiError` rendering) is held to the error-text scrub by a test and survives it unchanged.

### Bundle redaction

- Service principal and app registration records are reduced at collection time to `id`, `displayName`, `appId`, and the schedule fields of each credential (`keyId`, `displayName`, `type`, `usage`, `startDateTime`, `endDateTime`); `passwordCredential.hint`, `secretText`, `keyCredential.key`, and `customKeyIdentifier` never reach memory that a finding or the bundle could echo.
- API error bodies are reduced to the documented envelope (`error.code: error.message` for Graph and ARM, `error: error_description` for the token endpoint); non-JSON bodies are dropped, so `_errors.log`, `core_data/access.json`, and `manual` evidence never carry raw payloads. A `SyntaxError` reaching the error sink from any path is recorded by name only (`SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body`), because V8's parse message quotes a snippet of the rejected text. The scrub follows one boundary. A value inside any carrier (an `Authorization`, `Cookie`, `Set-Cookie`, `X-Auth-Key`, `X-Auth-Email`, or `x-api-key` header, a `Bearer`, `Basic`, `Token`, or `ApiKey` scheme, a session or cookie assignment, a URL's userinfo or a query pair, a key-value pair whose key names a credential) is removed whatever its shape. A quoted header or pair value (`Authorization: Bearer "value"`, `X-Auth-Key: "value"`, `Cookie: sid='value'`, `X-Api-Key: "value"`, with or without spaces, single or double quotes, plain or JSON-escaped) is removed whole between its quotes, so a short or name-shaped value never survives inside quotes as prose; the `Cookie`, `Set-Cookie`, `X-Auth-Key`, and `X-Auth-Email` values are consumed through the end of the line, quotes included. A quoted value that names no credential (`Content-Type: "application/json"`) stays. The configured Graph and ARM tokens, the client secret, and every token the client obtains are removed whatever their shape and in their JSON-escaped, URL-encoded, base64, and base64url forms. A bare run of 16 or more characters shaped like a token (base64 symbols, digits scattered through letters, camelCase pieces of one or two letters, hex digests, AWS key ids, JWTs, PEM blocks) is removed. A bare value shaped like a name (hyphen- or underscore-joined words with at most one digit group each, such as `prod-us-east-2026`, uppercase codes, UUIDs, camelCase identifiers such as `GetAccessKeyLastUsed`) stays, because in prose it is indistinguishable from a resource name; opaque identifiers whose shape is a token's are therefore removed from error text and travel in structured fields (`endpoint`, `request_url`, `http_status`). The tools read no configuration file: every setting comes from tool arguments and environment variables.
- Tokens and the client secret are never written; the export test drives a real client through fake secrets, hints, key blobs, and an echoing error body and scans every bundle file and every inflated zip entry for them.

## Control coverage

| # | Spec control | Tool | Finding | Status semantics |
|---|--------------|------|---------|------------------|
| 1 | Conditional Access | identity | AZURE-ID-01 | pass with enabled MFA policy or security defaults; report-only never counts; no MFA policy and an unreadable security defaults read is manual |
| 2 | MFA Enforcement | identity | AZURE-ID-03 | fail above 10% unregistered; zero users manual |
| 3 | Secure Score | monitoring | AZURE-MON-01 | pass at 75%+; no score manual |
| 4 | Legacy Auth Blocked | identity | AZURE-ID-02 | pass only with an enabled block policy on exchangeActiveSync/other or security defaults; no block policy and an unreadable security defaults read is manual |
| 5 | Privileged Roles | identity | AZURE-ID-04, AZURE-ID-06 | fail above 4 Global Admins or 2 permanent privileged PIM assignments; P2 required for ID-06 |
| 6 | Guest User Access | identity | AZURE-ID-07, AZURE-ID-08 | pass with restricted guestUserRoleId and admin-only invites; stale guests fail, unknown last sign-in warns |
| 7 | Sign-In Risk | identity | AZURE-ID-09, AZURE-ID-11 | enabled CA on medium/high signInRiskLevels with mfa or block; P2 required |
| 8 | User Risk | identity | AZURE-ID-10 | enabled CA on medium/high userRiskLevels with passwordChange or block; P2 required |
| 9 | Device Compliance | data_protection | AZURE-DP-01 | policies exist, no noncompliant devices, CA requires compliantDevice; Intune required |
| 10 | DLP Policies | data_protection | AZURE-DP-02 | always manual (no DLP policy resource in Graph v1.0 or beta) |
| 11 | Sensitivity Labels | data_protection | AZURE-DP-03 | pass with at least one isActive label; read from the Graph beta endpoint (the only documented tenant-wide form), which Microsoft may change |
| 12 | NSG Rules | network_and_policy | AZURE-NP-01 | fail on inbound Allow from any source to 22/3389/3306/1433 |
| 13 | Key Vault Access | data_protection | AZURE-DP-04 | fail without enableSoftDelete and enablePurgeProtection; access policies or open network warn |
| 14 | Storage Encryption | data_protection | AZURE-DP-05 | fail without supportsHttpsTrafficOnly or with allowBlobPublicAccess true; TLS below 1.2 warns |
| 15 | Diagnostic Logging | monitoring | AZURE-MON-05 | pass with an enabled log category and destination; a truncated settings page caps at warn |
| 16 | Defender Enabled | monitoring | AZURE-MON-04 | pass when every plan is Standard; a truncated pricing page caps at warn; a failed alerts read is named in evidence |
| 17 | RBAC Least Privilege | subscription_guardrails | AZURE-SUB-01, AZURE-SUB-02 | Owner above 2 or Contributor above 5 fails |
| 18 | Security Contacts | subscription_guardrails | AZURE-SUB-03 | pass with an emails value |
| 19 | Audit Log Retention | monitoring | AZURE-MON-02, AZURE-MON-03, AZURE-MON-06, AZURE-MON-07 | Log Analytics retentionInDays 90+; Entra export is manual |
| 20 | Mail Forwarding | data_protection | AZURE-DP-06, AZURE-DP-07 | inbox rules automated (denied mailboxes are named as a MailboxSettings.Read gap and cap at warn; all denied is manual); mailbox forwarding and transport rules manual |
| 21 | External Sharing | data_protection | AZURE-DP-08 | pass with disabled or existing-guest sharing; anonymous links fail |
| 22 | App Registrations | identity | AZURE-ID-12, AZURE-ID-13 | expired credentials fail; missing dates, long-lived secrets, or no owners warn; risky AllPrincipals grants fail; zero grants manual |
| 23 | Service Principals | identity, subscription_guardrails | AZURE-ID-05, AZURE-SUB-05 | expired credentials or Owner/Contributor service principals fail |
| 24 | Network Watcher | subscription_guardrails, network_and_policy | AZURE-SUB-04, AZURE-NP-04 | SUB-04 warns without a Network Watcher; NP-04 reads flow logs from every Network Watcher and passes only when every NSG has an enabled flow log whose targetResourceId is that NSG (partial coverage warns, none fails, truncation caps at warn) |
| 25 | Azure Policy | network_and_policy | AZURE-NP-02, AZURE-NP-03 | assignments must use enforcementMode Default; non-compliant policies warn. AZURE-NP-02 names absent mandatory built-ins under `mandatory_missing` only when the assignment page was complete; under a truncated page they move to `mandatory_not_seen` (`mandatory_missing` is `null`) and the summary says they "may exist among the unseen assignments" |

## Framework mappings

Every finding carries the spec control number, and the bundle's `compliance/` folder renders one report per framework from section 5 of the spec: FedRAMP (NIST 800-53), CMMC 2.0, SOC 2, CIS Azure v2.1, PCI-DSS v4.0, DISA STIG, IRAP, and ISMAP, plus `executive_summary.md` and `unified_compliance_matrix.md`.

## Live smoke

```bash
npm --prefix cli run test:azure:live
```

Skips with exit 0 unless `AZURE_TENANT_ID` and `AZURE_SUBSCRIPTION_ID` are set together with either tokens or client credentials. Otherwise it runs `azure_check_access` and the identity assessment.

## Limitations and manual controls

- DLP policies (control 10) have no Graph resource in v1.0 or beta, and Graph `mailboxSettings` exposes no forwarding property, so control 10 and the mailbox-forwarding and transport-rule half of control 20 always render `manual` with the exact PowerShell evidence to collect.
- Teams guest access (control 21) and Entra diagnostic settings for log export (control 19) are not read by this implementation; AZURE-DP-08 and AZURE-MON-07 name the admin center pages to collect.
- Sensitivity labels (control 11) are read from `GET /beta/security/informationProtection/sensitivityLabels`, the only documented tenant-wide (application permission) form; beta endpoints may change without notice and the finding says so.
- NSG flow logs (control 24) are read per Network Watcher from `Microsoft.Network/networkWatchers/{name}/flowLogs`; retention policy values are reported as evidence but not judged.
- Identity Protection, PIM, and risk-based Conditional Access require Entra ID P2; Intune and Purview require their licenses. Missing licenses render `manual`, never `pass`.
- Inbox rule inspection is capped by `max_mailboxes`; a capped or partially readable sample is reported as `warn` with seen and total counts, and denied mailboxes are counted apart from mailboxes without Exchange.
- Graph and ARM list walks stop at 5,000 items (500 for risk detections, 200 for alerts, audits, and sign-ins, 20 for secure scores, `max_assignments` for role assignments) and on a repeated or empty-page next link; every early exit is reported as truncated and demotes the dependent verdict.
- One subscription per run. Certificate credentials and managed identity are documented but not implemented.

## Official documentation

Endpoints, API versions, and fields are cited next to each request constant in `cli/extensions/grc-tools/azure.ts` (`AZURE_ENDPOINT_DOCS`, `AZURE_ARM_API_VERSIONS`). Key pages:

- [OAuth 2.0 client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [Microsoft Graph national cloud deployments](https://learn.microsoft.com/en-us/graph/deployments), [National cloud authentication endpoints](https://learn.microsoft.com/en-us/entra/identity-platform/authentication-national-cloud), and [Azure Government endpoints](https://learn.microsoft.com/en-us/azure/azure-government/compare-azure-government-global-azure)
- [conditionalAccessPolicy](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0), [conditionalAccessConditionSet](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0), [conditionalAccessGrantControls](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0)
- [authorizationPolicy](https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0), [List users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0), [signInActivity](https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0)
- [List riskyUsers](https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0), [List riskDetections](https://learn.microsoft.com/en-us/graph/api/riskdetection-list?view=graph-rest-1.0)
- [List roleEligibilitySchedules](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityschedules?view=graph-rest-1.0), [List roleAssignmentSchedules](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignmentschedules?view=graph-rest-1.0), [Entra role template IDs](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [List deviceCompliancePolicies](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0), [List managedDevices](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0), [complianceState](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-compliancestate?view=graph-rest-1.0)
- [List sensitivityLabels (beta)](https://learn.microsoft.com/en-us/graph/api/security-informationprotection-list-sensitivitylabels?view=graph-rest-beta), [informationProtection resource (beta)](https://learn.microsoft.com/en-us/graph/api/resources/security-informationprotection?view=graph-rest-beta), [Get-DlpCompliancePolicy](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpcompliancepolicy)
- [List messageRules](https://learn.microsoft.com/en-us/graph/api/mailfolder-list-messagerules?view=graph-rest-1.0), [messageRuleActions](https://learn.microsoft.com/en-us/graph/api/resources/messageruleactions?view=graph-rest-1.0), [mailboxSettings](https://learn.microsoft.com/en-us/graph/api/resources/mailboxsettings?view=graph-rest-1.0), [Set-Mailbox](https://learn.microsoft.com/en-us/powershell/module/exchange/set-mailbox), [Get-TransportRule](https://learn.microsoft.com/en-us/powershell/module/exchange/get-transportrule)
- [sharepointSettings](https://learn.microsoft.com/en-us/graph/api/resources/sharepointsettings?view=graph-rest-1.0), [List applications](https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0), [List oauth2PermissionGrants](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0), [List subscribedSkus](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0)
- [Pricings - List](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list), [Security Contacts - List](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list) (called with `api-version=2020-01-01-preview`, the version of the [spec file that defines `Microsoft.Security/securityContacts`](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/security/resource-manager/Microsoft.Security/Security/preview/2020-01-01-preview/securityContacts.json); the Learn page renders the composite package moniker), [Diagnostic Settings - List](https://learn.microsoft.com/en-us/rest/api/monitor/diagnostic-settings/list), [Workspaces - List](https://learn.microsoft.com/en-us/rest/api/loganalytics/workspaces/list), [Entra log retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)
- [Role Assignments - List For Subscription](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-subscription), [Network Security Groups - List All](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-security-groups/list-all), [Network Watchers - List All](https://learn.microsoft.com/en-us/rest/api/network-watcher/network-watchers/list-all), [Flow Logs - List](https://learn.microsoft.com/en-us/rest/api/network-watcher/flow-logs/list)
- [Vaults - List By Subscription](https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/list-by-subscription), [Storage Accounts - List](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list)
- [Policy Assignments - List](https://learn.microsoft.com/en-us/rest/api/policy-authorization/policy-assignments/list), [Policy States - Summarize For Subscription](https://learn.microsoft.com/en-us/rest/api/policyinsights/policy-states/summarize-for-subscription), [Built-in policy definitions](https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies)
