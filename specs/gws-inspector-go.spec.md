---
slug: "gws-inspector-go"
name: "Google Workspace Inspector"
vendor: "Google"
category: "identity-and-collaboration"
language: "language-neutral"
status: "generated"
version: "1.0.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# Google Workspace Inspector

Portable contract for the shipped Google Workspace tenant inspector, distinct from the gws operator bridge.

## Purpose

Inspect Google Workspace identity, delegated administration, third-party OAuth exposure, audit activity, alerts, and two-step-verification policy using read-only tenant APIs.

## Design guidance

This is the tenant security inspector, not the `gws` operator bridge. Keep directory, reporting, Alert Center, per-user token, and Cloud Identity policy evidence distinct. A failed child token read or unavailable policy token must demote every dependent finding.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- A separate Cloud Identity policy token is optional; when absent or denied, policy-dependent findings remain manual and user or audit evidence cannot substitute for policy evidence.
- Per-user token-list failures are retained as partial markers and demote every dependent finding; named application lists are withheld unless every required user token read completed.
- The shipped collector does not read Chrome Policy, device controls, installed-app OAuth grants, or expanded group membership; those claims remain outside automated coverage.
- Installed-app OAuth, Chrome Policy, endpoint device controls, and group-membership expansion are not shipped.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `gws_check_access` | Validate Google Workspace read access for delegated service-account or direct access-token auth and show which security-relevant Admin SDK, Alert Center, and Cloud Identity Policy surfaces are readable. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `gws_assess_identity` | Review Google Workspace identity posture: 2-step verification coverage, privileged-user MFA enforcement, super-admin protection, dormant accounts, and the organization-level 2SV enforcement policy from the Cloud Identity Policy API. | `GWS-ID-001`, `GWS-ID-002`, `GWS-ID-003`, `GWS-ID-004`, `GWS-ID-005` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `gws_assess_admin_access` | Review Google Workspace privileged-role population, super-admin sprawl, suspended privileged accounts, delegated-admin use, admin audit visibility, and group-based grants. | `GWS-ADMIN-001`, `GWS-ADMIN-002`, `GWS-ADMIN-003`, `GWS-ADMIN-004`, `GWS-ADMIN-005` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `gws_assess_integrations` | Review third-party OAuth token inventory, privileged-user app exposure, high-scope client sprawl, and token-audit visibility in Google Workspace. | `GWS-INTEG-001`, `GWS-INTEG-002`, `GWS-INTEG-003`, `GWS-INTEG-004` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `gws_assess_monitoring` | Review Google Workspace Alert Center visibility, suspicious-login signals, admin audit coverage, token audit coverage, and the current alert backlog. | `GWS-MON-001`, `GWS-MON-002`, `GWS-MON-003`, `GWS-MON-004`, `GWS-MON-005` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `gws_export_audit_bundle` | Collect the Google Workspace identity, admin-access, integrations, and monitoring evidence set once, then write core_data/, analysis/, compliance/ (executive summary, unified matrix, per-framework reports), QUICK_REFERENCE.md, _errors.log on partial collection, and a zip archive that never overwrites an earlier bundle. | `GWS-ID-001`, `GWS-ID-002`, `GWS-ID-003`, `GWS-ID-004`, `GWS-ID-005`, `GWS-ADMIN-001`, `GWS-ADMIN-002`, `GWS-ADMIN-003`, `GWS-ADMIN-004`, `GWS-ADMIN-005`, `GWS-INTEG-001`, `GWS-INTEG-002`, `GWS-INTEG-003`, `GWS-INTEG-004`, `GWS-MON-001`, `GWS-MON-002`, `GWS-MON-003`, `GWS-MON-004`, `GWS-MON-005` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `gws_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_mode` | string | no | Optional auth mode override. Supported values: service_account or access_token. |
| `credentials_file` | string | no | Optional service account JSON file path. Falls back to GWS_CREDENTIALS_FILE or GOOGLE_APPLICATION_CREDENTIALS. |
| `credentials_json` | string | no | Optional inline service account JSON payload. Useful when the caller already has the secret material in-memory. |
| `access_token` | string | no | Optional direct bearer token for read-only Google Workspace access. Falls back to GWS_ACCESS_TOKEN. |
| `admin_email` | string | no | Delegated admin email for service-account auth. Falls back to GWS_ADMIN_EMAIL. |
| `domain` | string | no | Optional primary domain label used for display. Falls back to GWS_DOMAIN. |
| `customer_id` | string | no | Optional customer ID. Defaults to my_customer and falls back to GWS_CUSTOMER_ID. |
| `lookback_days` | integer | no | Optional audit lookback window in days. Defaults to 30. |

#### `gws_assess_identity`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_mode` | string | no | Optional auth mode override. Supported values: service_account or access_token. |
| `credentials_file` | string | no | Optional service account JSON file path. Falls back to GWS_CREDENTIALS_FILE or GOOGLE_APPLICATION_CREDENTIALS. |
| `credentials_json` | string | no | Optional inline service account JSON payload. Useful when the caller already has the secret material in-memory. |
| `access_token` | string | no | Optional direct bearer token for read-only Google Workspace access. Falls back to GWS_ACCESS_TOKEN. |
| `admin_email` | string | no | Delegated admin email for service-account auth. Falls back to GWS_ADMIN_EMAIL. |
| `domain` | string | no | Optional primary domain label used for display. Falls back to GWS_DOMAIN. |
| `customer_id` | string | no | Optional customer ID. Defaults to my_customer and falls back to GWS_CUSTOMER_ID. |
| `lookback_days` | integer | no | Optional audit lookback window in days. Defaults to 30. |

#### `gws_assess_admin_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_mode` | string | no | Optional auth mode override. Supported values: service_account or access_token. |
| `credentials_file` | string | no | Optional service account JSON file path. Falls back to GWS_CREDENTIALS_FILE or GOOGLE_APPLICATION_CREDENTIALS. |
| `credentials_json` | string | no | Optional inline service account JSON payload. Useful when the caller already has the secret material in-memory. |
| `access_token` | string | no | Optional direct bearer token for read-only Google Workspace access. Falls back to GWS_ACCESS_TOKEN. |
| `admin_email` | string | no | Delegated admin email for service-account auth. Falls back to GWS_ADMIN_EMAIL. |
| `domain` | string | no | Optional primary domain label used for display. Falls back to GWS_DOMAIN. |
| `customer_id` | string | no | Optional customer ID. Defaults to my_customer and falls back to GWS_CUSTOMER_ID. |
| `lookback_days` | integer | no | Optional audit lookback window in days. Defaults to 30. |

#### `gws_assess_integrations`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_mode` | string | no | Optional auth mode override. Supported values: service_account or access_token. |
| `credentials_file` | string | no | Optional service account JSON file path. Falls back to GWS_CREDENTIALS_FILE or GOOGLE_APPLICATION_CREDENTIALS. |
| `credentials_json` | string | no | Optional inline service account JSON payload. Useful when the caller already has the secret material in-memory. |
| `access_token` | string | no | Optional direct bearer token for read-only Google Workspace access. Falls back to GWS_ACCESS_TOKEN. |
| `admin_email` | string | no | Delegated admin email for service-account auth. Falls back to GWS_ADMIN_EMAIL. |
| `domain` | string | no | Optional primary domain label used for display. Falls back to GWS_DOMAIN. |
| `customer_id` | string | no | Optional customer ID. Defaults to my_customer and falls back to GWS_CUSTOMER_ID. |
| `lookback_days` | integer | no | Optional audit lookback window in days. Defaults to 30. |

#### `gws_assess_monitoring`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_mode` | string | no | Optional auth mode override. Supported values: service_account or access_token. |
| `credentials_file` | string | no | Optional service account JSON file path. Falls back to GWS_CREDENTIALS_FILE or GOOGLE_APPLICATION_CREDENTIALS. |
| `credentials_json` | string | no | Optional inline service account JSON payload. Useful when the caller already has the secret material in-memory. |
| `access_token` | string | no | Optional direct bearer token for read-only Google Workspace access. Falls back to GWS_ACCESS_TOKEN. |
| `admin_email` | string | no | Delegated admin email for service-account auth. Falls back to GWS_ADMIN_EMAIL. |
| `domain` | string | no | Optional primary domain label used for display. Falls back to GWS_DOMAIN. |
| `customer_id` | string | no | Optional customer ID. Defaults to my_customer and falls back to GWS_CUSTOMER_ID. |
| `lookback_days` | integer | no | Optional audit lookback window in days. Defaults to 30. |

#### `gws_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_mode` | string | no | Optional auth mode override. Supported values: service_account or access_token. |
| `credentials_file` | string | no | Optional service account JSON file path. Falls back to GWS_CREDENTIALS_FILE or GOOGLE_APPLICATION_CREDENTIALS. |
| `credentials_json` | string | no | Optional inline service account JSON payload. Useful when the caller already has the secret material in-memory. |
| `access_token` | string | no | Optional direct bearer token for read-only Google Workspace access. Falls back to GWS_ACCESS_TOKEN. |
| `admin_email` | string | no | Delegated admin email for service-account auth. Falls back to GWS_ADMIN_EMAIL. |
| `domain` | string | no | Optional primary domain label used for display. Falls back to GWS_DOMAIN. |
| `customer_id` | string | no | Optional customer ID. Defaults to my_customer and falls back to GWS_CUSTOMER_ID. |
| `lookback_days` | integer | no | Optional audit lookback window in days. Defaults to 30. |
| `output_dir` | string | no | Optional output root for the Google Workspace audit bundle. Defaults to ./export/gws. |
| `frameworks` | array | no | Optional framework report filter. Supported values: fedramp, cmmc, soc2, disa_stig, irap, ismap, pci_dss, cis. Defaults to every framework. |


## Authentication

Supported modes:

- Service-account JWT assertion with domain-wide delegation
- Explicit access tokens for directory/reporting and Cloud Identity policy reads

Credential precedence, highest first:

1. Explicit tool arguments and tokens
2. Explicit service-account JSON
3. GOOGLE_* and GWS_* environment variables

Environment variables: `GOOGLE_APPLICATION_CREDENTIALS`, `GWS_SERVICE_ACCOUNT_FILE`, `GWS_ADMIN_EMAIL`, `GWS_CUSTOMER_ID`, `GWS_ACCESS_TOKEN`, `GWS_POLICY_ACCESS_TOKEN`

Configuration locations: Service-account JSON supplied by path

Credential and deployment variants: my_customer alias or explicit customer ID, Separate delegated subject and Cloud Identity policy token

Configuration fields: `client_email`, `private_key`, `private_key_id`, `adminEmail`, `customerId`, `accessToken`, `policyAccessToken`

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

Credential refresh: POST https://oauth2.googleapis.com/token with a signed JWT bearer grant and delegated administrator subject.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| oauth-scope | `https://www.googleapis.com/auth/admin.directory.user.readonly` | `directory-users` |  |
| oauth-scope | `https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly` | `roles`, `role-assignments` |  |
| oauth-scope | `https://www.googleapis.com/auth/admin.directory.user.security` | `user-tokens` |  |
| oauth-scope | `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `login-activities`, `admin-activities`, `token-activities` |  |
| oauth-scope | `https://www.googleapis.com/auth/apps.alerts` | `alerts` |  |
| oauth-scope | `https://www.googleapis.com/auth/cloud-identity.policies.readonly` | `two-step-policies` | Requested with the separate policy token; absence affects only policy-dependent findings. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `directory-users` | HTTP | `GET /admin/directory/v1/users` | Admin SDK Directory API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `primaryEmail`, `suspended`, `archived`, `isAdmin`, `isEnforcedIn2Sv`, `lastLoginTime` | [Official documentation](https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/list) |
| `roles` | HTTP | `GET /admin/directory/v1/customer/{customer}/roles` | Admin SDK Directory API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `roleId`, `roleName`, `isSystemRole`, `isSuperAdminRole`, `rolePrivileges` | [Official documentation](https://developers.google.com/admin-sdk/directory/reference/rest/v1/roles/list) |
| `role-assignments` | HTTP | `GET /admin/directory/v1/customer/{customer}/roleassignments` | Admin SDK Directory API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `roleAssignmentId`, `roleId`, `assignedTo`, `scopeType` | [Official documentation](https://developers.google.com/admin-sdk/directory/reference/rest/v1/roleAssignments/list) |
| `user-tokens` | HTTP | `GET /admin/directory/v1/users/{userKey}/tokens` | Admin SDK Directory API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `clientId`, `displayText`, `scopes`, `anonymous` | [Official documentation](https://developers.google.com/admin-sdk/directory/reference/rest/v1/tokens/list) |
| `login-activities` | HTTP | `GET /admin/reports/v1/activity/users/all/applications/login` | Admin SDK Reports API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `actor`, `events`, `ipAddress` | [Official documentation](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list) |
| `admin-activities` | HTTP | `GET /admin/reports/v1/activity/users/all/applications/admin` | Admin SDK Reports API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `actor`, `events`, `ipAddress` | [Official documentation](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list) |
| `token-activities` | HTTP | `GET /admin/reports/v1/activity/users/all/applications/token` | Admin SDK Reports API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `actor`, `events`, `ipAddress` | [Official documentation](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list) |
| `alerts` | HTTP | `GET /v1beta1/alerts` | Alert Center API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `alertId`, `type`, `source`, `createTime`, `endTime`, `metadata.status`, `metadata.severity` | [Official documentation](https://developers.google.com/admin-sdk/alertcenter/reference/rest/v1beta1/alerts/list) |
| `two-step-policies` | HTTP | `GET /v1/policies` | Cloud Identity API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `name`, `customer`, `type`, `policyQuery`, `setting.value.enforcedFrom`, `setting.value.allowEnrollment`, `setting.value.allowedSignInFactorSet` | [Official documentation](https://cloud.google.com/identity/docs/reference/rest/v1/policies/list) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `directory-users` | client | Use the configured Admin SDK Directory API origin; never follow a server link to a different origin. | yes |
| `directory-users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `directory-users` | response | A JSON object or list containing only the documented id, primaryEmail, suspended, archived, isAdmin, isEnforcedIn2Sv, lastLoginTime members consumed by verdicts. | yes |
| `roles` | client | Use the configured Admin SDK Directory API origin; never follow a server link to a different origin. | yes |
| `roles` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `roles` | response | A JSON object or list containing only the documented roleId, roleName, isSystemRole, isSuperAdminRole, rolePrivileges members consumed by verdicts. | yes |
| `role-assignments` | client | Use the configured Admin SDK Directory API origin; never follow a server link to a different origin. | yes |
| `role-assignments` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `role-assignments` | response | A JSON object or list containing only the documented roleAssignmentId, roleId, assignedTo, scopeType members consumed by verdicts. | yes |
| `user-tokens` | client | Use the configured Admin SDK Directory API origin; never follow a server link to a different origin. | yes |
| `user-tokens` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `user-tokens` | response | A JSON object or list containing only the documented clientId, displayText, scopes, anonymous members consumed by verdicts. | yes |
| `login-activities` | client | Use the configured Admin SDK Reports API origin; never follow a server link to a different origin. | yes |
| `login-activities` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `login-activities` | response | A JSON object or list containing only the documented id, actor, events, ipAddress members consumed by verdicts. | yes |
| `admin-activities` | client | Use the configured Admin SDK Reports API origin; never follow a server link to a different origin. | yes |
| `admin-activities` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `admin-activities` | response | A JSON object or list containing only the documented id, actor, events, ipAddress members consumed by verdicts. | yes |
| `token-activities` | client | Use the configured Admin SDK Reports API origin; never follow a server link to a different origin. | yes |
| `token-activities` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `token-activities` | response | A JSON object or list containing only the documented id, actor, events, ipAddress members consumed by verdicts. | yes |
| `alerts` | client | Use the configured Alert Center API origin; never follow a server link to a different origin. | yes |
| `alerts` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `alerts` | response | A JSON object or list containing only the documented alertId, type, source, createTime, endTime, metadata.status, metadata.severity members consumed by verdicts. | yes |
| `two-step-policies` | client | Use the configured Cloud Identity API origin; never follow a server link to a different origin. | yes |
| `two-step-policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `two-step-policies` | response | A JSON object or list containing only the documented name, customer, type, policyQuery, setting.value.enforcedFrom, setting.value.allowEnrollment, setting.value.allowedSignInFactorSet members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `directory-users` | `nextPageToken`, `pageToken` | 500 | 5000 | 1000 | No total is returned; a missing nextPageToken before the 5,000-user cap proves exhaustion. | No nextPageToken; 5,000-user cap; 1,000-page cap; Repeated token; Empty page with token |
| `roles` | `nextPageToken`, `pageToken` | 100 | 1000 | 1000 | No total is returned; completion requires a missing nextPageToken. | No nextPageToken; 1,000-role cap; Page cap; Repeated token; Empty page with token |
| `role-assignments` | `nextPageToken`, `pageToken` | 200 | 10000 | 1000 | No total is returned; completion requires a missing nextPageToken. | No nextPageToken; 10,000-assignment cap; Page cap; Repeated token; Empty page with token |
| `login-activities`, `admin-activities`, `token-activities` | `nextPageToken`, `pageToken` | 1000 | 5000 | 1000 | Reports omit a total; completion requires token exhaustion. | No nextPageToken; 5,000-record cap; Page cap; Repeated token; Empty page with token |
| `alerts`, `two-step-policies` | `nextPageToken`, `pageToken` | 100 | 1000 | 1000 | No authoritative total is used; completion requires token exhaustion. | No nextPageToken; 1,000-item cap; Page cap; Repeated token; Empty page with token |
| `user-tokens` | None | service default | 50 | none | tokens.list is a single request per user; only the first 50 users are queried and any skipped or failed user makes the aggregate inventory incomplete. | Single response; 50-user sampling cap; Per-user denial or error |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Google Workspace Inspector | Per-project and per-customer Google API quotas | `Retry-After` | 429, 500, 502, 503, 504 | Use bounded exponential backoff with jitter and honor Retry-After; exhausted requests become unreadable evidence. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | Privileged users enforce 2-step verification | GWS-ID-001 | Evaluate the ordered first-match rules for GWS-ID-001 below. |
| 2 | Broad 2-step verification coverage for active users | GWS-ID-002 | Evaluate the ordered first-match rules for GWS-ID-002 below. |
| 3 | Dormant active accounts stay limited | GWS-ID-003 | Evaluate the ordered first-match rules for GWS-ID-003 below. |
| 4 | Super admins stay strongly protected | GWS-ID-004 | Evaluate the ordered first-match rules for GWS-ID-004 below. |
| 5 | 2-step verification is enforced by organization policy | GWS-ID-005 | Evaluate the ordered first-match rules for GWS-ID-005 below. |
| 6 | Super admin population stays constrained | GWS-ADMIN-001 | Evaluate the ordered first-match rules for GWS-ADMIN-001 below. |
| 7 | Suspended or archived privileged accounts are removed | GWS-ADMIN-002 | Evaluate the ordered first-match rules for GWS-ADMIN-002 below. |
| 8 | Delegated roles reduce Super Admin dependence | GWS-ADMIN-003 | Evaluate the ordered first-match rules for GWS-ADMIN-003 below. |
| 9 | Privileged activity stays observable | GWS-ADMIN-004 | Evaluate the ordered first-match rules for GWS-ADMIN-004 below. |
| 10 | Group-based admin grants get explicit review | GWS-ADMIN-005 | Evaluate the ordered first-match rules for GWS-ADMIN-005 below. |
| 11 | Third-party token inventory is readable | GWS-INTEG-001 | Evaluate the ordered first-match rules for GWS-INTEG-001 below. |
| 12 | Privileged users avoid excessive third-party token exposure | GWS-INTEG-002 | Evaluate the ordered first-match rules for GWS-INTEG-002 below. |
| 13 | High-scope third-party apps stay limited | GWS-INTEG-003 | Evaluate the ordered first-match rules for GWS-INTEG-003 below. |
| 14 | Token activity telemetry stays available | GWS-INTEG-004 | Evaluate the ordered first-match rules for GWS-INTEG-004 below. |
| 15 | Alert Center is available for the tenant | GWS-MON-001 | Evaluate the ordered first-match rules for GWS-MON-001 below. |
| 16 | Suspicious login backlog stays low | GWS-MON-002 | Evaluate the ordered first-match rules for GWS-MON-002 below. |
| 17 | Admin audit telemetry stays available | GWS-MON-003 | Evaluate the ordered first-match rules for GWS-MON-003 below. |
| 18 | Token audit telemetry stays available | GWS-MON-004 | Evaluate the ordered first-match rules for GWS-MON-004 below. |
| 19 | Open alert backlog is manageable | GWS-MON-005 | Evaluate the ordered first-match rules for GWS-MON-005 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `GWS-ID-001` | high | `gws_assess_identity` | `directory-users` | `id`, `primaryEmail`, `suspended`, `archived`, `isAdmin`, `isEnforcedIn2Sv`, `lastLoginTime`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: for a non-empty privileged-user population, return pass when 100 percent enforce 2-step verification, warn from 80 percent through below 100 percent, and fail below 80 percent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for a non-empty privileged-user population, return pass when 100 percent enforce 2-step verification, warn from 80 percent through below 100 percent, and fail below 80 percent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for a non-empty privileged-user population, return pass when 100 percent enforce 2-step verification, warn from 80 percent through below 100 percent, and fail below 80 percent. | The required evidence for Privileged users enforce 2-step verification is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ID-002` | high | `gws_assess_identity` | `directory-users` | `id`, `primaryEmail`, `suspended`, `archived`, `isAdmin`, `isEnforcedIn2Sv`, `lastLoginTime`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: for a non-empty active-user population, return pass when at least 98 percent enforce 2-step verification, warn from 85 percent through below 98 percent, and fail below 85 percent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for a non-empty active-user population, return pass when at least 98 percent enforce 2-step verification, warn from 85 percent through below 98 percent, and fail below 85 percent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for a non-empty active-user population, return pass when at least 98 percent enforce 2-step verification, warn from 85 percent through below 98 percent, and fail below 85 percent. | The required evidence for Broad 2-step verification coverage for active users is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ID-003` | medium | `gws_assess_identity` | `directory-users` | `id`, `primaryEmail`, `suspended`, `archived`, `isAdmin`, `isEnforcedIn2Sv`, `lastLoginTime`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when more than 10 percent of active users have no login within the configured stale period, warn when one through 10 percent are dormant or login dates are missing, and pass when none are dormant or undated. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when more than 10 percent of active users have no login within the configured stale period, warn when one through 10 percent are dormant or login dates are missing, and pass when none are dormant or undated. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when more than 10 percent of active users have no login within the configured stale period, warn when one through 10 percent are dormant or login dates are missing, and pass when none are dormant or undated. | The required evidence for Dormant active accounts stay limited is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ID-004` | high | `gws_assess_identity` | `directory-users`, `login-activities` | `id`, `primaryEmail`, `suspended`, `archived`, `isAdmin`, `isEnforcedIn2Sv`, `lastLoginTime`, `actor`, `events`, `ipAddress`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every super admin enforces 2-step verification and has recent activity, fail when any super admin lacks enforced 2-step verification, and warn for stale, undated, or partial evidence. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every super admin enforces 2-step verification and has recent activity, fail when any super admin lacks enforced 2-step verification, and warn for stale, undated, or partial evidence. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every super admin enforces 2-step verification and has recent activity, fail when any super admin lacks enforced 2-step verification, and warn for stale, undated, or partial evidence. | The required evidence for Super admins stay strongly protected is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ID-005` | high | `gws_assess_identity` | `two-step-policies` | `name`, `customer`, `type`, `policyQuery`, `setting.value.enforcedFrom`, `setting.value.allowEnrollment`, `setting.value.allowedSignInFactorSet`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every returned enforcement policy has a past enforcedFrom date and enrollment is allowed, warn when only some scopes satisfy that state, fail when none do, and manual when the policy token or enforcement setting is unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every returned enforcement policy has a past enforcedFrom date and enrollment is allowed, warn when only some scopes satisfy that state, fail when none do, and manual when the policy token or enforcement setting is unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every returned enforcement policy has a past enforcedFrom date and enrollment is allowed, warn when only some scopes satisfy that state, fail when none do, and manual when the policy token or enforcement setting is unavailable. | The required evidence for 2-step verification is enforced by organization policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ADMIN-001` | high | `gws_assess_admin_access` | `directory-users`, `roles`, `role-assignments` | `id`, `primaryEmail`, `suspended`, `archived`, `isAdmin`, `isEnforcedIn2Sv`, `lastLoginTime`, `roleId`, `roleName`, `isSystemRole`, `isSuperAdminRole`, `rolePrivileges`, `roleAssignmentId`, `assignedTo`, `scopeType`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete privileged inventory has at most two super admins, warn with three through five, and fail above five. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete privileged inventory has at most two super admins, warn with three through five, and fail above five. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete privileged inventory has at most two super admins, warn with three through five, and fail above five. | The required evidence for Super admin population stays constrained is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ADMIN-002` | high | `gws_assess_admin_access` | `directory-users`, `roles`, `role-assignments` | `id`, `primaryEmail`, `suspended`, `archived`, `isAdmin`, `isEnforcedIn2Sv`, `lastLoginTime`, `roleId`, `roleName`, `isSystemRole`, `isSuperAdminRole`, `rolePrivileges`, `roleAssignmentId`, `assignedTo`, `scopeType`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any privileged user is suspended or archived and pass when none is, with partial evidence demoting pass to warn. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any privileged user is suspended or archived and pass when none is, with partial evidence demoting pass to warn. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any privileged user is suspended or archived and pass when none is, with partial evidence demoting pass to warn. | The required evidence for Suspended or archived privileged accounts are removed is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ADMIN-003` | high | `gws_assess_admin_access` | `roles`, `role-assignments` | `roleId`, `roleName`, `isSystemRole`, `isSuperAdminRole`, `rolePrivileges`, `roleAssignmentId`, `assignedTo`, `scopeType`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when at least one active delegated role assignment exists outside the Super Admin role, warn when none exists or role evidence is partial, and manual when role definitions or assignments are unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when at least one active delegated role assignment exists outside the Super Admin role, warn when none exists or role evidence is partial, and manual when role definitions or assignments are unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when at least one active delegated role assignment exists outside the Super Admin role, warn when none exists or role evidence is partial, and manual when role definitions or assignments are unavailable. | The required evidence for Delegated roles reduce Super Admin dependence is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ADMIN-004` | high | `gws_assess_admin_access` | `admin-activities` | `id`, `actor`, `events`, `ipAddress`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete admin-audit lookback contains activity, warn when it is empty or truncated, and manual when the audit read is denied or unreadable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete admin-audit lookback contains activity, warn when it is empty or truncated, and manual when the audit read is denied or unreadable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete admin-audit lookback contains activity, warn when it is empty or truncated, and manual when the audit read is denied or unreadable. | The required evidence for Privileged activity stays observable is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ADMIN-005` | medium | `gws_assess_admin_access` | `role-assignments` | `roleAssignmentId`, `roleId`, `assignedTo`, `scopeType`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: always return manual when group-based role assignments exist because expanded group membership is not collected; return pass only when complete role-assignment evidence proves no group-based grant. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: always return manual when group-based role assignments exist because expanded group membership is not collected; return pass only when complete role-assignment evidence proves no group-based grant. | Complete readable evidence satisfies the violation branch, which has first-match precedence: always return manual when group-based role assignments exist because expanded group membership is not collected; return pass only when complete role-assignment evidence proves no group-based grant. | The required evidence for Group-based admin grants get explicit review is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-INTEG-001` | medium | `gws_assess_integrations` | `directory-users`, `user-tokens` | `id`, `primaryEmail`, `suspended`, `archived`, `isAdmin`, `isEnforcedIn2Sv`, `lastLoginTime`, `clientId`, `displayText`, `scopes`, `anonymous`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every required per-user token read completes and at least one token is inventoried, warn when the complete inventory is empty, and manual when any token read is denied, failed, unattributed, or skipped. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every required per-user token read completes and at least one token is inventoried, warn when the complete inventory is empty, and manual when any token read is denied, failed, unattributed, or skipped. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every required per-user token read completes and at least one token is inventoried, warn when the complete inventory is empty, and manual when any token read is denied, failed, unattributed, or skipped. | The required evidence for Third-party token inventory is readable is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-INTEG-002` | high | `gws_assess_integrations` | `directory-users`, `roles`, `role-assignments`, `user-tokens` | `id`, `primaryEmail`, `suspended`, `archived`, `isAdmin`, `isEnforcedIn2Sv`, `lastLoginTime`, `roleId`, `roleName`, `isSystemRole`, `isSuperAdminRole`, `rolePrivileges`, `roleAssignmentId`, `assignedTo`, `scopeType`, `clientId`, `displayText`, `scopes`, `anonymous`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any privileged user has more than the configured token threshold, warn when any has a smaller non-zero exposure or reads are partial, and pass when complete reads show no excessive privileged exposure. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any privileged user has more than the configured token threshold, warn when any has a smaller non-zero exposure or reads are partial, and pass when complete reads show no excessive privileged exposure. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any privileged user has more than the configured token threshold, warn when any has a smaller non-zero exposure or reads are partial, and pass when complete reads show no excessive privileged exposure. | The required evidence for Privileged users avoid excessive third-party token exposure is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-INTEG-003` | medium | `gws_assess_integrations` | `user-tokens` | `clientId`, `displayText`, `scopes`, `anonymous`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any visible application grant contains a high-risk scope, warn when high-scope applications remain below the configured count or token evidence is partial, and pass when complete token evidence contains none. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any visible application grant contains a high-risk scope, warn when high-scope applications remain below the configured count or token evidence is partial, and pass when complete token evidence contains none. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any visible application grant contains a high-risk scope, warn when high-scope applications remain below the configured count or token evidence is partial, and pass when complete token evidence contains none. | The required evidence for High-scope third-party apps stay limited is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-INTEG-004` | medium | `gws_assess_integrations` | `token-activities` | `id`, `actor`, `events`, `ipAddress`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete token audit lookback contains at least one event, warn when it is empty or truncated, and manual when token audit telemetry is unreadable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete token audit lookback contains at least one event, warn when it is empty or truncated, and manual when token audit telemetry is unreadable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete token audit lookback contains at least one event, warn when it is empty or truncated, and manual when token audit telemetry is unreadable. | The required evidence for Token activity telemetry stays available is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-MON-001` | high | `gws_assess_monitoring` | `alerts` | `alertId`, `type`, `source`, `createTime`, `endTime`, `metadata.status`, `metadata.severity`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the Alert Center endpoint is readable, including a complete empty alert inventory, warn when its inventory is truncated, and manual when access is denied or unreadable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the Alert Center endpoint is readable, including a complete empty alert inventory, warn when its inventory is truncated, and manual when access is denied or unreadable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the Alert Center endpoint is readable, including a complete empty alert inventory, warn when its inventory is truncated, and manual when access is denied or unreadable. | The required evidence for Alert Center is available for the tenant is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-MON-002` | high | `gws_assess_monitoring` | `alerts` | `alertId`, `type`, `source`, `createTime`, `endTime`, `metadata.status`, `metadata.severity`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when open suspicious-login alerts exceed the configured threshold, warn when one through the threshold remain or alert evidence is partial, and pass when the complete inventory contains none. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when open suspicious-login alerts exceed the configured threshold, warn when one through the threshold remain or alert evidence is partial, and pass when the complete inventory contains none. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when open suspicious-login alerts exceed the configured threshold, warn when one through the threshold remain or alert evidence is partial, and pass when the complete inventory contains none. | The required evidence for Suspicious login backlog stays low is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-MON-003` | medium | `gws_assess_monitoring` | `admin-activities` | `id`, `actor`, `events`, `ipAddress`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete admin-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete admin-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete admin-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. | The required evidence for Admin audit telemetry stays available is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-MON-004` | medium | `gws_assess_monitoring` | `token-activities` | `id`, `actor`, `events`, `ipAddress`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete token-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete token-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete token-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. | The required evidence for Token audit telemetry stays available is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-MON-005` | medium | `gws_assess_monitoring` | `alerts` | `alertId`, `type`, `source`, `createTime`, `endTime`, `metadata.status`, `metadata.severity`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when open alerts exceed the configured backlog threshold, warn when a non-zero backlog is within the threshold or the inventory is partial, and pass when a complete inventory has no open alerts. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when open alerts exceed the configured backlog threshold, warn when a non-zero backlog is within the threshold or the inventory is partial, and pass when a complete inventory has no open alerts. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when open alerts exceed the configured backlog threshold, warn when a non-zero backlog is within the threshold or the inventory is partial, and pass when a complete inventory has no open alerts. | The required evidence for Open alert backlog is manageable is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `GWS-ID-001` | 1 | fail | `gws_id_001_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `GWS-ID-001` | 2 | manual | any of (`gws_id_001_required_evidence_readable` equals false; not (`gws_id_001_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-ID-001` | 3 | warn | any of (`gws_id_001_warning_matches` equals true; `gws_id_001_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-ID-001` | 4 | pass | all of (`gws_id_001_compliant_matches` equals true; `gws_id_001_required_evidence_readable` equals true; `gws_id_001_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-ID-001` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-ID-002` | 1 | fail | `gws_id_002_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `GWS-ID-002` | 2 | manual | any of (`gws_id_002_required_evidence_readable` equals false; not (`gws_id_002_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-ID-002` | 3 | warn | any of (`gws_id_002_warning_matches` equals true; `gws_id_002_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-ID-002` | 4 | pass | all of (`gws_id_002_compliant_matches` equals true; `gws_id_002_required_evidence_readable` equals true; `gws_id_002_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-ID-002` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-ID-003` | 1 | fail | `gws_id_003_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `GWS-ID-003` | 2 | manual | any of (`gws_id_003_required_evidence_readable` equals false; not (`gws_id_003_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-ID-003` | 3 | warn | any of (`gws_id_003_warning_matches` equals true; `gws_id_003_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-ID-003` | 4 | pass | all of (`gws_id_003_compliant_matches` equals true; `gws_id_003_required_evidence_readable` equals true; `gws_id_003_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-ID-003` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-ID-004` | 1 | fail | `gws_id_004_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `GWS-ID-004` | 2 | manual | any of (`gws_id_004_required_evidence_readable` equals false; not (`gws_id_004_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-ID-004` | 3 | warn | any of (`gws_id_004_warning_matches` equals true; `gws_id_004_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-ID-004` | 4 | pass | all of (`gws_id_004_compliant_matches` equals true; `gws_id_004_required_evidence_readable` equals true; `gws_id_004_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-ID-004` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-ID-005` | 1 | fail | `gws_id_005_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `GWS-ID-005` | 2 | manual | any of (`gws_id_005_required_evidence_readable` equals false; not (`gws_id_005_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-ID-005` | 3 | warn | any of (`gws_id_005_warning_matches` equals true; `gws_id_005_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-ID-005` | 4 | pass | all of (`gws_id_005_compliant_matches` equals true; `gws_id_005_required_evidence_readable` equals true; `gws_id_005_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-ID-005` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-ADMIN-001` | 1 | fail | `gws_admin_001_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `GWS-ADMIN-001` | 2 | manual | any of (`gws_admin_001_required_evidence_readable` equals false; not (`gws_admin_001_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-ADMIN-001` | 3 | warn | any of (`gws_admin_001_warning_matches` equals true; `gws_admin_001_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-ADMIN-001` | 4 | pass | all of (`gws_admin_001_compliant_matches` equals true; `gws_admin_001_required_evidence_readable` equals true; `gws_admin_001_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-ADMIN-001` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-ADMIN-002` | 1 | fail | `gws_admin_002_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `GWS-ADMIN-002` | 2 | manual | any of (`gws_admin_002_required_evidence_readable` equals false; not (`gws_admin_002_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-ADMIN-002` | 3 | warn | any of (`gws_admin_002_warning_matches` equals true; `gws_admin_002_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-ADMIN-002` | 4 | pass | all of (`gws_admin_002_compliant_matches` equals true; `gws_admin_002_required_evidence_readable` equals true; `gws_admin_002_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-ADMIN-002` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-ADMIN-003` | 1 | manual | any of (`gws_admin_003_required_evidence_readable` equals false; not (`gws_admin_003_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-ADMIN-003` | 2 | warn | any of (`gws_admin_003_warning_matches` equals true; `gws_admin_003_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-ADMIN-003` | 3 | pass | all of (`gws_admin_003_compliant_matches` equals true; `gws_admin_003_required_evidence_readable` equals true; `gws_admin_003_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-ADMIN-003` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-ADMIN-004` | 1 | manual | any of (`gws_admin_004_required_evidence_readable` equals false; not (`gws_admin_004_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-ADMIN-004` | 2 | warn | any of (`gws_admin_004_warning_matches` equals true; `gws_admin_004_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-ADMIN-004` | 3 | pass | all of (`gws_admin_004_compliant_matches` equals true; `gws_admin_004_required_evidence_readable` equals true; `gws_admin_004_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-ADMIN-004` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-ADMIN-005` | 1 | manual | any of (`gws_admin_005_required_evidence_readable` equals false; not (`gws_admin_005_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-ADMIN-005` | 2 | pass | all of (`gws_admin_005_compliant_matches` equals true; `gws_admin_005_required_evidence_readable` equals true; `gws_admin_005_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-ADMIN-005` | 3 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-INTEG-001` | 1 | manual | any of (`gws_integ_001_required_evidence_readable` equals false; not (`gws_integ_001_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-INTEG-001` | 2 | warn | any of (`gws_integ_001_warning_matches` equals true; `gws_integ_001_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-INTEG-001` | 3 | pass | all of (`gws_integ_001_compliant_matches` equals true; `gws_integ_001_required_evidence_readable` equals true; `gws_integ_001_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-INTEG-001` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-INTEG-002` | 1 | fail | `gws_integ_002_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `GWS-INTEG-002` | 2 | manual | any of (`gws_integ_002_required_evidence_readable` equals false; not (`gws_integ_002_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-INTEG-002` | 3 | warn | any of (`gws_integ_002_warning_matches` equals true; `gws_integ_002_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-INTEG-002` | 4 | pass | all of (`gws_integ_002_compliant_matches` equals true; `gws_integ_002_required_evidence_readable` equals true; `gws_integ_002_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-INTEG-002` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-INTEG-003` | 1 | fail | `gws_integ_003_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `GWS-INTEG-003` | 2 | manual | any of (`gws_integ_003_required_evidence_readable` equals false; not (`gws_integ_003_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-INTEG-003` | 3 | warn | any of (`gws_integ_003_warning_matches` equals true; `gws_integ_003_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-INTEG-003` | 4 | pass | all of (`gws_integ_003_compliant_matches` equals true; `gws_integ_003_required_evidence_readable` equals true; `gws_integ_003_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-INTEG-003` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-INTEG-004` | 1 | manual | any of (`gws_integ_004_required_evidence_readable` equals false; not (`gws_integ_004_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-INTEG-004` | 2 | warn | any of (`gws_integ_004_warning_matches` equals true; `gws_integ_004_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-INTEG-004` | 3 | pass | all of (`gws_integ_004_compliant_matches` equals true; `gws_integ_004_required_evidence_readable` equals true; `gws_integ_004_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-INTEG-004` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-MON-001` | 1 | manual | any of (`gws_mon_001_required_evidence_readable` equals false; not (`gws_mon_001_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-MON-001` | 2 | warn | any of (`gws_mon_001_warning_matches` equals true; `gws_mon_001_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-MON-001` | 3 | pass | all of (`gws_mon_001_compliant_matches` equals true; `gws_mon_001_required_evidence_readable` equals true; `gws_mon_001_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-MON-001` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-MON-002` | 1 | fail | `gws_mon_002_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `GWS-MON-002` | 2 | manual | any of (`gws_mon_002_required_evidence_readable` equals false; not (`gws_mon_002_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-MON-002` | 3 | warn | any of (`gws_mon_002_warning_matches` equals true; `gws_mon_002_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-MON-002` | 4 | pass | all of (`gws_mon_002_compliant_matches` equals true; `gws_mon_002_required_evidence_readable` equals true; `gws_mon_002_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-MON-002` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-MON-003` | 1 | manual | any of (`gws_mon_003_required_evidence_readable` equals false; not (`gws_mon_003_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-MON-003` | 2 | warn | any of (`gws_mon_003_warning_matches` equals true; `gws_mon_003_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-MON-003` | 3 | pass | all of (`gws_mon_003_compliant_matches` equals true; `gws_mon_003_required_evidence_readable` equals true; `gws_mon_003_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-MON-003` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-MON-004` | 1 | manual | any of (`gws_mon_004_required_evidence_readable` equals false; not (`gws_mon_004_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-MON-004` | 2 | warn | any of (`gws_mon_004_warning_matches` equals true; `gws_mon_004_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-MON-004` | 3 | pass | all of (`gws_mon_004_compliant_matches` equals true; `gws_mon_004_required_evidence_readable` equals true; `gws_mon_004_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-MON-004` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `GWS-MON-005` | 1 | fail | `gws_mon_005_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `GWS-MON-005` | 2 | manual | any of (`gws_mon_005_required_evidence_readable` equals false; not (`gws_mon_005_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `GWS-MON-005` | 3 | warn | any of (`gws_mon_005_warning_matches` equals true; `gws_mon_005_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `GWS-MON-005` | 4 | pass | all of (`gws_mon_005_compliant_matches` equals true; `gws_mon_005_required_evidence_readable` equals true; `gws_mon_005_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `GWS-MON-005` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `GWS-ID-001` | `gws_id_001_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-ID-001 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-ID-001` | `gws_id_001_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-ID-001` | `gws_id_001_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: for a non-empty privileged-user population, return pass when 100 percent enforce 2-step verification, warn from 80 percent through below 100 percent, and fail below 80 percent. |
| `GWS-ID-001` | `gws_id_001_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: for a non-empty privileged-user population, return pass when 100 percent enforce 2-step verification, warn from 80 percent through below 100 percent, and fail below 80 percent. |
| `GWS-ID-001` | `gws_id_001_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: for a non-empty privileged-user population, return pass when 100 percent enforce 2-step verification, warn from 80 percent through below 100 percent, and fail below 80 percent. |
| `GWS-ID-002` | `gws_id_002_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-ID-002 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-ID-002` | `gws_id_002_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-ID-002` | `gws_id_002_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: for a non-empty active-user population, return pass when at least 98 percent enforce 2-step verification, warn from 85 percent through below 98 percent, and fail below 85 percent. |
| `GWS-ID-002` | `gws_id_002_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: for a non-empty active-user population, return pass when at least 98 percent enforce 2-step verification, warn from 85 percent through below 98 percent, and fail below 85 percent. |
| `GWS-ID-002` | `gws_id_002_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: for a non-empty active-user population, return pass when at least 98 percent enforce 2-step verification, warn from 85 percent through below 98 percent, and fail below 85 percent. |
| `GWS-ID-003` | `gws_id_003_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-ID-003 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-ID-003` | `gws_id_003_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-ID-003` | `gws_id_003_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when more than 10 percent of active users have no login within the configured stale period, warn when one through 10 percent are dormant or login dates are missing, and pass when none are dormant or undated. |
| `GWS-ID-003` | `gws_id_003_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when more than 10 percent of active users have no login within the configured stale period, warn when one through 10 percent are dormant or login dates are missing, and pass when none are dormant or undated. |
| `GWS-ID-003` | `gws_id_003_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when more than 10 percent of active users have no login within the configured stale period, warn when one through 10 percent are dormant or login dates are missing, and pass when none are dormant or undated. |
| `GWS-ID-004` | `gws_id_004_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-ID-004 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-ID-004` | `gws_id_004_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-ID-004` | `gws_id_004_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when every super admin enforces 2-step verification and has recent activity, fail when any super admin lacks enforced 2-step verification, and warn for stale, undated, or partial evidence. |
| `GWS-ID-004` | `gws_id_004_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when every super admin enforces 2-step verification and has recent activity, fail when any super admin lacks enforced 2-step verification, and warn for stale, undated, or partial evidence. |
| `GWS-ID-004` | `gws_id_004_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when every super admin enforces 2-step verification and has recent activity, fail when any super admin lacks enforced 2-step verification, and warn for stale, undated, or partial evidence. |
| `GWS-ID-005` | `gws_id_005_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-ID-005 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-ID-005` | `gws_id_005_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-ID-005` | `gws_id_005_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when every returned enforcement policy has a past enforcedFrom date and enrollment is allowed, warn when only some scopes satisfy that state, fail when none do, and manual when the policy token or enforcement setting is unavailable. |
| `GWS-ID-005` | `gws_id_005_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when every returned enforcement policy has a past enforcedFrom date and enrollment is allowed, warn when only some scopes satisfy that state, fail when none do, and manual when the policy token or enforcement setting is unavailable. |
| `GWS-ID-005` | `gws_id_005_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when every returned enforcement policy has a past enforcedFrom date and enrollment is allowed, warn when only some scopes satisfy that state, fail when none do, and manual when the policy token or enforcement setting is unavailable. |
| `GWS-ADMIN-001` | `gws_admin_001_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-ADMIN-001 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-ADMIN-001` | `gws_admin_001_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-ADMIN-001` | `gws_admin_001_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the complete privileged inventory has at most two super admins, warn with three through five, and fail above five. |
| `GWS-ADMIN-001` | `gws_admin_001_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the complete privileged inventory has at most two super admins, warn with three through five, and fail above five. |
| `GWS-ADMIN-001` | `gws_admin_001_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the complete privileged inventory has at most two super admins, warn with three through five, and fail above five. |
| `GWS-ADMIN-002` | `gws_admin_002_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-ADMIN-002 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-ADMIN-002` | `gws_admin_002_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-ADMIN-002` | `gws_admin_002_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any privileged user is suspended or archived and pass when none is, with partial evidence demoting pass to warn. |
| `GWS-ADMIN-002` | `gws_admin_002_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any privileged user is suspended or archived and pass when none is, with partial evidence demoting pass to warn. |
| `GWS-ADMIN-002` | `gws_admin_002_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any privileged user is suspended or archived and pass when none is, with partial evidence demoting pass to warn. |
| `GWS-ADMIN-003` | `gws_admin_003_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-ADMIN-003 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-ADMIN-003` | `gws_admin_003_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-ADMIN-003` | `gws_admin_003_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when at least one active delegated role assignment exists outside the Super Admin role, warn when none exists or role evidence is partial, and manual when role definitions or assignments are unavailable. |
| `GWS-ADMIN-003` | `gws_admin_003_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when at least one active delegated role assignment exists outside the Super Admin role, warn when none exists or role evidence is partial, and manual when role definitions or assignments are unavailable. |
| `GWS-ADMIN-003` | `gws_admin_003_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when at least one active delegated role assignment exists outside the Super Admin role, warn when none exists or role evidence is partial, and manual when role definitions or assignments are unavailable. |
| `GWS-ADMIN-004` | `gws_admin_004_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-ADMIN-004 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-ADMIN-004` | `gws_admin_004_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-ADMIN-004` | `gws_admin_004_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the complete admin-audit lookback contains activity, warn when it is empty or truncated, and manual when the audit read is denied or unreadable. |
| `GWS-ADMIN-004` | `gws_admin_004_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the complete admin-audit lookback contains activity, warn when it is empty or truncated, and manual when the audit read is denied or unreadable. |
| `GWS-ADMIN-004` | `gws_admin_004_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the complete admin-audit lookback contains activity, warn when it is empty or truncated, and manual when the audit read is denied or unreadable. |
| `GWS-ADMIN-005` | `gws_admin_005_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-ADMIN-005 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-ADMIN-005` | `gws_admin_005_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-ADMIN-005` | `gws_admin_005_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: always return manual when group-based role assignments exist because expanded group membership is not collected; return pass only when complete role-assignment evidence proves no group-based grant. |
| `GWS-ADMIN-005` | `gws_admin_005_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: always return manual when group-based role assignments exist because expanded group membership is not collected; return pass only when complete role-assignment evidence proves no group-based grant. |
| `GWS-ADMIN-005` | `gws_admin_005_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: always return manual when group-based role assignments exist because expanded group membership is not collected; return pass only when complete role-assignment evidence proves no group-based grant. |
| `GWS-INTEG-001` | `gws_integ_001_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-INTEG-001 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-INTEG-001` | `gws_integ_001_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-INTEG-001` | `gws_integ_001_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when every required per-user token read completes and at least one token is inventoried, warn when the complete inventory is empty, and manual when any token read is denied, failed, unattributed, or skipped. |
| `GWS-INTEG-001` | `gws_integ_001_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when every required per-user token read completes and at least one token is inventoried, warn when the complete inventory is empty, and manual when any token read is denied, failed, unattributed, or skipped. |
| `GWS-INTEG-001` | `gws_integ_001_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when every required per-user token read completes and at least one token is inventoried, warn when the complete inventory is empty, and manual when any token read is denied, failed, unattributed, or skipped. |
| `GWS-INTEG-002` | `gws_integ_002_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-INTEG-002 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-INTEG-002` | `gws_integ_002_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-INTEG-002` | `gws_integ_002_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any privileged user has more than the configured token threshold, warn when any has a smaller non-zero exposure or reads are partial, and pass when complete reads show no excessive privileged exposure. |
| `GWS-INTEG-002` | `gws_integ_002_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any privileged user has more than the configured token threshold, warn when any has a smaller non-zero exposure or reads are partial, and pass when complete reads show no excessive privileged exposure. |
| `GWS-INTEG-002` | `gws_integ_002_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any privileged user has more than the configured token threshold, warn when any has a smaller non-zero exposure or reads are partial, and pass when complete reads show no excessive privileged exposure. |
| `GWS-INTEG-003` | `gws_integ_003_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-INTEG-003 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-INTEG-003` | `gws_integ_003_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-INTEG-003` | `gws_integ_003_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any visible application grant contains a high-risk scope, warn when high-scope applications remain below the configured count or token evidence is partial, and pass when complete token evidence contains none. |
| `GWS-INTEG-003` | `gws_integ_003_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any visible application grant contains a high-risk scope, warn when high-scope applications remain below the configured count or token evidence is partial, and pass when complete token evidence contains none. |
| `GWS-INTEG-003` | `gws_integ_003_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any visible application grant contains a high-risk scope, warn when high-scope applications remain below the configured count or token evidence is partial, and pass when complete token evidence contains none. |
| `GWS-INTEG-004` | `gws_integ_004_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-INTEG-004 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-INTEG-004` | `gws_integ_004_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-INTEG-004` | `gws_integ_004_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the complete token audit lookback contains at least one event, warn when it is empty or truncated, and manual when token audit telemetry is unreadable. |
| `GWS-INTEG-004` | `gws_integ_004_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the complete token audit lookback contains at least one event, warn when it is empty or truncated, and manual when token audit telemetry is unreadable. |
| `GWS-INTEG-004` | `gws_integ_004_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the complete token audit lookback contains at least one event, warn when it is empty or truncated, and manual when token audit telemetry is unreadable. |
| `GWS-MON-001` | `gws_mon_001_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-MON-001 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-MON-001` | `gws_mon_001_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-MON-001` | `gws_mon_001_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the Alert Center endpoint is readable, including a complete empty alert inventory, warn when its inventory is truncated, and manual when access is denied or unreadable. |
| `GWS-MON-001` | `gws_mon_001_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the Alert Center endpoint is readable, including a complete empty alert inventory, warn when its inventory is truncated, and manual when access is denied or unreadable. |
| `GWS-MON-001` | `gws_mon_001_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the Alert Center endpoint is readable, including a complete empty alert inventory, warn when its inventory is truncated, and manual when access is denied or unreadable. |
| `GWS-MON-002` | `gws_mon_002_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-MON-002 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-MON-002` | `gws_mon_002_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-MON-002` | `gws_mon_002_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when open suspicious-login alerts exceed the configured threshold, warn when one through the threshold remain or alert evidence is partial, and pass when the complete inventory contains none. |
| `GWS-MON-002` | `gws_mon_002_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when open suspicious-login alerts exceed the configured threshold, warn when one through the threshold remain or alert evidence is partial, and pass when the complete inventory contains none. |
| `GWS-MON-002` | `gws_mon_002_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when open suspicious-login alerts exceed the configured threshold, warn when one through the threshold remain or alert evidence is partial, and pass when the complete inventory contains none. |
| `GWS-MON-003` | `gws_mon_003_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-MON-003 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-MON-003` | `gws_mon_003_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-MON-003` | `gws_mon_003_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the complete admin-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. |
| `GWS-MON-003` | `gws_mon_003_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the complete admin-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. |
| `GWS-MON-003` | `gws_mon_003_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the complete admin-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. |
| `GWS-MON-004` | `gws_mon_004_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-MON-004 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-MON-004` | `gws_mon_004_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-MON-004` | `gws_mon_004_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the complete token-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. |
| `GWS-MON-004` | `gws_mon_004_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the complete token-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. |
| `GWS-MON-004` | `gws_mon_004_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the complete token-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. |
| `GWS-MON-005` | `gws_mon_005_required_evidence_readable` | From the declared source surfaces, set true only when every value required by GWS-MON-005 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `GWS-MON-005` | `gws_mon_005_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `GWS-MON-005` | `gws_mon_005_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when open alerts exceed the configured backlog threshold, warn when a non-zero backlog is within the threshold or the inventory is partial, and pass when a complete inventory has no open alerts. |
| `GWS-MON-005` | `gws_mon_005_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when open alerts exceed the configured backlog threshold, warn when a non-zero backlog is within the threshold or the inventory is partial, and pass when a complete inventory has no open alerts. |
| `GWS-MON-005` | `gws_mon_005_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when open alerts exceed the configured backlog threshold, warn when a non-zero backlog is within the threshold or the inventory is partial, and pass when a complete inventory has no open alerts. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `GWS-ID-001` | `requiredEvidenceReadable` | true |
| `GWS-ID-001` | `requiredEvidenceComplete` | true |
| `GWS-ID-002` | `requiredEvidenceReadable` | true |
| `GWS-ID-002` | `requiredEvidenceComplete` | true |
| `GWS-ID-003` | `requiredEvidenceReadable` | true |
| `GWS-ID-003` | `requiredEvidenceComplete` | true |
| `GWS-ID-004` | `requiredEvidenceReadable` | true |
| `GWS-ID-004` | `requiredEvidenceComplete` | true |
| `GWS-ID-005` | `requiredEvidenceReadable` | true |
| `GWS-ID-005` | `requiredEvidenceComplete` | true |
| `GWS-ADMIN-001` | `requiredEvidenceReadable` | true |
| `GWS-ADMIN-001` | `requiredEvidenceComplete` | true |
| `GWS-ADMIN-002` | `requiredEvidenceReadable` | true |
| `GWS-ADMIN-002` | `requiredEvidenceComplete` | true |
| `GWS-ADMIN-003` | `requiredEvidenceReadable` | true |
| `GWS-ADMIN-003` | `requiredEvidenceComplete` | true |
| `GWS-ADMIN-004` | `requiredEvidenceReadable` | true |
| `GWS-ADMIN-004` | `requiredEvidenceComplete` | true |
| `GWS-ADMIN-005` | `requiredEvidenceReadable` | true |
| `GWS-ADMIN-005` | `requiredEvidenceComplete` | true |
| `GWS-INTEG-001` | `requiredEvidenceReadable` | true |
| `GWS-INTEG-001` | `requiredEvidenceComplete` | true |
| `GWS-INTEG-002` | `requiredEvidenceReadable` | true |
| `GWS-INTEG-002` | `requiredEvidenceComplete` | true |
| `GWS-INTEG-003` | `requiredEvidenceReadable` | true |
| `GWS-INTEG-003` | `requiredEvidenceComplete` | true |
| `GWS-INTEG-004` | `requiredEvidenceReadable` | true |
| `GWS-INTEG-004` | `requiredEvidenceComplete` | true |
| `GWS-MON-001` | `requiredEvidenceReadable` | true |
| `GWS-MON-001` | `requiredEvidenceComplete` | true |
| `GWS-MON-002` | `requiredEvidenceReadable` | true |
| `GWS-MON-002` | `requiredEvidenceComplete` | true |
| `GWS-MON-003` | `requiredEvidenceReadable` | true |
| `GWS-MON-003` | `requiredEvidenceComplete` | true |
| `GWS-MON-004` | `requiredEvidenceReadable` | true |
| `GWS-MON-004` | `requiredEvidenceComplete` | true |
| `GWS-MON-005` | `requiredEvidenceReadable` | true |
| `GWS-MON-005` | `requiredEvidenceComplete` | true |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `GWS-ID-001` | compliant | All required source reads are complete and this derivation returns pass: for a non-empty privileged-user population, return pass when 100 percent enforce 2-step verification, warn from 80 percent through below 100 percent, and fail below 80 percent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ID-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: for a non-empty privileged-user population, return pass when 100 percent enforce 2-step verification, warn from 80 percent through below 100 percent, and fail below 80 percent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ID-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ID-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ID-002` | compliant | All required source reads are complete and this derivation returns pass: for a non-empty active-user population, return pass when at least 98 percent enforce 2-step verification, warn from 85 percent through below 98 percent, and fail below 85 percent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ID-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: for a non-empty active-user population, return pass when at least 98 percent enforce 2-step verification, warn from 85 percent through below 98 percent, and fail below 85 percent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ID-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ID-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ID-003` | compliant | All required source reads are complete and this derivation returns pass: return fail when more than 10 percent of active users have no login within the configured stale period, warn when one through 10 percent are dormant or login dates are missing, and pass when none are dormant or undated. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ID-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when more than 10 percent of active users have no login within the configured stale period, warn when one through 10 percent are dormant or login dates are missing, and pass when none are dormant or undated. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ID-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ID-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ID-004` | compliant | All required source reads are complete and this derivation returns pass: return pass when every super admin enforces 2-step verification and has recent activity, fail when any super admin lacks enforced 2-step verification, and warn for stale, undated, or partial evidence. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ID-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every super admin enforces 2-step verification and has recent activity, fail when any super admin lacks enforced 2-step verification, and warn for stale, undated, or partial evidence. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ID-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ID-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ID-005` | compliant | All required source reads are complete and this derivation returns pass: return pass when every returned enforcement policy has a past enforcedFrom date and enrollment is allowed, warn when only some scopes satisfy that state, fail when none do, and manual when the policy token or enforcement setting is unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ID-005` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every returned enforcement policy has a past enforcedFrom date and enrollment is allowed, warn when only some scopes satisfy that state, fail when none do, and manual when the policy token or enforcement setting is unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ID-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ID-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ADMIN-001` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete privileged inventory has at most two super admins, warn with three through five, and fail above five. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ADMIN-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete privileged inventory has at most two super admins, warn with three through five, and fail above five. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ADMIN-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ADMIN-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ADMIN-002` | compliant | All required source reads are complete and this derivation returns pass: return fail when any privileged user is suspended or archived and pass when none is, with partial evidence demoting pass to warn. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ADMIN-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any privileged user is suspended or archived and pass when none is, with partial evidence demoting pass to warn. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ADMIN-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ADMIN-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ADMIN-003` | compliant | All required source reads are complete and this derivation returns pass: return pass when at least one active delegated role assignment exists outside the Super Admin role, warn when none exists or role evidence is partial, and manual when role definitions or assignments are unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ADMIN-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when at least one active delegated role assignment exists outside the Super Admin role, warn when none exists or role evidence is partial, and manual when role definitions or assignments are unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ADMIN-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ADMIN-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ADMIN-004` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete admin-audit lookback contains activity, warn when it is empty or truncated, and manual when the audit read is denied or unreadable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ADMIN-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete admin-audit lookback contains activity, warn when it is empty or truncated, and manual when the audit read is denied or unreadable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ADMIN-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ADMIN-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ADMIN-005` | compliant | All required source reads are complete and this derivation returns pass: always return manual when group-based role assignments exist because expanded group membership is not collected; return pass only when complete role-assignment evidence proves no group-based grant. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ADMIN-005` | noncompliant | A complete source read satisfies the fail branch of this derivation: always return manual when group-based role assignments exist because expanded group membership is not collected; return pass only when complete role-assignment evidence proves no group-based grant. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ADMIN-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ADMIN-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-INTEG-001` | compliant | All required source reads are complete and this derivation returns pass: return pass when every required per-user token read completes and at least one token is inventoried, warn when the complete inventory is empty, and manual when any token read is denied, failed, unattributed, or skipped. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-INTEG-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every required per-user token read completes and at least one token is inventoried, warn when the complete inventory is empty, and manual when any token read is denied, failed, unattributed, or skipped. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-INTEG-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-INTEG-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-INTEG-002` | compliant | All required source reads are complete and this derivation returns pass: return fail when any privileged user has more than the configured token threshold, warn when any has a smaller non-zero exposure or reads are partial, and pass when complete reads show no excessive privileged exposure. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-INTEG-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any privileged user has more than the configured token threshold, warn when any has a smaller non-zero exposure or reads are partial, and pass when complete reads show no excessive privileged exposure. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-INTEG-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-INTEG-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-INTEG-003` | compliant | All required source reads are complete and this derivation returns pass: return fail when any visible application grant contains a high-risk scope, warn when high-scope applications remain below the configured count or token evidence is partial, and pass when complete token evidence contains none. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-INTEG-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any visible application grant contains a high-risk scope, warn when high-scope applications remain below the configured count or token evidence is partial, and pass when complete token evidence contains none. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-INTEG-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-INTEG-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-INTEG-004` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete token audit lookback contains at least one event, warn when it is empty or truncated, and manual when token audit telemetry is unreadable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-INTEG-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete token audit lookback contains at least one event, warn when it is empty or truncated, and manual when token audit telemetry is unreadable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-INTEG-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-INTEG-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-MON-001` | compliant | All required source reads are complete and this derivation returns pass: return pass when the Alert Center endpoint is readable, including a complete empty alert inventory, warn when its inventory is truncated, and manual when access is denied or unreadable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-MON-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the Alert Center endpoint is readable, including a complete empty alert inventory, warn when its inventory is truncated, and manual when access is denied or unreadable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-MON-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-MON-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-MON-002` | compliant | All required source reads are complete and this derivation returns pass: return fail when open suspicious-login alerts exceed the configured threshold, warn when one through the threshold remain or alert evidence is partial, and pass when the complete inventory contains none. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-MON-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when open suspicious-login alerts exceed the configured threshold, warn when one through the threshold remain or alert evidence is partial, and pass when the complete inventory contains none. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-MON-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-MON-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-MON-003` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete admin-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-MON-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete admin-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-MON-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-MON-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-MON-004` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete token-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-MON-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete token-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-MON-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-MON-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-MON-005` | compliant | All required source reads are complete and this derivation returns pass: return fail when open alerts exceed the configured backlog threshold, warn when a non-zero backlog is within the threshold or the inventory is partial, and pass when a complete inventory has no open alerts. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-MON-005` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when open alerts exceed the configured backlog threshold, warn when a non-zero backlog is within the threshold or the inventory is partial, and pass when a complete inventory has no open alerts. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-MON-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-MON-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Privileged users enforce 2-step verification | IA-2, IA-2(1) | 3.5.3 | CC6.1 | 1.2 | 8.4.2 | SRG-APP-000149 | ISM-1504 | CPS.IA-2 |
| 2 | Broad 2-step verification coverage for active users | IA-2 | 3.5.3 | CC6.1 | 1.1 | 8.4.1 | SRG-APP-000149 | ISM-1504 | CPS.IA-2 |
| 3 | Dormant active accounts stay limited | AC-2, AC-2(3) | 3.1.1 | CC6.2 | 1.8 | 7.2.4 | SRG-APP-000163 | ISM-0430 | CPS.AC-2 |
| 4 | Super admins stay strongly protected | AC-6, IA-2 | 3.1.5 | CC6.2 | 1.3 | 7.2.5 | SRG-APP-000033 | ISM-0414 | CPS.AC-6 |
| 5 | 2-step verification is enforced by organization policy | IA-2, IA-2(1), CM-6 | 3.5.3 | CC6.1 | 1.1 | 8.4.2 | SRG-APP-000149 | ISM-1504 | CPS.IA-2 |
| 6 | Super admin population stays constrained | AC-5, AC-6 | 3.1.5 | CC6.2 | 2.1 | 7.2.5 | SRG-APP-000033 | ISM-0414 | CPS.AC-6 |
| 7 | Suspended or archived privileged accounts are removed | AC-2, AC-2(3) | 3.1.1 | CC6.2 | 2.4 | 7.2.4 | SRG-APP-000163 | ISM-0430 | CPS.AC-2 |
| 8 | Delegated roles reduce Super Admin dependence | AC-5, AC-6 | 3.1.5 | CC6.3 | 2.2 | 7.2.5 | SRG-APP-000033 | ISM-0414 | CPS.AC-6 |
| 9 | Privileged activity stays observable | AU-2, AU-6 | 3.3.1 | CC7.2 | 5.1 | 10.2.1 | SRG-APP-000089 | ISM-1387 | CPS.AU-2 |
| 10 | Group-based admin grants get explicit review | AC-2, AC-6 | 3.1.1 | CC6.2 | 2.3 | 7.2.1 | SRG-APP-000038 | ISM-0430 | CPS.AC-2 |
| 11 | Third-party token inventory is readable | CA-7, CM-8 | 3.4.1 | CC7.1 | 4.1 | 2.4 | SRG-APP-000516 | ISM-1840 | CPS.CM-8 |
| 12 | Privileged users avoid excessive third-party token exposure | AC-6, SA-9 | 3.1.5 | CC6.2 | 4.2 | 7.2.5 | SRG-APP-000033 | ISM-0414 | CPS.AC-6 |
| 13 | High-scope third-party apps stay limited | CM-8, SA-9 | 3.4.1 | CC7.1 | 4.3 | 2.4 | SRG-APP-000516 | ISM-1840 | CPS.CM-8 |
| 14 | Token activity telemetry stays available | AU-6, CA-7 | 3.3.1 | CC7.2 | 4.4 | 10.2.1 | SRG-APP-000089 | ISM-1387 | CPS.AU-6 |
| 15 | Alert Center is available for the tenant | SI-4, CA-7 | 3.3.1 | CC7.2 | 5.1 | 10.6.1 | SRG-APP-000516 | ISM-1807 | CPS.SI-4 |
| 16 | Suspicious login backlog stays low | SI-4, IR-5 | 3.3.1 | CC7.2 | 5.2 | 10.2.1 | SRG-APP-000516 | ISM-1807 | CPS.SI-4 |
| 17 | Admin audit telemetry stays available | AU-2, AU-6 | 3.3.1 | CC7.2 | 5.3 | 10.2.1 | SRG-APP-000089 | ISM-1387 | CPS.AU-2 |
| 18 | Token audit telemetry stays available | AU-6, CA-7 | 3.3.1 | CC7.2 | 5.4 | 10.2.1 | SRG-APP-000089 | ISM-1387 | CPS.AU-6 |
| 19 | Open alert backlog is manageable | IR-5, SI-4 | 3.6.2 | CC7.4 | 5.5 | 12.10.5 | SRG-APP-000516 | ISM-1807 | CPS.IR-5 |

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

Sensitive fields and values: private_key, access_token, refresh_token, authorization, cookie

Credential formats: Google service-account private keys, OAuth bearer tokens, signed JWT assertions

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `directory-users` | `id`, `primaryEmail`, `suspended`, `archived`, `isAdmin`, `isEnforcedIn2Sv`, `lastLoginTime` |
| `roles` | `roleId`, `roleName`, `isSystemRole`, `isSuperAdminRole`, `rolePrivileges` |
| `role-assignments` | `roleAssignmentId`, `roleId`, `assignedTo`, `scopeType` |
| `user-tokens` | `clientId`, `displayText`, `scopes`, `anonymous` |
| `login-activities` | `id`, `actor`, `events`, `ipAddress` |
| `admin-activities` | `id`, `actor`, `events`, `ipAddress` |
| `token-activities` | `id`, `actor`, `events`, `ipAddress` |
| `alerts` | `alertId`, `type`, `source`, `createTime`, `endTime`, `metadata.status`, `metadata.severity` |
| `two-step-policies` | `name`, `customer`, `type`, `policyQuery`, `setting.value.enforcedFrom`, `setting.value.allowEnrollment`, `setting.value.allowedSignInFactorSet` |

## Export layout

Required paths:

- `core_data/users.json`
- `core_data/roles.json`
- `core_data/role_assignments.json`
- `core_data/login_activities.json`
- `core_data/admin_activities.json`
- `core_data/token_activities.json`
- `core_data/token_inventory.json`
- `core_data/alerts.json`
- `core_data/two_step_verification_policies.json`
- `analysis/findings.json`
- `analysis/identity.json`
- `analysis/identity.md`
- `analysis/admin_access.json`
- `analysis/admin_access.md`
- `analysis/integrations.json`
- `analysis/integrations.md`
- `analysis/monitoring.json`
- `analysis/monitoring.md`
- `compliance/executive_summary.md`
- `compliance/unified_compliance_matrix.md`
- `QUICK_REFERENCE.md`

Conditional paths:

- `compliance/fedramp/fedramp_compliance_report.md`
- `compliance/cmmc/cmmc_compliance_report.md`
- `compliance/soc2/soc2_compliance_report.md`
- `compliance/cis/cis_compliance_report.md`
- `compliance/pci_dss/pci_dss_compliance_report.md`
- `compliance/disa_stig/stig_compliance_checklist.md`
- `compliance/irap/irap_compliance_report.md`
- `compliance/ismap/ismap_compliance_report.md`
- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `core_data/users.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/roles.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/role_assignments.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/login_activities.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/admin_activities.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/token_activities.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/token_inventory.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/alerts.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/two_step_verification_policies.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/findings.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/identity.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/identity.md` | markdown | Always. | Runtime assessment or finding records. | UTF-8 text. |
| `analysis/admin_access.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/admin_access.md` | markdown | Always. | Runtime assessment or finding records. | UTF-8 text. |
| `analysis/integrations.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/integrations.md` | markdown | Always. | Runtime assessment or finding records. | UTF-8 text. |
| `analysis/monitoring.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/monitoring.md` | markdown | Always. | Runtime assessment or finding records. | UTF-8 text. |
| `compliance/executive_summary.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/unified_compliance_matrix.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `QUICK_REFERENCE.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `compliance/fedramp/fedramp_compliance_report.md` | markdown | When the effective framework selection includes fedramp. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cmmc/cmmc_compliance_report.md` | markdown | When the effective framework selection includes cmmc. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/soc2/soc2_compliance_report.md` | markdown | When the effective framework selection includes soc2. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cis/cis_compliance_report.md` | markdown | When the effective framework selection includes cis. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/pci_dss/pci_dss_compliance_report.md` | markdown | When the effective framework selection includes pci_dss. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/disa_stig/stig_compliance_checklist.md` | markdown | When the effective framework selection includes disa_stig. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/irap/irap_compliance_report.md` | markdown | When the effective framework selection includes irap. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/ismap/ismap_compliance_report.md` | markdown | When the effective framework selection includes ismap. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `_errors.log` | text | When at least one collection error or truncation warning exists. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |

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

Overwrite policy: Allocate a new <organization>-gws-audit directory with a numeric suffix; never overwrite an existing directory or paired archive.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Create <allocated-directory>.zip beside the allocated audit directory.
