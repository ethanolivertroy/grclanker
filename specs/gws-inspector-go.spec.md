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
| role | `admin.directory.user.readonly` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `admin.directory.rolemanagement.readonly` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `admin.directory.user.security` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `admin.reports.audit.readonly` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `apps.alerts` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `cloud-identity.policies.readonly` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `directory-users` | HTTP | `GET /admin/directory/v1/users` | Admin SDK Directory API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `primaryEmail`, `suspended`, `archived`, `isAdmin`, `isEnforcedIn2Sv`, `lastLoginTime` | [Official documentation](https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/list) |
| `role-assignments` | HTTP | `GET /admin/directory/v1/customer/{customer}/roleassignments` | Admin SDK Directory API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `roleAssignmentId`, `roleId`, `assignedTo`, `scopeType` | [Official documentation](https://developers.google.com/admin-sdk/directory/reference/rest/v1/roleAssignments/list) |
| `user-tokens` | HTTP | `GET /admin/directory/v1/users/{userKey}/tokens` | Admin SDK Directory API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `clientId`, `displayText`, `scopes`, `anonymous` | [Official documentation](https://developers.google.com/admin-sdk/directory/reference/rest/v1/tokens/list) |
| `activities` | HTTP | `GET /admin/reports/v1/activity/users/all/applications/{applicationName}` | Admin SDK Reports API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `actor`, `events`, `ipAddress` | [Official documentation](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list) |
| `alerts` | HTTP | `GET /v1beta1/alerts` | Alert Center API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `alertId`, `type`, `source`, `createTime`, `endTime` | [Official documentation](https://developers.google.com/admin-sdk/alertcenter/reference/rest/v1beta1/alerts/list) |
| `policies` | HTTP | `GET /v1/policies` | Cloud Identity API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `name`, `setting`, `policyQuery`, `customer` | [Official documentation](https://cloud.google.com/identity/docs/reference/rest/v1/policies/list) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `directory-users` | client | Use the configured Admin SDK Directory API origin; never follow a server link to a different origin. | yes |
| `directory-users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `directory-users` | response | A JSON object or list containing only the documented id, primaryEmail, suspended, archived, isAdmin, isEnforcedIn2Sv, lastLoginTime members consumed by verdicts. | yes |
| `role-assignments` | client | Use the configured Admin SDK Directory API origin; never follow a server link to a different origin. | yes |
| `role-assignments` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `role-assignments` | response | A JSON object or list containing only the documented roleAssignmentId, roleId, assignedTo, scopeType members consumed by verdicts. | yes |
| `user-tokens` | client | Use the configured Admin SDK Directory API origin; never follow a server link to a different origin. | yes |
| `user-tokens` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `user-tokens` | response | A JSON object or list containing only the documented clientId, displayText, scopes, anonymous members consumed by verdicts. | yes |
| `activities` | client | Use the configured Admin SDK Reports API origin; never follow a server link to a different origin. | yes |
| `activities` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `activities` | response | A JSON object or list containing only the documented id, actor, events, ipAddress members consumed by verdicts. | yes |
| `alerts` | client | Use the configured Alert Center API origin; never follow a server link to a different origin. | yes |
| `alerts` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `alerts` | response | A JSON object or list containing only the documented alertId, type, source, createTime, endTime members consumed by verdicts. | yes |
| `policies` | client | Use the configured Cloud Identity API origin; never follow a server link to a different origin. | yes |
| `policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `policies` | response | A JSON object or list containing only the documented name, setting, policyQuery, customer members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `nextPageToken`, `pageToken` | service default | caller limit | 1000 | Google list APIs generally omit authoritative totals; completion requires a missing nextPageToken. | No nextPageToken; Configured item cap; Page cap; Repeated page token; Empty page with token; Per-user child request denied or errored |

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
| `GWS-ID-001` | high | `gws_assess_identity` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Privileged users enforce 2-step verification; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Privileged users enforce 2-step verification, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Privileged users enforce 2-step verification; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Privileged users enforce 2-step verification is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ID-002` | high | `gws_assess_identity` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Broad 2-step verification coverage for active users; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Broad 2-step verification coverage for active users, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Broad 2-step verification coverage for active users; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Broad 2-step verification coverage for active users is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ID-003` | medium | `gws_assess_identity` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Dormant active accounts stay limited; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Dormant active accounts stay limited, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Dormant active accounts stay limited; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Dormant active accounts stay limited is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ID-004` | high | `gws_assess_identity` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Super admins stay strongly protected; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Super admins stay strongly protected, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Super admins stay strongly protected; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Super admins stay strongly protected is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ID-005` | high | `gws_assess_identity` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for 2-step verification is enforced by organization policy; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for 2-step verification is enforced by organization policy, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of 2-step verification is enforced by organization policy; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for 2-step verification is enforced by organization policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ADMIN-001` | high | `gws_assess_admin_access` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Super admin population stays constrained; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Super admin population stays constrained, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Super admin population stays constrained; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Super admin population stays constrained is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ADMIN-002` | high | `gws_assess_admin_access` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Suspended or archived privileged accounts are removed; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Suspended or archived privileged accounts are removed, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Suspended or archived privileged accounts are removed; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Suspended or archived privileged accounts are removed is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ADMIN-003` | high | `gws_assess_admin_access` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Delegated roles reduce Super Admin dependence; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Delegated roles reduce Super Admin dependence, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Delegated roles reduce Super Admin dependence; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Delegated roles reduce Super Admin dependence is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ADMIN-004` | high | `gws_assess_admin_access` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Privileged activity stays observable; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Privileged activity stays observable, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Privileged activity stays observable; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Privileged activity stays observable is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-ADMIN-005` | medium | `gws_assess_admin_access` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Group-based admin grants get explicit review; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Group-based admin grants get explicit review, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Group-based admin grants get explicit review; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Group-based admin grants get explicit review is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-INTEG-001` | medium | `gws_assess_integrations` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Third-party token inventory is readable; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Third-party token inventory is readable, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Third-party token inventory is readable; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Third-party token inventory is readable is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-INTEG-002` | high | `gws_assess_integrations` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Privileged users avoid excessive third-party token exposure; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Privileged users avoid excessive third-party token exposure, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Privileged users avoid excessive third-party token exposure; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Privileged users avoid excessive third-party token exposure is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-INTEG-003` | medium | `gws_assess_integrations` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for High-scope third-party apps stay limited; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for High-scope third-party apps stay limited, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of High-scope third-party apps stay limited; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for High-scope third-party apps stay limited is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-INTEG-004` | medium | `gws_assess_integrations` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Token activity telemetry stays available; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Token activity telemetry stays available, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Token activity telemetry stays available; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Token activity telemetry stays available is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-MON-001` | high | `gws_assess_monitoring` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Alert Center is available for the tenant; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Alert Center is available for the tenant, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Alert Center is available for the tenant; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Alert Center is available for the tenant is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-MON-002` | high | `gws_assess_monitoring` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Suspicious login backlog stays low; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Suspicious login backlog stays low, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Suspicious login backlog stays low; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Suspicious login backlog stays low is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-MON-003` | medium | `gws_assess_monitoring` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Admin audit telemetry stays available; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Admin audit telemetry stays available, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Admin audit telemetry stays available; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Admin audit telemetry stays available is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-MON-004` | medium | `gws_assess_monitoring` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Token audit telemetry stays available; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Token audit telemetry stays available, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Token audit telemetry stays available; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Token audit telemetry stays available is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `GWS-MON-005` | medium | `gws_assess_monitoring` | `directory-users`, `role-assignments`, `user-tokens`, `activities`, `alerts`, `policies` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Open alert backlog is manageable; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Open alert backlog is manageable, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Open alert backlog is manageable; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Open alert backlog is manageable is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `GWS-ID-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-ID-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-ID-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-ID-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-ID-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-ID-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-ID-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-ID-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-ID-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-ID-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-ID-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-ID-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-ID-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-ID-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-ID-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-ID-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-ID-005` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-ID-005` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-ID-005` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-ID-005` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-ADMIN-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-ADMIN-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-ADMIN-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-ADMIN-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-ADMIN-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-ADMIN-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-ADMIN-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-ADMIN-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-ADMIN-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-ADMIN-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-ADMIN-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-ADMIN-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-ADMIN-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-ADMIN-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-ADMIN-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-ADMIN-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-ADMIN-005` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-ADMIN-005` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-ADMIN-005` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-ADMIN-005` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-INTEG-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-INTEG-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-INTEG-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-INTEG-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-INTEG-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-INTEG-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-INTEG-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-INTEG-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-INTEG-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-INTEG-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-INTEG-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-INTEG-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-INTEG-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-INTEG-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-INTEG-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-INTEG-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-MON-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-MON-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-MON-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-MON-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-MON-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-MON-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-MON-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-MON-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-MON-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-MON-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-MON-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-MON-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-MON-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-MON-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-MON-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-MON-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `GWS-MON-005` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `GWS-MON-005` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `GWS-MON-005` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `GWS-MON-005` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `GWS-ID-001` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-ID-002` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-ID-003` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-ID-004` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-ID-005` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-ADMIN-001` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-ADMIN-002` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-ADMIN-003` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-ADMIN-004` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-ADMIN-005` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-INTEG-001` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-INTEG-002` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-INTEG-003` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-INTEG-004` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-MON-001` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-MON-002` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-MON-003` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-MON-004` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `GWS-MON-005` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `GWS-ID-001` | `passStatus` | pass |
| `GWS-ID-001` | `warnStatus` | warn |
| `GWS-ID-001` | `failStatus` | fail |
| `GWS-ID-001` | `manualStatus` | manual |
| `GWS-ID-002` | `passStatus` | pass |
| `GWS-ID-002` | `warnStatus` | warn |
| `GWS-ID-002` | `failStatus` | fail |
| `GWS-ID-002` | `manualStatus` | manual |
| `GWS-ID-003` | `passStatus` | pass |
| `GWS-ID-003` | `warnStatus` | warn |
| `GWS-ID-003` | `failStatus` | fail |
| `GWS-ID-003` | `manualStatus` | manual |
| `GWS-ID-004` | `passStatus` | pass |
| `GWS-ID-004` | `warnStatus` | warn |
| `GWS-ID-004` | `failStatus` | fail |
| `GWS-ID-004` | `manualStatus` | manual |
| `GWS-ID-005` | `passStatus` | pass |
| `GWS-ID-005` | `warnStatus` | warn |
| `GWS-ID-005` | `failStatus` | fail |
| `GWS-ID-005` | `manualStatus` | manual |
| `GWS-ADMIN-001` | `passStatus` | pass |
| `GWS-ADMIN-001` | `warnStatus` | warn |
| `GWS-ADMIN-001` | `failStatus` | fail |
| `GWS-ADMIN-001` | `manualStatus` | manual |
| `GWS-ADMIN-002` | `passStatus` | pass |
| `GWS-ADMIN-002` | `warnStatus` | warn |
| `GWS-ADMIN-002` | `failStatus` | fail |
| `GWS-ADMIN-002` | `manualStatus` | manual |
| `GWS-ADMIN-003` | `passStatus` | pass |
| `GWS-ADMIN-003` | `warnStatus` | warn |
| `GWS-ADMIN-003` | `failStatus` | fail |
| `GWS-ADMIN-003` | `manualStatus` | manual |
| `GWS-ADMIN-004` | `passStatus` | pass |
| `GWS-ADMIN-004` | `warnStatus` | warn |
| `GWS-ADMIN-004` | `failStatus` | fail |
| `GWS-ADMIN-004` | `manualStatus` | manual |
| `GWS-ADMIN-005` | `passStatus` | pass |
| `GWS-ADMIN-005` | `warnStatus` | warn |
| `GWS-ADMIN-005` | `failStatus` | fail |
| `GWS-ADMIN-005` | `manualStatus` | manual |
| `GWS-INTEG-001` | `passStatus` | pass |
| `GWS-INTEG-001` | `warnStatus` | warn |
| `GWS-INTEG-001` | `failStatus` | fail |
| `GWS-INTEG-001` | `manualStatus` | manual |
| `GWS-INTEG-002` | `passStatus` | pass |
| `GWS-INTEG-002` | `warnStatus` | warn |
| `GWS-INTEG-002` | `failStatus` | fail |
| `GWS-INTEG-002` | `manualStatus` | manual |
| `GWS-INTEG-003` | `passStatus` | pass |
| `GWS-INTEG-003` | `warnStatus` | warn |
| `GWS-INTEG-003` | `failStatus` | fail |
| `GWS-INTEG-003` | `manualStatus` | manual |
| `GWS-INTEG-004` | `passStatus` | pass |
| `GWS-INTEG-004` | `warnStatus` | warn |
| `GWS-INTEG-004` | `failStatus` | fail |
| `GWS-INTEG-004` | `manualStatus` | manual |
| `GWS-MON-001` | `passStatus` | pass |
| `GWS-MON-001` | `warnStatus` | warn |
| `GWS-MON-001` | `failStatus` | fail |
| `GWS-MON-001` | `manualStatus` | manual |
| `GWS-MON-002` | `passStatus` | pass |
| `GWS-MON-002` | `warnStatus` | warn |
| `GWS-MON-002` | `failStatus` | fail |
| `GWS-MON-002` | `manualStatus` | manual |
| `GWS-MON-003` | `passStatus` | pass |
| `GWS-MON-003` | `warnStatus` | warn |
| `GWS-MON-003` | `failStatus` | fail |
| `GWS-MON-003` | `manualStatus` | manual |
| `GWS-MON-004` | `passStatus` | pass |
| `GWS-MON-004` | `warnStatus` | warn |
| `GWS-MON-004` | `failStatus` | fail |
| `GWS-MON-004` | `manualStatus` | manual |
| `GWS-MON-005` | `passStatus` | pass |
| `GWS-MON-005` | `warnStatus` | warn |
| `GWS-MON-005` | `failStatus` | fail |
| `GWS-MON-005` | `manualStatus` | manual |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `GWS-ID-001` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ID-001` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ID-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ID-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ID-002` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ID-002` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ID-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ID-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ID-003` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ID-003` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ID-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ID-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ID-004` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ID-004` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ID-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ID-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ID-005` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ID-005` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ID-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ID-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ADMIN-001` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ADMIN-001` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ADMIN-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ADMIN-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ADMIN-002` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ADMIN-002` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ADMIN-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ADMIN-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ADMIN-003` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ADMIN-003` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ADMIN-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ADMIN-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ADMIN-004` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ADMIN-004` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ADMIN-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ADMIN-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-ADMIN-005` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-ADMIN-005` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-ADMIN-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-ADMIN-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-INTEG-001` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-INTEG-001` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-INTEG-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-INTEG-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-INTEG-002` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-INTEG-002` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-INTEG-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-INTEG-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-INTEG-003` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-INTEG-003` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-INTEG-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-INTEG-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-INTEG-004` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-INTEG-004` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-INTEG-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-INTEG-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-MON-001` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-MON-001` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-MON-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-MON-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-MON-002` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-MON-002` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-MON-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-MON-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-MON-003` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-MON-003` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-MON-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-MON-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-MON-004` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-MON-004` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-MON-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-MON-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `GWS-MON-005` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `GWS-MON-005` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `GWS-MON-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `GWS-MON-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Privileged users enforce 2-step verification | - | - | - | - | - | - | - | - |
| 2 | Broad 2-step verification coverage for active users | - | - | - | - | - | - | - | - |
| 3 | Dormant active accounts stay limited | - | - | - | - | - | - | - | - |
| 4 | Super admins stay strongly protected | - | - | - | - | - | - | - | - |
| 5 | 2-step verification is enforced by organization policy | - | - | - | - | - | - | - | - |
| 6 | Super admin population stays constrained | - | - | - | - | - | - | - | - |
| 7 | Suspended or archived privileged accounts are removed | - | - | - | - | - | - | - | - |
| 8 | Delegated roles reduce Super Admin dependence | - | - | - | - | - | - | - | - |
| 9 | Privileged activity stays observable | - | - | - | - | - | - | - | - |
| 10 | Group-based admin grants get explicit review | - | - | - | - | - | - | - | - |
| 11 | Third-party token inventory is readable | - | - | - | - | - | - | - | - |
| 12 | Privileged users avoid excessive third-party token exposure | - | - | - | - | - | - | - | - |
| 13 | High-scope third-party apps stay limited | - | - | - | - | - | - | - | - |
| 14 | Token activity telemetry stays available | - | - | - | - | - | - | - | - |
| 15 | Alert Center is available for the tenant | - | - | - | - | - | - | - | - |
| 16 | Suspicious login backlog stays low | - | - | - | - | - | - | - | - |
| 17 | Admin audit telemetry stays available | - | - | - | - | - | - | - | - |
| 18 | Token audit telemetry stays available | - | - | - | - | - | - | - | - |
| 19 | Open alert backlog is manageable | - | - | - | - | - | - | - | - |

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
| `role-assignments` | `roleAssignmentId`, `roleId`, `assignedTo`, `scopeType` |
| `user-tokens` | `clientId`, `displayText`, `scopes`, `anonymous` |
| `activities` | `id`, `actor`, `events`, `ipAddress` |
| `alerts` | `alertId`, `type`, `source`, `createTime`, `endTime` |
| `policies` | `name`, `setting`, `policyQuery`, `customer` |

## Export layout

Required paths:

- `core_data/access.json`
- `analysis/findings.json`
- `compliance/executive_summary.md`
- `compliance/unified_compliance_matrix.md`
- `compliance/fedramp/fedramp_compliance_report.md`
- `compliance/cmmc/cmmc_compliance_report.md`
- `compliance/soc2/soc2_compliance_report.md`
- `compliance/cis/cis_compliance_report.md`
- `compliance/pci_dss/pci_dss_compliance_report.md`
- `compliance/disa_stig/stig_compliance_checklist.md`
- `compliance/irap/irap_compliance_report.md`
- `compliance/ismap/ismap_compliance_report.md`
- `QUICK_REFERENCE.md`

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `core_data/{dataset}.json` | json | The dataset is part of the assessment, including explicit not-collected markers. | Projected source records or a structured unavailable marker; unavailable values remain null. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/findings.json` | json | Always. | Array of finding id, control, title, severity, status, summary, evidence, mappings, and optional manual evidence. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `compliance/executive_summary.md` | markdown | Always. | Human-readable counts and findings grouped by status. | UTF-8 Markdown. |
| `compliance/unified_compliance_matrix.md` | markdown | Always. | Finding-to-framework mapping matrix. | UTF-8 Markdown. |
| `compliance/{framework}/{report}.md` | markdown | Always for each supported framework. | Framework-specific finding rows and mappings. | UTF-8 Markdown. |
| `QUICK_REFERENCE.md` | markdown | Always. | Bundle navigation and operator next steps. | UTF-8 Markdown. |
| `_errors.log` | text | At least one collection read failed, was denied, or was incomplete. | Scrubbed collection error summaries without response bodies or credentials. | UTF-8 text. |

### Record schemas

#### finding

- `id`
- `control`
- `title`
- `severity`
- `status`
- `summary`
- `evidence`
- `mappings`
- `manualEvidence`

#### collection_marker

- `collected`
- `status`
- `endpoint`
- `error`
- `reason`

#### access_surface

- `name`
- `endpoint`
- `status`
- `count`
- `error`

#### assessment

- `area`
- `title`
- `summary`
- `findings`
- `errors`

#### bundle_manifest

- `outputDir`
- `zipPath`
- `fileCount`
- `findingCount`
- `errorCount`

JSON formatting: UTF-8 JSON with deterministic field order, two-space indentation, and a trailing newline.

Overwrite policy: Allocate a new suffixed output directory on every rerun; never overwrite an earlier bundle.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Create gws-audit.zip beside the allocated gws-audit directory, applying the same suffix to both.
