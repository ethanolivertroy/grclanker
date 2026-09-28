---
slug: "duo-sec-inspector"
name: "Duo Security Inspector"
vendor: "Cisco Duo"
category: "identity-and-access"
language: "language-neutral"
status: "generated"
version: "1.0.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# Duo Security Inspector

Portable contract for the shipped Duo authentication, administrator, protected-application, and monitoring assessments.

## Purpose

Audit Duo tenant authentication, administrator, protected-application, and security-monitoring posture through read-only Admin API evidence.

## Design guidance

Keep edition and permission gaps explicit. A missing policy, denied inventory, or incomplete log window is not proof of a secure state. Retain manual Admin Panel instructions where the public API does not expose a decisive setting.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- Duo edition and endpoint availability gaps are explicit manual findings; a denied Admin API surface never becomes an empty compliant inventory.
- The Admin API offset walker records cap, repeated offset, empty-page, missing-total, and total-mismatch exits as incomplete evidence.
- Trust Monitor analysis is limited to the fields returned by the shipped Admin API collector and does not implement the deeper trend analysis described by the historical design.
- Auth API and Accounts API authentication modes, richer Trust Monitor analysis, and trend reporting are not shipped.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `duo_check_access` | Validate Duo Admin API access for a read-only audit principal and report which core GRC surfaces are readable. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `duo_assess_authentication` | Evaluate Duo global MFA policy, factor strength, bypass-code hygiene, remembered devices, and trusted endpoint posture. | `DUO-AUTH-001`, `DUO-AUTH-002`, `DUO-AUTH-003`, `DUO-AUTH-004`, `DUO-AUTH-005`, `DUO-AUTH-006`, `DUO-AUTH-007`, `DUO-AUTH-008`, `DUO-AUTH-009`, `DUO-AUTH-010`, `DUO-AUTH-011` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `duo_assess_admin_access` | Review Duo privileged administrators, owner concentration, admin MFA methods, help-desk bypass governance, and stale privileged accounts. | `DUO-ADMIN-001`, `DUO-ADMIN-002`, `DUO-ADMIN-003`, `DUO-ADMIN-004`, `DUO-ADMIN-005` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `duo_assess_integrations` | Review Duo protected application inventory, explicit policy attachment, Universal Prompt adoption, self-service posture, and Admin API least privilege. | `DUO-INTEGRATIONS-001`, `DUO-INTEGRATIONS-002`, `DUO-INTEGRATIONS-003`, `DUO-INTEGRATIONS-004`, `DUO-INTEGRATIONS-005`, `DUO-INTEGRATIONS-006` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `duo_assess_monitoring` | Review Duo authentication telemetry, Trust Monitor coverage, telephony reliance, credits, and notification posture. | `DUO-MON-001`, `DUO-MON-002`, `DUO-MON-003`, `DUO-MON-004`, `DUO-MON-005` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `duo_export_audit_bundle` | Export a multi-framework Duo audit package with raw API data, normalized findings, markdown reports, and a zip archive. | `DUO-AUTH-001`, `DUO-AUTH-002`, `DUO-AUTH-003`, `DUO-AUTH-004`, `DUO-AUTH-005`, `DUO-AUTH-006`, `DUO-AUTH-007`, `DUO-AUTH-008`, `DUO-AUTH-009`, `DUO-AUTH-010`, `DUO-AUTH-011`, `DUO-ADMIN-001`, `DUO-ADMIN-002`, `DUO-ADMIN-003`, `DUO-ADMIN-004`, `DUO-ADMIN-005`, `DUO-INTEGRATIONS-001`, `DUO-INTEGRATIONS-002`, `DUO-INTEGRATIONS-003`, `DUO-INTEGRATIONS-004`, `DUO-INTEGRATIONS-005`, `DUO-INTEGRATIONS-006`, `DUO-MON-001`, `DUO-MON-002`, `DUO-MON-003`, `DUO-MON-004`, `DUO-MON-005` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `duo_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `api_host` | string | no | Optional Duo Admin API hostname, like api-XXXXXXXX.duosecurity.com. Falls back to DUO_API_HOST. |
| `ikey` | string | no | Optional Duo Admin API integration key. Falls back to DUO_IKEY. |
| `skey` | string | no | Optional Duo Admin API secret key. Falls back to DUO_SKEY. |
| `lookback_days` | integer | no | Optional Duo log lookback window in days for monitoring-focused collection. Defaults to 30. |

#### `duo_assess_authentication`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `api_host` | string | no | Optional Duo Admin API hostname, like api-XXXXXXXX.duosecurity.com. Falls back to DUO_API_HOST. |
| `ikey` | string | no | Optional Duo Admin API integration key. Falls back to DUO_IKEY. |
| `skey` | string | no | Optional Duo Admin API secret key. Falls back to DUO_SKEY. |
| `lookback_days` | integer | no | Optional Duo log lookback window in days for monitoring-focused collection. Defaults to 30. |

#### `duo_assess_admin_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `api_host` | string | no | Optional Duo Admin API hostname, like api-XXXXXXXX.duosecurity.com. Falls back to DUO_API_HOST. |
| `ikey` | string | no | Optional Duo Admin API integration key. Falls back to DUO_IKEY. |
| `skey` | string | no | Optional Duo Admin API secret key. Falls back to DUO_SKEY. |
| `lookback_days` | integer | no | Optional Duo log lookback window in days for monitoring-focused collection. Defaults to 30. |

#### `duo_assess_integrations`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `api_host` | string | no | Optional Duo Admin API hostname, like api-XXXXXXXX.duosecurity.com. Falls back to DUO_API_HOST. |
| `ikey` | string | no | Optional Duo Admin API integration key. Falls back to DUO_IKEY. |
| `skey` | string | no | Optional Duo Admin API secret key. Falls back to DUO_SKEY. |
| `lookback_days` | integer | no | Optional Duo log lookback window in days for monitoring-focused collection. Defaults to 30. |

#### `duo_assess_monitoring`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `api_host` | string | no | Optional Duo Admin API hostname, like api-XXXXXXXX.duosecurity.com. Falls back to DUO_API_HOST. |
| `ikey` | string | no | Optional Duo Admin API integration key. Falls back to DUO_IKEY. |
| `skey` | string | no | Optional Duo Admin API secret key. Falls back to DUO_SKEY. |
| `lookback_days` | integer | no | Optional Duo log lookback window in days for monitoring-focused collection. Defaults to 30. |

#### `duo_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `api_host` | string | no | Optional Duo Admin API hostname, like api-XXXXXXXX.duosecurity.com. Falls back to DUO_API_HOST. |
| `ikey` | string | no | Optional Duo Admin API integration key. Falls back to DUO_IKEY. |
| `skey` | string | no | Optional Duo Admin API secret key. Falls back to DUO_SKEY. |
| `lookback_days` | integer | no | Optional Duo log lookback window in days for monitoring-focused collection. Defaults to 30. |
| `output_dir` | string | no | Optional output root. Defaults to ./export/duo. |


## Authentication

Supported modes:

- Duo Admin API HMAC integration key and secret key

Credential precedence, highest first:

1. Explicit tool arguments
2. DUO_* environment variables

Environment variables: `DUO_API_HOST`, `DUO_IKEY`, `DUO_SKEY`, `DUO_LOOKBACK_DAYS`

Configuration locations: (none)

Credential and deployment variants: Commercial and FedRAMP Duo API hostnames selected by api_host

Configuration fields: None

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| role | `Grant resource - Read` | `global-policy`, `policies`, `users`, `bypass-codes`, `webauthn-credentials`, `integrations`, `offline-enrollment-logs` |  |
| role | `Grant administrators - Read` | `admins`, `admin-auth-methods` |  |
| role | `Grant settings` | `settings` |  |
| role | `Grant read log` | `authentication-logs`, `activity-logs`, `telephony-logs`, `offline-enrollment-logs`, `trust-monitor-events` |  |
| role | `Grant read information` | `info-summary`, `authentication-attempts` |  |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `settings` | HTTP | `GET /admin/v1/settings` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `helpdesk_bypass`, `user_lockout`, `notifications` | [Official documentation](https://duo.com/docs/adminapi) |
| `info-summary` | HTTP | `GET /admin/v1/info/summary` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `telephony_credits_remaining`, `user_count`, `integration_count` | [Official documentation](https://duo.com/docs/adminapi) |
| `authentication-attempts` | HTTP | `GET /admin/v1/info/authentication_attempts` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `count`, `result`, `reason` | [Official documentation](https://duo.com/docs/adminapi) |
| `admin-auth-methods` | HTTP | `GET /admin/v1/admins/allowed_auth_methods` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `webauthn`, `duo_push`, `sms`, `phone` | [Official documentation](https://duo.com/docs/adminapi) |
| `global-policy` | HTTP | `GET /admin/v2/policies/global` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `authentication_methods`, `new_user_policy`, `remembered_devices`, `trusted_endpoints`, `device_health` | [Official documentation](https://duo.com/docs/adminapi) |
| `policies` | HTTP | `GET /admin/v2/policies` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `policy_id`, `name`, `authentication_methods`, `remembered_devices`, `device_health` | [Official documentation](https://duo.com/docs/adminapi) |
| `users` | HTTP | `GET /admin/v1/users` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `user_id`, `username`, `status`, `last_login`, `is_enrolled` | [Official documentation](https://duo.com/docs/adminapi) |
| `bypass-codes` | HTTP | `GET /admin/v1/bypass_codes` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `user_id`, `created`, `expires`, `remaining_uses` | [Official documentation](https://duo.com/docs/adminapi) |
| `webauthn-credentials` | HTTP | `GET /admin/v1/webauthncredentials` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `user_id`, `credential_name`, `date_added` | [Official documentation](https://duo.com/docs/adminapi) |
| `admins` | HTTP | `GET /admin/v1/admins` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `admin_id`, `name`, `role`, `status`, `last_login` | [Official documentation](https://duo.com/docs/adminapi) |
| `integrations` | HTTP | `GET /admin/v3/integrations` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `integration_key`, `name`, `type`, `policy`, `prompt_type`, `permissions` | [Official documentation](https://duo.com/docs/adminapi) |
| `authentication-logs` | HTTP | `GET /admin/v2/logs/authentication` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `timestamp`, `result`, `reason`, `factor`, `access_device`, `location` | [Official documentation](https://duo.com/docs/adminapi) |
| `activity-logs` | HTTP | `GET /admin/v2/logs/activity` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `timestamp`, `action`, `username`, `description` | [Official documentation](https://duo.com/docs/adminapi) |
| `telephony-logs` | HTTP | `GET /admin/v2/logs/telephony` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `timestamp`, `type`, `context`, `credits` | [Official documentation](https://duo.com/docs/adminapi) |
| `offline-enrollment-logs` | HTTP | `GET /admin/v1/logs/offline_enrollment` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `timestamp`, `username`, `action`, `application` | [Official documentation](https://duo.com/docs/adminapi) |
| `trust-monitor-events` | HTTP | `GET /admin/v1/trust_monitor/events` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `type`, `timestamp`, `risk`, `location` | [Official documentation](https://duo.com/docs/adminapi) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `settings` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `settings` | response | A JSON object or list containing only the documented helpdesk_bypass, user_lockout, notifications members consumed by verdicts. | yes |
| `info-summary` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `info-summary` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `info-summary` | response | A JSON object or list containing only the documented telephony_credits_remaining, user_count, integration_count members consumed by verdicts. | yes |
| `authentication-attempts` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `authentication-attempts` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `authentication-attempts` | response | A JSON object or list containing only the documented count, result, reason members consumed by verdicts. | yes |
| `admin-auth-methods` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `admin-auth-methods` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `admin-auth-methods` | response | A JSON object or list containing only the documented webauthn, duo_push, sms, phone members consumed by verdicts. | yes |
| `global-policy` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `global-policy` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `global-policy` | response | A JSON object or list containing only the documented authentication_methods, new_user_policy, remembered_devices, trusted_endpoints, device_health members consumed by verdicts. | yes |
| `policies` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `policies` | response | A JSON object or list containing only the documented policy_id, name, authentication_methods, remembered_devices, device_health members consumed by verdicts. | yes |
| `users` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `users` | response | A JSON object or list containing only the documented user_id, username, status, last_login, is_enrolled members consumed by verdicts. | yes |
| `bypass-codes` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `bypass-codes` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `bypass-codes` | response | A JSON object or list containing only the documented user_id, created, expires, remaining_uses members consumed by verdicts. | yes |
| `webauthn-credentials` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `webauthn-credentials` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `webauthn-credentials` | response | A JSON object or list containing only the documented user_id, credential_name, date_added members consumed by verdicts. | yes |
| `admins` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `admins` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `admins` | response | A JSON object or list containing only the documented admin_id, name, role, status, last_login members consumed by verdicts. | yes |
| `integrations` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `integrations` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `integrations` | response | A JSON object or list containing only the documented integration_key, name, type, policy, prompt_type, permissions members consumed by verdicts. | yes |
| `authentication-logs` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `authentication-logs` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `authentication-logs` | response | A JSON object or list containing only the documented timestamp, result, reason, factor, access_device, location members consumed by verdicts. | yes |
| `activity-logs` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `activity-logs` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `activity-logs` | response | A JSON object or list containing only the documented timestamp, action, username, description members consumed by verdicts. | yes |
| `telephony-logs` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `telephony-logs` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `telephony-logs` | response | A JSON object or list containing only the documented timestamp, type, context, credits members consumed by verdicts. | yes |
| `offline-enrollment-logs` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `offline-enrollment-logs` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `offline-enrollment-logs` | response | A JSON object or list containing only the documented timestamp, username, action, application members consumed by verdicts. | yes |
| `trust-monitor-events` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `trust-monitor-events` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `trust-monitor-events` | response | A JSON object or list containing only the documented id, type, timestamp, risk, location members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `policies`, `users`, `bypass-codes`, `webauthn-credentials`, `admins`, `integrations` | `offset`, `metadata.next_offset`, `metadata.total_objects` | 100 | caller limit | 1000 | metadata.total_objects is authoritative when present; seen records below that total are incomplete. | Total reached; No next_offset; Page cap; Repeated offset; Empty page with offset; Missing or inconsistent total |
| `authentication-logs`, `activity-logs`, `telephony-logs`, `trust-monitor-events` | `metadata.next_offset` | 200 | 400 | 1000 | Log walks are complete only when next_offset is absent before the caller record cap. | No next_offset; 400-record cap; Repeated offset; Empty page with offset; Page cap |
| `offline-enrollment-logs` | `mintime`, `timestamp` | 1000 | 5000 | 5 | Advance mintime from the latest event; the 5,000-record cap leaves the dataset incomplete. | Short page; 5,000-record cap; Timestamp fails to advance |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Duo Security Inspector | Duo applies integration- and endpoint-specific limits | `Retry-After`, `X-RateLimit-Remaining` | 429, 500, 502, 503, 504 | Honor bounded Retry-After, otherwise use bounded exponential retry and surface exhaustion. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | Phishing-resistant authentication methods | DUO-AUTH-001 | Evaluate the ordered first-match rules for DUO-AUTH-001 below. |
| 2 | Deprecated authentication methods restricted | DUO-AUTH-002 | Evaluate the ordered first-match rules for DUO-AUTH-002 below. |
| 3 | New user enrollment policy | DUO-AUTH-003 | Evaluate the ordered first-match rules for DUO-AUTH-003 below. |
| 4 | Remembered devices posture | DUO-AUTH-004 | Evaluate the ordered first-match rules for DUO-AUTH-004 below. |
| 5 | Trusted endpoints and device health | DUO-AUTH-005 | Evaluate the ordered first-match rules for DUO-AUTH-005 below. |
| 6 | Bypass code hygiene | DUO-AUTH-006 | Evaluate the ordered first-match rules for DUO-AUTH-006 below. |
| 7 | Global MFA enforcement mode | DUO-AUTH-007 | Evaluate the ordered first-match rules for DUO-AUTH-007 below. |
| 8 | User enrollment completeness | DUO-AUTH-008 | Evaluate the ordered first-match rules for DUO-AUTH-008 below. |
| 9 | Inactive user detection | DUO-AUTH-009 | Evaluate the ordered first-match rules for DUO-AUTH-009 below. |
| 10 | WebAuthn and U2F credential adoption | DUO-AUTH-010 | Evaluate the ordered first-match rules for DUO-AUTH-010 below. |
| 11 | Offline access configuration | DUO-AUTH-011 | Evaluate the ordered first-match rules for DUO-AUTH-011 below. |
| 12 | Owner and privileged admin concentration | DUO-ADMIN-001 | Evaluate the ordered first-match rules for DUO-ADMIN-001 below. |
| 13 | Administrator authentication strength | DUO-ADMIN-002 | Evaluate the ordered first-match rules for DUO-ADMIN-002 below. |
| 14 | Help desk bypass governance | DUO-ADMIN-003 | Evaluate the ordered first-match rules for DUO-ADMIN-003 below. |
| 15 | Stale privileged administrator review | DUO-ADMIN-004 | Evaluate the ordered first-match rules for DUO-ADMIN-004 below. |
| 16 | User lockout policy | DUO-ADMIN-005 | Evaluate the ordered first-match rules for DUO-ADMIN-005 below. |
| 17 | Protected integrations have explicit policy coverage | DUO-INTEGRATIONS-001 | Evaluate the ordered first-match rules for DUO-INTEGRATIONS-001 below. |
| 18 | Universal Prompt adoption | DUO-INTEGRATIONS-002 | Evaluate the ordered first-match rules for DUO-INTEGRATIONS-002 below. |
| 19 | Self-service portal governance | DUO-INTEGRATIONS-003 | Evaluate the ordered first-match rules for DUO-INTEGRATIONS-003 below. |
| 20 | Administrative API integration permissions | DUO-INTEGRATIONS-004 | Evaluate the ordered first-match rules for DUO-INTEGRATIONS-004 below. |
| 21 | Critical application protection coverage | DUO-INTEGRATIONS-005 | Evaluate the ordered first-match rules for DUO-INTEGRATIONS-005 below. |
| 22 | Device health requirements depth | DUO-INTEGRATIONS-006 | Evaluate the ordered first-match rules for DUO-INTEGRATIONS-006 below. |
| 23 | Authentication log visibility and factor hygiene | DUO-MON-001 | Evaluate the ordered first-match rules for DUO-MON-001 below. |
| 24 | Trust Monitor coverage | DUO-MON-002 | Evaluate the ordered first-match rules for DUO-MON-002 below. |
| 25 | Telephony reliance and credit headroom | DUO-MON-003 | Evaluate the ordered first-match rules for DUO-MON-003 below. |
| 26 | Administrative and fraud notifications | DUO-MON-004 | Evaluate the ordered first-match rules for DUO-MON-004 below. |
| 27 | Authentication outcome and travel anomalies | DUO-MON-005 | Evaluate the ordered first-match rules for DUO-MON-005 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `DUO-AUTH-001` | medium | `duo_assess_authentication` | `global-policy` | `policy_readable`, `has_webauthn`, `allows_push`, `requires_verified_push`, `supporting_strong_method_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the global policy allows WebAuthn or requires Verified Duo Push, warn when only ordinary Duo Push or supporting administrator hardening exists, and fail when neither phishing-resistant option is present. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the global policy allows WebAuthn or requires Verified Duo Push, warn when only ordinary Duo Push or supporting administrator hardening exists, and fail when neither phishing-resistant option is present. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the global policy allows WebAuthn or requires Verified Duo Push, warn when only ordinary Duo Push or supporting administrator hardening exists, and fail when neither phishing-resistant option is present. | The required evidence for Phishing-resistant authentication methods is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-002` | medium | `duo_assess_authentication` | `global-policy` | `policy_readable`, `allowed_list_exposed`, `blocked_list_exposed`, `explicitly_allowed_telephony_count`, `blocked_telephony_count`, `permitted_telephony_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass only when both SMS and phone callback are explicitly blocked, fail when neither is blocked, warn when only one is blocked or telephony is explicitly allowed alongside a partial block, and manual when the allow and block lists are absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass only when both SMS and phone callback are explicitly blocked, fail when neither is blocked, warn when only one is blocked or telephony is explicitly allowed alongside a partial block, and manual when the allow and block lists are absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass only when both SMS and phone callback are explicitly blocked, fail when neither is blocked, warn when only one is blocked or telephony is explicitly allowed alongside a partial block, and manual when the allow and block lists are absent. | The required evidence for Deprecated authentication methods restricted is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-003` | medium | `duo_assess_authentication` | `global-policy` | `new_user_behavior` | Complete readable evidence satisfies the compliant branch of this derivation: return pass for new_user_behavior=enroll, fail for no-mfa, warn for any other readable behavior, and manual when the value is absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass for new_user_behavior=enroll, fail for no-mfa, warn for any other readable behavior, and manual when the value is absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass for new_user_behavior=enroll, fail for no-mfa, warn for any other readable behavior, and manual when the value is absent. | The required evidence for New user enrollment policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-004` | medium | `duo_assess_authentication` | `global-policy` | `policy_readable`, `remembered_device_days` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when remembered devices are disabled or last at most 14 days, warn for 15 through 30 days, fail above 30 days, and manual when the duration cannot be normalized. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when remembered devices are disabled or last at most 14 days, warn for 15 through 30 days, fail above 30 days, and manual when the duration cannot be normalized. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when remembered devices are disabled or last at most 14 days, warn for 15 through 30 days, fail above 30 days, and manual when the duration cannot be normalized. | The required evidence for Remembered devices posture is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-005` | medium | `duo_assess_authentication` | `global-policy` | `policy_readable`, `trusted_endpoint_checking` | Complete readable evidence satisfies the compliant branch of this derivation: return pass for trusted_endpoint_checking=require-trusted, warn for allow-all, and fail for any other readable configuration. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass for trusted_endpoint_checking=require-trusted, warn for allow-all, and fail for any other readable configuration. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass for trusted_endpoint_checking=require-trusted, warn for allow-all, and fail for any other readable configuration. | The required evidence for Trusted endpoints and device health is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-006` | high | `duo_assess_authentication` | `bypass-codes`, `settings` | `readable`, `complete`, `settings_readable`, `bypass_code_count`, `flagged_code_count`, `undated_code_count`, `helpdesk_bypass`, `helpdesk_bypass_expiration` | Complete readable evidence satisfies the compliant branch of this derivation: return pass only for an empty bypass-code inventory with readable help-desk limits, fail when any unexpired code is older than 24 hours, has unlimited uses, lacks expiration, or help-desk issuance is unlimited, and warn for every other non-empty or undated inventory. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass only for an empty bypass-code inventory with readable help-desk limits, fail when any unexpired code is older than 24 hours, has unlimited uses, lacks expiration, or help-desk issuance is unlimited, and warn for every other non-empty or undated inventory. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass only for an empty bypass-code inventory with readable help-desk limits, fail when any unexpired code is older than 24 hours, has unlimited uses, lacks expiration, or help-desk issuance is unlimited, and warn for every other non-empty or undated inventory. | The required evidence for Bypass code hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-007` | high | `duo_assess_authentication` | `global-policy` | `policy_readable`, `user_auth_behavior` | Complete readable evidence satisfies the compliant branch of this derivation: return pass for user_auth_behavior=enforce, fail for bypass, warn for another readable value such as deny, and manual when the authentication policy or value is absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass for user_auth_behavior=enforce, fail for bypass, warn for another readable value such as deny, and manual when the authentication policy or value is absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass for user_auth_behavior=enforce, fail for bypass, warn for another readable value such as deny, and manual when the authentication policy or value is absent. | The required evidence for Global MFA enforcement mode is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-008` | medium | `duo_assess_authentication` | `users` | `readable`, `complete`, `user_count`, `known_enrollment_count`, `bypass_user_count`, `unenrolled_user_count`, `enrollment_percent` | Complete readable evidence satisfies the compliant branch of this derivation: for users with known enrollment state, return pass when all active users are enrolled and none has bypass status, warn when at least 90 percent are enrolled with no bypass users, and fail otherwise. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for users with known enrollment state, return pass when all active users are enrolled and none has bypass status, warn when at least 90 percent are enrolled with no bypass users, and fail otherwise. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for users with known enrollment state, return pass when all active users are enrolled and none has bypass status, warn when at least 90 percent are enrolled with no bypass users, and fail otherwise. | The required evidence for User enrollment completeness is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-009` | medium | `duo_assess_authentication` | `users` | `readable`, `complete`, `access_user_count`, `inactive_user_count`, `undated_user_count`, `inactive_percent` | Complete readable evidence satisfies the compliant branch of this derivation: for a non-empty active-or-bypass population, return pass when every last-login date is present and no login is older than 90 days, warn when dates are missing or at most 10 percent are stale, and fail when more than 10 percent are stale. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for a non-empty active-or-bypass population, return pass when every last-login date is present and no login is older than 90 days, warn when dates are missing or at most 10 percent are stale, and fail when more than 10 percent are stale. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for a non-empty active-or-bypass population, return pass when every last-login date is present and no login is older than 90 days, warn when dates are missing or at most 10 percent are stale, and fail when more than 10 percent are stale. | The required evidence for Inactive user detection is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-010` | medium | `duo_assess_authentication` | `users`, `webauthn-credentials` | `readable`, `complete`, `enrolled_user_count`, `webauthn_user_count`, `deprecated_u2f_user_count`, `adoption_percent` | Complete readable evidence satisfies the compliant branch of this derivation: for enrolled users, return pass when at least 75 percent have WebAuthn and none has deprecated U2F, warn when any user has WebAuthn but that bar is not met, and fail when none has WebAuthn. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for enrolled users, return pass when at least 75 percent have WebAuthn and none has deprecated U2F, warn when any user has WebAuthn but that bar is not met, and fail when none has WebAuthn. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for enrolled users, return pass when at least 75 percent have WebAuthn and none has deprecated U2F, warn when any user has WebAuthn but that bar is not met, and fail when none has WebAuthn. | The required evidence for WebAuthn and U2F credential adoption is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-011` | medium | `duo_assess_authentication` | `global-policy`, `offline-enrollment-logs` | None | Complete readable evidence satisfies the compliant branch of this derivation: always return manual because the Admin API exposes offline-enrollment events but not the offline-access policy limits. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: always return manual because the Admin API exposes offline-enrollment events but not the offline-access policy limits. | Complete readable evidence satisfies the violation branch, which has first-match precedence: always return manual because the Admin API exposes offline-enrollment events but not the offline-access policy limits. | The required evidence for Offline access configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-001` | high | `duo_assess_admin_access` | `admins` | `readable`, `complete`, `admin_count`, `owner_count`, `warning_owner_maximum` | Complete readable evidence satisfies the compliant branch of this derivation: for a non-empty administrator inventory, return pass with at most two active owners, warn when owners are at most the greater of three or half of all administrators, and fail above that bound. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for a non-empty administrator inventory, return pass with at most two active owners, warn when owners are at most the greater of three or half of all administrators, and fail above that bound. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for a non-empty administrator inventory, return pass with at most two active owners, warn when owners are at most the greater of three or half of all administrators, and fail above that bound. | The required evidence for Owner and privileged admin concentration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-002` | medium | `duo_assess_admin_access` | `admin-auth-methods`, `global-policy` | `readable`, `strong_method_enabled`, `weak_method_enabled` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when WebAuthn or Verified Duo Push is enabled and SMS and voice are disabled, warn when a strong method is enabled alongside SMS or voice, and fail when neither strong method is enabled. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when WebAuthn or Verified Duo Push is enabled and SMS and voice are disabled, warn when a strong method is enabled alongside SMS or voice, and fail when neither strong method is enabled. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when WebAuthn or Verified Duo Push is enabled and SMS and voice are disabled, warn when a strong method is enabled alongside SMS or voice, and fail when neither strong method is enabled. | The required evidence for Administrator authentication strength is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-003` | high | `duo_assess_admin_access` | `settings` | `readable`, `helpdesk_bypass`, `helpdesk_bypass_expiration` | Complete readable evidence satisfies the compliant branch of this derivation: return pass for helpdesk_bypass=deny, warn for limit with a positive expiration, and fail for every other readable setting. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass for helpdesk_bypass=deny, warn for limit with a positive expiration, and fail for every other readable setting. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass for helpdesk_bypass=deny, warn for limit with a positive expiration, and fail for every other readable setting. | The required evidence for Help desk bypass governance is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-004` | high | `duo_assess_admin_access` | `admins` | `readable`, `complete`, `admin_count`, `stale_admin_count`, `undated_admin_count`, `stale_at_least_one_third` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every active administrator has a parseable last login no older than 90 days, warn for missing dates or a smaller stale set, and fail when stale administrators are at least one third of active administrators. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every active administrator has a parseable last login no older than 90 days, warn for missing dates or a smaller stale set, and fail when stale administrators are at least one third of active administrators. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every active administrator has a parseable last login no older than 90 days, warn for missing dates or a smaller stale set, and fail when stale administrators are at least one third of active administrators. | The required evidence for Stale privileged administrator review is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-005` | medium | `duo_assess_admin_access` | `settings` | `readable`, `lockout_threshold` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when the numeric lockout threshold is zero or negative, pass from one through ten failed attempts, warn above ten, and manual when the threshold is absent or nonnumeric. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when the numeric lockout threshold is zero or negative, pass from one through ten failed attempts, warn above ten, and manual when the threshold is absent or nonnumeric. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when the numeric lockout threshold is zero or negative, pass from one through ten failed attempts, warn above ten, and manual when the threshold is absent or nonnumeric. | The required evidence for User lockout policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-001` | medium | `duo_assess_integrations` | `integrations` | `readable`, `complete`, `protected_integration_count`, `policy_attached_count` | Complete readable evidence satisfies the compliant branch of this derivation: for non-empty active protected integrations, return pass when every integration has a policy key, warn when only some do, and fail when none do; an empty readable inventory is warn. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for non-empty active protected integrations, return pass when every integration has a policy key, warn when only some do, and fail when none do; an empty readable inventory is warn. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for non-empty active protected integrations, return pass when every integration has a policy key, warn when only some do, and fail when none do; an empty readable inventory is warn. | The required evidence for Protected integrations have explicit policy coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-002` | medium | `duo_assess_integrations` | `integrations` | `readable`, `complete`, `applicable_integration_count`, `universal_prompt_count` | Complete readable evidence satisfies the compliant branch of this derivation: for integrations exposing prompt posture, return pass when all use Universal Prompt, warn when only some do, and fail when none do. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for integrations exposing prompt posture, return pass when all use Universal Prompt, warn when only some do, and fail when none do. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for integrations exposing prompt posture, return pass when all use Universal Prompt, warn when only some do, and fail when none do. | The required evidence for Universal Prompt adoption is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-003` | medium | `duo_assess_integrations` | `integrations` | `readable`, `complete`, `protected_integration_count`, `field_exposed_count`, `self_service_enabled_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every protected integration exposing self_service_allowed disables it, warn when only some disable it or the protected inventory is empty, fail when all exposed values enable it, and manual when no integration exposes the field. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every protected integration exposing self_service_allowed disables it, warn when only some disable it or the protected inventory is empty, fail when all exposed values enable it, and manual when no integration exposes the field. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every protected integration exposing self_service_allowed disables it, warn when only some disable it or the protected inventory is empty, fail when all exposed values enable it, and manual when no integration exposes the field. | The required evidence for Self-service portal governance is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-004` | high | `duo_assess_integrations` | `integrations` | `readable`, `complete`, `admin_api_count`, `overprivileged_admin_api_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when all visible Admin API integrations omit write, settings, integration-management, and permission-management grants, warn when only some are overprivileged or the inventory omits the audit integration, and fail when all are overprivileged. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when all visible Admin API integrations omit write, settings, integration-management, and permission-management grants, warn when only some are overprivileged or the inventory omits the audit integration, and fail when all are overprivileged. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when all visible Admin API integrations omit write, settings, integration-management, and permission-management grants, warn when only some are overprivileged or the inventory omits the audit integration, and fail when all are overprivileged. | The required evidence for Administrative API integration permissions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-005` | high | `duo_assess_integrations` | `integrations` | `readable`, `complete`, `protected_integration_count`, `tagged_integration_count`, `tagged_without_policy_count` | Complete readable evidence satisfies the compliant branch of this derivation: for protected applications tagged Critical, High, or regulated, return pass when each has an explicit policy, warn when only some do, fail when none do, and manual when no protected application has usable criticality tags. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for protected applications tagged Critical, High, or regulated, return pass when each has an explicit policy, warn when only some do, fail when none do, and manual when no protected application has usable criticality tags. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for protected applications tagged Critical, High, or regulated, return pass when each has an explicit policy, warn when only some do, fail when none do, and manual when no protected application has usable criticality tags. | The required evidence for Critical application protection coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-006` | medium | `duo_assess_integrations` | `global-policy` | `policy_readable`, `edition_sections_present`, `satisfied_group_count` | Complete readable evidence satisfies the compliant branch of this derivation: evaluate five groups: Duo Desktop, encryption, firewall, system-password or screen-lock, and operating-system restrictions; return pass for all five, fail for none, warn for one through four, and manual when the tenant edition exposes no device-health sections. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: evaluate five groups: Duo Desktop, encryption, firewall, system-password or screen-lock, and operating-system restrictions; return pass for all five, fail for none, warn for one through four, and manual when the tenant edition exposes no device-health sections. | Complete readable evidence satisfies the violation branch, which has first-match precedence: evaluate five groups: Duo Desktop, encryption, firewall, system-password or screen-lock, and operating-system restrictions; return pass for all five, fail for none, warn for one through four, and manual when the tenant edition exposes no device-health sections. | The required evidence for Device health requirements depth is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-001` | medium | `duo_assess_monitoring` | `authentication-logs` | `readable`, `complete`, `event_count`, `review_event_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass for a non-empty authentication-log window with no bypass, SMS, phone, or fraud events; warn when the window is empty or any such event exists. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass for a non-empty authentication-log window with no bypass, SMS, phone, or fraud events; warn when the window is empty or any such event exists. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass for a non-empty authentication-log window with no bypass, SMS, phone, or fraud events; warn when the window is empty or any such event exists. | The required evidence for Authentication log visibility and factor hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-002` | medium | `duo_assess_monitoring` | `trust-monitor-events` | `readable`, `complete`, `event_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the Trust Monitor window contains events and warn when its complete window is empty. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the Trust Monitor window contains events and warn when its complete window is empty. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the Trust Monitor window contains events and warn when its complete window is empty. | The required evidence for Trust Monitor coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-003` | medium | `duo_assess_monitoring` | `info-summary`, `telephony-logs` | `readable`, `complete`, `credits_remaining`, `telephony_event_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when telephony use exists and credits are below 25, warn when telephony use exists or credits are below 100, pass otherwise, and manual when credits or logs are unreadable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when telephony use exists and credits are below 25, warn when telephony use exists or credits are below 100, pass otherwise, and manual when credits or logs are unreadable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when telephony use exists and credits are below 25, warn when telephony use exists or credits are below 100, pass otherwise, and manual when credits or logs are unreadable. | The required evidence for Telephony reliance and credit headroom is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-004` | medium | `duo_assess_monitoring` | `settings` | `readable`, `enabled_notification_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when any fraud-email, push-activity, or email-activity notification is enabled and warn when all readable notification signals are false or absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when any fraud-email, push-activity, or email-activity notification is enabled and warn when all readable notification signals are false or absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when any fraud-email, push-activity, or email-activity notification is enabled and warn when all readable notification signals are false or absent. | The required evidence for Administrative and fraud notifications is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-005` | medium | `duo_assess_monitoring` | `authentication-attempts`, `authentication-logs` | `attempts_readable`, `logs_readable`, `counts_present`, `complete`, `attempt_count`, `event_count`, `located_event_count`, `impossible_travel_count`, `fraud_count`, `denied_percent` | Complete readable evidence satisfies the compliant branch of this derivation: return fail for any successful country change within 60 minutes, warn for fraud or a denied-attempt share above 20 percent, pass otherwise, manual when counts or all location fields are absent, and warn when both summary and event windows are empty. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail for any successful country change within 60 minutes, warn for fraud or a denied-attempt share above 20 percent, pass otherwise, manual when counts or all location fields are absent, and warn when both summary and event windows are empty. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail for any successful country change within 60 minutes, warn for fraud or a denied-attempt share above 20 percent, pass otherwise, manual when counts or all location fields are absent, and warn when both summary and event windows are empty. | The required evidence for Authentication outcome and travel anomalies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `DUO-AUTH-001` | 1 | manual | `policy_readable` does not equal true |  |
| `DUO-AUTH-001` | 2 | fail | all of (`has_webauthn` equals false; `allows_push` equals false; `supporting_strong_method_count` equals 0) |  |
| `DUO-AUTH-001` | 3 | warn | all of (`has_webauthn` equals false; not (all of (`allows_push` equals true; `requires_verified_push` equals true)); any of (`allows_push` equals true; `supporting_strong_method_count` is greater than 0)) |  |
| `DUO-AUTH-001` | 4 | pass | any of (`has_webauthn` equals true; all of (`allows_push` equals true; `requires_verified_push` equals true)) |  |
| `DUO-AUTH-001` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-AUTH-002` | 1 | manual | any of (`policy_readable` does not equal true; all of (`allowed_list_exposed` does not equal true; `blocked_list_exposed` does not equal true); all of (`blocked_list_exposed` does not equal true; `explicitly_allowed_telephony_count` equals 0)) |  |
| `DUO-AUTH-002` | 2 | fail | all of (any of (`explicitly_allowed_telephony_count` is greater than 0; `permitted_telephony_count` is greater than 0); `blocked_telephony_count` equals 0) |  |
| `DUO-AUTH-002` | 3 | warn | any of (`explicitly_allowed_telephony_count` is greater than 0; `permitted_telephony_count` is greater than 0) |  |
| `DUO-AUTH-002` | 4 | pass | `permitted_telephony_count` equals 0 |  |
| `DUO-AUTH-002` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-AUTH-003` | 1 | manual | not (`new_user_behavior` is present and non-null) |  |
| `DUO-AUTH-003` | 2 | fail | `new_user_behavior` equals "no-mfa" |  |
| `DUO-AUTH-003` | 3 | warn | `new_user_behavior` does not equal "enroll" |  |
| `DUO-AUTH-003` | 4 | pass | `new_user_behavior` equals "enroll" |  |
| `DUO-AUTH-003` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-AUTH-004` | 1 | manual | any of (`policy_readable` does not equal true; not (`remembered_device_days` is present and non-null)) |  |
| `DUO-AUTH-004` | 2 | fail | `remembered_device_days` is greater than 30 |  |
| `DUO-AUTH-004` | 3 | warn | `remembered_device_days` is greater than 14 |  |
| `DUO-AUTH-004` | 4 | pass | `remembered_device_days` is at most 14 |  |
| `DUO-AUTH-004` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-AUTH-005` | 1 | manual | `policy_readable` does not equal true |  |
| `DUO-AUTH-005` | 2 | fail | all of (`trusted_endpoint_checking` does not equal "require-trusted"; `trusted_endpoint_checking` does not equal "allow-all") |  |
| `DUO-AUTH-005` | 3 | warn | `trusted_endpoint_checking` equals "allow-all" |  |
| `DUO-AUTH-005` | 4 | pass | `trusted_endpoint_checking` equals "require-trusted" |  |
| `DUO-AUTH-005` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-AUTH-006` | 1 | manual | `readable` does not equal true |  |
| `DUO-AUTH-006` | 2 | fail | any of (`flagged_code_count` is greater than 0; `helpdesk_bypass` equals "allow"; all of (`helpdesk_bypass` equals "limit"; `helpdesk_bypass_expiration` is at most 0)) |  |
| `DUO-AUTH-006` | 3 | warn | any of (`complete` does not equal true; `settings_readable` does not equal true; `bypass_code_count` is greater than 0; `undated_code_count` is greater than 0) |  |
| `DUO-AUTH-006` | 4 | pass | `bypass_code_count` equals 0 |  |
| `DUO-AUTH-006` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-AUTH-007` | 1 | manual | any of (`policy_readable` does not equal true; not (`user_auth_behavior` is present and non-null)) |  |
| `DUO-AUTH-007` | 2 | fail | `user_auth_behavior` equals "bypass" |  |
| `DUO-AUTH-007` | 3 | warn | `user_auth_behavior` does not equal "enforce" |  |
| `DUO-AUTH-007` | 4 | pass | `user_auth_behavior` equals "enforce" |  |
| `DUO-AUTH-007` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-AUTH-008` | 1 | manual | any of (`readable` does not equal true; `user_count` equals 0; `known_enrollment_count` equals 0) |  |
| `DUO-AUTH-008` | 2 | fail | any of (`bypass_user_count` is greater than 0; all of (`unenrolled_user_count` is greater than 0; `enrollment_percent` is less than 90)) |  |
| `DUO-AUTH-008` | 3 | warn | any of (`complete` does not equal true; `unenrolled_user_count` is greater than 0) |  |
| `DUO-AUTH-008` | 4 | pass | all of (`bypass_user_count` equals 0; `unenrolled_user_count` equals 0) |  |
| `DUO-AUTH-008` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-AUTH-009` | 1 | manual | any of (`readable` does not equal true; `access_user_count` equals 0) |  |
| `DUO-AUTH-009` | 2 | fail | `inactive_percent` is greater than 10 |  |
| `DUO-AUTH-009` | 3 | warn | any of (`complete` does not equal true; `inactive_user_count` is greater than 0; `undated_user_count` is greater than 0) |  |
| `DUO-AUTH-009` | 4 | pass | all of (`inactive_user_count` equals 0; `undated_user_count` equals 0) |  |
| `DUO-AUTH-009` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-AUTH-010` | 1 | manual | any of (`readable` does not equal true; `enrolled_user_count` equals 0) |  |
| `DUO-AUTH-010` | 2 | fail | `webauthn_user_count` equals 0 |  |
| `DUO-AUTH-010` | 3 | warn | any of (`complete` does not equal true; `adoption_percent` is less than 75; `deprecated_u2f_user_count` is greater than 0) |  |
| `DUO-AUTH-010` | 4 | pass | all of (`adoption_percent` is at least 75; `deprecated_u2f_user_count` equals 0) |  |
| `DUO-AUTH-010` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-AUTH-011` | 1 | manual | always |  |
| `DUO-ADMIN-001` | 1 | manual | any of (`readable` does not equal true; `admin_count` equals 0) |  |
| `DUO-ADMIN-001` | 2 | fail | `owner_count` is greater than `warning_owner_maximum` |  |
| `DUO-ADMIN-001` | 3 | warn | any of (`complete` does not equal true; `owner_count` is greater than 2) |  |
| `DUO-ADMIN-001` | 4 | pass | `owner_count` is at most 2 |  |
| `DUO-ADMIN-001` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-ADMIN-002` | 1 | manual | `readable` does not equal true |  |
| `DUO-ADMIN-002` | 2 | fail | `strong_method_enabled` does not equal true |  |
| `DUO-ADMIN-002` | 3 | warn | `weak_method_enabled` equals true |  |
| `DUO-ADMIN-002` | 4 | pass | `weak_method_enabled` equals false |  |
| `DUO-ADMIN-002` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-ADMIN-003` | 1 | manual | `readable` does not equal true |  |
| `DUO-ADMIN-003` | 2 | fail | all of (`helpdesk_bypass` does not equal "deny"; not (all of (`helpdesk_bypass` equals "limit"; `helpdesk_bypass_expiration` is greater than 0))) |  |
| `DUO-ADMIN-003` | 3 | warn | all of (`helpdesk_bypass` equals "limit"; `helpdesk_bypass_expiration` is greater than 0) |  |
| `DUO-ADMIN-003` | 4 | pass | `helpdesk_bypass` equals "deny" |  |
| `DUO-ADMIN-003` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-ADMIN-004` | 1 | manual | any of (`readable` does not equal true; `admin_count` equals 0) |  |
| `DUO-ADMIN-004` | 2 | fail | `stale_at_least_one_third` equals true |  |
| `DUO-ADMIN-004` | 3 | warn | any of (`complete` does not equal true; `stale_admin_count` is greater than 0; `undated_admin_count` is greater than 0) |  |
| `DUO-ADMIN-004` | 4 | pass | all of (`stale_admin_count` equals 0; `undated_admin_count` equals 0) |  |
| `DUO-ADMIN-004` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-ADMIN-005` | 1 | manual | any of (`readable` does not equal true; not (`lockout_threshold` is present and non-null)) |  |
| `DUO-ADMIN-005` | 2 | fail | `lockout_threshold` is at most 0 |  |
| `DUO-ADMIN-005` | 3 | warn | `lockout_threshold` is greater than 10 |  |
| `DUO-ADMIN-005` | 4 | pass | all of (`lockout_threshold` is greater than 0; `lockout_threshold` is at most 10) |  |
| `DUO-ADMIN-005` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-INTEGRATIONS-001` | 1 | manual | `readable` does not equal true |  |
| `DUO-INTEGRATIONS-001` | 2 | fail | all of (`protected_integration_count` is greater than 0; `policy_attached_count` equals 0) |  |
| `DUO-INTEGRATIONS-001` | 3 | warn | any of (`complete` does not equal true; `protected_integration_count` equals 0; `policy_attached_count` is less than `protected_integration_count`) |  |
| `DUO-INTEGRATIONS-001` | 4 | pass | `policy_attached_count` equals `protected_integration_count` |  |
| `DUO-INTEGRATIONS-001` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-INTEGRATIONS-002` | 1 | manual | any of (`readable` does not equal true; `applicable_integration_count` equals 0) |  |
| `DUO-INTEGRATIONS-002` | 2 | fail | `universal_prompt_count` equals 0 |  |
| `DUO-INTEGRATIONS-002` | 3 | warn | any of (`complete` does not equal true; `universal_prompt_count` is less than `applicable_integration_count`) |  |
| `DUO-INTEGRATIONS-002` | 4 | pass | `universal_prompt_count` equals `applicable_integration_count` |  |
| `DUO-INTEGRATIONS-002` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-INTEGRATIONS-003` | 1 | manual | any of (`readable` does not equal true; all of (`protected_integration_count` is greater than 0; `field_exposed_count` equals 0)) |  |
| `DUO-INTEGRATIONS-003` | 2 | fail | all of (`field_exposed_count` is greater than 0; `self_service_enabled_count` equals `field_exposed_count`) |  |
| `DUO-INTEGRATIONS-003` | 3 | warn | any of (`complete` does not equal true; `protected_integration_count` equals 0; `self_service_enabled_count` is greater than 0) |  |
| `DUO-INTEGRATIONS-003` | 4 | pass | all of (`field_exposed_count` is greater than 0; `self_service_enabled_count` equals 0) |  |
| `DUO-INTEGRATIONS-003` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-INTEGRATIONS-004` | 1 | manual | `readable` does not equal true |  |
| `DUO-INTEGRATIONS-004` | 2 | fail | all of (`admin_api_count` is greater than 0; `overprivileged_admin_api_count` equals `admin_api_count`) |  |
| `DUO-INTEGRATIONS-004` | 3 | warn | any of (`complete` does not equal true; `admin_api_count` equals 0; `overprivileged_admin_api_count` is greater than 0) |  |
| `DUO-INTEGRATIONS-004` | 4 | pass | all of (`admin_api_count` is greater than 0; `overprivileged_admin_api_count` equals 0) |  |
| `DUO-INTEGRATIONS-004` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-INTEGRATIONS-005` | 1 | manual | any of (`readable` does not equal true; `protected_integration_count` equals 0; `tagged_integration_count` equals 0) |  |
| `DUO-INTEGRATIONS-005` | 2 | fail | `tagged_without_policy_count` equals `tagged_integration_count` |  |
| `DUO-INTEGRATIONS-005` | 3 | warn | any of (`complete` does not equal true; `tagged_without_policy_count` is greater than 0) |  |
| `DUO-INTEGRATIONS-005` | 4 | pass | `tagged_without_policy_count` equals 0 |  |
| `DUO-INTEGRATIONS-005` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-INTEGRATIONS-006` | 1 | manual | any of (`policy_readable` does not equal true; `edition_sections_present` does not equal true) |  |
| `DUO-INTEGRATIONS-006` | 2 | fail | `satisfied_group_count` equals 0 |  |
| `DUO-INTEGRATIONS-006` | 3 | warn | `satisfied_group_count` is less than 5 |  |
| `DUO-INTEGRATIONS-006` | 4 | pass | `satisfied_group_count` equals 5 |  |
| `DUO-INTEGRATIONS-006` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-MON-001` | 1 | manual | `readable` does not equal true |  |
| `DUO-MON-001` | 2 | warn | any of (`complete` does not equal true; `event_count` equals 0; `review_event_count` is greater than 0) |  |
| `DUO-MON-001` | 3 | pass | all of (`event_count` is greater than 0; `review_event_count` equals 0) |  |
| `DUO-MON-001` | 4 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-MON-002` | 1 | manual | `readable` does not equal true |  |
| `DUO-MON-002` | 2 | warn | any of (`complete` does not equal true; `event_count` equals 0) |  |
| `DUO-MON-002` | 3 | pass | `event_count` is greater than 0 |  |
| `DUO-MON-002` | 4 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-MON-003` | 1 | manual | any of (`readable` does not equal true; not (`credits_remaining` is present and non-null)) |  |
| `DUO-MON-003` | 2 | fail | all of (`telephony_event_count` is greater than 0; `credits_remaining` is less than 25) |  |
| `DUO-MON-003` | 3 | warn | any of (`complete` does not equal true; `telephony_event_count` is greater than 0; `credits_remaining` is less than 100) |  |
| `DUO-MON-003` | 4 | pass | `credits_remaining` is at least 100 |  |
| `DUO-MON-003` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-MON-004` | 1 | manual | `readable` does not equal true |  |
| `DUO-MON-004` | 2 | warn | `enabled_notification_count` equals 0 |  |
| `DUO-MON-004` | 3 | pass | `enabled_notification_count` is greater than 0 |  |
| `DUO-MON-004` | 4 | manual | always | Unknown or contradictory evidence requires manual review. |
| `DUO-MON-005` | 1 | manual | any of (`attempts_readable` does not equal true; `logs_readable` does not equal true; `counts_present` does not equal true; all of (`impossible_travel_count` equals 0; `located_event_count` equals 0; `event_count` is greater than 0)) |  |
| `DUO-MON-005` | 2 | fail | `impossible_travel_count` is greater than 0 |  |
| `DUO-MON-005` | 3 | warn | any of (`complete` does not equal true; all of (`attempt_count` equals 0; `event_count` equals 0); `fraud_count` is greater than 0; `denied_percent` is greater than 20) |  |
| `DUO-MON-005` | 4 | pass | always |  |
| `DUO-MON-005` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| None |  |  |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `DUO-AUTH-001` | `requiredEvidenceReadable` | true |
| `DUO-AUTH-001` | `requiredEvidenceComplete` | true |
| `DUO-AUTH-002` | `requiredEvidenceReadable` | true |
| `DUO-AUTH-002` | `requiredEvidenceComplete` | true |
| `DUO-AUTH-003` | `requiredEvidenceReadable` | true |
| `DUO-AUTH-003` | `requiredEvidenceComplete` | true |
| `DUO-AUTH-004` | `pass_maximum_days` | 14 |
| `DUO-AUTH-004` | `warn_maximum_days` | 30 |
| `DUO-AUTH-005` | `requiredEvidenceReadable` | true |
| `DUO-AUTH-005` | `requiredEvidenceComplete` | true |
| `DUO-AUTH-006` | `maximum_age_hours` | 24 |
| `DUO-AUTH-007` | `requiredEvidenceReadable` | true |
| `DUO-AUTH-007` | `requiredEvidenceComplete` | true |
| `DUO-AUTH-008` | `warning_minimum_percent` | 90 |
| `DUO-AUTH-009` | `inactive_days` | 90 |
| `DUO-AUTH-009` | `failure_percent` | 10 |
| `DUO-AUTH-010` | `pass_minimum_percent` | 75 |
| `DUO-AUTH-011` | `requiredEvidenceReadable` | true |
| `DUO-AUTH-011` | `requiredEvidenceComplete` | true |
| `DUO-ADMIN-001` | `pass_maximum` | 2 |
| `DUO-ADMIN-002` | `requiredEvidenceReadable` | true |
| `DUO-ADMIN-002` | `requiredEvidenceComplete` | true |
| `DUO-ADMIN-003` | `requiredEvidenceReadable` | true |
| `DUO-ADMIN-003` | `requiredEvidenceComplete` | true |
| `DUO-ADMIN-004` | `inactive_days` | 90 |
| `DUO-ADMIN-005` | `pass_maximum` | 10 |
| `DUO-INTEGRATIONS-001` | `requiredEvidenceReadable` | true |
| `DUO-INTEGRATIONS-001` | `requiredEvidenceComplete` | true |
| `DUO-INTEGRATIONS-002` | `requiredEvidenceReadable` | true |
| `DUO-INTEGRATIONS-002` | `requiredEvidenceComplete` | true |
| `DUO-INTEGRATIONS-003` | `requiredEvidenceReadable` | true |
| `DUO-INTEGRATIONS-003` | `requiredEvidenceComplete` | true |
| `DUO-INTEGRATIONS-004` | `requiredEvidenceReadable` | true |
| `DUO-INTEGRATIONS-004` | `requiredEvidenceComplete` | true |
| `DUO-INTEGRATIONS-005` | `requiredEvidenceReadable` | true |
| `DUO-INTEGRATIONS-005` | `requiredEvidenceComplete` | true |
| `DUO-INTEGRATIONS-006` | `requirement_group_count` | 5 |
| `DUO-MON-001` | `requiredEvidenceReadable` | true |
| `DUO-MON-001` | `requiredEvidenceComplete` | true |
| `DUO-MON-002` | `requiredEvidenceReadable` | true |
| `DUO-MON-002` | `requiredEvidenceComplete` | true |
| `DUO-MON-003` | `critical_credit_floor` | 25 |
| `DUO-MON-003` | `warning_credit_floor` | 100 |
| `DUO-MON-004` | `requiredEvidenceReadable` | true |
| `DUO-MON-004` | `requiredEvidenceComplete` | true |
| `DUO-MON-005` | `travel_window_minutes` | 60 |
| `DUO-MON-005` | `denied_warning_percent` | 20 |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `DUO-AUTH-001` | compliant | All required source reads are complete and this derivation returns pass: return pass when the global policy allows WebAuthn or requires Verified Duo Push, warn when only ordinary Duo Push or supporting administrator hardening exists, and fail when neither phishing-resistant option is present. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the global policy allows WebAuthn or requires Verified Duo Push, warn when only ordinary Duo Push or supporting administrator hardening exists, and fail when neither phishing-resistant option is present. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-002` | compliant | All required source reads are complete and this derivation returns pass: return pass only when both SMS and phone callback are explicitly blocked, fail when neither is blocked, warn when only one is blocked or telephony is explicitly allowed alongside a partial block, and manual when the allow and block lists are absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass only when both SMS and phone callback are explicitly blocked, fail when neither is blocked, warn when only one is blocked or telephony is explicitly allowed alongside a partial block, and manual when the allow and block lists are absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-003` | compliant | All required source reads are complete and this derivation returns pass: return pass for new_user_behavior=enroll, fail for no-mfa, warn for any other readable behavior, and manual when the value is absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass for new_user_behavior=enroll, fail for no-mfa, warn for any other readable behavior, and manual when the value is absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-004` | compliant | All required source reads are complete and this derivation returns pass: return pass when remembered devices are disabled or last at most 14 days, warn for 15 through 30 days, fail above 30 days, and manual when the duration cannot be normalized. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when remembered devices are disabled or last at most 14 days, warn for 15 through 30 days, fail above 30 days, and manual when the duration cannot be normalized. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-005` | compliant | All required source reads are complete and this derivation returns pass: return pass for trusted_endpoint_checking=require-trusted, warn for allow-all, and fail for any other readable configuration. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-005` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass for trusted_endpoint_checking=require-trusted, warn for allow-all, and fail for any other readable configuration. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-006` | compliant | All required source reads are complete and this derivation returns pass: return pass only for an empty bypass-code inventory with readable help-desk limits, fail when any unexpired code is older than 24 hours, has unlimited uses, lacks expiration, or help-desk issuance is unlimited, and warn for every other non-empty or undated inventory. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-006` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass only for an empty bypass-code inventory with readable help-desk limits, fail when any unexpired code is older than 24 hours, has unlimited uses, lacks expiration, or help-desk issuance is unlimited, and warn for every other non-empty or undated inventory. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-006` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-006` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-007` | compliant | All required source reads are complete and this derivation returns pass: return pass for user_auth_behavior=enforce, fail for bypass, warn for another readable value such as deny, and manual when the authentication policy or value is absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-007` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass for user_auth_behavior=enforce, fail for bypass, warn for another readable value such as deny, and manual when the authentication policy or value is absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-007` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-007` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-008` | compliant | All required source reads are complete and this derivation returns pass: for users with known enrollment state, return pass when all active users are enrolled and none has bypass status, warn when at least 90 percent are enrolled with no bypass users, and fail otherwise. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-008` | noncompliant | A complete source read satisfies the fail branch of this derivation: for users with known enrollment state, return pass when all active users are enrolled and none has bypass status, warn when at least 90 percent are enrolled with no bypass users, and fail otherwise. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-008` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-008` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-009` | compliant | All required source reads are complete and this derivation returns pass: for a non-empty active-or-bypass population, return pass when every last-login date is present and no login is older than 90 days, warn when dates are missing or at most 10 percent are stale, and fail when more than 10 percent are stale. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-009` | noncompliant | A complete source read satisfies the fail branch of this derivation: for a non-empty active-or-bypass population, return pass when every last-login date is present and no login is older than 90 days, warn when dates are missing or at most 10 percent are stale, and fail when more than 10 percent are stale. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-009` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-009` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-010` | compliant | All required source reads are complete and this derivation returns pass: for enrolled users, return pass when at least 75 percent have WebAuthn and none has deprecated U2F, warn when any user has WebAuthn but that bar is not met, and fail when none has WebAuthn. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-010` | noncompliant | A complete source read satisfies the fail branch of this derivation: for enrolled users, return pass when at least 75 percent have WebAuthn and none has deprecated U2F, warn when any user has WebAuthn but that bar is not met, and fail when none has WebAuthn. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-010` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-010` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-011` | compliant | All required source reads are complete and this derivation returns pass: always return manual because the Admin API exposes offline-enrollment events but not the offline-access policy limits. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-011` | noncompliant | A complete source read satisfies the fail branch of this derivation: always return manual because the Admin API exposes offline-enrollment events but not the offline-access policy limits. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-011` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-011` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-ADMIN-001` | compliant | All required source reads are complete and this derivation returns pass: for a non-empty administrator inventory, return pass with at most two active owners, warn when owners are at most the greater of three or half of all administrators, and fail above that bound. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-ADMIN-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: for a non-empty administrator inventory, return pass with at most two active owners, warn when owners are at most the greater of three or half of all administrators, and fail above that bound. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-ADMIN-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-ADMIN-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-ADMIN-002` | compliant | All required source reads are complete and this derivation returns pass: return pass when WebAuthn or Verified Duo Push is enabled and SMS and voice are disabled, warn when a strong method is enabled alongside SMS or voice, and fail when neither strong method is enabled. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-ADMIN-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when WebAuthn or Verified Duo Push is enabled and SMS and voice are disabled, warn when a strong method is enabled alongside SMS or voice, and fail when neither strong method is enabled. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-ADMIN-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-ADMIN-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-ADMIN-003` | compliant | All required source reads are complete and this derivation returns pass: return pass for helpdesk_bypass=deny, warn for limit with a positive expiration, and fail for every other readable setting. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-ADMIN-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass for helpdesk_bypass=deny, warn for limit with a positive expiration, and fail for every other readable setting. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-ADMIN-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-ADMIN-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-ADMIN-004` | compliant | All required source reads are complete and this derivation returns pass: return pass when every active administrator has a parseable last login no older than 90 days, warn for missing dates or a smaller stale set, and fail when stale administrators are at least one third of active administrators. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-ADMIN-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every active administrator has a parseable last login no older than 90 days, warn for missing dates or a smaller stale set, and fail when stale administrators are at least one third of active administrators. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-ADMIN-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-ADMIN-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-ADMIN-005` | compliant | All required source reads are complete and this derivation returns pass: return fail when the numeric lockout threshold is zero or negative, pass from one through ten failed attempts, warn above ten, and manual when the threshold is absent or nonnumeric. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-ADMIN-005` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when the numeric lockout threshold is zero or negative, pass from one through ten failed attempts, warn above ten, and manual when the threshold is absent or nonnumeric. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-ADMIN-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-ADMIN-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-001` | compliant | All required source reads are complete and this derivation returns pass: for non-empty active protected integrations, return pass when every integration has a policy key, warn when only some do, and fail when none do; an empty readable inventory is warn. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: for non-empty active protected integrations, return pass when every integration has a policy key, warn when only some do, and fail when none do; an empty readable inventory is warn. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-002` | compliant | All required source reads are complete and this derivation returns pass: for integrations exposing prompt posture, return pass when all use Universal Prompt, warn when only some do, and fail when none do. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: for integrations exposing prompt posture, return pass when all use Universal Prompt, warn when only some do, and fail when none do. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-003` | compliant | All required source reads are complete and this derivation returns pass: return pass when every protected integration exposing self_service_allowed disables it, warn when only some disable it or the protected inventory is empty, fail when all exposed values enable it, and manual when no integration exposes the field. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every protected integration exposing self_service_allowed disables it, warn when only some disable it or the protected inventory is empty, fail when all exposed values enable it, and manual when no integration exposes the field. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-004` | compliant | All required source reads are complete and this derivation returns pass: return pass when all visible Admin API integrations omit write, settings, integration-management, and permission-management grants, warn when only some are overprivileged or the inventory omits the audit integration, and fail when all are overprivileged. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when all visible Admin API integrations omit write, settings, integration-management, and permission-management grants, warn when only some are overprivileged or the inventory omits the audit integration, and fail when all are overprivileged. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-005` | compliant | All required source reads are complete and this derivation returns pass: for protected applications tagged Critical, High, or regulated, return pass when each has an explicit policy, warn when only some do, fail when none do, and manual when no protected application has usable criticality tags. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-005` | noncompliant | A complete source read satisfies the fail branch of this derivation: for protected applications tagged Critical, High, or regulated, return pass when each has an explicit policy, warn when only some do, fail when none do, and manual when no protected application has usable criticality tags. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-006` | compliant | All required source reads are complete and this derivation returns pass: evaluate five groups: Duo Desktop, encryption, firewall, system-password or screen-lock, and operating-system restrictions; return pass for all five, fail for none, warn for one through four, and manual when the tenant edition exposes no device-health sections. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-006` | noncompliant | A complete source read satisfies the fail branch of this derivation: evaluate five groups: Duo Desktop, encryption, firewall, system-password or screen-lock, and operating-system restrictions; return pass for all five, fail for none, warn for one through four, and manual when the tenant edition exposes no device-health sections. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-006` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-006` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-MON-001` | compliant | All required source reads are complete and this derivation returns pass: return pass for a non-empty authentication-log window with no bypass, SMS, phone, or fraud events; warn when the window is empty or any such event exists. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-MON-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass for a non-empty authentication-log window with no bypass, SMS, phone, or fraud events; warn when the window is empty or any such event exists. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-MON-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-MON-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-MON-002` | compliant | All required source reads are complete and this derivation returns pass: return pass when the Trust Monitor window contains events and warn when its complete window is empty. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-MON-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the Trust Monitor window contains events and warn when its complete window is empty. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-MON-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-MON-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-MON-003` | compliant | All required source reads are complete and this derivation returns pass: return fail when telephony use exists and credits are below 25, warn when telephony use exists or credits are below 100, pass otherwise, and manual when credits or logs are unreadable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-MON-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when telephony use exists and credits are below 25, warn when telephony use exists or credits are below 100, pass otherwise, and manual when credits or logs are unreadable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-MON-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-MON-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-MON-004` | compliant | All required source reads are complete and this derivation returns pass: return pass when any fraud-email, push-activity, or email-activity notification is enabled and warn when all readable notification signals are false or absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-MON-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when any fraud-email, push-activity, or email-activity notification is enabled and warn when all readable notification signals are false or absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-MON-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-MON-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-MON-005` | compliant | All required source reads are complete and this derivation returns pass: return fail for any successful country change within 60 minutes, warn for fraud or a denied-attempt share above 20 percent, pass otherwise, manual when counts or all location fields are absent, and warn when both summary and event windows are empty. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-MON-005` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail for any successful country change within 60 minutes, warn for fraud or a denied-attempt share above 20 percent, pass otherwise, manual when counts or all location fields are absent, and warn when both summary and event windows are empty. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-MON-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-MON-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Phishing-resistant authentication methods | IA-2(1), IA-2(11) | 3.5.3 | CC6.1 | 6.3 | 8.4.2 | SRG-APP-000149 | ISM-1504 | CPS.AT-2 |
| 2 | Deprecated authentication methods restricted | IA-2(6) | 3.5.3 | CC6.1 | 6.4 | 8.4.3 | SRG-APP-000156 | ISM-1515 | CPS.IA-2 |
| 3 | New user enrollment policy | AC-2(2) | 3.1.1 | CC6.2 | 5.3 | 8.2.1 | SRG-APP-000024 | ISM-0415 | CPS.AC-2 |
| 4 | Remembered devices posture | AC-12 | 3.1.10 | CC6.1 | 5.4 | 8.2.8 | SRG-APP-000295 | ISM-1164 | CPS.AC-7 |
| 5 | Trusted endpoints and device health | CM-6, CM-8(3) | 3.4.1, 3.4.2 | CC6.7 | 4.1 | 2.2.1 | SRG-APP-000383, SRG-APP-000384 | ISM-1082, ISM-1599 | CPS.CM-6, CPS.CM-8 |
| 6 | Bypass code hygiene | IA-5(1) | 3.5.10 | CC6.1 | 6.6 | 8.6.3 | SRG-APP-000175 | ISM-1557 | CPS.IA-5 |
| 7 | Global MFA enforcement mode | IA-2(1) | 3.5.3 | CC6.1 | 6.3 | 8.4.2 | SRG-APP-000149 | ISM-1504 | CPS.AT-2 |
| 8 | User enrollment completeness | IA-2(2) | 3.5.3 | CC6.1 | 6.3 | 8.4.1 | SRG-APP-000150 | ISM-1504 | CPS.AT-2 |
| 9 | Inactive user detection | AC-2(3) | 3.1.12 | CC6.2 | 5.3 | 8.1.4 | SRG-APP-000025 | ISM-1591 | CPS.AC-2 |
| 10 | WebAuthn and U2F credential adoption | IA-2(12) | 3.5.3 | CC6.1 | 6.4 | 8.4.3 | SRG-APP-000395 | ISM-1515 | CPS.IA-2 |
| 11 | Offline access configuration | IA-2(11) | 3.5.3 | CC6.1 | - | 8.4.1 | SRG-APP-000394 | ISM-1504 | CPS.IA-2 |
| 12 | Owner and privileged admin concentration | AC-6(5) | 3.1.5 | CC6.3 | 4.3 | 7.1.1 | SRG-APP-000340 | ISM-1507 | CPS.AC-6 |
| 13 | Administrator authentication strength | IA-2(1), IA-2(11) | 3.5.3 | CC6.1 | 6.4 | 8.4.2 | SRG-APP-000149 | ISM-1504 | CPS.AT-2 |
| 14 | Help desk bypass governance | AC-6(10) | 3.1.7 | CC6.3 | 6.7 | 7.2.1 | SRG-APP-000343 | ISM-0988 | CPS.AC-6 |
| 15 | Stale privileged administrator review | AC-2(3) | 3.1.12 | CC6.2 | 5.3 | 8.1.4 | SRG-APP-000025 | ISM-1591 | CPS.AC-2 |
| 16 | User lockout policy | AC-7 | 3.1.8 | CC6.1 | 5.4 | 8.3.4 | SRG-APP-000065 | ISM-1403 | CPS.AC-7 |
| 17 | Protected integrations have explicit policy coverage | CM-2, CM-8 | 3.4.1 | CC6.8 | 4.5 | 2.2.1 | SRG-APP-000386 | ISM-1624 | CPS.CM-2 |
| 18 | Universal Prompt adoption | IA-2(1) | 3.5.3 | CC6.1 | 6.4 | 8.4.2 | SRG-APP-000149 | ISM-1515 | CPS.IA-2 |
| 19 | Self-service portal governance | AC-2(1) | 3.1.1 | CC6.2 | 5.3 | 8.2.4 | SRG-APP-000023 | ISM-1594 | CPS.AC-2 |
| 20 | Administrative API integration permissions | AC-6(10) | 3.1.7 | CC6.3 | 4.3 | 7.2.1 | SRG-APP-000343 | ISM-0988 | CPS.AC-6 |
| 21 | Critical application protection coverage | CM-8 | 3.4.1 | CC6.1 | - | 2.4 | SRG-APP-000383 | ISM-1599 | CPS.CM-8 |
| 22 | Device health requirements depth | CM-6 | 3.4.2 | CC6.7 | - | 2.2.1 | SRG-APP-000384 | ISM-1082 | CPS.CM-6 |
| 23 | Authentication log visibility and factor hygiene | AU-6, SI-4 | 3.3.5, 3.14.6 | CC7.2 | 8.2 | 10.6.1 | SRG-APP-000516 | ISM-0109 | CPS.AU-6 |
| 24 | Trust Monitor coverage | SI-4 | 3.14.6 | CC7.2 | 8.7 | 10.6.1 | SRG-APP-000516 | ISM-0580 | CPS.SI-4 |
| 25 | Telephony reliance and credit headroom | SA-9 | 3.13.2 | CC9.1 | 13.1 | - | SRG-APP-000516 | ISM-0888 | CPS.SA-9 |
| 26 | Administrative and fraud notifications | AU-5, AU-6 | 3.3.6 | CC7.2 | 8.8 | 10.7.2 | SRG-APP-000516 | ISM-0109 | CPS.AU-6 |
| 27 | Authentication outcome and travel anomalies | AU-6 | 3.3.5 | CC7.2 | - | 10.6.1 | SRG-APP-000516 | ISM-0109 | CPS.AU-6 |

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

Sensitive fields and values: skey, integration_key, authorization, cookie, bypass_code

Credential formats: Duo integration keys, Duo secret keys, HMAC Authorization signatures

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `settings` | `helpdesk_bypass`, `user_lockout`, `notifications` |
| `info-summary` | `telephony_credits_remaining`, `user_count`, `integration_count` |
| `authentication-attempts` | `count`, `result`, `reason` |
| `admin-auth-methods` | `webauthn`, `duo_push`, `sms`, `phone` |
| `global-policy` | `authentication_methods`, `new_user_policy`, `remembered_devices`, `trusted_endpoints`, `device_health` |
| `policies` | `policy_id`, `name`, `authentication_methods`, `remembered_devices`, `device_health` |
| `users` | `user_id`, `username`, `status`, `last_login`, `is_enrolled` |
| `bypass-codes` | `user_id`, `created`, `expires`, `remaining_uses` |
| `webauthn-credentials` | `user_id`, `credential_name`, `date_added` |
| `admins` | `admin_id`, `name`, `role`, `status`, `last_login` |
| `integrations` | `integration_key`, `name`, `type`, `policy`, `prompt_type`, `permissions` |
| `authentication-logs` | `timestamp`, `result`, `reason`, `factor`, `access_device`, `location` |
| `activity-logs` | `timestamp`, `action`, `username`, `description` |
| `telephony-logs` | `timestamp`, `type`, `context`, `credits` |
| `offline-enrollment-logs` | `timestamp`, `username`, `action`, `application` |
| `trust-monitor-events` | `id`, `type`, `timestamp`, `risk`, `location` |

## Export layout

Required paths:

- `QUICK_REFERENCE.md`
- `config.json`
- `core_data/settings.json`
- `core_data/policies.json`
- `core_data/global_policy.json`
- `core_data/users.json`
- `core_data/bypass_codes.json`
- `core_data/webauthn_credentials.json`
- `core_data/admin_allowed_auth_methods.json`
- `core_data/authentication_logs.json`
- `core_data/offline_enrollment_logs.json`
- `core_data/admins.json`
- `core_data/activity_logs.json`
- `core_data/integrations.json`
- `core_data/info_summary.json`
- `core_data/telephony_logs.json`
- `core_data/trust_monitor_events.json`
- `core_data/authentication_attempts.json`
- `core_data/collection_status.json`
- `analysis/authentication.json`
- `analysis/admin_access.json`
- `analysis/integrations.json`
- `analysis/monitoring.json`
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

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `QUICK_REFERENCE.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `config.json` | json | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/settings.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/policies.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/global_policy.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/users.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/bypass_codes.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/webauthn_credentials.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/admin_allowed_auth_methods.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/authentication_logs.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/offline_enrollment_logs.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/admins.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/activity_logs.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/integrations.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/info_summary.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/telephony_logs.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/trust_monitor_events.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/authentication_attempts.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/collection_status.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/authentication.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/admin_access.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/integrations.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/monitoring.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/findings.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `compliance/executive_summary.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/unified_compliance_matrix.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/fedramp/fedramp_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cmmc/cmmc_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/soc2/soc2_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cis/cis_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/pci_dss/pci_dss_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/disa_stig/stig_compliance_checklist.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/irap/irap_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/ismap/ismap_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
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

Overwrite policy: Allocate a timestamped <api-host> directory and add a numeric suffix if that directory already exists; allocate the archive independently without overwriting.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Create a zip named from the allocated directory beside it; if that zip exists, add an independent numeric suffix.
