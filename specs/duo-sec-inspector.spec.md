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
2. Explicit config file
3. DUO_* environment variables

Environment variables: `DUO_IKEY`, `DUO_SKEY`, `DUO_API_HOSTNAME`, `DUO_CONFIG_FILE`

Configuration locations: Explicit JSON or YAML config file

Credential and deployment variants: Commercial and FedRAMP Duo API hostnames selected by api_hostname

Configuration fields: `integrationKey`, `secretKey`, `apiHostname`, `timeoutMs`

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| role | `Grant resource - Read` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `Grant administrators - Read` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `Grant settings - Read` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `Grant logs - Read` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `Grant information - Read` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `settings` | HTTP | `GET /admin/v1/settings` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `global_policy`, `user_lockout`, `notifications`, `helpdesk_bypass` | [Official documentation](https://duo.com/docs/adminapi) |
| `policies` | HTTP | `GET /admin/v2/policies` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `policy_id`, `name`, `authentication_methods`, `remembered_devices`, `device_health` | [Official documentation](https://duo.com/docs/adminapi#policies) |
| `users` | HTTP | `GET /admin/v1/users` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `user_id`, `username`, `status`, `last_login`, `is_enrolled` | [Official documentation](https://duo.com/docs/adminapi#users) |
| `integrations` | HTTP | `GET /admin/v3/integrations` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `integration_key`, `name`, `type`, `policy`, `prompt_type` | [Official documentation](https://duo.com/docs/adminapi#integrations) |
| `authentication-logs` | HTTP | `GET /admin/v2/logs/authentication` | Duo Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `timestamp`, `result`, `reason`, `factor`, `access_device`, `location` | [Official documentation](https://duo.com/docs/adminapi#authentication-logs) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `settings` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `settings` | response | A JSON object or list containing only the documented global_policy, user_lockout, notifications, helpdesk_bypass members consumed by verdicts. | yes |
| `policies` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `policies` | response | A JSON object or list containing only the documented policy_id, name, authentication_methods, remembered_devices, device_health members consumed by verdicts. | yes |
| `users` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `users` | response | A JSON object or list containing only the documented user_id, username, status, last_login, is_enrolled members consumed by verdicts. | yes |
| `integrations` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `integrations` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `integrations` | response | A JSON object or list containing only the documented integration_key, name, type, policy, prompt_type members consumed by verdicts. | yes |
| `authentication-logs` | client | Use the configured Duo Admin API origin; never follow a server link to a different origin. | yes |
| `authentication-logs` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `authentication-logs` | response | A JSON object or list containing only the documented timestamp, result, reason, factor, access_device, location members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `offset`, `next_offset`, `metadata.total_objects` | 500 | caller limit | 1000 | metadata.total_objects is authoritative when present; seen records below that total are truncated. | Proven total reached; No next offset; Configured item cap; Page cap; Repeated offset; Empty page with offset; Missing or inconsistent total |

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
| `DUO-AUTH-001` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Phishing-resistant authentication methods returns pass from complete, readable evidence. | The portable derivation for Phishing-resistant authentication methods returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Phishing-resistant authentication methods returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Phishing-resistant authentication methods is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-002` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Deprecated authentication methods restricted returns pass from complete, readable evidence. | The portable derivation for Deprecated authentication methods restricted returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Deprecated authentication methods restricted returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Deprecated authentication methods restricted is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-003` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for New user enrollment policy returns pass from complete, readable evidence. | The portable derivation for New user enrollment policy returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for New user enrollment policy returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for New user enrollment policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-004` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Remembered devices posture returns pass from complete, readable evidence. | The portable derivation for Remembered devices posture returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Remembered devices posture returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Remembered devices posture is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-005` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Trusted endpoints and device health returns pass from complete, readable evidence. | The portable derivation for Trusted endpoints and device health returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Trusted endpoints and device health returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Trusted endpoints and device health is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-006` | high | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Bypass code hygiene returns pass from complete, readable evidence. | The portable derivation for Bypass code hygiene returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Bypass code hygiene returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Bypass code hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-007` | high | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Global MFA enforcement mode returns pass from complete, readable evidence. | The portable derivation for Global MFA enforcement mode returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Global MFA enforcement mode returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Global MFA enforcement mode is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-008` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for User enrollment completeness returns pass from complete, readable evidence. | The portable derivation for User enrollment completeness returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for User enrollment completeness returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for User enrollment completeness is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-009` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Inactive user detection returns pass from complete, readable evidence. | The portable derivation for Inactive user detection returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Inactive user detection returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Inactive user detection is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-010` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for WebAuthn and U2F credential adoption returns pass from complete, readable evidence. | The portable derivation for WebAuthn and U2F credential adoption returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for WebAuthn and U2F credential adoption returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for WebAuthn and U2F credential adoption is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-011` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Offline access configuration returns pass from complete, readable evidence. | The portable derivation for Offline access configuration returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Offline access configuration returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Offline access configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-001` | high | `duo_assess_admin_access` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Owner and privileged admin concentration returns pass from complete, readable evidence. | The portable derivation for Owner and privileged admin concentration returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Owner and privileged admin concentration returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Owner and privileged admin concentration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-002` | medium | `duo_assess_admin_access` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Administrator authentication strength returns pass from complete, readable evidence. | The portable derivation for Administrator authentication strength returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Administrator authentication strength returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Administrator authentication strength is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-003` | high | `duo_assess_admin_access` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Help desk bypass governance returns pass from complete, readable evidence. | The portable derivation for Help desk bypass governance returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Help desk bypass governance returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Help desk bypass governance is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-004` | high | `duo_assess_admin_access` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Stale privileged administrator review returns pass from complete, readable evidence. | The portable derivation for Stale privileged administrator review returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Stale privileged administrator review returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Stale privileged administrator review is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-005` | medium | `duo_assess_admin_access` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for User lockout policy returns pass from complete, readable evidence. | The portable derivation for User lockout policy returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for User lockout policy returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for User lockout policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-001` | medium | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Protected integrations have explicit policy coverage returns pass from complete, readable evidence. | The portable derivation for Protected integrations have explicit policy coverage returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Protected integrations have explicit policy coverage returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Protected integrations have explicit policy coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-002` | medium | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Universal Prompt adoption returns pass from complete, readable evidence. | The portable derivation for Universal Prompt adoption returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Universal Prompt adoption returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Universal Prompt adoption is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-003` | medium | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Self-service portal governance returns pass from complete, readable evidence. | The portable derivation for Self-service portal governance returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Self-service portal governance returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Self-service portal governance is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-004` | high | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Administrative API integration permissions returns pass from complete, readable evidence. | The portable derivation for Administrative API integration permissions returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Administrative API integration permissions returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Administrative API integration permissions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-005` | high | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Critical application protection coverage returns pass from complete, readable evidence. | The portable derivation for Critical application protection coverage returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Critical application protection coverage returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Critical application protection coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-006` | medium | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Device health requirements depth returns pass from complete, readable evidence. | The portable derivation for Device health requirements depth returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Device health requirements depth returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Device health requirements depth is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-001` | medium | `duo_assess_monitoring` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Authentication log visibility and factor hygiene returns pass from complete, readable evidence. | The portable derivation for Authentication log visibility and factor hygiene returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Authentication log visibility and factor hygiene returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Authentication log visibility and factor hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-002` | medium | `duo_assess_monitoring` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Trust Monitor coverage returns pass from complete, readable evidence. | The portable derivation for Trust Monitor coverage returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Trust Monitor coverage returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Trust Monitor coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-003` | medium | `duo_assess_monitoring` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Telephony reliance and credit headroom returns pass from complete, readable evidence. | The portable derivation for Telephony reliance and credit headroom returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Telephony reliance and credit headroom returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Telephony reliance and credit headroom is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-004` | medium | `duo_assess_monitoring` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Administrative and fraud notifications returns pass from complete, readable evidence. | The portable derivation for Administrative and fraud notifications returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Administrative and fraud notifications returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Administrative and fraud notifications is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-005` | medium | `duo_assess_monitoring` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | The portable derivation for Authentication outcome and travel anomalies returns pass from complete, readable evidence. | The portable derivation for Authentication outcome and travel anomalies returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Authentication outcome and travel anomalies returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Authentication outcome and travel anomalies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `DUO-AUTH-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-AUTH-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-AUTH-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-AUTH-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-AUTH-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-AUTH-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-AUTH-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-AUTH-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-AUTH-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-AUTH-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-AUTH-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-AUTH-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-AUTH-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-AUTH-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-AUTH-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-AUTH-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-AUTH-005` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-AUTH-005` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-AUTH-005` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-AUTH-005` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-AUTH-006` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-AUTH-006` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-AUTH-006` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-AUTH-006` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-AUTH-007` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-AUTH-007` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-AUTH-007` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-AUTH-007` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-AUTH-008` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-AUTH-008` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-AUTH-008` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-AUTH-008` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-AUTH-009` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-AUTH-009` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-AUTH-009` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-AUTH-009` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-AUTH-010` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-AUTH-010` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-AUTH-010` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-AUTH-010` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-AUTH-011` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-AUTH-011` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-AUTH-011` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-AUTH-011` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-ADMIN-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-ADMIN-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-ADMIN-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-ADMIN-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-ADMIN-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-ADMIN-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-ADMIN-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-ADMIN-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-ADMIN-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-ADMIN-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-ADMIN-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-ADMIN-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-ADMIN-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-ADMIN-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-ADMIN-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-ADMIN-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-ADMIN-005` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-ADMIN-005` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-ADMIN-005` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-ADMIN-005` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-INTEGRATIONS-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-INTEGRATIONS-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-INTEGRATIONS-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-INTEGRATIONS-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-INTEGRATIONS-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-INTEGRATIONS-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-INTEGRATIONS-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-INTEGRATIONS-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-INTEGRATIONS-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-INTEGRATIONS-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-INTEGRATIONS-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-INTEGRATIONS-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-INTEGRATIONS-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-INTEGRATIONS-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-INTEGRATIONS-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-INTEGRATIONS-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-INTEGRATIONS-005` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-INTEGRATIONS-005` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-INTEGRATIONS-005` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-INTEGRATIONS-005` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-INTEGRATIONS-006` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-INTEGRATIONS-006` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-INTEGRATIONS-006` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-INTEGRATIONS-006` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-MON-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-MON-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-MON-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-MON-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-MON-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-MON-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-MON-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-MON-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-MON-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-MON-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-MON-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-MON-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-MON-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-MON-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-MON-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-MON-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `DUO-MON-005` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `DUO-MON-005` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `DUO-MON-005` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `DUO-MON-005` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `DUO-AUTH-001` | `decision_status` | Using complete source cardinalities, return pass when the global policy allows WebAuthn or requires Verified Duo Push, warn when only ordinary Duo Push or supporting administrator hardening exists, and fail when neither phishing-resistant option is present. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-AUTH-002` | `decision_status` | Using complete source cardinalities, return pass only when both SMS and phone callback are explicitly blocked, fail when neither is blocked, warn when only one is blocked or telephony is explicitly allowed alongside a partial block, and manual when the allow and block lists are absent. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-AUTH-003` | `decision_status` | Using complete source cardinalities, return pass for new_user_behavior=enroll, fail for no-mfa, warn for any other readable behavior, and manual when the value is absent. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-AUTH-004` | `decision_status` | Using complete source cardinalities, return pass when remembered devices are disabled or last at most 14 days, warn for 15 through 30 days, fail above 30 days, and manual when the duration cannot be normalized. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-AUTH-005` | `decision_status` | Using complete source cardinalities, return pass for trusted_endpoint_checking=require-trusted, warn for allow-all, and fail for any other readable configuration. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-AUTH-006` | `decision_status` | Using complete source cardinalities, return pass only for an empty bypass-code inventory with readable help-desk limits, fail when any unexpired code is older than 24 hours, has unlimited uses, lacks expiration, or help-desk issuance is unlimited, and warn for every other non-empty or undated inventory. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-AUTH-007` | `decision_status` | Using complete source cardinalities, return pass for user_auth_behavior=enforce, fail for bypass, warn for another readable value such as deny, and manual when the authentication policy or value is absent. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-AUTH-008` | `decision_status` | Using complete source cardinalities, for users with known enrollment state, return pass when all active users are enrolled and none has bypass status, warn when at least 90 percent are enrolled with no bypass users, and fail otherwise. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-AUTH-009` | `decision_status` | Using complete source cardinalities, for a non-empty active-or-bypass population, return pass when every last-login date is present and no login is older than 90 days, warn when dates are missing or at most 10 percent are stale, and fail when more than 10 percent are stale. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-AUTH-010` | `decision_status` | Using complete source cardinalities, for enrolled users, return pass when at least 75 percent have WebAuthn and none has deprecated U2F, warn when any user has WebAuthn but that bar is not met, and fail when none has WebAuthn. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-AUTH-011` | `decision_status` | Using complete source cardinalities, always return manual because the Admin API exposes offline-enrollment events but not the offline-access policy limits. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-ADMIN-001` | `decision_status` | Using complete source cardinalities, for a non-empty administrator inventory, return pass with at most two active owners, warn when owners are at most the greater of three or half of all administrators, and fail above that bound. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-ADMIN-002` | `decision_status` | Using complete source cardinalities, return pass when WebAuthn or Verified Duo Push is enabled and SMS and voice are disabled, warn when a strong method is enabled alongside SMS or voice, and fail when neither strong method is enabled. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-ADMIN-003` | `decision_status` | Using complete source cardinalities, return pass for helpdesk_bypass=deny, warn for limit with a positive expiration, and fail for every other readable setting. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-ADMIN-004` | `decision_status` | Using complete source cardinalities, return pass when every active administrator has a parseable last login no older than 90 days, warn for missing dates or a smaller stale set, and fail when stale administrators are at least one third of active administrators. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-ADMIN-005` | `decision_status` | Using complete source cardinalities, return fail when the numeric lockout threshold is zero or negative, pass from one through ten failed attempts, warn above ten, and manual when the threshold is absent or nonnumeric. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-INTEGRATIONS-001` | `decision_status` | Using complete source cardinalities, for non-empty active protected integrations, return pass when every integration has a policy key, warn when only some do, and fail when none do; an empty readable inventory is warn. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-INTEGRATIONS-002` | `decision_status` | Using complete source cardinalities, for integrations exposing prompt posture, return pass when all use Universal Prompt, warn when only some do, and fail when none do. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-INTEGRATIONS-003` | `decision_status` | Using complete source cardinalities, return pass when every protected integration exposing self_service_allowed disables it, warn when only some disable it or the protected inventory is empty, fail when all exposed values enable it, and manual when no integration exposes the field. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-INTEGRATIONS-004` | `decision_status` | Using complete source cardinalities, return pass when all visible Admin API integrations omit write, settings, integration-management, and permission-management grants, warn when only some are overprivileged or the inventory omits the audit integration, and fail when all are overprivileged. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-INTEGRATIONS-005` | `decision_status` | Using complete source cardinalities, for protected applications tagged Critical, High, or regulated, return pass when each has an explicit policy, warn when only some do, fail when none do, and manual when no protected application has usable criticality tags. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-INTEGRATIONS-006` | `decision_status` | Using complete source cardinalities, evaluate five groups: Duo Desktop, encryption, firewall, system-password or screen-lock, and operating-system restrictions; return pass for all five, fail for none, warn for one through four, and manual when the tenant edition exposes no device-health sections. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-MON-001` | `decision_status` | Using complete source cardinalities, return pass for a non-empty authentication-log window with no bypass, SMS, phone, or fraud events; warn when the window is empty or any such event exists. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-MON-002` | `decision_status` | Using complete source cardinalities, return pass when the Trust Monitor window contains events and warn when its complete window is empty. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-MON-003` | `decision_status` | Using complete source cardinalities, return fail when telephony use exists and credits are below 25, warn when telephony use exists or credits are below 100, pass otherwise, and manual when credits or logs are unreadable. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-MON-004` | `decision_status` | Using complete source cardinalities, return pass when any fraud-email, push-activity, or email-activity notification is enabled and warn when all readable notification signals are false or absent. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `DUO-MON-005` | `decision_status` | Using complete source cardinalities, return fail for any successful country change within 60 minutes, warn for fraud or a denied-attempt share above 20 percent, pass otherwise, manual when counts or all location fields are absent, and warn when both summary and event windows are empty. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `DUO-AUTH-001` | `passStatus` | pass |
| `DUO-AUTH-001` | `warnStatus` | warn |
| `DUO-AUTH-001` | `failStatus` | fail |
| `DUO-AUTH-001` | `manualStatus` | manual |
| `DUO-AUTH-002` | `passStatus` | pass |
| `DUO-AUTH-002` | `warnStatus` | warn |
| `DUO-AUTH-002` | `failStatus` | fail |
| `DUO-AUTH-002` | `manualStatus` | manual |
| `DUO-AUTH-003` | `passStatus` | pass |
| `DUO-AUTH-003` | `warnStatus` | warn |
| `DUO-AUTH-003` | `failStatus` | fail |
| `DUO-AUTH-003` | `manualStatus` | manual |
| `DUO-AUTH-004` | `passStatus` | pass |
| `DUO-AUTH-004` | `warnStatus` | warn |
| `DUO-AUTH-004` | `failStatus` | fail |
| `DUO-AUTH-004` | `manualStatus` | manual |
| `DUO-AUTH-005` | `passStatus` | pass |
| `DUO-AUTH-005` | `warnStatus` | warn |
| `DUO-AUTH-005` | `failStatus` | fail |
| `DUO-AUTH-005` | `manualStatus` | manual |
| `DUO-AUTH-006` | `passStatus` | pass |
| `DUO-AUTH-006` | `warnStatus` | warn |
| `DUO-AUTH-006` | `failStatus` | fail |
| `DUO-AUTH-006` | `manualStatus` | manual |
| `DUO-AUTH-007` | `passStatus` | pass |
| `DUO-AUTH-007` | `warnStatus` | warn |
| `DUO-AUTH-007` | `failStatus` | fail |
| `DUO-AUTH-007` | `manualStatus` | manual |
| `DUO-AUTH-008` | `passStatus` | pass |
| `DUO-AUTH-008` | `warnStatus` | warn |
| `DUO-AUTH-008` | `failStatus` | fail |
| `DUO-AUTH-008` | `manualStatus` | manual |
| `DUO-AUTH-009` | `passStatus` | pass |
| `DUO-AUTH-009` | `warnStatus` | warn |
| `DUO-AUTH-009` | `failStatus` | fail |
| `DUO-AUTH-009` | `manualStatus` | manual |
| `DUO-AUTH-010` | `passStatus` | pass |
| `DUO-AUTH-010` | `warnStatus` | warn |
| `DUO-AUTH-010` | `failStatus` | fail |
| `DUO-AUTH-010` | `manualStatus` | manual |
| `DUO-AUTH-011` | `passStatus` | pass |
| `DUO-AUTH-011` | `warnStatus` | warn |
| `DUO-AUTH-011` | `failStatus` | fail |
| `DUO-AUTH-011` | `manualStatus` | manual |
| `DUO-ADMIN-001` | `passStatus` | pass |
| `DUO-ADMIN-001` | `warnStatus` | warn |
| `DUO-ADMIN-001` | `failStatus` | fail |
| `DUO-ADMIN-001` | `manualStatus` | manual |
| `DUO-ADMIN-002` | `passStatus` | pass |
| `DUO-ADMIN-002` | `warnStatus` | warn |
| `DUO-ADMIN-002` | `failStatus` | fail |
| `DUO-ADMIN-002` | `manualStatus` | manual |
| `DUO-ADMIN-003` | `passStatus` | pass |
| `DUO-ADMIN-003` | `warnStatus` | warn |
| `DUO-ADMIN-003` | `failStatus` | fail |
| `DUO-ADMIN-003` | `manualStatus` | manual |
| `DUO-ADMIN-004` | `passStatus` | pass |
| `DUO-ADMIN-004` | `warnStatus` | warn |
| `DUO-ADMIN-004` | `failStatus` | fail |
| `DUO-ADMIN-004` | `manualStatus` | manual |
| `DUO-ADMIN-005` | `passStatus` | pass |
| `DUO-ADMIN-005` | `warnStatus` | warn |
| `DUO-ADMIN-005` | `failStatus` | fail |
| `DUO-ADMIN-005` | `manualStatus` | manual |
| `DUO-INTEGRATIONS-001` | `passStatus` | pass |
| `DUO-INTEGRATIONS-001` | `warnStatus` | warn |
| `DUO-INTEGRATIONS-001` | `failStatus` | fail |
| `DUO-INTEGRATIONS-001` | `manualStatus` | manual |
| `DUO-INTEGRATIONS-002` | `passStatus` | pass |
| `DUO-INTEGRATIONS-002` | `warnStatus` | warn |
| `DUO-INTEGRATIONS-002` | `failStatus` | fail |
| `DUO-INTEGRATIONS-002` | `manualStatus` | manual |
| `DUO-INTEGRATIONS-003` | `passStatus` | pass |
| `DUO-INTEGRATIONS-003` | `warnStatus` | warn |
| `DUO-INTEGRATIONS-003` | `failStatus` | fail |
| `DUO-INTEGRATIONS-003` | `manualStatus` | manual |
| `DUO-INTEGRATIONS-004` | `passStatus` | pass |
| `DUO-INTEGRATIONS-004` | `warnStatus` | warn |
| `DUO-INTEGRATIONS-004` | `failStatus` | fail |
| `DUO-INTEGRATIONS-004` | `manualStatus` | manual |
| `DUO-INTEGRATIONS-005` | `passStatus` | pass |
| `DUO-INTEGRATIONS-005` | `warnStatus` | warn |
| `DUO-INTEGRATIONS-005` | `failStatus` | fail |
| `DUO-INTEGRATIONS-005` | `manualStatus` | manual |
| `DUO-INTEGRATIONS-006` | `passStatus` | pass |
| `DUO-INTEGRATIONS-006` | `warnStatus` | warn |
| `DUO-INTEGRATIONS-006` | `failStatus` | fail |
| `DUO-INTEGRATIONS-006` | `manualStatus` | manual |
| `DUO-MON-001` | `passStatus` | pass |
| `DUO-MON-001` | `warnStatus` | warn |
| `DUO-MON-001` | `failStatus` | fail |
| `DUO-MON-001` | `manualStatus` | manual |
| `DUO-MON-002` | `passStatus` | pass |
| `DUO-MON-002` | `warnStatus` | warn |
| `DUO-MON-002` | `failStatus` | fail |
| `DUO-MON-002` | `manualStatus` | manual |
| `DUO-MON-003` | `passStatus` | pass |
| `DUO-MON-003` | `warnStatus` | warn |
| `DUO-MON-003` | `failStatus` | fail |
| `DUO-MON-003` | `manualStatus` | manual |
| `DUO-MON-004` | `passStatus` | pass |
| `DUO-MON-004` | `warnStatus` | warn |
| `DUO-MON-004` | `failStatus` | fail |
| `DUO-MON-004` | `manualStatus` | manual |
| `DUO-MON-005` | `passStatus` | pass |
| `DUO-MON-005` | `warnStatus` | warn |
| `DUO-MON-005` | `failStatus` | fail |
| `DUO-MON-005` | `manualStatus` | manual |

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
| 1 | Phishing-resistant authentication methods | - | - | - | - | - | - | - | - |
| 2 | Deprecated authentication methods restricted | - | - | - | - | - | - | - | - |
| 3 | New user enrollment policy | - | - | - | - | - | - | - | - |
| 4 | Remembered devices posture | - | - | - | - | - | - | - | - |
| 5 | Trusted endpoints and device health | - | - | - | - | - | - | - | - |
| 6 | Bypass code hygiene | - | - | - | - | - | - | - | - |
| 7 | Global MFA enforcement mode | - | - | - | - | - | - | - | - |
| 8 | User enrollment completeness | - | - | - | - | - | - | - | - |
| 9 | Inactive user detection | - | - | - | - | - | - | - | - |
| 10 | WebAuthn and U2F credential adoption | - | - | - | - | - | - | - | - |
| 11 | Offline access configuration | - | - | - | - | - | - | - | - |
| 12 | Owner and privileged admin concentration | - | - | - | - | - | - | - | - |
| 13 | Administrator authentication strength | - | - | - | - | - | - | - | - |
| 14 | Help desk bypass governance | - | - | - | - | - | - | - | - |
| 15 | Stale privileged administrator review | - | - | - | - | - | - | - | - |
| 16 | User lockout policy | - | - | - | - | - | - | - | - |
| 17 | Protected integrations have explicit policy coverage | - | - | - | - | - | - | - | - |
| 18 | Universal Prompt adoption | - | - | - | - | - | - | - | - |
| 19 | Self-service portal governance | - | - | - | - | - | - | - | - |
| 20 | Administrative API integration permissions | - | - | - | - | - | - | - | - |
| 21 | Critical application protection coverage | - | - | - | - | - | - | - | - |
| 22 | Device health requirements depth | - | - | - | - | - | - | - | - |
| 23 | Authentication log visibility and factor hygiene | - | - | - | - | - | - | - | - |
| 24 | Trust Monitor coverage | - | - | - | - | - | - | - | - |
| 25 | Telephony reliance and credit headroom | - | - | - | - | - | - | - | - |
| 26 | Administrative and fraud notifications | - | - | - | - | - | - | - | - |
| 27 | Authentication outcome and travel anomalies | - | - | - | - | - | - | - | - |

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
| `settings` | `global_policy`, `user_lockout`, `notifications`, `helpdesk_bypass` |
| `policies` | `policy_id`, `name`, `authentication_methods`, `remembered_devices`, `device_health` |
| `users` | `user_id`, `username`, `status`, `last_login`, `is_enrolled` |
| `integrations` | `integration_key`, `name`, `type`, `policy`, `prompt_type` |
| `authentication-logs` | `timestamp`, `result`, `reason`, `factor`, `access_device`, `location` |

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

Archive pairing: Create duo-audit.zip beside the allocated duo-audit directory, applying the same suffix to both.
