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
| `DUO-AUTH-001` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Phishing-resistant authentication methods; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Phishing-resistant authentication methods, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Phishing-resistant authentication methods; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Phishing-resistant authentication methods is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-002` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Deprecated authentication methods restricted; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Deprecated authentication methods restricted, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Deprecated authentication methods restricted; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Deprecated authentication methods restricted is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-003` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for New user enrollment policy; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for New user enrollment policy, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of New user enrollment policy; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for New user enrollment policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-004` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Remembered devices posture; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Remembered devices posture, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Remembered devices posture; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Remembered devices posture is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-005` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Trusted endpoints and device health; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Trusted endpoints and device health, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Trusted endpoints and device health; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Trusted endpoints and device health is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-006` | high | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Bypass code hygiene; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Bypass code hygiene, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Bypass code hygiene; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Bypass code hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-007` | high | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Global MFA enforcement mode; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Global MFA enforcement mode, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Global MFA enforcement mode; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Global MFA enforcement mode is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-008` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for User enrollment completeness; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for User enrollment completeness, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of User enrollment completeness; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for User enrollment completeness is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-009` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Inactive user detection; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Inactive user detection, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Inactive user detection; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Inactive user detection is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-010` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for WebAuthn and U2F credential adoption; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for WebAuthn and U2F credential adoption, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of WebAuthn and U2F credential adoption; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for WebAuthn and U2F credential adoption is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-AUTH-011` | medium | `duo_assess_authentication` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Offline access configuration; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Offline access configuration, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Offline access configuration; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Offline access configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-001` | high | `duo_assess_admin_access` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Owner and privileged admin concentration; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Owner and privileged admin concentration, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Owner and privileged admin concentration; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Owner and privileged admin concentration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-002` | medium | `duo_assess_admin_access` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Administrator authentication strength; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Administrator authentication strength, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Administrator authentication strength; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Administrator authentication strength is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-003` | high | `duo_assess_admin_access` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Help desk bypass governance; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Help desk bypass governance, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Help desk bypass governance; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Help desk bypass governance is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-004` | high | `duo_assess_admin_access` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Stale privileged administrator review; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Stale privileged administrator review, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Stale privileged administrator review; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Stale privileged administrator review is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-ADMIN-005` | medium | `duo_assess_admin_access` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for User lockout policy; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for User lockout policy, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of User lockout policy; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for User lockout policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-001` | medium | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Protected integrations have explicit policy coverage; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Protected integrations have explicit policy coverage, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Protected integrations have explicit policy coverage; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Protected integrations have explicit policy coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-002` | medium | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Universal Prompt adoption; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Universal Prompt adoption, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Universal Prompt adoption; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Universal Prompt adoption is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-003` | medium | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Self-service portal governance; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Self-service portal governance, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Self-service portal governance; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Self-service portal governance is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-004` | high | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Administrative API integration permissions; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Administrative API integration permissions, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Administrative API integration permissions; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Administrative API integration permissions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-005` | high | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Critical application protection coverage; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Critical application protection coverage, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Critical application protection coverage; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Critical application protection coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-INTEGRATIONS-006` | medium | `duo_assess_integrations` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Device health requirements depth; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Device health requirements depth, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Device health requirements depth; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Device health requirements depth is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-001` | medium | `duo_assess_monitoring` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Authentication log visibility and factor hygiene; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Authentication log visibility and factor hygiene, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Authentication log visibility and factor hygiene; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Authentication log visibility and factor hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-002` | medium | `duo_assess_monitoring` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Trust Monitor coverage; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Trust Monitor coverage, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Trust Monitor coverage; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Trust Monitor coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-003` | medium | `duo_assess_monitoring` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Telephony reliance and credit headroom; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Telephony reliance and credit headroom, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Telephony reliance and credit headroom; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Telephony reliance and credit headroom is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-004` | medium | `duo_assess_monitoring` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Administrative and fraud notifications; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Administrative and fraud notifications, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Administrative and fraud notifications; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Administrative and fraud notifications is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `DUO-MON-005` | medium | `duo_assess_monitoring` | `settings`, `policies`, `users`, `integrations`, `authentication-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Authentication outcome and travel anomalies; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Authentication outcome and travel anomalies, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Authentication outcome and travel anomalies; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Authentication outcome and travel anomalies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

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
| `DUO-AUTH-001` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-AUTH-002` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-AUTH-003` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-AUTH-004` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-AUTH-005` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-AUTH-006` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-AUTH-007` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-AUTH-008` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-AUTH-009` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-AUTH-010` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-AUTH-011` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-ADMIN-001` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-ADMIN-002` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-ADMIN-003` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-ADMIN-004` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-ADMIN-005` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-INTEGRATIONS-001` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-INTEGRATIONS-002` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-INTEGRATIONS-003` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-INTEGRATIONS-004` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-INTEGRATIONS-005` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-INTEGRATIONS-006` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-MON-001` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-MON-002` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-MON-003` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-MON-004` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `DUO-MON-005` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |

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
| `DUO-AUTH-001` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-001` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-002` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-002` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-003` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-003` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-004` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-004` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-005` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-005` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-006` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-006` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-006` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-006` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-007` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-007` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-007` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-007` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-008` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-008` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-008` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-008` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-009` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-009` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-009` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-009` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-010` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-010` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-010` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-010` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-AUTH-011` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-AUTH-011` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-AUTH-011` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-AUTH-011` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-ADMIN-001` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-ADMIN-001` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-ADMIN-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-ADMIN-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-ADMIN-002` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-ADMIN-002` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-ADMIN-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-ADMIN-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-ADMIN-003` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-ADMIN-003` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-ADMIN-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-ADMIN-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-ADMIN-004` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-ADMIN-004` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-ADMIN-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-ADMIN-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-ADMIN-005` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-ADMIN-005` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-ADMIN-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-ADMIN-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-001` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-001` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-002` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-002` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-003` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-003` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-004` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-004` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-005` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-005` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-INTEGRATIONS-006` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-INTEGRATIONS-006` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-INTEGRATIONS-006` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-INTEGRATIONS-006` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-MON-001` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-MON-001` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-MON-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-MON-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-MON-002` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-MON-002` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-MON-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-MON-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-MON-003` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-MON-003` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-MON-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-MON-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-MON-004` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-MON-004` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `DUO-MON-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `DUO-MON-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `DUO-MON-005` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `DUO-MON-005` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
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
