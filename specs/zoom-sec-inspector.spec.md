---
slug: "zoom-sec-inspector"
name: "Zoom Security Inspector"
vendor: "Zoom"
category: "collaboration"
language: "language-neutral"
status: "generated"
version: "1.0.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# Zoom Security Inspector

Portable contract for the shipped Zoom identity, collaboration-governance, and meeting-security assessments.

## Purpose

Assess Zoom account identity, collaboration, recording, chat, routing, and meeting-security posture from read-only account and reporting APIs.

## Design guidance

Evaluate account settings together with locks and group overrides. Sampling may support review but cannot prove tenant-wide compliance. Plan-gated Zoom Phone and Team Chat evidence must remain unavailable or manual when the licensed surface cannot be read.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- Account settings are read through documented option views and sampled group overrides; a pass requires complete account and group evidence plus every required account-level lock.
- User, role-member, group, operation-log, and IM-group verdict facts use complete seen and declared-total counts, while exported evidence may retain bounded record samples.
- The account API exposes neither a decisive Team Chat encryption setting nor account vanity URL field; those findings remain manual rather than inferred from unrelated fields.
- User OAuth, per-user settings drift, deeper Zoom Phone policy, and usage analytics are deferred.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `zoom_check_access` | Validate Zoom read-only access across account settings and lock settings (the default view plus the meeting_authentication, security, and meeting_security option views this tool reads; recording_authentication is not requested because no verdict reads it), users, roles, groups, operation logs, IM groups, managed and trusted domains, and Zoom Phone account settings. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zoom_assess_identity` | Assess Zoom identity posture: SSO enforcement, blocked personal sign-in methods, admin two-factor authentication, managed domain verification, admin privilege concentration, session inactivity timeout, and the manual vanity URL control. | `ZOOM-ID-01`, `ZOOM-ID-02`, `ZOOM-ID-03`, `ZOOM-ID-04`, `ZOOM-ID-05`, `ZOOM-ID-06`, `ZOOM-ID-07` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zoom_assess_collaboration_governance` | Assess Zoom collaboration governance: trusted domains, in-meeting file transfer, cloud recording auto-delete retention, Zoom Phone recording policies, admin operation logs, IM group restrictions, external contact restrictions, and the manual chat encryption control. | `ZOOM-COLLAB-01`, `ZOOM-COLLAB-02`, `ZOOM-COLLAB-03`, `ZOOM-COLLAB-04`, `ZOOM-COLLAB-05`, `ZOOM-COLLAB-06`, `ZOOM-COLLAB-07`, `ZOOM-COLLAB-08` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zoom_assess_meeting_security` | Assess Zoom meeting security: passcode enforcement and lock, waiting room, host-only screen sharing, local recording, end-to-end encryption, join-link passcode embedding, PMI restrictions, authenticated join, data center regions, and recording consent disclaimers, with group override detection. | `ZOOM-MTG-01`, `ZOOM-MTG-02`, `ZOOM-MTG-03`, `ZOOM-MTG-04`, `ZOOM-MTG-05`, `ZOOM-MTG-06`, `ZOOM-MTG-07`, `ZOOM-MTG-08`, `ZOOM-MTG-09`, `ZOOM-MTG-10` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zoom_export_audit_bundle` | Export a Zoom audit bundle: core_data raw snapshots, analysis findings, compliance reports per framework, QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a zip archive named after the allocated directory. | `ZOOM-ID-01`, `ZOOM-ID-02`, `ZOOM-ID-03`, `ZOOM-ID-04`, `ZOOM-ID-05`, `ZOOM-ID-06`, `ZOOM-ID-07`, `ZOOM-COLLAB-01`, `ZOOM-COLLAB-02`, `ZOOM-COLLAB-03`, `ZOOM-COLLAB-04`, `ZOOM-COLLAB-05`, `ZOOM-COLLAB-06`, `ZOOM-COLLAB-07`, `ZOOM-COLLAB-08`, `ZOOM-MTG-01`, `ZOOM-MTG-02`, `ZOOM-MTG-03`, `ZOOM-MTG-04`, `ZOOM-MTG-05`, `ZOOM-MTG-06`, `ZOOM-MTG-07`, `ZOOM-MTG-08`, `ZOOM-MTG-09`, `ZOOM-MTG-10` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `zoom_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `account_id` | string | no | Zoom account ID. Defaults to ZOOM_ACCOUNT_ID or the config file. |
| `token` | string | no | Pre-issued Zoom OAuth access token. Defaults to ZOOM_TOKEN. |
| `client_id` | string | no | Zoom Server-to-Server OAuth client ID. Defaults to ZOOM_CLIENT_ID or the config file. |
| `client_secret` | string | no | Zoom Server-to-Server OAuth client secret. Defaults to ZOOM_CLIENT_SECRET or the config file. |
| `base_url` | string | no | Zoom REST API base URL. Defaults to https://api.zoom.us/v2. |
| `oauth_base_url` | string | no | Zoom OAuth base URL. Defaults to https://zoom.us or https://zoomgov.com based on base_url. |
| `config_file` | string | no | JSON config file with account_id, client_id, client_secret, base_url. Defaults to ZOOM_CONFIG_FILE, ./.zoom.json, or ~/.zoom.json. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |

#### `zoom_assess_identity`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `account_id` | string | no | Zoom account ID. Defaults to ZOOM_ACCOUNT_ID or the config file. |
| `token` | string | no | Pre-issued Zoom OAuth access token. Defaults to ZOOM_TOKEN. |
| `client_id` | string | no | Zoom Server-to-Server OAuth client ID. Defaults to ZOOM_CLIENT_ID or the config file. |
| `client_secret` | string | no | Zoom Server-to-Server OAuth client secret. Defaults to ZOOM_CLIENT_SECRET or the config file. |
| `base_url` | string | no | Zoom REST API base URL. Defaults to https://api.zoom.us/v2. |
| `oauth_base_url` | string | no | Zoom OAuth base URL. Defaults to https://zoom.us or https://zoomgov.com based on base_url. |
| `config_file` | string | no | JSON config file with account_id, client_id, client_secret, base_url. Defaults to ZOOM_CONFIG_FILE, ./.zoom.json, or ~/.zoom.json. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `user_limit` | number | no | Maximum users to enumerate before flagging a partial inventory. Defaults to 1000. |
| `max_admins` | number | no | Maximum acceptable distinct admin users before warning. Defaults to 10. |
| `max_session_inactivity_minutes` | number | no | Maximum acceptable inactivity sign-out period in minutes. Defaults to 120. |

#### `zoom_assess_collaboration_governance`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `account_id` | string | no | Zoom account ID. Defaults to ZOOM_ACCOUNT_ID or the config file. |
| `token` | string | no | Pre-issued Zoom OAuth access token. Defaults to ZOOM_TOKEN. |
| `client_id` | string | no | Zoom Server-to-Server OAuth client ID. Defaults to ZOOM_CLIENT_ID or the config file. |
| `client_secret` | string | no | Zoom Server-to-Server OAuth client secret. Defaults to ZOOM_CLIENT_SECRET or the config file. |
| `base_url` | string | no | Zoom REST API base URL. Defaults to https://api.zoom.us/v2. |
| `oauth_base_url` | string | no | Zoom OAuth base URL. Defaults to https://zoom.us or https://zoomgov.com based on base_url. |
| `config_file` | string | no | JSON config file with account_id, client_id, client_secret, base_url. Defaults to ZOOM_CONFIG_FILE, ./.zoom.json, or ~/.zoom.json. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `group_limit` | number | no | Maximum groups to inspect. Defaults to 50. |
| `operation_log_limit` | number | no | Maximum admin operation log entries to enumerate (30-day window). Defaults to 300. |
| `max_recording_retention_days` | number | no | Maximum acceptable cloud recording retention in days before warning. Defaults to 120. |

#### `zoom_assess_meeting_security`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `account_id` | string | no | Zoom account ID. Defaults to ZOOM_ACCOUNT_ID or the config file. |
| `token` | string | no | Pre-issued Zoom OAuth access token. Defaults to ZOOM_TOKEN. |
| `client_id` | string | no | Zoom Server-to-Server OAuth client ID. Defaults to ZOOM_CLIENT_ID or the config file. |
| `client_secret` | string | no | Zoom Server-to-Server OAuth client secret. Defaults to ZOOM_CLIENT_SECRET or the config file. |
| `base_url` | string | no | Zoom REST API base URL. Defaults to https://api.zoom.us/v2. |
| `oauth_base_url` | string | no | Zoom OAuth base URL. Defaults to https://zoom.us or https://zoomgov.com based on base_url. |
| `config_file` | string | no | JSON config file with account_id, client_id, client_secret, base_url. Defaults to ZOOM_CONFIG_FILE, ./.zoom.json, or ~/.zoom.json. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `group_limit` | number | no | Maximum groups to inspect for override drift. Defaults to 50. |

#### `zoom_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `account_id` | string | no | Zoom account ID. Defaults to ZOOM_ACCOUNT_ID or the config file. |
| `token` | string | no | Pre-issued Zoom OAuth access token. Defaults to ZOOM_TOKEN. |
| `client_id` | string | no | Zoom Server-to-Server OAuth client ID. Defaults to ZOOM_CLIENT_ID or the config file. |
| `client_secret` | string | no | Zoom Server-to-Server OAuth client secret. Defaults to ZOOM_CLIENT_SECRET or the config file. |
| `base_url` | string | no | Zoom REST API base URL. Defaults to https://api.zoom.us/v2. |
| `oauth_base_url` | string | no | Zoom OAuth base URL. Defaults to https://zoom.us or https://zoomgov.com based on base_url. |
| `config_file` | string | no | JSON config file with account_id, client_id, client_secret, base_url. Defaults to ZOOM_CONFIG_FILE, ./.zoom.json, or ~/.zoom.json. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `output_dir` | string | no | Output root. Defaults to ./export/zoom. |
| `user_limit` | number | no | Maximum users to enumerate before flagging a partial inventory. Defaults to 1000. |
| `max_admins` | number | no | Maximum acceptable distinct admin users before warning. Defaults to 10. |
| `max_session_inactivity_minutes` | number | no | Maximum acceptable inactivity sign-out period in minutes. Defaults to 120. |
| `group_limit` | number | no | Maximum groups to inspect. Defaults to 50. |
| `operation_log_limit` | number | no | Maximum admin operation log entries to enumerate (30-day window). Defaults to 300. |
| `max_recording_retention_days` | number | no | Maximum acceptable cloud recording retention in days before warning. Defaults to 120. |


## Authentication

Supported modes:

- Server-to-Server OAuth client credentials
- Explicit access token

Credential precedence, highest first:

1. Explicit access token
2. Explicit account/client credentials
3. Config file
4. ZOOM_* environment variables

Environment variables: `ZOOM_ACCOUNT_ID`, `ZOOM_CLIENT_ID`, `ZOOM_CLIENT_SECRET`, `ZOOM_ACCESS_TOKEN`, `ZOOM_BASE_URL`

Configuration locations: .zoom.json, .grclanker-zoom.json

Credential and deployment variants: Master or sub-account ID supplied explicitly

Configuration fields: `accountId`, `clientId`, `clientSecret`, `accessToken`, `baseUrl`, `oauthBaseUrl`, `timeoutMs`

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

Credential refresh: POST /oauth/token?grant_type=account_credentials&account_id={accountId} with client Basic authentication.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| oauth-scope | `account:read:admin` | `account-settings`, `account-lock-settings`, `managed-domains`, `trusted-domains` |  |
| oauth-scope | `user:read:list_users:admin` | `current-user`, `users`, `user-settings` |  |
| oauth-scope | `role:read:list_roles:admin` | `roles`, `role-members` |  |
| oauth-scope | `group:read:list_groups:admin` | `groups`, `group-settings`, `group-lock-settings` |  |
| oauth-scope | `report:read:operation_logs:admin` | `operation-logs` |  |
| oauth-scope | `imgroup:read:admin` | `im-groups` |  |
| oauth-scope | `phone:read:admin` | `phone-settings` | Requires Zoom Phone licensing in addition to scope. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `current-user` | HTTP | `GET /v2/users/me` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `account-settings` | HTTP | `GET /v2/accounts/{accountId}/settings` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `account-lock-settings` | HTTP | `GET /v2/accounts/{accountId}/lock_settings` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `users` | HTTP | `GET /v2/users` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `user-settings` | HTTP | `GET /v2/users/{userId}/settings` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `roles` | HTTP | `GET /v2/roles` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `role-members` | HTTP | `GET /v2/roles/{roleId}/members` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `groups` | HTTP | `GET /v2/groups` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `group-settings` | HTTP | `GET /v2/groups/{groupId}/settings` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `group-lock-settings` | HTTP | `GET /v2/groups/{groupId}/lock_settings` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `operation-logs` | HTTP | `GET /v2/report/operationlogs` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `im-groups` | HTTP | `GET /v2/im/groups` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `managed-domains` | HTTP | `GET /v2/accounts/{accountId}/managed_domains` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `trusted-domains` | HTTP | `GET /v2/accounts/{accountId}/trusted_domains` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |
| `phone-settings` | HTTP | `GET /v2/phone/account_settings` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developers.zoom.us/docs/api/) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `current-user` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `current-user` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `current-user` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `account-settings` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `account-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `account-settings` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `account-lock-settings` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `account-lock-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `account-lock-settings` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `users` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `users` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `user-settings` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `user-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `user-settings` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `roles` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `roles` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `roles` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `role-members` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `role-members` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `role-members` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `groups` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `groups` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `groups` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `group-settings` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `group-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `group-settings` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `group-lock-settings` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `group-lock-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `group-lock-settings` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `operation-logs` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `operation-logs` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `operation-logs` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `im-groups` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `im-groups` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `im-groups` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `managed-domains` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `managed-domains` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `managed-domains` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `trusted-domains` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `trusted-domains` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `trusted-domains` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `phone-settings` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `phone-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `phone-settings` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `users`, `role-members`, `groups`, `operation-logs` | `next_page_token`, `total_records` | 300 | caller limit | 500 | total_records is authoritative when returned; otherwise completion requires next_page_token exhaustion. | No next_page_token; Declared total reached; Caller cap; 500-page cap; Repeated token; Empty page with token; Missing or inconsistent total |
| `roles`, `im-groups`, `managed-domains`, `trusted-domains` | None | service default | caller limit | none | The runtime treats these documented single-response lists as complete on success. | Single response |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Zoom Security Inspector | Zoom applies endpoint labels and app-level daily request limits | `Retry-After`, `X-RateLimit-Category`, `X-RateLimit-Remaining` | 429, 500, 502, 503, 504 | Honor Retry-After up to 30 seconds and retry three times with bounded backoff. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | Meeting password enforcement and account lock | ZOOM-MTG-01 | Evaluate the ordered first-match rules for ZOOM-MTG-01 below. |
| 2 | Waiting room enabled by default | ZOOM-MTG-02 | Evaluate the ordered first-match rules for ZOOM-MTG-02 below. |
| 3 | Screen sharing restricted to host only | ZOOM-MTG-03 | Evaluate the ordered first-match rules for ZOOM-MTG-03 below. |
| 4 | Recording consent disclaimer shown to participants | ZOOM-MTG-10 | Evaluate the ordered first-match rules for ZOOM-MTG-10 below. |
| 5 | SSO enforcement for all users | ZOOM-ID-01 | Evaluate the ordered first-match rules for ZOOM-ID-01 below. |
| 6 | Administrative privilege concentration | ZOOM-ID-02, ZOOM-ID-04 | Evaluate the ordered first-match rules for ZOOM-ID-02, ZOOM-ID-04 below. |
| 7 | End-to-end encryption available and default | ZOOM-MTG-05 | Evaluate the ordered first-match rules for ZOOM-MTG-05 below. |
| 8 | Chat encryption enabled | ZOOM-COLLAB-08 | Evaluate the ordered first-match rules for ZOOM-COLLAB-08 below. |
| 9 | In-meeting file transfer restricted | ZOOM-COLLAB-02 | Evaluate the ordered first-match rules for ZOOM-COLLAB-02 below. |
| 10 | Cloud recording auto-delete retention | ZOOM-COLLAB-03 | Evaluate the ordered first-match rules for ZOOM-COLLAB-03 below. |
| 12 | External contacts restricted | ZOOM-COLLAB-01, ZOOM-COLLAB-07 | Evaluate the ordered first-match rules for ZOOM-COLLAB-01, ZOOM-COLLAB-07 below. |
| 13 | Vanity URL configured and secured | ZOOM-ID-07 | Evaluate the ordered first-match rules for ZOOM-ID-07 below. |
| 14 | Managed domains verified | ZOOM-ID-03 | Evaluate the ordered first-match rules for ZOOM-ID-03 below. |
| 15 | IM group restrictions enforced | ZOOM-COLLAB-06 | Evaluate the ordered first-match rules for ZOOM-COLLAB-06 below. |
| 16 | Personal and social sign-in methods blocked | ZOOM-ID-05 | Evaluate the ordered first-match rules for ZOOM-ID-05 below. |
| 17 | Session inactivity timeout enforced | ZOOM-ID-06 | Evaluate the ordered first-match rules for ZOOM-ID-06 below. |
| 18 | Data routing control enabled | ZOOM-MTG-09 | Evaluate the ordered first-match rules for ZOOM-MTG-09 below. |
| 19 | Zoom Phone recording policies enforced | ZOOM-COLLAB-04 | Evaluate the ordered first-match rules for ZOOM-COLLAB-04 below. |
| 20 | Local recording disabled | ZOOM-MTG-04 | Evaluate the ordered first-match rules for ZOOM-MTG-04 below. |
| 22 | Embed password in join link disabled | ZOOM-MTG-06 | Evaluate the ordered first-match rules for ZOOM-MTG-06 below. |
| 23 | Only authenticated users can join meetings | ZOOM-MTG-08 | Evaluate the ordered first-match rules for ZOOM-MTG-08 below. |
| 24 | Admin operation logs readable and recent | ZOOM-COLLAB-05 | Evaluate the ordered first-match rules for ZOOM-COLLAB-05 below. |
| 25 | Personal Meeting ID usage restricted | ZOOM-MTG-07 | Evaluate the ordered first-match rules for ZOOM-MTG-07 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `ZOOM-ID-01` | critical | `zoom_assess_identity` | `users` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any active user has a login type other than 101, pass when every user in a complete non-empty inventory is SSO-only, and warn for unknown login types or partial evidence. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any active user has a login type other than 101, pass when every user in a complete non-empty inventory is SSO-only, and warn for unknown login types or partial evidence. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any active user has a login type other than 101, pass when every user in a complete non-empty inventory is SSO-only, and warn for unknown login types or partial evidence. | The required evidence for SSO enforcement for all users is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-02` | critical | `zoom_assess_identity` | `account-settings`, `roles`, `role-members` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass for two-factor mode all with complete roles or mode role covering every admin role, fail for none or an uncovered admin role, warn for group mode or partial roles, and manual for absent or undocumented settings. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass for two-factor mode all with complete roles or mode role covering every admin role, fail for none or an uncovered admin role, warn for group mode or partial roles, and manual for absent or undocumented settings. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass for two-factor mode all with complete roles or mode role covering every admin role, fail for none or an uncovered admin role, warn for group mode or partial roles, and manual for absent or undocumented settings. | The required evidence for Two-factor authentication for admins is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-03` | high | `zoom_assess_identity` | `managed-domains` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any managed domain is not verified, pass when every domain in a complete non-empty inventory is verified, warn for truncation, and manual when no domain is returned. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any managed domain is not verified, pass when every domain in a complete non-empty inventory is verified, warn for truncation, and manual when no domain is returned. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any managed domain is not verified, pass when every domain in a complete non-empty inventory is verified, warn for truncation, and manual when no domain is returned. | The required evidence for Managed domains verified is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-04` | medium | `zoom_assess_identity` | `roles`, `role-members` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when complete admin-role membership contains at most the configured administrator maximum and warn when it exceeds that maximum or role evidence is partial. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when complete admin-role membership contains at most the configured administrator maximum and warn when it exceeds that maximum or role evidence is partial. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when complete admin-role membership contains at most the configured administrator maximum and warn when it exceeds that maximum or role evidence is partial. | The required evidence for Administrative privilege concentration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-05` | high | `zoom_assess_identity` | `users` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any active user uses a password or social login, pass when every login code in a complete non-empty inventory is documented and neither category, and warn for unknown, other, or partial evidence. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any active user uses a password or social login, pass when every login code in a complete non-empty inventory is documented and neither category, and warn for unknown, other, or partial evidence. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any active user uses a password or social login, pass when every login code in a complete non-empty inventory is documented and neither category, and warn for unknown, other, or partial evidence. | The required evidence for Personal and social sign-in methods blocked is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-06` | medium | `zoom_assess_identity` | `account-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when client or web inactivity sign-out is disabled, warn when either exceeds the configured maximum, pass when both positive values are within it, and manual when neither setting is exposed. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when client or web inactivity sign-out is disabled, warn when either exceeds the configured maximum, pass when both positive values are within it, and manual when neither setting is exposed. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when client or web inactivity sign-out is disabled, warn when either exceeds the configured maximum, pass when both positive values are within it, and manual when neither setting is exposed. | The required evidence for Session inactivity timeout enforced is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-07` | low | `zoom_assess_identity` | None | `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: always return manual because the account settings API exposes no account vanity URL field. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: always return manual because the account settings API exposes no account vanity URL field. | Complete readable evidence satisfies the violation branch, which has first-match precedence: always return manual because the account settings API exposes no account vanity URL field. | The required evidence for Vanity URL configured and secured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-01` | high | `zoom_assess_collaboration_governance` | `trusted-domains` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the non-empty trusted-domain inventory contains no wildcard, fail when any wildcard exists, and manual when the inventory is empty or unreadable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the non-empty trusted-domain inventory contains no wildcard, fail when any wildcard exists, and manual when the inventory is empty or unreadable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the non-empty trusted-domain inventory contains no wildcard, fail when any wildcard exists, and manual when the inventory is empty or unreadable. | The required evidence for Trusted domain restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-02` | high | `zoom_assess_collaboration_governance` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when in-meeting file transfer is enabled, pass when disabled, locked, and no group relaxes it, and warn when disabled but unlocked or group evidence is incomplete. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when in-meeting file transfer is enabled, pass when disabled, locked, and no group relaxes it, and warn when disabled but unlocked or group evidence is incomplete. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when in-meeting file transfer is enabled, pass when disabled, locked, and no group relaxes it, and warn when disabled but unlocked or group evidence is incomplete. | The required evidence for In-meeting file transfer restricted is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-03` | high | `zoom_assess_collaboration_governance` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when cloud recording is enabled without auto-delete, pass when auto-delete days are at or below the configured maximum, locked, and not relaxed by a group, warn for missing days, excessive retention, or incomplete enforcement, and manual when cloud recording is disabled. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when cloud recording is enabled without auto-delete, pass when auto-delete days are at or below the configured maximum, locked, and not relaxed by a group, warn for missing days, excessive retention, or incomplete enforcement, and manual when cloud recording is disabled. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when cloud recording is enabled without auto-delete, pass when auto-delete days are at or below the configured maximum, locked, and not relaxed by a group, warn for missing days, excessive retention, or incomplete enforcement, and manual when cloud recording is disabled. | The required evidence for Cloud recording auto-delete retention is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-04` | medium | `zoom_assess_collaboration_governance` | `phone-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when both auto-call and ad-hoc Zoom Phone recording policies expose enable flags and are locked, warn when either is unlocked, and manual when Phone or either policy is unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when both auto-call and ad-hoc Zoom Phone recording policies expose enable flags and are locked, warn when either is unlocked, and manual when Phone or either policy is unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when both auto-call and ad-hoc Zoom Phone recording policies expose enable flags and are locked, warn when either is unlocked, and manual when Phone or either policy is unavailable. | The required evidence for Zoom Phone recording policies enforced is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-05` | medium | `zoom_assess_collaboration_governance` | `operation-logs` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when a complete admin-operation-log window is non-empty and every row is dated, and warn when the window is empty, truncated, or contains undated rows. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when a complete admin-operation-log window is non-empty and every row is dated, and warn when the window is empty, truncated, or contains undated rows. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when a complete admin-operation-log window is non-empty and every row is dated, and warn when the window is empty, truncated, or contains undated rows. | The required evidence for Admin operation logs readable and recent is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-06` | medium | `zoom_assess_collaboration_governance` | `im-groups` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every IM group in a complete non-empty inventory is normal or restricted without master-account search, warn for shared, unknown, cross-account, or partial groups, and manual when no group exists. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every IM group in a complete non-empty inventory is normal or restricted without master-account search, warn for shared, unknown, cross-account, or partial groups, and manual when no group exists. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every IM group in a complete non-empty inventory is normal or restricted without master-account search, warn for shared, unknown, cross-account, or partial groups, and manual when no group exists. | The required evidence for IM group restrictions enforced is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-07` | medium | `zoom_assess_collaboration_governance` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when add-contact or chat-with-others policy allows anyone, pass when both are organization-restricted, locked, and not relaxed by groups, warn when restrictions are not fully locked, and manual for absent policy fields. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when add-contact or chat-with-others policy allows anyone, pass when both are organization-restricted, locked, and not relaxed by groups, warn when restrictions are not fully locked, and manual for absent policy fields. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when add-contact or chat-with-others policy allows anyone, pass when both are organization-restricted, locked, and not relaxed by groups, warn when restrictions are not fully locked, and manual for absent policy fields. | The required evidence for External contacts restricted is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-08` | medium | `zoom_assess_collaboration_governance` | None | `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: always return manual because the account settings API documents no account-level Team Chat encryption setting. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: always return manual because the account settings API documents no account-level Team Chat encryption setting. | Complete readable evidence satisfies the violation branch, which has first-match precedence: always return manual because the account settings API documents no account-level Team Chat encryption setting. | The required evidence for Chat encryption enabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-01` | critical | `zoom_assess_meeting_security` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when new scheduled meetings do not require a password, pass when the requirement is true, locked, and not relaxed by groups, and warn when compliant but not fully enforced. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when new scheduled meetings do not require a password, pass when the requirement is true, locked, and not relaxed by groups, and warn when compliant but not fully enforced. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when new scheduled meetings do not require a password, pass when the requirement is true, locked, and not relaxed by groups, and warn when compliant but not fully enforced. | The required evidence for Meeting password enforcement and account lock is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-02` | critical | `zoom_assess_meeting_security` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when waiting room is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when waiting room is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when waiting room is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. | The required evidence for Waiting room enabled by default is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-03` | high | `zoom_assess_meeting_security` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when screen sharing is enabled for all participants, pass when disabled or host-only and locked without relaxed groups, warn when compliant but not fully enforced, and manual for absent or undocumented values. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when screen sharing is enabled for all participants, pass when disabled or host-only and locked without relaxed groups, warn when compliant but not fully enforced, and manual for absent or undocumented values. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when screen sharing is enabled for all participants, pass when disabled or host-only and locked without relaxed groups, warn when compliant but not fully enforced, and manual for absent or undocumented values. | The required evidence for Screen sharing restricted to host only is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-04` | high | `zoom_assess_meeting_security` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when local recording is enabled, pass when disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when local recording is enabled, pass when disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when local recording is enabled, pass when disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. | The required evidence for Local recording disabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-05` | high | `zoom_assess_meeting_security` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when end-to-end encrypted meetings are unavailable, pass when available, default, locked, and not relaxed by groups, and warn when available but not default or not fully enforced. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when end-to-end encrypted meetings are unavailable, pass when available, default, locked, and not relaxed by groups, and warn when available but not default or not fully enforced. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when end-to-end encrypted meetings are unavailable, pass when available, default, locked, and not relaxed by groups, and warn when available but not default or not fully enforced. | The required evidence for End-to-end encryption available and default is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-06` | medium | `zoom_assess_meeting_security` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when passcodes are embedded in join links, pass when embedding is disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when passcodes are embedded in join links, pass when embedding is disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when passcodes are embedded in join links, pass when embedding is disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. | The required evidence for Embed password in join link disabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-07` | medium | `zoom_assess_meeting_security` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when PMI is used for scheduled or instant meetings, pass when PMI is disabled or unused and both controls are locked without relaxed groups, and warn when compliant but not fully enforced. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when PMI is used for scheduled or instant meetings, pass when PMI is disabled or unused and both controls are locked without relaxed groups, and warn when compliant but not fully enforced. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when PMI is used for scheduled or instant meetings, pass when PMI is disabled or unused and both controls are locked without relaxed groups, and warn when compliant but not fully enforced. | The required evidence for Personal Meeting ID usage restricted is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-08` | high | `zoom_assess_meeting_security` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when meeting authentication is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when meeting authentication is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when meeting authentication is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. | The required evidence for Only authenticated users can join meetings is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-09` | critical | `zoom_assess_meeting_security` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when custom data-center routing is disabled, pass when enabled with a non-empty region list, locked, and not relaxed by groups, and warn when regions are absent or enforcement is incomplete. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when custom data-center routing is disabled, pass when enabled with a non-empty region list, locked, and not relaxed by groups, and warn when regions are absent or enforcement is incomplete. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when custom data-center routing is disabled, pass when enabled with a non-empty region list, locked, and not relaxed by groups, and warn when regions are absent or enforcement is incomplete. | The required evidence for Data routing control enabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-10` | high | `zoom_assess_meeting_security` | `account-settings`, `account-lock-settings`, `groups`, `group-settings`, `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every participant sees the recording disclaimer, warn for guest-only, unknown, or group-relaxed settings, fail when the legacy disclaimer is explicitly false, and manual when no documented setting is exposed. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every participant sees the recording disclaimer, warn for guest-only, unknown, or group-relaxed settings, fail when the legacy disclaimer is explicitly false, and manual when no documented setting is exposed. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every participant sees the recording disclaimer, warn for guest-only, unknown, or group-relaxed settings, fail when the legacy disclaimer is explicitly false, and manual when no documented setting is exposed. | The required evidence for Recording consent disclaimer shown to participants is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `ZOOM-ID-01` | 1 | fail | `zoom_id_01_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-ID-01` | 2 | manual | any of (`zoom_id_01_required_evidence_readable` equals false; not (`zoom_id_01_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-ID-01` | 3 | warn | any of (`zoom_id_01_warning_matches` equals true; `zoom_id_01_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-ID-01` | 4 | pass | all of (`zoom_id_01_compliant_matches` equals true; `zoom_id_01_required_evidence_readable` equals true; `zoom_id_01_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-ID-01` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-ID-02` | 1 | fail | `zoom_id_02_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-ID-02` | 2 | manual | any of (`zoom_id_02_required_evidence_readable` equals false; not (`zoom_id_02_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-ID-02` | 3 | warn | any of (`zoom_id_02_warning_matches` equals true; `zoom_id_02_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-ID-02` | 4 | pass | all of (`zoom_id_02_compliant_matches` equals true; `zoom_id_02_required_evidence_readable` equals true; `zoom_id_02_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-ID-02` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-ID-03` | 1 | fail | `zoom_id_03_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-ID-03` | 2 | manual | any of (`zoom_id_03_required_evidence_readable` equals false; not (`zoom_id_03_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-ID-03` | 3 | warn | any of (`zoom_id_03_warning_matches` equals true; `zoom_id_03_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-ID-03` | 4 | pass | all of (`zoom_id_03_compliant_matches` equals true; `zoom_id_03_required_evidence_readable` equals true; `zoom_id_03_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-ID-03` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-ID-04` | 1 | manual | any of (`zoom_id_04_required_evidence_readable` equals false; not (`zoom_id_04_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-ID-04` | 2 | warn | any of (`zoom_id_04_warning_matches` equals true; `zoom_id_04_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-ID-04` | 3 | pass | all of (`zoom_id_04_compliant_matches` equals true; `zoom_id_04_required_evidence_readable` equals true; `zoom_id_04_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-ID-04` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-ID-05` | 1 | fail | `zoom_id_05_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-ID-05` | 2 | manual | any of (`zoom_id_05_required_evidence_readable` equals false; not (`zoom_id_05_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-ID-05` | 3 | warn | any of (`zoom_id_05_warning_matches` equals true; `zoom_id_05_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-ID-05` | 4 | pass | all of (`zoom_id_05_compliant_matches` equals true; `zoom_id_05_required_evidence_readable` equals true; `zoom_id_05_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-ID-05` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-ID-06` | 1 | fail | `zoom_id_06_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-ID-06` | 2 | manual | any of (`zoom_id_06_required_evidence_readable` equals false; not (`zoom_id_06_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-ID-06` | 3 | warn | any of (`zoom_id_06_warning_matches` equals true; `zoom_id_06_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-ID-06` | 4 | pass | all of (`zoom_id_06_compliant_matches` equals true; `zoom_id_06_required_evidence_readable` equals true; `zoom_id_06_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-ID-06` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-ID-07` | 1 | manual | any of (`zoom_id_07_required_evidence_readable` equals false; not (`zoom_id_07_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-ID-07` | 2 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-COLLAB-01` | 1 | fail | `zoom_collab_01_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-COLLAB-01` | 2 | manual | any of (`zoom_collab_01_required_evidence_readable` equals false; not (`zoom_collab_01_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-COLLAB-01` | 3 | pass | all of (`zoom_collab_01_compliant_matches` equals true; `zoom_collab_01_required_evidence_readable` equals true; `zoom_collab_01_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-COLLAB-01` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-COLLAB-02` | 1 | fail | `zoom_collab_02_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-COLLAB-02` | 2 | manual | any of (`zoom_collab_02_required_evidence_readable` equals false; not (`zoom_collab_02_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-COLLAB-02` | 3 | warn | any of (`zoom_collab_02_warning_matches` equals true; `zoom_collab_02_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-COLLAB-02` | 4 | pass | all of (`zoom_collab_02_compliant_matches` equals true; `zoom_collab_02_required_evidence_readable` equals true; `zoom_collab_02_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-COLLAB-02` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-COLLAB-03` | 1 | fail | `zoom_collab_03_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-COLLAB-03` | 2 | manual | any of (`zoom_collab_03_required_evidence_readable` equals false; not (`zoom_collab_03_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-COLLAB-03` | 3 | warn | any of (`zoom_collab_03_warning_matches` equals true; `zoom_collab_03_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-COLLAB-03` | 4 | pass | all of (`zoom_collab_03_compliant_matches` equals true; `zoom_collab_03_required_evidence_readable` equals true; `zoom_collab_03_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-COLLAB-03` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-COLLAB-04` | 1 | manual | any of (`zoom_collab_04_required_evidence_readable` equals false; not (`zoom_collab_04_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-COLLAB-04` | 2 | warn | any of (`zoom_collab_04_warning_matches` equals true; `zoom_collab_04_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-COLLAB-04` | 3 | pass | all of (`zoom_collab_04_compliant_matches` equals true; `zoom_collab_04_required_evidence_readable` equals true; `zoom_collab_04_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-COLLAB-04` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-COLLAB-05` | 1 | manual | any of (`zoom_collab_05_required_evidence_readable` equals false; not (`zoom_collab_05_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-COLLAB-05` | 2 | warn | any of (`zoom_collab_05_warning_matches` equals true; `zoom_collab_05_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-COLLAB-05` | 3 | pass | all of (`zoom_collab_05_compliant_matches` equals true; `zoom_collab_05_required_evidence_readable` equals true; `zoom_collab_05_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-COLLAB-05` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-COLLAB-06` | 1 | manual | any of (`zoom_collab_06_required_evidence_readable` equals false; not (`zoom_collab_06_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-COLLAB-06` | 2 | warn | any of (`zoom_collab_06_warning_matches` equals true; `zoom_collab_06_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-COLLAB-06` | 3 | pass | all of (`zoom_collab_06_compliant_matches` equals true; `zoom_collab_06_required_evidence_readable` equals true; `zoom_collab_06_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-COLLAB-06` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-COLLAB-07` | 1 | fail | `zoom_collab_07_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-COLLAB-07` | 2 | manual | any of (`zoom_collab_07_required_evidence_readable` equals false; not (`zoom_collab_07_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-COLLAB-07` | 3 | warn | any of (`zoom_collab_07_warning_matches` equals true; `zoom_collab_07_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-COLLAB-07` | 4 | pass | all of (`zoom_collab_07_compliant_matches` equals true; `zoom_collab_07_required_evidence_readable` equals true; `zoom_collab_07_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-COLLAB-07` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-COLLAB-08` | 1 | manual | any of (`zoom_collab_08_required_evidence_readable` equals false; not (`zoom_collab_08_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-COLLAB-08` | 2 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-MTG-01` | 1 | fail | `zoom_mtg_01_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-MTG-01` | 2 | manual | any of (`zoom_mtg_01_required_evidence_readable` equals false; not (`zoom_mtg_01_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-MTG-01` | 3 | warn | any of (`zoom_mtg_01_warning_matches` equals true; `zoom_mtg_01_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-MTG-01` | 4 | pass | all of (`zoom_mtg_01_compliant_matches` equals true; `zoom_mtg_01_required_evidence_readable` equals true; `zoom_mtg_01_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-MTG-01` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-MTG-02` | 1 | fail | `zoom_mtg_02_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-MTG-02` | 2 | manual | any of (`zoom_mtg_02_required_evidence_readable` equals false; not (`zoom_mtg_02_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-MTG-02` | 3 | warn | any of (`zoom_mtg_02_warning_matches` equals true; `zoom_mtg_02_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-MTG-02` | 4 | pass | all of (`zoom_mtg_02_compliant_matches` equals true; `zoom_mtg_02_required_evidence_readable` equals true; `zoom_mtg_02_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-MTG-02` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-MTG-03` | 1 | fail | `zoom_mtg_03_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-MTG-03` | 2 | manual | any of (`zoom_mtg_03_required_evidence_readable` equals false; not (`zoom_mtg_03_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-MTG-03` | 3 | warn | any of (`zoom_mtg_03_warning_matches` equals true; `zoom_mtg_03_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-MTG-03` | 4 | pass | all of (`zoom_mtg_03_compliant_matches` equals true; `zoom_mtg_03_required_evidence_readable` equals true; `zoom_mtg_03_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-MTG-03` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-MTG-04` | 1 | fail | `zoom_mtg_04_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-MTG-04` | 2 | manual | any of (`zoom_mtg_04_required_evidence_readable` equals false; not (`zoom_mtg_04_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-MTG-04` | 3 | warn | any of (`zoom_mtg_04_warning_matches` equals true; `zoom_mtg_04_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-MTG-04` | 4 | pass | all of (`zoom_mtg_04_compliant_matches` equals true; `zoom_mtg_04_required_evidence_readable` equals true; `zoom_mtg_04_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-MTG-04` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-MTG-05` | 1 | fail | `zoom_mtg_05_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-MTG-05` | 2 | manual | any of (`zoom_mtg_05_required_evidence_readable` equals false; not (`zoom_mtg_05_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-MTG-05` | 3 | warn | any of (`zoom_mtg_05_warning_matches` equals true; `zoom_mtg_05_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-MTG-05` | 4 | pass | all of (`zoom_mtg_05_compliant_matches` equals true; `zoom_mtg_05_required_evidence_readable` equals true; `zoom_mtg_05_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-MTG-05` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-MTG-06` | 1 | fail | `zoom_mtg_06_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-MTG-06` | 2 | manual | any of (`zoom_mtg_06_required_evidence_readable` equals false; not (`zoom_mtg_06_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-MTG-06` | 3 | warn | any of (`zoom_mtg_06_warning_matches` equals true; `zoom_mtg_06_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-MTG-06` | 4 | pass | all of (`zoom_mtg_06_compliant_matches` equals true; `zoom_mtg_06_required_evidence_readable` equals true; `zoom_mtg_06_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-MTG-06` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-MTG-07` | 1 | fail | `zoom_mtg_07_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-MTG-07` | 2 | manual | any of (`zoom_mtg_07_required_evidence_readable` equals false; not (`zoom_mtg_07_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-MTG-07` | 3 | warn | any of (`zoom_mtg_07_warning_matches` equals true; `zoom_mtg_07_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-MTG-07` | 4 | pass | all of (`zoom_mtg_07_compliant_matches` equals true; `zoom_mtg_07_required_evidence_readable` equals true; `zoom_mtg_07_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-MTG-07` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-MTG-08` | 1 | fail | `zoom_mtg_08_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-MTG-08` | 2 | manual | any of (`zoom_mtg_08_required_evidence_readable` equals false; not (`zoom_mtg_08_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-MTG-08` | 3 | warn | any of (`zoom_mtg_08_warning_matches` equals true; `zoom_mtg_08_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-MTG-08` | 4 | pass | all of (`zoom_mtg_08_compliant_matches` equals true; `zoom_mtg_08_required_evidence_readable` equals true; `zoom_mtg_08_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-MTG-08` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-MTG-09` | 1 | fail | `zoom_mtg_09_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-MTG-09` | 2 | manual | any of (`zoom_mtg_09_required_evidence_readable` equals false; not (`zoom_mtg_09_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-MTG-09` | 3 | warn | any of (`zoom_mtg_09_warning_matches` equals true; `zoom_mtg_09_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-MTG-09` | 4 | pass | all of (`zoom_mtg_09_compliant_matches` equals true; `zoom_mtg_09_required_evidence_readable` equals true; `zoom_mtg_09_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-MTG-09` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZOOM-MTG-10` | 1 | fail | `zoom_mtg_10_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZOOM-MTG-10` | 2 | manual | any of (`zoom_mtg_10_required_evidence_readable` equals false; not (`zoom_mtg_10_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZOOM-MTG-10` | 3 | warn | any of (`zoom_mtg_10_warning_matches` equals true; `zoom_mtg_10_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZOOM-MTG-10` | 4 | pass | all of (`zoom_mtg_10_compliant_matches` equals true; `zoom_mtg_10_required_evidence_readable` equals true; `zoom_mtg_10_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZOOM-MTG-10` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `ZOOM-ID-01` | `zoom_id_01_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-ID-01 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-ID-01` | `zoom_id_01_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-ID-01` | `zoom_id_01_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any active user has a login type other than 101, pass when every user in a complete non-empty inventory is SSO-only, and warn for unknown login types or partial evidence. |
| `ZOOM-ID-01` | `zoom_id_01_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any active user has a login type other than 101, pass when every user in a complete non-empty inventory is SSO-only, and warn for unknown login types or partial evidence. |
| `ZOOM-ID-01` | `zoom_id_01_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any active user has a login type other than 101, pass when every user in a complete non-empty inventory is SSO-only, and warn for unknown login types or partial evidence. |
| `ZOOM-ID-02` | `zoom_id_02_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-ID-02 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-ID-02` | `zoom_id_02_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-ID-02` | `zoom_id_02_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass for two-factor mode all with complete roles or mode role covering every admin role, fail for none or an uncovered admin role, warn for group mode or partial roles, and manual for absent or undocumented settings. |
| `ZOOM-ID-02` | `zoom_id_02_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass for two-factor mode all with complete roles or mode role covering every admin role, fail for none or an uncovered admin role, warn for group mode or partial roles, and manual for absent or undocumented settings. |
| `ZOOM-ID-02` | `zoom_id_02_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass for two-factor mode all with complete roles or mode role covering every admin role, fail for none or an uncovered admin role, warn for group mode or partial roles, and manual for absent or undocumented settings. |
| `ZOOM-ID-03` | `zoom_id_03_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-ID-03 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-ID-03` | `zoom_id_03_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-ID-03` | `zoom_id_03_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any managed domain is not verified, pass when every domain in a complete non-empty inventory is verified, warn for truncation, and manual when no domain is returned. |
| `ZOOM-ID-03` | `zoom_id_03_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any managed domain is not verified, pass when every domain in a complete non-empty inventory is verified, warn for truncation, and manual when no domain is returned. |
| `ZOOM-ID-03` | `zoom_id_03_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any managed domain is not verified, pass when every domain in a complete non-empty inventory is verified, warn for truncation, and manual when no domain is returned. |
| `ZOOM-ID-04` | `zoom_id_04_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-ID-04 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-ID-04` | `zoom_id_04_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-ID-04` | `zoom_id_04_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when complete admin-role membership contains at most the configured administrator maximum and warn when it exceeds that maximum or role evidence is partial. |
| `ZOOM-ID-04` | `zoom_id_04_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when complete admin-role membership contains at most the configured administrator maximum and warn when it exceeds that maximum or role evidence is partial. |
| `ZOOM-ID-04` | `zoom_id_04_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when complete admin-role membership contains at most the configured administrator maximum and warn when it exceeds that maximum or role evidence is partial. |
| `ZOOM-ID-05` | `zoom_id_05_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-ID-05 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-ID-05` | `zoom_id_05_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-ID-05` | `zoom_id_05_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any active user uses a password or social login, pass when every login code in a complete non-empty inventory is documented and neither category, and warn for unknown, other, or partial evidence. |
| `ZOOM-ID-05` | `zoom_id_05_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any active user uses a password or social login, pass when every login code in a complete non-empty inventory is documented and neither category, and warn for unknown, other, or partial evidence. |
| `ZOOM-ID-05` | `zoom_id_05_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any active user uses a password or social login, pass when every login code in a complete non-empty inventory is documented and neither category, and warn for unknown, other, or partial evidence. |
| `ZOOM-ID-06` | `zoom_id_06_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-ID-06 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-ID-06` | `zoom_id_06_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-ID-06` | `zoom_id_06_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when client or web inactivity sign-out is disabled, warn when either exceeds the configured maximum, pass when both positive values are within it, and manual when neither setting is exposed. |
| `ZOOM-ID-06` | `zoom_id_06_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when client or web inactivity sign-out is disabled, warn when either exceeds the configured maximum, pass when both positive values are within it, and manual when neither setting is exposed. |
| `ZOOM-ID-06` | `zoom_id_06_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when client or web inactivity sign-out is disabled, warn when either exceeds the configured maximum, pass when both positive values are within it, and manual when neither setting is exposed. |
| `ZOOM-ID-07` | `zoom_id_07_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-ID-07 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-ID-07` | `zoom_id_07_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-ID-07` | `zoom_id_07_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: always return manual because the account settings API exposes no account vanity URL field. |
| `ZOOM-ID-07` | `zoom_id_07_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: always return manual because the account settings API exposes no account vanity URL field. |
| `ZOOM-ID-07` | `zoom_id_07_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: always return manual because the account settings API exposes no account vanity URL field. |
| `ZOOM-COLLAB-01` | `zoom_collab_01_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-COLLAB-01 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-COLLAB-01` | `zoom_collab_01_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-COLLAB-01` | `zoom_collab_01_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the non-empty trusted-domain inventory contains no wildcard, fail when any wildcard exists, and manual when the inventory is empty or unreadable. |
| `ZOOM-COLLAB-01` | `zoom_collab_01_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the non-empty trusted-domain inventory contains no wildcard, fail when any wildcard exists, and manual when the inventory is empty or unreadable. |
| `ZOOM-COLLAB-01` | `zoom_collab_01_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the non-empty trusted-domain inventory contains no wildcard, fail when any wildcard exists, and manual when the inventory is empty or unreadable. |
| `ZOOM-COLLAB-02` | `zoom_collab_02_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-COLLAB-02 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-COLLAB-02` | `zoom_collab_02_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-COLLAB-02` | `zoom_collab_02_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when in-meeting file transfer is enabled, pass when disabled, locked, and no group relaxes it, and warn when disabled but unlocked or group evidence is incomplete. |
| `ZOOM-COLLAB-02` | `zoom_collab_02_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when in-meeting file transfer is enabled, pass when disabled, locked, and no group relaxes it, and warn when disabled but unlocked or group evidence is incomplete. |
| `ZOOM-COLLAB-02` | `zoom_collab_02_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when in-meeting file transfer is enabled, pass when disabled, locked, and no group relaxes it, and warn when disabled but unlocked or group evidence is incomplete. |
| `ZOOM-COLLAB-03` | `zoom_collab_03_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-COLLAB-03 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-COLLAB-03` | `zoom_collab_03_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-COLLAB-03` | `zoom_collab_03_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when cloud recording is enabled without auto-delete, pass when auto-delete days are at or below the configured maximum, locked, and not relaxed by a group, warn for missing days, excessive retention, or incomplete enforcement, and manual when cloud recording is disabled. |
| `ZOOM-COLLAB-03` | `zoom_collab_03_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when cloud recording is enabled without auto-delete, pass when auto-delete days are at or below the configured maximum, locked, and not relaxed by a group, warn for missing days, excessive retention, or incomplete enforcement, and manual when cloud recording is disabled. |
| `ZOOM-COLLAB-03` | `zoom_collab_03_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when cloud recording is enabled without auto-delete, pass when auto-delete days are at or below the configured maximum, locked, and not relaxed by a group, warn for missing days, excessive retention, or incomplete enforcement, and manual when cloud recording is disabled. |
| `ZOOM-COLLAB-04` | `zoom_collab_04_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-COLLAB-04 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-COLLAB-04` | `zoom_collab_04_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-COLLAB-04` | `zoom_collab_04_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when both auto-call and ad-hoc Zoom Phone recording policies expose enable flags and are locked, warn when either is unlocked, and manual when Phone or either policy is unavailable. |
| `ZOOM-COLLAB-04` | `zoom_collab_04_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when both auto-call and ad-hoc Zoom Phone recording policies expose enable flags and are locked, warn when either is unlocked, and manual when Phone or either policy is unavailable. |
| `ZOOM-COLLAB-04` | `zoom_collab_04_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when both auto-call and ad-hoc Zoom Phone recording policies expose enable flags and are locked, warn when either is unlocked, and manual when Phone or either policy is unavailable. |
| `ZOOM-COLLAB-05` | `zoom_collab_05_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-COLLAB-05 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-COLLAB-05` | `zoom_collab_05_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-COLLAB-05` | `zoom_collab_05_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when a complete admin-operation-log window is non-empty and every row is dated, and warn when the window is empty, truncated, or contains undated rows. |
| `ZOOM-COLLAB-05` | `zoom_collab_05_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when a complete admin-operation-log window is non-empty and every row is dated, and warn when the window is empty, truncated, or contains undated rows. |
| `ZOOM-COLLAB-05` | `zoom_collab_05_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when a complete admin-operation-log window is non-empty and every row is dated, and warn when the window is empty, truncated, or contains undated rows. |
| `ZOOM-COLLAB-06` | `zoom_collab_06_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-COLLAB-06 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-COLLAB-06` | `zoom_collab_06_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-COLLAB-06` | `zoom_collab_06_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when every IM group in a complete non-empty inventory is normal or restricted without master-account search, warn for shared, unknown, cross-account, or partial groups, and manual when no group exists. |
| `ZOOM-COLLAB-06` | `zoom_collab_06_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when every IM group in a complete non-empty inventory is normal or restricted without master-account search, warn for shared, unknown, cross-account, or partial groups, and manual when no group exists. |
| `ZOOM-COLLAB-06` | `zoom_collab_06_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when every IM group in a complete non-empty inventory is normal or restricted without master-account search, warn for shared, unknown, cross-account, or partial groups, and manual when no group exists. |
| `ZOOM-COLLAB-07` | `zoom_collab_07_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-COLLAB-07 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-COLLAB-07` | `zoom_collab_07_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-COLLAB-07` | `zoom_collab_07_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when add-contact or chat-with-others policy allows anyone, pass when both are organization-restricted, locked, and not relaxed by groups, warn when restrictions are not fully locked, and manual for absent policy fields. |
| `ZOOM-COLLAB-07` | `zoom_collab_07_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when add-contact or chat-with-others policy allows anyone, pass when both are organization-restricted, locked, and not relaxed by groups, warn when restrictions are not fully locked, and manual for absent policy fields. |
| `ZOOM-COLLAB-07` | `zoom_collab_07_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when add-contact or chat-with-others policy allows anyone, pass when both are organization-restricted, locked, and not relaxed by groups, warn when restrictions are not fully locked, and manual for absent policy fields. |
| `ZOOM-COLLAB-08` | `zoom_collab_08_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-COLLAB-08 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-COLLAB-08` | `zoom_collab_08_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-COLLAB-08` | `zoom_collab_08_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: always return manual because the account settings API documents no account-level Team Chat encryption setting. |
| `ZOOM-COLLAB-08` | `zoom_collab_08_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: always return manual because the account settings API documents no account-level Team Chat encryption setting. |
| `ZOOM-COLLAB-08` | `zoom_collab_08_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: always return manual because the account settings API documents no account-level Team Chat encryption setting. |
| `ZOOM-MTG-01` | `zoom_mtg_01_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-MTG-01 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-MTG-01` | `zoom_mtg_01_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-MTG-01` | `zoom_mtg_01_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when new scheduled meetings do not require a password, pass when the requirement is true, locked, and not relaxed by groups, and warn when compliant but not fully enforced. |
| `ZOOM-MTG-01` | `zoom_mtg_01_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when new scheduled meetings do not require a password, pass when the requirement is true, locked, and not relaxed by groups, and warn when compliant but not fully enforced. |
| `ZOOM-MTG-01` | `zoom_mtg_01_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when new scheduled meetings do not require a password, pass when the requirement is true, locked, and not relaxed by groups, and warn when compliant but not fully enforced. |
| `ZOOM-MTG-02` | `zoom_mtg_02_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-MTG-02 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-MTG-02` | `zoom_mtg_02_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-MTG-02` | `zoom_mtg_02_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when waiting room is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. |
| `ZOOM-MTG-02` | `zoom_mtg_02_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when waiting room is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. |
| `ZOOM-MTG-02` | `zoom_mtg_02_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when waiting room is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. |
| `ZOOM-MTG-03` | `zoom_mtg_03_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-MTG-03 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-MTG-03` | `zoom_mtg_03_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-MTG-03` | `zoom_mtg_03_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when screen sharing is enabled for all participants, pass when disabled or host-only and locked without relaxed groups, warn when compliant but not fully enforced, and manual for absent or undocumented values. |
| `ZOOM-MTG-03` | `zoom_mtg_03_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when screen sharing is enabled for all participants, pass when disabled or host-only and locked without relaxed groups, warn when compliant but not fully enforced, and manual for absent or undocumented values. |
| `ZOOM-MTG-03` | `zoom_mtg_03_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when screen sharing is enabled for all participants, pass when disabled or host-only and locked without relaxed groups, warn when compliant but not fully enforced, and manual for absent or undocumented values. |
| `ZOOM-MTG-04` | `zoom_mtg_04_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-MTG-04 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-MTG-04` | `zoom_mtg_04_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-MTG-04` | `zoom_mtg_04_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when local recording is enabled, pass when disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. |
| `ZOOM-MTG-04` | `zoom_mtg_04_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when local recording is enabled, pass when disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. |
| `ZOOM-MTG-04` | `zoom_mtg_04_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when local recording is enabled, pass when disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. |
| `ZOOM-MTG-05` | `zoom_mtg_05_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-MTG-05 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-MTG-05` | `zoom_mtg_05_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-MTG-05` | `zoom_mtg_05_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when end-to-end encrypted meetings are unavailable, pass when available, default, locked, and not relaxed by groups, and warn when available but not default or not fully enforced. |
| `ZOOM-MTG-05` | `zoom_mtg_05_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when end-to-end encrypted meetings are unavailable, pass when available, default, locked, and not relaxed by groups, and warn when available but not default or not fully enforced. |
| `ZOOM-MTG-05` | `zoom_mtg_05_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when end-to-end encrypted meetings are unavailable, pass when available, default, locked, and not relaxed by groups, and warn when available but not default or not fully enforced. |
| `ZOOM-MTG-06` | `zoom_mtg_06_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-MTG-06 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-MTG-06` | `zoom_mtg_06_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-MTG-06` | `zoom_mtg_06_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when passcodes are embedded in join links, pass when embedding is disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. |
| `ZOOM-MTG-06` | `zoom_mtg_06_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when passcodes are embedded in join links, pass when embedding is disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. |
| `ZOOM-MTG-06` | `zoom_mtg_06_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when passcodes are embedded in join links, pass when embedding is disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. |
| `ZOOM-MTG-07` | `zoom_mtg_07_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-MTG-07 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-MTG-07` | `zoom_mtg_07_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-MTG-07` | `zoom_mtg_07_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when PMI is used for scheduled or instant meetings, pass when PMI is disabled or unused and both controls are locked without relaxed groups, and warn when compliant but not fully enforced. |
| `ZOOM-MTG-07` | `zoom_mtg_07_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when PMI is used for scheduled or instant meetings, pass when PMI is disabled or unused and both controls are locked without relaxed groups, and warn when compliant but not fully enforced. |
| `ZOOM-MTG-07` | `zoom_mtg_07_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when PMI is used for scheduled or instant meetings, pass when PMI is disabled or unused and both controls are locked without relaxed groups, and warn when compliant but not fully enforced. |
| `ZOOM-MTG-08` | `zoom_mtg_08_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-MTG-08 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-MTG-08` | `zoom_mtg_08_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-MTG-08` | `zoom_mtg_08_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when meeting authentication is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. |
| `ZOOM-MTG-08` | `zoom_mtg_08_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when meeting authentication is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. |
| `ZOOM-MTG-08` | `zoom_mtg_08_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when meeting authentication is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. |
| `ZOOM-MTG-09` | `zoom_mtg_09_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-MTG-09 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-MTG-09` | `zoom_mtg_09_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-MTG-09` | `zoom_mtg_09_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when custom data-center routing is disabled, pass when enabled with a non-empty region list, locked, and not relaxed by groups, and warn when regions are absent or enforcement is incomplete. |
| `ZOOM-MTG-09` | `zoom_mtg_09_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when custom data-center routing is disabled, pass when enabled with a non-empty region list, locked, and not relaxed by groups, and warn when regions are absent or enforcement is incomplete. |
| `ZOOM-MTG-09` | `zoom_mtg_09_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when custom data-center routing is disabled, pass when enabled with a non-empty region list, locked, and not relaxed by groups, and warn when regions are absent or enforcement is incomplete. |
| `ZOOM-MTG-10` | `zoom_mtg_10_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZOOM-MTG-10 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZOOM-MTG-10` | `zoom_mtg_10_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZOOM-MTG-10` | `zoom_mtg_10_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when every participant sees the recording disclaimer, warn for guest-only, unknown, or group-relaxed settings, fail when the legacy disclaimer is explicitly false, and manual when no documented setting is exposed. |
| `ZOOM-MTG-10` | `zoom_mtg_10_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when every participant sees the recording disclaimer, warn for guest-only, unknown, or group-relaxed settings, fail when the legacy disclaimer is explicitly false, and manual when no documented setting is exposed. |
| `ZOOM-MTG-10` | `zoom_mtg_10_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when every participant sees the recording disclaimer, warn for guest-only, unknown, or group-relaxed settings, fail when the legacy disclaimer is explicitly false, and manual when no documented setting is exposed. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `ZOOM-ID-01` | `requiredEvidenceReadable` | true |
| `ZOOM-ID-01` | `requiredEvidenceComplete` | true |
| `ZOOM-ID-02` | `requiredEvidenceReadable` | true |
| `ZOOM-ID-02` | `requiredEvidenceComplete` | true |
| `ZOOM-ID-03` | `requiredEvidenceReadable` | true |
| `ZOOM-ID-03` | `requiredEvidenceComplete` | true |
| `ZOOM-ID-04` | `requiredEvidenceReadable` | true |
| `ZOOM-ID-04` | `requiredEvidenceComplete` | true |
| `ZOOM-ID-05` | `requiredEvidenceReadable` | true |
| `ZOOM-ID-05` | `requiredEvidenceComplete` | true |
| `ZOOM-ID-06` | `requiredEvidenceReadable` | true |
| `ZOOM-ID-06` | `requiredEvidenceComplete` | true |
| `ZOOM-ID-07` | `requiredEvidenceReadable` | true |
| `ZOOM-ID-07` | `requiredEvidenceComplete` | true |
| `ZOOM-COLLAB-01` | `requiredEvidenceReadable` | true |
| `ZOOM-COLLAB-01` | `requiredEvidenceComplete` | true |
| `ZOOM-COLLAB-02` | `requiredEvidenceReadable` | true |
| `ZOOM-COLLAB-02` | `requiredEvidenceComplete` | true |
| `ZOOM-COLLAB-03` | `requiredEvidenceReadable` | true |
| `ZOOM-COLLAB-03` | `requiredEvidenceComplete` | true |
| `ZOOM-COLLAB-04` | `requiredEvidenceReadable` | true |
| `ZOOM-COLLAB-04` | `requiredEvidenceComplete` | true |
| `ZOOM-COLLAB-05` | `requiredEvidenceReadable` | true |
| `ZOOM-COLLAB-05` | `requiredEvidenceComplete` | true |
| `ZOOM-COLLAB-06` | `requiredEvidenceReadable` | true |
| `ZOOM-COLLAB-06` | `requiredEvidenceComplete` | true |
| `ZOOM-COLLAB-07` | `requiredEvidenceReadable` | true |
| `ZOOM-COLLAB-07` | `requiredEvidenceComplete` | true |
| `ZOOM-COLLAB-08` | `requiredEvidenceReadable` | true |
| `ZOOM-COLLAB-08` | `requiredEvidenceComplete` | true |
| `ZOOM-MTG-01` | `requiredEvidenceReadable` | true |
| `ZOOM-MTG-01` | `requiredEvidenceComplete` | true |
| `ZOOM-MTG-02` | `requiredEvidenceReadable` | true |
| `ZOOM-MTG-02` | `requiredEvidenceComplete` | true |
| `ZOOM-MTG-03` | `requiredEvidenceReadable` | true |
| `ZOOM-MTG-03` | `requiredEvidenceComplete` | true |
| `ZOOM-MTG-04` | `requiredEvidenceReadable` | true |
| `ZOOM-MTG-04` | `requiredEvidenceComplete` | true |
| `ZOOM-MTG-05` | `requiredEvidenceReadable` | true |
| `ZOOM-MTG-05` | `requiredEvidenceComplete` | true |
| `ZOOM-MTG-06` | `requiredEvidenceReadable` | true |
| `ZOOM-MTG-06` | `requiredEvidenceComplete` | true |
| `ZOOM-MTG-07` | `requiredEvidenceReadable` | true |
| `ZOOM-MTG-07` | `requiredEvidenceComplete` | true |
| `ZOOM-MTG-08` | `requiredEvidenceReadable` | true |
| `ZOOM-MTG-08` | `requiredEvidenceComplete` | true |
| `ZOOM-MTG-09` | `requiredEvidenceReadable` | true |
| `ZOOM-MTG-09` | `requiredEvidenceComplete` | true |
| `ZOOM-MTG-10` | `requiredEvidenceReadable` | true |
| `ZOOM-MTG-10` | `requiredEvidenceComplete` | true |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `ZOOM-ID-01` | compliant | All required source reads are complete and this derivation returns pass: return fail when any active user has a login type other than 101, pass when every user in a complete non-empty inventory is SSO-only, and warn for unknown login types or partial evidence. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-ID-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any active user has a login type other than 101, pass when every user in a complete non-empty inventory is SSO-only, and warn for unknown login types or partial evidence. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-ID-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-ID-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-ID-02` | compliant | All required source reads are complete and this derivation returns pass: return pass for two-factor mode all with complete roles or mode role covering every admin role, fail for none or an uncovered admin role, warn for group mode or partial roles, and manual for absent or undocumented settings. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-ID-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass for two-factor mode all with complete roles or mode role covering every admin role, fail for none or an uncovered admin role, warn for group mode or partial roles, and manual for absent or undocumented settings. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-ID-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-ID-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-ID-03` | compliant | All required source reads are complete and this derivation returns pass: return fail when any managed domain is not verified, pass when every domain in a complete non-empty inventory is verified, warn for truncation, and manual when no domain is returned. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-ID-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any managed domain is not verified, pass when every domain in a complete non-empty inventory is verified, warn for truncation, and manual when no domain is returned. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-ID-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-ID-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-ID-04` | compliant | All required source reads are complete and this derivation returns pass: return pass when complete admin-role membership contains at most the configured administrator maximum and warn when it exceeds that maximum or role evidence is partial. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-ID-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when complete admin-role membership contains at most the configured administrator maximum and warn when it exceeds that maximum or role evidence is partial. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-ID-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-ID-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-ID-05` | compliant | All required source reads are complete and this derivation returns pass: return fail when any active user uses a password or social login, pass when every login code in a complete non-empty inventory is documented and neither category, and warn for unknown, other, or partial evidence. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-ID-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any active user uses a password or social login, pass when every login code in a complete non-empty inventory is documented and neither category, and warn for unknown, other, or partial evidence. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-ID-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-ID-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-ID-06` | compliant | All required source reads are complete and this derivation returns pass: return fail when client or web inactivity sign-out is disabled, warn when either exceeds the configured maximum, pass when both positive values are within it, and manual when neither setting is exposed. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-ID-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when client or web inactivity sign-out is disabled, warn when either exceeds the configured maximum, pass when both positive values are within it, and manual when neither setting is exposed. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-ID-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-ID-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-ID-07` | compliant | All required source reads are complete and this derivation returns pass: always return manual because the account settings API exposes no account vanity URL field. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-ID-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: always return manual because the account settings API exposes no account vanity URL field. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-ID-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-ID-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-COLLAB-01` | compliant | All required source reads are complete and this derivation returns pass: return pass when the non-empty trusted-domain inventory contains no wildcard, fail when any wildcard exists, and manual when the inventory is empty or unreadable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-COLLAB-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the non-empty trusted-domain inventory contains no wildcard, fail when any wildcard exists, and manual when the inventory is empty or unreadable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-COLLAB-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-COLLAB-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-COLLAB-02` | compliant | All required source reads are complete and this derivation returns pass: return fail when in-meeting file transfer is enabled, pass when disabled, locked, and no group relaxes it, and warn when disabled but unlocked or group evidence is incomplete. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-COLLAB-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when in-meeting file transfer is enabled, pass when disabled, locked, and no group relaxes it, and warn when disabled but unlocked or group evidence is incomplete. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-COLLAB-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-COLLAB-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-COLLAB-03` | compliant | All required source reads are complete and this derivation returns pass: return fail when cloud recording is enabled without auto-delete, pass when auto-delete days are at or below the configured maximum, locked, and not relaxed by a group, warn for missing days, excessive retention, or incomplete enforcement, and manual when cloud recording is disabled. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-COLLAB-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when cloud recording is enabled without auto-delete, pass when auto-delete days are at or below the configured maximum, locked, and not relaxed by a group, warn for missing days, excessive retention, or incomplete enforcement, and manual when cloud recording is disabled. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-COLLAB-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-COLLAB-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-COLLAB-04` | compliant | All required source reads are complete and this derivation returns pass: return pass when both auto-call and ad-hoc Zoom Phone recording policies expose enable flags and are locked, warn when either is unlocked, and manual when Phone or either policy is unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-COLLAB-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when both auto-call and ad-hoc Zoom Phone recording policies expose enable flags and are locked, warn when either is unlocked, and manual when Phone or either policy is unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-COLLAB-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-COLLAB-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-COLLAB-05` | compliant | All required source reads are complete and this derivation returns pass: return pass when a complete admin-operation-log window is non-empty and every row is dated, and warn when the window is empty, truncated, or contains undated rows. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-COLLAB-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when a complete admin-operation-log window is non-empty and every row is dated, and warn when the window is empty, truncated, or contains undated rows. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-COLLAB-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-COLLAB-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-COLLAB-06` | compliant | All required source reads are complete and this derivation returns pass: return pass when every IM group in a complete non-empty inventory is normal or restricted without master-account search, warn for shared, unknown, cross-account, or partial groups, and manual when no group exists. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-COLLAB-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every IM group in a complete non-empty inventory is normal or restricted without master-account search, warn for shared, unknown, cross-account, or partial groups, and manual when no group exists. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-COLLAB-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-COLLAB-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-COLLAB-07` | compliant | All required source reads are complete and this derivation returns pass: return fail when add-contact or chat-with-others policy allows anyone, pass when both are organization-restricted, locked, and not relaxed by groups, warn when restrictions are not fully locked, and manual for absent policy fields. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-COLLAB-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when add-contact or chat-with-others policy allows anyone, pass when both are organization-restricted, locked, and not relaxed by groups, warn when restrictions are not fully locked, and manual for absent policy fields. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-COLLAB-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-COLLAB-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-COLLAB-08` | compliant | All required source reads are complete and this derivation returns pass: always return manual because the account settings API documents no account-level Team Chat encryption setting. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-COLLAB-08` | noncompliant | A complete source read satisfies the fail branch of this derivation: always return manual because the account settings API documents no account-level Team Chat encryption setting. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-COLLAB-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-COLLAB-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-MTG-01` | compliant | All required source reads are complete and this derivation returns pass: return fail when new scheduled meetings do not require a password, pass when the requirement is true, locked, and not relaxed by groups, and warn when compliant but not fully enforced. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-MTG-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when new scheduled meetings do not require a password, pass when the requirement is true, locked, and not relaxed by groups, and warn when compliant but not fully enforced. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-MTG-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-MTG-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-MTG-02` | compliant | All required source reads are complete and this derivation returns pass: return fail when waiting room is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-MTG-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when waiting room is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-MTG-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-MTG-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-MTG-03` | compliant | All required source reads are complete and this derivation returns pass: return fail when screen sharing is enabled for all participants, pass when disabled or host-only and locked without relaxed groups, warn when compliant but not fully enforced, and manual for absent or undocumented values. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-MTG-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when screen sharing is enabled for all participants, pass when disabled or host-only and locked without relaxed groups, warn when compliant but not fully enforced, and manual for absent or undocumented values. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-MTG-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-MTG-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-MTG-04` | compliant | All required source reads are complete and this derivation returns pass: return fail when local recording is enabled, pass when disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-MTG-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when local recording is enabled, pass when disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-MTG-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-MTG-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-MTG-05` | compliant | All required source reads are complete and this derivation returns pass: return fail when end-to-end encrypted meetings are unavailable, pass when available, default, locked, and not relaxed by groups, and warn when available but not default or not fully enforced. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-MTG-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when end-to-end encrypted meetings are unavailable, pass when available, default, locked, and not relaxed by groups, and warn when available but not default or not fully enforced. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-MTG-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-MTG-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-MTG-06` | compliant | All required source reads are complete and this derivation returns pass: return fail when passcodes are embedded in join links, pass when embedding is disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-MTG-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when passcodes are embedded in join links, pass when embedding is disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-MTG-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-MTG-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-MTG-07` | compliant | All required source reads are complete and this derivation returns pass: return fail when PMI is used for scheduled or instant meetings, pass when PMI is disabled or unused and both controls are locked without relaxed groups, and warn when compliant but not fully enforced. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-MTG-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when PMI is used for scheduled or instant meetings, pass when PMI is disabled or unused and both controls are locked without relaxed groups, and warn when compliant but not fully enforced. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-MTG-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-MTG-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-MTG-08` | compliant | All required source reads are complete and this derivation returns pass: return fail when meeting authentication is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-MTG-08` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when meeting authentication is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-MTG-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-MTG-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-MTG-09` | compliant | All required source reads are complete and this derivation returns pass: return fail when custom data-center routing is disabled, pass when enabled with a non-empty region list, locked, and not relaxed by groups, and warn when regions are absent or enforcement is incomplete. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-MTG-09` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when custom data-center routing is disabled, pass when enabled with a non-empty region list, locked, and not relaxed by groups, and warn when regions are absent or enforcement is incomplete. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-MTG-09` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-MTG-09` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZOOM-MTG-10` | compliant | All required source reads are complete and this derivation returns pass: return pass when every participant sees the recording disclaimer, warn for guest-only, unknown, or group-relaxed settings, fail when the legacy disclaimer is explicitly false, and manual when no documented setting is exposed. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZOOM-MTG-10` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every participant sees the recording disclaimer, warn for guest-only, unknown, or group-relaxed settings, fail when the legacy disclaimer is explicitly false, and manual when no documented setting is exposed. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZOOM-MTG-10` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZOOM-MTG-10` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Meeting password enforcement and account lock | AC-3 | AC.L2-3.1.1 | CC6.1 | 5.2 | 8.3.1 | SRG-APP-000033 | ISM-0974 | 8.1.1 |
| 2 | Waiting room enabled by default | AC-3 | AC.L2-3.1.2 | CC6.1 | 5.2 | 7.1.1 | SRG-APP-000033 | ISM-0974 | 8.1.1 |
| 3 | Screen sharing restricted to host only | AC-3 | AC.L2-3.1.5 | CC6.1 | 5.3 | 7.1.2 | SRG-APP-000038 | ISM-1146 | 8.1.2 |
| 4 | Recording consent disclaimer shown to participants | AU-14 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.1 | SRG-APP-000092 | ISM-0580 | 12.1.1 |
| 5 | SSO enforcement for all users | IA-2 | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 6 | Administrative privilege concentration | IA-2(1) | IA.L2-3.5.3 | CC6.1 | 4.5 | 8.3.2 | SRG-APP-000149 | ISM-1401 | 8.2.2 |
| 7 | End-to-end encryption available and default | SC-8(1) | SC.L2-3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0487 | 10.1.1 |
| 8 | Chat encryption enabled | SC-8 | SC.L2-3.13.1 | CC6.7 | 14.4 | 4.1 | SRG-APP-000439 | ISM-0487 | 10.1.1 |
| 9 | In-meeting file transfer restricted | SC-7 | SC.L2-3.13.6 | CC6.6 | 13.1 | 1.3.1 | SRG-APP-000383 | ISM-1284 | 10.2.1 |
| 10 | Cloud recording auto-delete retention | SI-12 | MP.L2-3.8.3 | CC6.5 | 3.1 | 3.1 | SRG-APP-000504 | ISM-0261 | 7.1.1 |
| 12 | External contacts restricted | AC-4 | AC.L2-3.1.3 | CC6.6 | 13.4 | 1.3.4 | SRG-APP-000039 | ISM-1284 | 8.1.3 |
| 13 | Vanity URL configured and secured | IA-8 | IA.L2-3.5.2 | CC6.1 | 4.1 | 8.1.1 | SRG-APP-000153 | ISM-1557 | 8.2.1 |
| 14 | Managed domains verified | IA-8 | IA.L2-3.5.2 | CC6.1 | 4.1 | 8.1.1 | SRG-APP-000153 | ISM-1557 | 8.2.1 |
| 15 | IM group restrictions enforced | AC-4 | AC.L2-3.1.3 | CC6.6 | 13.4 | 7.1.2 | SRG-APP-000039 | ISM-1284 | 8.1.3 |
| 16 | Personal and social sign-in methods blocked | IA-5 | IA.L2-3.5.7 | CC6.1 | 4.1 | 8.2.1 | SRG-APP-000170 | ISM-1557 | 8.2.3 |
| 17 | Session inactivity timeout enforced | AC-12 | AC.L2-3.1.10 | CC6.1 | 5.6 | 8.1.8 | SRG-APP-000295 | ISM-1164 | 8.3.1 |
| 18 | Data routing control enabled | SC-7 | SC.L2-3.13.1 | CC6.6 | 13.1 | 1.3.1 | SRG-APP-000383 | ISM-1037 | 10.2.1 |
| 19 | Zoom Phone recording policies enforced | AU-14 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.1 | SRG-APP-000092 | ISM-0580 | 12.1.1 |
| 20 | Local recording disabled | AC-3 | MP.L2-3.8.1 | CC6.1 | 3.1 | 3.4.1 | SRG-APP-000033 | ISM-0261 | 7.1.2 |
| 22 | Embed password in join link disabled | IA-5 | IA.L2-3.5.10 | CC6.1 | 5.2 | 8.2.1 | SRG-APP-000170 | ISM-0974 | 8.2.3 |
| 23 | Only authenticated users can join meetings | IA-2 | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 24 | Admin operation logs readable and recent | AU-11 | AU.L2-3.3.1 | CC7.2 | 8.3 | 10.7 | SRG-APP-000515 | ISM-0859 | 12.1.2 |
| 25 | Personal Meeting ID usage restricted | AC-3 | AC.L2-3.1.5 | CC6.1 | 5.3 | 8.1.1 | SRG-APP-000038 | ISM-0974 | 8.1.2 |

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

Sensitive fields and values: client_secret, access_token, authorization, cookie, join_url, start_url

Credential formats: Zoom OAuth bearer tokens, OAuth client secrets, meeting start and join URLs

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `current-user` | `projected fields consumed by the corresponding runtime assessment` |
| `account-settings` | `projected fields consumed by the corresponding runtime assessment` |
| `account-lock-settings` | `projected fields consumed by the corresponding runtime assessment` |
| `users` | `projected fields consumed by the corresponding runtime assessment` |
| `user-settings` | `projected fields consumed by the corresponding runtime assessment` |
| `roles` | `projected fields consumed by the corresponding runtime assessment` |
| `role-members` | `projected fields consumed by the corresponding runtime assessment` |
| `groups` | `projected fields consumed by the corresponding runtime assessment` |
| `group-settings` | `projected fields consumed by the corresponding runtime assessment` |
| `group-lock-settings` | `projected fields consumed by the corresponding runtime assessment` |
| `operation-logs` | `projected fields consumed by the corresponding runtime assessment` |
| `im-groups` | `projected fields consumed by the corresponding runtime assessment` |
| `managed-domains` | `projected fields consumed by the corresponding runtime assessment` |
| `trusted-domains` | `projected fields consumed by the corresponding runtime assessment` |
| `phone-settings` | `projected fields consumed by the corresponding runtime assessment` |

## Export layout

Required paths:

- `README.md`
- `QUICK_REFERENCE.md`
- `metadata.json`
- `summary.md`
- `core_data/access.json`
- `core_data/current_user.json`
- `core_data/account_settings.json`
- `core_data/account_lock_settings.json`
- `core_data/users.json`
- `core_data/roles.json`
- `core_data/groups.json`
- `core_data/im_groups.json`
- `core_data/managed_domains.json`
- `core_data/trusted_domains.json`
- `core_data/operation_logs.json`
- `core_data/phone_account_settings.json`
- `analysis/findings.json`
- `analysis/identity.json`
- `analysis/collaboration-governance.json`
- `analysis/meeting-security.json`
- `analysis/summary.json`
- `compliance/executive_summary.md`
- `compliance/unified_compliance_matrix.md`
- `compliance/fedramp.md`
- `compliance/cmmc.md`
- `compliance/soc-2.md`
- `compliance/cis.md`
- `compliance/pci-dss.md`
- `compliance/stig.md`
- `compliance/irap.md`
- `compliance/ismap.md`

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `README.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `QUICK_REFERENCE.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `metadata.json` | json | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `summary.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `core_data/access.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/current_user.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/account_settings.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/account_lock_settings.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/users.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/roles.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/groups.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/im_groups.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/managed_domains.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/trusted_domains.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/operation_logs.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/phone_account_settings.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/findings.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/identity.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/collaboration-governance.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/meeting-security.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/summary.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `compliance/executive_summary.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/unified_compliance_matrix.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/fedramp.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cmmc.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/soc-2.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cis.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/pci-dss.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/stig.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
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

JSON formatting: UTF-8 JSON with two-space indentation and a trailing newline.

Overwrite policy: Allocate zoom-audit-<UTC timestamp> and add a numeric suffix when either the directory or paired archive exists.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Create <allocated-directory>.zip beside the allocated Zoom audit directory with the same suffix.
