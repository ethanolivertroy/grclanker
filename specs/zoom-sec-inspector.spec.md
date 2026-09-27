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
| role | `account:read:admin settings and lock-settings scopes` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `user and role read scopes` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `report:read:operation_logs:admin` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `contact_group and Zoom Phone account-setting read scopes where licensed` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `account-settings` | HTTP | `GET /v2/accounts/{accountId}/settings` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `security`, `meeting_security`, `schedule_meeting`, `in_meeting`, `recording`, `chat` | [Official documentation](https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/settings) |
| `lock-settings` | HTTP | `GET /v2/accounts/{accountId}/lock_settings` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `meeting_security`, `schedule_meeting`, `in_meeting`, `recording`, `chat` | [Official documentation](https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/lock_settings) |
| `users` | HTTP | `GET /v2/users` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `email`, `status`, `type`, `login_types` | [Official documentation](https://developers.zoom.us/docs/api/users/#tag/users/GET/users) |
| `groups` | HTTP | `GET /v2/groups` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `total_members` | [Official documentation](https://developers.zoom.us/docs/api/users/#tag/groups/GET/groups) |
| `operation-logs` | HTTP | `GET /v2/report/operationlogs` | Zoom REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `time`, `operator`, `category_type`, `operation_detail` | [Official documentation](https://developers.zoom.us/docs/api/meetings/#tag/reports/GET/report/operationlogs) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `account-settings` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `account-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `account-settings` | response | A JSON object or list containing only the documented security, meeting_security, schedule_meeting, in_meeting, recording, chat members consumed by verdicts. | yes |
| `lock-settings` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `lock-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `lock-settings` | response | A JSON object or list containing only the documented meeting_security, schedule_meeting, in_meeting, recording, chat members consumed by verdicts. | yes |
| `users` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `users` | response | A JSON object or list containing only the documented id, email, status, type, login_types members consumed by verdicts. | yes |
| `groups` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `groups` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `groups` | response | A JSON object or list containing only the documented id, name, total_members members consumed by verdicts. | yes |
| `operation-logs` | client | Use the configured Zoom REST API origin; never follow a server link to a different origin. | yes |
| `operation-logs` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `operation-logs` | response | A JSON object or list containing only the documented time, operator, category_type, operation_detail members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `next_page_token`, `page_number`, `page_count`, `total_records` | 300 | caller limit | 500 | total_records is checked when returned; missing totals require explicit token exhaustion and never imply empty completeness. | No next_page_token; Declared total reached; Configured item cap; Page cap; Repeated token; Empty page with token; Missing or inconsistent total |

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
| `ZOOM-ID-01` | critical | `zoom_assess_identity` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for SSO enforcement for all users returns pass from complete, readable evidence. | The portable derivation for SSO enforcement for all users returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for SSO enforcement for all users returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for SSO enforcement for all users is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-02` | critical | `zoom_assess_identity` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Two-factor authentication for admins returns pass from complete, readable evidence. | The portable derivation for Two-factor authentication for admins returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Two-factor authentication for admins returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Two-factor authentication for admins is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-03` | high | `zoom_assess_identity` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Managed domains verified returns pass from complete, readable evidence. | The portable derivation for Managed domains verified returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Managed domains verified returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Managed domains verified is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-04` | medium | `zoom_assess_identity` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Administrative privilege concentration returns pass from complete, readable evidence. | The portable derivation for Administrative privilege concentration returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Administrative privilege concentration returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Administrative privilege concentration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-05` | high | `zoom_assess_identity` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Personal and social sign-in methods blocked returns pass from complete, readable evidence. | The portable derivation for Personal and social sign-in methods blocked returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Personal and social sign-in methods blocked returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Personal and social sign-in methods blocked is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-06` | medium | `zoom_assess_identity` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Session inactivity timeout enforced returns pass from complete, readable evidence. | The portable derivation for Session inactivity timeout enforced returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Session inactivity timeout enforced returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Session inactivity timeout enforced is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-ID-07` | low | `zoom_assess_identity` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Vanity URL configured and secured returns pass from complete, readable evidence. | The portable derivation for Vanity URL configured and secured returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Vanity URL configured and secured returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Vanity URL configured and secured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-01` | high | `zoom_assess_collaboration_governance` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Trusted domain restrictions returns pass from complete, readable evidence. | The portable derivation for Trusted domain restrictions returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Trusted domain restrictions returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Trusted domain restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-02` | high | `zoom_assess_collaboration_governance` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for In-meeting file transfer restricted returns pass from complete, readable evidence. | The portable derivation for In-meeting file transfer restricted returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for In-meeting file transfer restricted returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for In-meeting file transfer restricted is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-03` | high | `zoom_assess_collaboration_governance` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Cloud recording auto-delete retention returns pass from complete, readable evidence. | The portable derivation for Cloud recording auto-delete retention returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Cloud recording auto-delete retention returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Cloud recording auto-delete retention is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-04` | medium | `zoom_assess_collaboration_governance` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Zoom Phone recording policies enforced returns pass from complete, readable evidence. | The portable derivation for Zoom Phone recording policies enforced returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Zoom Phone recording policies enforced returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Zoom Phone recording policies enforced is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-05` | medium | `zoom_assess_collaboration_governance` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Admin operation logs readable and recent returns pass from complete, readable evidence. | The portable derivation for Admin operation logs readable and recent returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Admin operation logs readable and recent returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Admin operation logs readable and recent is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-06` | medium | `zoom_assess_collaboration_governance` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for IM group restrictions enforced returns pass from complete, readable evidence. | The portable derivation for IM group restrictions enforced returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for IM group restrictions enforced returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for IM group restrictions enforced is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-07` | medium | `zoom_assess_collaboration_governance` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for External contacts restricted returns pass from complete, readable evidence. | The portable derivation for External contacts restricted returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for External contacts restricted returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for External contacts restricted is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-COLLAB-08` | medium | `zoom_assess_collaboration_governance` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Chat encryption enabled returns pass from complete, readable evidence. | The portable derivation for Chat encryption enabled returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Chat encryption enabled returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Chat encryption enabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-01` | critical | `zoom_assess_meeting_security` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Meeting password enforcement and account lock returns pass from complete, readable evidence. | The portable derivation for Meeting password enforcement and account lock returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Meeting password enforcement and account lock returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Meeting password enforcement and account lock is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-02` | critical | `zoom_assess_meeting_security` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Waiting room enabled by default returns pass from complete, readable evidence. | The portable derivation for Waiting room enabled by default returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Waiting room enabled by default returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Waiting room enabled by default is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-03` | high | `zoom_assess_meeting_security` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Screen sharing restricted to host only returns pass from complete, readable evidence. | The portable derivation for Screen sharing restricted to host only returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Screen sharing restricted to host only returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Screen sharing restricted to host only is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-04` | high | `zoom_assess_meeting_security` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Local recording disabled returns pass from complete, readable evidence. | The portable derivation for Local recording disabled returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Local recording disabled returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Local recording disabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-05` | high | `zoom_assess_meeting_security` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for End-to-end encryption available and default returns pass from complete, readable evidence. | The portable derivation for End-to-end encryption available and default returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for End-to-end encryption available and default returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for End-to-end encryption available and default is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-06` | medium | `zoom_assess_meeting_security` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Embed password in join link disabled returns pass from complete, readable evidence. | The portable derivation for Embed password in join link disabled returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Embed password in join link disabled returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Embed password in join link disabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-07` | medium | `zoom_assess_meeting_security` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Personal Meeting ID usage restricted returns pass from complete, readable evidence. | The portable derivation for Personal Meeting ID usage restricted returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Personal Meeting ID usage restricted returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Personal Meeting ID usage restricted is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-08` | high | `zoom_assess_meeting_security` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Only authenticated users can join meetings returns pass from complete, readable evidence. | The portable derivation for Only authenticated users can join meetings returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Only authenticated users can join meetings returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Only authenticated users can join meetings is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-09` | critical | `zoom_assess_meeting_security` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Data routing control enabled returns pass from complete, readable evidence. | The portable derivation for Data routing control enabled returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Data routing control enabled returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Data routing control enabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZOOM-MTG-10` | high | `zoom_assess_meeting_security` | `account-settings`, `lock-settings`, `users`, `groups`, `operation-logs` | `decision_status` | The portable derivation for Recording consent disclaimer shown to participants returns pass from complete, readable evidence. | The portable derivation for Recording consent disclaimer shown to participants returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Recording consent disclaimer shown to participants returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Recording consent disclaimer shown to participants is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `ZOOM-ID-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-ID-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-ID-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-ID-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-ID-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-ID-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-ID-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-ID-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-ID-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-ID-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-ID-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-ID-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-ID-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-ID-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-ID-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-ID-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-ID-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-ID-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-ID-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-ID-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-ID-06` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-ID-06` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-ID-06` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-ID-06` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-ID-07` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-ID-07` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-ID-07` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-ID-07` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-COLLAB-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-COLLAB-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-COLLAB-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-COLLAB-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-COLLAB-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-COLLAB-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-COLLAB-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-COLLAB-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-COLLAB-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-COLLAB-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-COLLAB-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-COLLAB-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-COLLAB-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-COLLAB-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-COLLAB-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-COLLAB-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-COLLAB-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-COLLAB-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-COLLAB-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-COLLAB-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-COLLAB-06` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-COLLAB-06` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-COLLAB-06` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-COLLAB-06` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-COLLAB-07` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-COLLAB-07` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-COLLAB-07` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-COLLAB-07` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-COLLAB-08` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-COLLAB-08` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-COLLAB-08` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-COLLAB-08` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-MTG-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-MTG-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-MTG-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-MTG-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-MTG-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-MTG-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-MTG-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-MTG-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-MTG-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-MTG-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-MTG-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-MTG-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-MTG-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-MTG-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-MTG-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-MTG-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-MTG-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-MTG-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-MTG-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-MTG-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-MTG-06` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-MTG-06` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-MTG-06` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-MTG-06` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-MTG-07` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-MTG-07` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-MTG-07` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-MTG-07` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-MTG-08` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-MTG-08` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-MTG-08` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-MTG-08` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-MTG-09` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-MTG-09` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-MTG-09` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-MTG-09` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZOOM-MTG-10` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZOOM-MTG-10` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZOOM-MTG-10` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZOOM-MTG-10` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `ZOOM-ID-01` | `decision_status` | Using complete source cardinalities, return fail when any active user has a login type other than 101, pass when every user in a complete non-empty inventory is SSO-only, and warn for unknown login types or partial evidence. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-ID-02` | `decision_status` | Using complete source cardinalities, return pass for two-factor mode all with complete roles or mode role covering every admin role, fail for none or an uncovered admin role, warn for group mode or partial roles, and manual for absent or undocumented settings. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-ID-03` | `decision_status` | Using complete source cardinalities, return fail when any managed domain is not verified, pass when every domain in a complete non-empty inventory is verified, warn for truncation, and manual when no domain is returned. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-ID-04` | `decision_status` | Using complete source cardinalities, return pass when complete admin-role membership contains at most the configured administrator maximum and warn when it exceeds that maximum or role evidence is partial. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-ID-05` | `decision_status` | Using complete source cardinalities, return fail when any active user uses a password or social login, pass when every login code in a complete non-empty inventory is documented and neither category, and warn for unknown, other, or partial evidence. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-ID-06` | `decision_status` | Using complete source cardinalities, return fail when client or web inactivity sign-out is disabled, warn when either exceeds the configured maximum, pass when both positive values are within it, and manual when neither setting is exposed. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-ID-07` | `decision_status` | Using complete source cardinalities, always return manual because the account settings API exposes no account vanity URL field. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-COLLAB-01` | `decision_status` | Using complete source cardinalities, return pass when the non-empty trusted-domain inventory contains no wildcard, fail when any wildcard exists, and manual when the inventory is empty or unreadable. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-COLLAB-02` | `decision_status` | Using complete source cardinalities, return fail when in-meeting file transfer is enabled, pass when disabled, locked, and no group relaxes it, and warn when disabled but unlocked or group evidence is incomplete. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-COLLAB-03` | `decision_status` | Using complete source cardinalities, return fail when cloud recording is enabled without auto-delete, pass when auto-delete days are at or below the configured maximum, locked, and not relaxed by a group, warn for missing days, excessive retention, or incomplete enforcement, and manual when cloud recording is disabled. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-COLLAB-04` | `decision_status` | Using complete source cardinalities, return pass when both auto-call and ad-hoc Zoom Phone recording policies expose enable flags and are locked, warn when either is unlocked, and manual when Phone or either policy is unavailable. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-COLLAB-05` | `decision_status` | Using complete source cardinalities, return pass when a complete admin-operation-log window is non-empty and every row is dated, and warn when the window is empty, truncated, or contains undated rows. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-COLLAB-06` | `decision_status` | Using complete source cardinalities, return pass when every IM group in a complete non-empty inventory is normal or restricted without master-account search, warn for shared, unknown, cross-account, or partial groups, and manual when no group exists. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-COLLAB-07` | `decision_status` | Using complete source cardinalities, return fail when add-contact or chat-with-others policy allows anyone, pass when both are organization-restricted, locked, and not relaxed by groups, warn when restrictions are not fully locked, and manual for absent policy fields. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-COLLAB-08` | `decision_status` | Using complete source cardinalities, always return manual because the account settings API documents no account-level Team Chat encryption setting. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-MTG-01` | `decision_status` | Using complete source cardinalities, return fail when new scheduled meetings do not require a password, pass when the requirement is true, locked, and not relaxed by groups, and warn when compliant but not fully enforced. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-MTG-02` | `decision_status` | Using complete source cardinalities, return fail when waiting room is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-MTG-03` | `decision_status` | Using complete source cardinalities, return fail when screen sharing is enabled for all participants, pass when disabled or host-only and locked without relaxed groups, warn when compliant but not fully enforced, and manual for absent or undocumented values. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-MTG-04` | `decision_status` | Using complete source cardinalities, return fail when local recording is enabled, pass when disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-MTG-05` | `decision_status` | Using complete source cardinalities, return fail when end-to-end encrypted meetings are unavailable, pass when available, default, locked, and not relaxed by groups, and warn when available but not default or not fully enforced. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-MTG-06` | `decision_status` | Using complete source cardinalities, return fail when passcodes are embedded in join links, pass when embedding is disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-MTG-07` | `decision_status` | Using complete source cardinalities, return fail when PMI is used for scheduled or instant meetings, pass when PMI is disabled or unused and both controls are locked without relaxed groups, and warn when compliant but not fully enforced. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-MTG-08` | `decision_status` | Using complete source cardinalities, return fail when meeting authentication is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-MTG-09` | `decision_status` | Using complete source cardinalities, return fail when custom data-center routing is disabled, pass when enabled with a non-empty region list, locked, and not relaxed by groups, and warn when regions are absent or enforcement is incomplete. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `ZOOM-MTG-10` | `decision_status` | Using complete source cardinalities, return pass when every participant sees the recording disclaimer, warn for guest-only, unknown, or group-relaxed settings, fail when the legacy disclaimer is explicitly false, and manual when no documented setting is exposed. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `ZOOM-ID-01` | `passStatus` | pass |
| `ZOOM-ID-01` | `warnStatus` | warn |
| `ZOOM-ID-01` | `failStatus` | fail |
| `ZOOM-ID-01` | `manualStatus` | manual |
| `ZOOM-ID-02` | `passStatus` | pass |
| `ZOOM-ID-02` | `warnStatus` | warn |
| `ZOOM-ID-02` | `failStatus` | fail |
| `ZOOM-ID-02` | `manualStatus` | manual |
| `ZOOM-ID-03` | `passStatus` | pass |
| `ZOOM-ID-03` | `warnStatus` | warn |
| `ZOOM-ID-03` | `failStatus` | fail |
| `ZOOM-ID-03` | `manualStatus` | manual |
| `ZOOM-ID-04` | `passStatus` | pass |
| `ZOOM-ID-04` | `warnStatus` | warn |
| `ZOOM-ID-04` | `failStatus` | fail |
| `ZOOM-ID-04` | `manualStatus` | manual |
| `ZOOM-ID-05` | `passStatus` | pass |
| `ZOOM-ID-05` | `warnStatus` | warn |
| `ZOOM-ID-05` | `failStatus` | fail |
| `ZOOM-ID-05` | `manualStatus` | manual |
| `ZOOM-ID-06` | `passStatus` | pass |
| `ZOOM-ID-06` | `warnStatus` | warn |
| `ZOOM-ID-06` | `failStatus` | fail |
| `ZOOM-ID-06` | `manualStatus` | manual |
| `ZOOM-ID-07` | `passStatus` | pass |
| `ZOOM-ID-07` | `warnStatus` | warn |
| `ZOOM-ID-07` | `failStatus` | fail |
| `ZOOM-ID-07` | `manualStatus` | manual |
| `ZOOM-COLLAB-01` | `passStatus` | pass |
| `ZOOM-COLLAB-01` | `warnStatus` | warn |
| `ZOOM-COLLAB-01` | `failStatus` | fail |
| `ZOOM-COLLAB-01` | `manualStatus` | manual |
| `ZOOM-COLLAB-02` | `passStatus` | pass |
| `ZOOM-COLLAB-02` | `warnStatus` | warn |
| `ZOOM-COLLAB-02` | `failStatus` | fail |
| `ZOOM-COLLAB-02` | `manualStatus` | manual |
| `ZOOM-COLLAB-03` | `passStatus` | pass |
| `ZOOM-COLLAB-03` | `warnStatus` | warn |
| `ZOOM-COLLAB-03` | `failStatus` | fail |
| `ZOOM-COLLAB-03` | `manualStatus` | manual |
| `ZOOM-COLLAB-04` | `passStatus` | pass |
| `ZOOM-COLLAB-04` | `warnStatus` | warn |
| `ZOOM-COLLAB-04` | `failStatus` | fail |
| `ZOOM-COLLAB-04` | `manualStatus` | manual |
| `ZOOM-COLLAB-05` | `passStatus` | pass |
| `ZOOM-COLLAB-05` | `warnStatus` | warn |
| `ZOOM-COLLAB-05` | `failStatus` | fail |
| `ZOOM-COLLAB-05` | `manualStatus` | manual |
| `ZOOM-COLLAB-06` | `passStatus` | pass |
| `ZOOM-COLLAB-06` | `warnStatus` | warn |
| `ZOOM-COLLAB-06` | `failStatus` | fail |
| `ZOOM-COLLAB-06` | `manualStatus` | manual |
| `ZOOM-COLLAB-07` | `passStatus` | pass |
| `ZOOM-COLLAB-07` | `warnStatus` | warn |
| `ZOOM-COLLAB-07` | `failStatus` | fail |
| `ZOOM-COLLAB-07` | `manualStatus` | manual |
| `ZOOM-COLLAB-08` | `passStatus` | pass |
| `ZOOM-COLLAB-08` | `warnStatus` | warn |
| `ZOOM-COLLAB-08` | `failStatus` | fail |
| `ZOOM-COLLAB-08` | `manualStatus` | manual |
| `ZOOM-MTG-01` | `passStatus` | pass |
| `ZOOM-MTG-01` | `warnStatus` | warn |
| `ZOOM-MTG-01` | `failStatus` | fail |
| `ZOOM-MTG-01` | `manualStatus` | manual |
| `ZOOM-MTG-02` | `passStatus` | pass |
| `ZOOM-MTG-02` | `warnStatus` | warn |
| `ZOOM-MTG-02` | `failStatus` | fail |
| `ZOOM-MTG-02` | `manualStatus` | manual |
| `ZOOM-MTG-03` | `passStatus` | pass |
| `ZOOM-MTG-03` | `warnStatus` | warn |
| `ZOOM-MTG-03` | `failStatus` | fail |
| `ZOOM-MTG-03` | `manualStatus` | manual |
| `ZOOM-MTG-04` | `passStatus` | pass |
| `ZOOM-MTG-04` | `warnStatus` | warn |
| `ZOOM-MTG-04` | `failStatus` | fail |
| `ZOOM-MTG-04` | `manualStatus` | manual |
| `ZOOM-MTG-05` | `passStatus` | pass |
| `ZOOM-MTG-05` | `warnStatus` | warn |
| `ZOOM-MTG-05` | `failStatus` | fail |
| `ZOOM-MTG-05` | `manualStatus` | manual |
| `ZOOM-MTG-06` | `passStatus` | pass |
| `ZOOM-MTG-06` | `warnStatus` | warn |
| `ZOOM-MTG-06` | `failStatus` | fail |
| `ZOOM-MTG-06` | `manualStatus` | manual |
| `ZOOM-MTG-07` | `passStatus` | pass |
| `ZOOM-MTG-07` | `warnStatus` | warn |
| `ZOOM-MTG-07` | `failStatus` | fail |
| `ZOOM-MTG-07` | `manualStatus` | manual |
| `ZOOM-MTG-08` | `passStatus` | pass |
| `ZOOM-MTG-08` | `warnStatus` | warn |
| `ZOOM-MTG-08` | `failStatus` | fail |
| `ZOOM-MTG-08` | `manualStatus` | manual |
| `ZOOM-MTG-09` | `passStatus` | pass |
| `ZOOM-MTG-09` | `warnStatus` | warn |
| `ZOOM-MTG-09` | `failStatus` | fail |
| `ZOOM-MTG-09` | `manualStatus` | manual |
| `ZOOM-MTG-10` | `passStatus` | pass |
| `ZOOM-MTG-10` | `warnStatus` | warn |
| `ZOOM-MTG-10` | `failStatus` | fail |
| `ZOOM-MTG-10` | `manualStatus` | manual |

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
| 1 | Meeting password enforcement and account lock | - | - | - | - | - | - | - | - |
| 2 | Waiting room enabled by default | - | - | - | - | - | - | - | - |
| 3 | Screen sharing restricted to host only | - | - | - | - | - | - | - | - |
| 4 | Recording consent disclaimer shown to participants | - | - | - | - | - | - | - | - |
| 5 | SSO enforcement for all users | - | - | - | - | - | - | - | - |
| 6 | Administrative privilege concentration | - | - | - | - | - | - | - | - |
| 7 | End-to-end encryption available and default | - | - | - | - | - | - | - | - |
| 8 | Chat encryption enabled | - | - | - | - | - | - | - | - |
| 9 | In-meeting file transfer restricted | - | - | - | - | - | - | - | - |
| 10 | Cloud recording auto-delete retention | - | - | - | - | - | - | - | - |
| 12 | External contacts restricted | - | - | - | - | - | - | - | - |
| 13 | Vanity URL configured and secured | - | - | - | - | - | - | - | - |
| 14 | Managed domains verified | - | - | - | - | - | - | - | - |
| 15 | IM group restrictions enforced | - | - | - | - | - | - | - | - |
| 16 | Personal and social sign-in methods blocked | - | - | - | - | - | - | - | - |
| 17 | Session inactivity timeout enforced | - | - | - | - | - | - | - | - |
| 18 | Data routing control enabled | - | - | - | - | - | - | - | - |
| 19 | Zoom Phone recording policies enforced | - | - | - | - | - | - | - | - |
| 20 | Local recording disabled | - | - | - | - | - | - | - | - |
| 22 | Embed password in join link disabled | - | - | - | - | - | - | - | - |
| 23 | Only authenticated users can join meetings | - | - | - | - | - | - | - | - |
| 24 | Admin operation logs readable and recent | - | - | - | - | - | - | - | - |
| 25 | Personal Meeting ID usage restricted | - | - | - | - | - | - | - | - |

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
| `account-settings` | `security`, `meeting_security`, `schedule_meeting`, `in_meeting`, `recording`, `chat` |
| `lock-settings` | `meeting_security`, `schedule_meeting`, `in_meeting`, `recording`, `chat` |
| `users` | `id`, `email`, `status`, `type`, `login_types` |
| `groups` | `id`, `name`, `total_members` |
| `operation-logs` | `time`, `operator`, `category_type`, `operation_detail` |

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

Archive pairing: Create zoom-audit.zip beside the allocated zoom-audit directory, applying the same suffix to both.
