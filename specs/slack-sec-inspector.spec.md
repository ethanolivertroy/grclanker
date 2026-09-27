---
slug: "slack-sec-inspector"
name: "Slack Security Inspector"
vendor: "Slack"
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

# Slack Security Inspector

Portable contract for the shipped Slack Enterprise Grid identity, administration, app, channel, and monitoring assessments.

## Purpose

Provide a read-only Enterprise Grid assessment across identity, administration, applications, channel governance, SCIM lifecycle, and audit monitoring.

## Design guidance

Model Slack's Web, Admin, SCIM, and Audit Logs APIs as separate evidence domains with separate scopes and plan gates. Do not infer private organization settings from unrelated public fields; preserve manual review where Slack offers no read method.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- Eight controls remain manual because the public read APIs do not expose a decisive setting; the runtime names the exact Admin Console or SIEM evidence instead of calling write endpoints.
- Cross-inventory findings require every dependent workspace, admin, channel, SCIM, or audit inventory to be complete before pass; partial secondary reads demote the dependent result.
- SCIM, Web API, Admin API, and Audit Logs pagination use different cursor locations and preserve stalled cursors, page caps, item caps, and unknown totals as incomplete evidence.
- Discovery DLP details, guest expiry, several workspace restrictions, and standalone reporters remain unavailable.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `slack_check_access` | Validate read-only Slack Enterprise Grid API access and show which Web API, Admin API, SCIM, and Audit Logs surfaces are readable with the configured user, bot, and SCIM tokens. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `slack_assess_identity` | Assess Slack MFA enrollment (has_2fa), guest inventory, SCIM provisioning coverage, user lifecycle alignment, and deactivated user visibility. | `SLACK-ID-01`, `SLACK-ID-02`, `SLACK-ID-03`, `SLACK-ID-04`, `SLACK-ID-05` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `slack_assess_admin_access` | Assess Slack workspace admin inventory, SSO coverage (has_sso), session duration, idle timeout, discoverability, mobile session controls, email domain restrictions, custom emoji governance, and analytics access. | `SLACK-ADMIN-01`, `SLACK-ADMIN-02`, `SLACK-ADMIN-03`, `SLACK-ADMIN-04`, `SLACK-ADMIN-05`, `SLACK-ADMIN-06`, `SLACK-ADMIN-07`, `SLACK-ADMIN-08`, `SLACK-ADMIN-09` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `slack_assess_integrations` | Assess Slack approved and restricted app inventories, internal and sensitive-scope apps, information barriers, DLP and Discovery evidence, file upload restrictions (team.preferences.list), and token rotation. | `SLACK-APP-01`, `SLACK-APP-02`, `SLACK-APP-03`, `SLACK-APP-04`, `SLACK-APP-05`, `SLACK-APP-06`, `SLACK-APP-07` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `slack_assess_channel_governance` | Assess Slack Connect exposure, posting restrictions on general and org default channels, channel retention overrides, external email ingestion, and link preview settings. | `SLACK-CHAN-01`, `SLACK-CHAN-02`, `SLACK-CHAN-03`, `SLACK-CHAN-04`, `SLACK-CHAN-05` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `slack_assess_monitoring` | Assess Slack Audit Logs API access, event recency, security administration events, schema visibility, external sharing monitoring, and SIEM streaming evidence. | `SLACK-MON-01`, `SLACK-MON-02`, `SLACK-MON-03`, `SLACK-MON-04`, `SLACK-MON-05`, `SLACK-MON-06` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `slack_export_audit_bundle` | Export a Slack audit bundle with core_data snapshots, analysis JSON, per-framework compliance reports, QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a zip archive named after the allocated directory. | `SLACK-ID-01`, `SLACK-ID-02`, `SLACK-ID-03`, `SLACK-ID-04`, `SLACK-ID-05`, `SLACK-ADMIN-01`, `SLACK-ADMIN-02`, `SLACK-ADMIN-03`, `SLACK-ADMIN-04`, `SLACK-ADMIN-05`, `SLACK-ADMIN-06`, `SLACK-ADMIN-07`, `SLACK-ADMIN-08`, `SLACK-ADMIN-09`, `SLACK-APP-01`, `SLACK-APP-02`, `SLACK-APP-03`, `SLACK-APP-04`, `SLACK-APP-05`, `SLACK-APP-06`, `SLACK-APP-07`, `SLACK-CHAN-01`, `SLACK-CHAN-02`, `SLACK-CHAN-03`, `SLACK-CHAN-04`, `SLACK-CHAN-05`, `SLACK-MON-01`, `SLACK-MON-02`, `SLACK-MON-03`, `SLACK-MON-04`, `SLACK-MON-05`, `SLACK-MON-06` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `slack_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Slack org-level user token. Defaults to SLACK_USER_TOKEN, then the config file. |
| `bot_token` | string | no | Slack bot token for bot-capable methods (auth.test, users.list). Defaults to SLACK_BOT_TOKEN. |
| `scim_token` | string | no | Slack SCIM bearer token. Defaults to SLACK_SCIM_TOKEN. |
| `org_id` | string | no | Slack Enterprise Grid org ID. Defaults to SLACK_ORG_ID or SLACK_ENTERPRISE_ID. |
| `timeout_seconds` | number | no | Request timeout in seconds. Defaults to 30. |

#### `slack_assess_identity`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Slack org-level user token. Defaults to SLACK_USER_TOKEN, then the config file. |
| `bot_token` | string | no | Slack bot token for bot-capable methods (auth.test, users.list). Defaults to SLACK_BOT_TOKEN. |
| `scim_token` | string | no | Slack SCIM bearer token. Defaults to SLACK_SCIM_TOKEN. |
| `org_id` | string | no | Slack Enterprise Grid org ID. Defaults to SLACK_ORG_ID or SLACK_ENTERPRISE_ID. |
| `timeout_seconds` | number | no | Request timeout in seconds. Defaults to 30. |
| `user_limit` | number | no | Maximum users to read. Defaults to 1000. |
| `skip_scim` | boolean | no | Skip SCIM provisioning checks. Defaults to false. |

#### `slack_assess_admin_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Slack org-level user token. Defaults to SLACK_USER_TOKEN, then the config file. |
| `bot_token` | string | no | Slack bot token for bot-capable methods (auth.test, users.list). Defaults to SLACK_BOT_TOKEN. |
| `scim_token` | string | no | Slack SCIM bearer token. Defaults to SLACK_SCIM_TOKEN. |
| `org_id` | string | no | Slack Enterprise Grid org ID. Defaults to SLACK_ORG_ID or SLACK_ENTERPRISE_ID. |
| `timeout_seconds` | number | no | Request timeout in seconds. Defaults to 30. |
| `workspace_limit` | number | no | Maximum workspaces to read. Defaults to 50. |
| `user_limit` | number | no | Maximum org users to read from admin.users.list. Defaults to 1000. |
| `max_workspace_admins` | number | no | Maximum expected admins per workspace. Defaults to 5. |
| `max_session_hours` | number | no | Maximum acceptable session duration in hours. Defaults to 24. |
| `session_sample` | number | no | Maximum users whose session settings are sampled. Defaults to 100. |

#### `slack_assess_integrations`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Slack org-level user token. Defaults to SLACK_USER_TOKEN, then the config file. |
| `bot_token` | string | no | Slack bot token for bot-capable methods (auth.test, users.list). Defaults to SLACK_BOT_TOKEN. |
| `scim_token` | string | no | Slack SCIM bearer token. Defaults to SLACK_SCIM_TOKEN. |
| `org_id` | string | no | Slack Enterprise Grid org ID. Defaults to SLACK_ORG_ID or SLACK_ENTERPRISE_ID. |
| `timeout_seconds` | number | no | Request timeout in seconds. Defaults to 30. |
| `app_limit` | number | no | Maximum approved/restricted apps to read. Defaults to 500. |
| `workspace_limit` | number | no | Maximum workspaces to read when scoping team.preferences.list. Defaults to 50. |

#### `slack_assess_channel_governance`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Slack org-level user token. Defaults to SLACK_USER_TOKEN, then the config file. |
| `bot_token` | string | no | Slack bot token for bot-capable methods (auth.test, users.list). Defaults to SLACK_BOT_TOKEN. |
| `scim_token` | string | no | Slack SCIM bearer token. Defaults to SLACK_SCIM_TOKEN. |
| `org_id` | string | no | Slack Enterprise Grid org ID. Defaults to SLACK_ORG_ID or SLACK_ENTERPRISE_ID. |
| `timeout_seconds` | number | no | Request timeout in seconds. Defaults to 30. |
| `channel_limit` | number | no | Maximum active channels to sample for prefs and retention. Defaults to 40. |
| `min_retention_days` | number | no | Minimum acceptable custom retention in days. Defaults to 365. |

#### `slack_assess_monitoring`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Slack org-level user token. Defaults to SLACK_USER_TOKEN, then the config file. |
| `bot_token` | string | no | Slack bot token for bot-capable methods (auth.test, users.list). Defaults to SLACK_BOT_TOKEN. |
| `scim_token` | string | no | Slack SCIM bearer token. Defaults to SLACK_SCIM_TOKEN. |
| `org_id` | string | no | Slack Enterprise Grid org ID. Defaults to SLACK_ORG_ID or SLACK_ENTERPRISE_ID. |
| `timeout_seconds` | number | no | Request timeout in seconds. Defaults to 30. |
| `days` | number | no | Audit log lookback window in days. Defaults to 30. |
| `audit_limit` | number | no | Maximum audit events to read (1-9999). Defaults to 200. |

#### `slack_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Slack org-level user token. Defaults to SLACK_USER_TOKEN, then the config file. |
| `bot_token` | string | no | Slack bot token for bot-capable methods (auth.test, users.list). Defaults to SLACK_BOT_TOKEN. |
| `scim_token` | string | no | Slack SCIM bearer token. Defaults to SLACK_SCIM_TOKEN. |
| `org_id` | string | no | Slack Enterprise Grid org ID. Defaults to SLACK_ORG_ID or SLACK_ENTERPRISE_ID. |
| `timeout_seconds` | number | no | Request timeout in seconds. Defaults to 30. |
| `output_dir` | string | no | Output root. Defaults to ./export/slack. |
| `user_limit` | number | no | Maximum users to read. Defaults to 1000. |
| `workspace_limit` | number | no | Maximum workspaces to read. Defaults to 50. |
| `app_limit` | number | no | Maximum approved/restricted apps to read. Defaults to 500. |
| `audit_limit` | number | no | Maximum audit events to read. Defaults to 200. |
| `channel_limit` | number | no | Maximum channels to sample. Defaults to 40. |
| `days` | number | no | Audit log lookback window in days. Defaults to 30. |
| `max_workspace_admins` | number | no | Maximum expected admins per workspace. Defaults to 5. |
| `max_session_hours` | number | no | Maximum acceptable session duration in hours. Defaults to 24. |
| `min_retention_days` | number | no | Minimum acceptable custom retention in days. Defaults to 365. |
| `skip_scim` | boolean | no | Skip SCIM provisioning checks. Defaults to false. |


## Authentication

Supported modes:

- User OAuth token
- Bot OAuth token
- SCIM bearer token

Credential precedence, highest first:

1. Explicit tool arguments
2. Explicit config file
3. SLACK_* environment variables

Environment variables: `SLACK_USER_TOKEN`, `SLACK_BOT_TOKEN`, `SLACK_SCIM_TOKEN`, `SLACK_ORG_ID`, `SLACK_CONFIG_FILE`

Configuration locations: ~/.config/grclanker/slack.json

Credential and deployment variants: Enterprise Grid org token plus optional bot and SCIM credentials

Configuration fields: `token`, `botToken`, `scimToken`, `orgId`, `webApiBaseUrl`, `scimBaseUrl`, `auditBaseUrl`

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| role | `Slack Enterprise Grid org-admin OAuth scopes` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `SCIM API entitlement and token` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `Audit Logs API entitlement and scope` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `Discovery and DLP plan features where applicable` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `users` | HTTP | `GET /api/users.list` | Slack Web API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `deleted`, `is_admin`, `is_owner`, `is_restricted`, `has_2fa`, `has_sso` | [Official documentation](https://api.slack.com/methods/users.list) |
| `admin-users` | HTTP | `POST /api/admin.users.list` | Slack Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `team_id`, `email`, `is_admin`, `is_owner` | [Official documentation](https://api.slack.com/methods/admin.users.list) |
| `admin-apps` | HTTP | `GET /api/admin.apps.approved.list` | Slack Admin API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `app_id`, `name`, `scopes`, `is_internal` | [Official documentation](https://api.slack.com/methods/admin.apps.approved.list) |
| `scim-users` | HTTP | `GET /scim/v1/Users` | Slack SCIM API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `userName`, `active`, `groups` | [Official documentation](https://docs.slack.dev/admins/scim-api/) |
| `audit-logs` | HTTP | `GET /audit/v1/logs` | Slack Audit Logs API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `date_create`, `action`, `actor`, `entity`, `context` | [Official documentation](https://docs.slack.dev/admins/audit-logs-api/) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `users` | client | Use the configured Slack Web API origin; never follow a server link to a different origin. | yes |
| `users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `users` | response | A JSON object or list containing only the documented id, deleted, is_admin, is_owner, is_restricted, has_2fa, has_sso members consumed by verdicts. | yes |
| `admin-users` | client | Use the configured Slack Admin API origin; never follow a server link to a different origin. | yes |
| `admin-users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `admin-users` | response | A JSON object or list containing only the documented id, team_id, email, is_admin, is_owner members consumed by verdicts. | yes |
| `admin-apps` | client | Use the configured Slack Admin API origin; never follow a server link to a different origin. | yes |
| `admin-apps` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `admin-apps` | response | A JSON object or list containing only the documented app_id, name, scopes, is_internal members consumed by verdicts. | yes |
| `scim-users` | client | Use the configured Slack SCIM API origin; never follow a server link to a different origin. | yes |
| `scim-users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `scim-users` | response | A JSON object or list containing only the documented id, userName, active, groups members consumed by verdicts. | yes |
| `audit-logs` | client | Use the configured Slack Audit Logs API origin; never follow a server link to a different origin. | yes |
| `audit-logs` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `audit-logs` | response | A JSON object or list containing only the documented id, date_create, action, actor, entity, context members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `response_metadata.next_cursor`, `next_cursor`, `startIndex`, `totalResults` | service default | caller limit | 50 | SCIM totals are authoritative; Slack cursor APIs prove completion only with an empty next cursor. | Empty next cursor or SCIM total reached; Configured item cap; Page cap; Repeated cursor; Empty page with cursor; Unknown or inconsistent SCIM total |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Slack Security Inspector | Method-specific Slack rate tiers | `Retry-After` | 429, 500, 502, 503, 504 | Honor Retry-After up to the runtime bound and retry 429 responses twice; exhausted reads stay explicit. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | SSO enforcement | SLACK-ADMIN-02 | Evaluate the ordered first-match rules for SLACK-ADMIN-02 below. |
| 2 | MFA enrollment | SLACK-ID-01 | Evaluate the ordered first-match rules for SLACK-ID-01 below. |
| 3 | Session duration limits | SLACK-ADMIN-03 | Evaluate the ordered first-match rules for SLACK-ADMIN-03 below. |
| 4 | Session idle timeout | SLACK-ADMIN-04 | Evaluate the ordered first-match rules for SLACK-ADMIN-04 below. |
| 5 | Mobile session controls | SLACK-ADMIN-06 | Evaluate the ordered first-match rules for SLACK-ADMIN-06 below. |
| 6 | File upload restrictions | SLACK-APP-06 | Evaluate the ordered first-match rules for SLACK-APP-06 below. |
| 7 | External sharing monitoring | SLACK-CHAN-01, SLACK-MON-05 | Evaluate the ordered first-match rules for SLACK-CHAN-01, SLACK-MON-05 below. |
| 8 | Information barriers | SLACK-APP-04 | Evaluate the ordered first-match rules for SLACK-APP-04 below. |
| 9 | Restricted app policy | SLACK-APP-01, SLACK-APP-02 | Evaluate the ordered first-match rules for SLACK-APP-01, SLACK-APP-02 below. |
| 10 | Custom and sensitive-scope apps | SLACK-APP-03 | Evaluate the ordered first-match rules for SLACK-APP-03 below. |
| 11 | DLP and Discovery evidence | SLACK-APP-05 | Evaluate the ordered first-match rules for SLACK-APP-05 below. |
| 12 | Channel retention overrides | SLACK-CHAN-03 | Evaluate the ordered first-match rules for SLACK-CHAN-03 below. |
| 13 | SIEM streaming evidence | SLACK-MON-01, SLACK-MON-02, SLACK-MON-03, SLACK-MON-04, SLACK-MON-06 | Evaluate the ordered first-match rules for SLACK-MON-01, SLACK-MON-02, SLACK-MON-03, SLACK-MON-04, SLACK-MON-06 below. |
| 14 | Workspace admin inventory | SLACK-ADMIN-01 | Evaluate the ordered first-match rules for SLACK-ADMIN-01 below. |
| 15 | Guest account inventory | SLACK-ID-02 | Evaluate the ordered first-match rules for SLACK-ID-02 below. |
| 16 | Email domain restrictions | SLACK-ADMIN-07 | Evaluate the ordered first-match rules for SLACK-ADMIN-07 below. |
| 17 | Workspace discoverability | SLACK-ADMIN-05 | Evaluate the ordered first-match rules for SLACK-ADMIN-05 below. |
| 18 | Channel posting restrictions | SLACK-CHAN-02 | Evaluate the ordered first-match rules for SLACK-CHAN-02 below. |
| 19 | Custom emoji governance | SLACK-ADMIN-08 | Evaluate the ordered first-match rules for SLACK-ADMIN-08 below. |
| 20 | External email ingestion | SLACK-CHAN-04 | Evaluate the ordered first-match rules for SLACK-CHAN-04 below. |
| 21 | Link previews and URL unfurling | SLACK-CHAN-05 | Evaluate the ordered first-match rules for SLACK-CHAN-05 below. |
| 22 | SCIM provisioning coverage | SLACK-ID-03 | Evaluate the ordered first-match rules for SLACK-ID-03 below. |
| 23 | Deactivated user visibility | SLACK-ID-04, SLACK-ID-05 | Evaluate the ordered first-match rules for SLACK-ID-04, SLACK-ID-05 below. |
| 24 | Workspace analytics access | SLACK-ADMIN-09 | Evaluate the ordered first-match rules for SLACK-ADMIN-09 below. |
| 25 | Token rotation and revocation | SLACK-APP-07 | Evaluate the ordered first-match rules for SLACK-APP-07 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `SLACK-ID-01` | critical | `slack_assess_identity` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for MFA enrollment; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for MFA enrollment, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of MFA enrollment; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for MFA enrollment is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ID-02` | medium | `slack_assess_identity` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Guest account inventory; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Guest account inventory, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Guest account inventory; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Guest account inventory is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ID-03` | high | `slack_assess_identity` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for SCIM provisioning coverage; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for SCIM provisioning coverage, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of SCIM provisioning coverage; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for SCIM provisioning coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ID-04` | high | `slack_assess_identity` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for User lifecycle alignment; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for User lifecycle alignment, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of User lifecycle alignment; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for User lifecycle alignment is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ID-05` | info | `slack_assess_identity` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Deactivated user visibility; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Deactivated user visibility, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Deactivated user visibility; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Deactivated user visibility is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ADMIN-01` | high | `slack_assess_admin_access` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Workspace admin inventory; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Workspace admin inventory, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Workspace admin inventory; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Workspace admin inventory is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ADMIN-02` | critical | `slack_assess_admin_access` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for SSO enforcement; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for SSO enforcement, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of SSO enforcement; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for SSO enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ADMIN-03` | high | `slack_assess_admin_access` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Session duration limits; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Session duration limits, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Session duration limits; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Session duration limits is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ADMIN-04` | medium | `slack_assess_admin_access` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Session idle timeout; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Session idle timeout, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Session idle timeout; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Session idle timeout is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ADMIN-05` | medium | `slack_assess_admin_access` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Workspace discoverability; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Workspace discoverability, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Workspace discoverability; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Workspace discoverability is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ADMIN-06` | medium | `slack_assess_admin_access` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Mobile session controls; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Mobile session controls, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Mobile session controls; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Mobile session controls is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ADMIN-07` | high | `slack_assess_admin_access` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Email domain restrictions; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Email domain restrictions, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Email domain restrictions; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Email domain restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ADMIN-08` | low | `slack_assess_admin_access` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Custom emoji governance; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Custom emoji governance, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Custom emoji governance; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Custom emoji governance is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-ADMIN-09` | medium | `slack_assess_admin_access` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Workspace analytics access; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Workspace analytics access, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Workspace analytics access; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Workspace analytics access is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-APP-01` | high | `slack_assess_integrations` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Approved app inventory; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Approved app inventory, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Approved app inventory; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Approved app inventory is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-APP-02` | medium | `slack_assess_integrations` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Restricted app policy; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Restricted app policy, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Restricted app policy; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Restricted app policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-APP-03` | medium | `slack_assess_integrations` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Custom and sensitive-scope apps; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Custom and sensitive-scope apps, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Custom and sensitive-scope apps; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Custom and sensitive-scope apps is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-APP-04` | high | `slack_assess_integrations` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Information barriers; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Information barriers, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Information barriers; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Information barriers is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-APP-05` | medium | `slack_assess_integrations` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for DLP and Discovery evidence; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for DLP and Discovery evidence, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of DLP and Discovery evidence; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for DLP and Discovery evidence is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-APP-06` | medium | `slack_assess_integrations` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for File upload restrictions; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for File upload restrictions, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of File upload restrictions; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for File upload restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-APP-07` | medium | `slack_assess_integrations` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Token rotation and revocation; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Token rotation and revocation, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Token rotation and revocation; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Token rotation and revocation is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-CHAN-01` | high | `slack_assess_channel_governance` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Slack Connect exposure; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Slack Connect exposure, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Slack Connect exposure; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Slack Connect exposure is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-CHAN-02` | medium | `slack_assess_channel_governance` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Channel posting restrictions; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Channel posting restrictions, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Channel posting restrictions; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Channel posting restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-CHAN-03` | medium | `slack_assess_channel_governance` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Channel retention overrides; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Channel retention overrides, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Channel retention overrides; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Channel retention overrides is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-CHAN-04` | medium | `slack_assess_channel_governance` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for External email ingestion; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for External email ingestion, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of External email ingestion; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for External email ingestion is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-CHAN-05` | medium | `slack_assess_channel_governance` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Link previews and URL unfurling; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Link previews and URL unfurling, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Link previews and URL unfurling; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Link previews and URL unfurling is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-MON-01` | critical | `slack_assess_monitoring` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Audit Logs API access; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Audit Logs API access, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Audit Logs API access; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Audit Logs API access is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-MON-02` | high | `slack_assess_monitoring` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Audit log recency; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Audit log recency, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Audit log recency; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Audit log recency is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-MON-03` | medium | `slack_assess_monitoring` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Security event visibility; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Security event visibility, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Security event visibility; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Security event visibility is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-MON-04` | low | `slack_assess_monitoring` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Audit schema visibility; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Audit schema visibility, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Audit schema visibility; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Audit schema visibility is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-MON-05` | medium | `slack_assess_monitoring` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for External sharing monitoring; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for External sharing monitoring, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of External sharing monitoring; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for External sharing monitoring is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SLACK-MON-06` | medium | `slack_assess_monitoring` | `users`, `admin-users`, `admin-apps`, `scim-users`, `audit-logs` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for SIEM streaming evidence; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for SIEM streaming evidence, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of SIEM streaming evidence; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for SIEM streaming evidence is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `SLACK-ID-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ID-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ID-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ID-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ID-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ID-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ID-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ID-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ID-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ID-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ID-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ID-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ID-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ID-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ID-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ID-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ID-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ID-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ID-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ID-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ADMIN-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ADMIN-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ADMIN-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ADMIN-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ADMIN-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ADMIN-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ADMIN-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ADMIN-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ADMIN-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ADMIN-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ADMIN-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ADMIN-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ADMIN-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ADMIN-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ADMIN-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ADMIN-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ADMIN-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ADMIN-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ADMIN-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ADMIN-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ADMIN-06` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ADMIN-06` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ADMIN-06` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ADMIN-06` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ADMIN-07` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ADMIN-07` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ADMIN-07` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ADMIN-07` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ADMIN-08` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ADMIN-08` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ADMIN-08` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ADMIN-08` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-ADMIN-09` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-ADMIN-09` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-ADMIN-09` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-ADMIN-09` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-APP-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-APP-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-APP-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-APP-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-APP-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-APP-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-APP-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-APP-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-APP-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-APP-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-APP-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-APP-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-APP-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-APP-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-APP-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-APP-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-APP-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-APP-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-APP-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-APP-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-APP-06` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-APP-06` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-APP-06` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-APP-06` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-APP-07` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-APP-07` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-APP-07` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-APP-07` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-CHAN-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-CHAN-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-CHAN-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-CHAN-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-CHAN-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-CHAN-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-CHAN-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-CHAN-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-CHAN-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-CHAN-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-CHAN-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-CHAN-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-CHAN-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-CHAN-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-CHAN-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-CHAN-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-CHAN-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-CHAN-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-CHAN-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-CHAN-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-MON-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-MON-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-MON-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-MON-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-MON-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-MON-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-MON-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-MON-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-MON-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-MON-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-MON-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-MON-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-MON-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-MON-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-MON-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-MON-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-MON-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-MON-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-MON-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-MON-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SLACK-MON-06` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SLACK-MON-06` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SLACK-MON-06` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SLACK-MON-06` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `SLACK-ID-01` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ID-02` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ID-03` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ID-04` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ID-05` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ADMIN-01` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ADMIN-02` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ADMIN-03` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ADMIN-04` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ADMIN-05` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ADMIN-06` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ADMIN-07` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ADMIN-08` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-ADMIN-09` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-APP-01` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-APP-02` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-APP-03` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-APP-04` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-APP-05` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-APP-06` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-APP-07` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-CHAN-01` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-CHAN-02` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-CHAN-03` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-CHAN-04` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-CHAN-05` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-MON-01` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-MON-02` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-MON-03` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-MON-04` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-MON-05` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SLACK-MON-06` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `SLACK-ID-01` | `passStatus` | pass |
| `SLACK-ID-01` | `warnStatus` | warn |
| `SLACK-ID-01` | `failStatus` | fail |
| `SLACK-ID-01` | `manualStatus` | manual |
| `SLACK-ID-02` | `passStatus` | pass |
| `SLACK-ID-02` | `warnStatus` | warn |
| `SLACK-ID-02` | `failStatus` | fail |
| `SLACK-ID-02` | `manualStatus` | manual |
| `SLACK-ID-03` | `passStatus` | pass |
| `SLACK-ID-03` | `warnStatus` | warn |
| `SLACK-ID-03` | `failStatus` | fail |
| `SLACK-ID-03` | `manualStatus` | manual |
| `SLACK-ID-04` | `passStatus` | pass |
| `SLACK-ID-04` | `warnStatus` | warn |
| `SLACK-ID-04` | `failStatus` | fail |
| `SLACK-ID-04` | `manualStatus` | manual |
| `SLACK-ID-05` | `passStatus` | pass |
| `SLACK-ID-05` | `warnStatus` | warn |
| `SLACK-ID-05` | `failStatus` | fail |
| `SLACK-ID-05` | `manualStatus` | manual |
| `SLACK-ADMIN-01` | `passStatus` | pass |
| `SLACK-ADMIN-01` | `warnStatus` | warn |
| `SLACK-ADMIN-01` | `failStatus` | fail |
| `SLACK-ADMIN-01` | `manualStatus` | manual |
| `SLACK-ADMIN-02` | `passStatus` | pass |
| `SLACK-ADMIN-02` | `warnStatus` | warn |
| `SLACK-ADMIN-02` | `failStatus` | fail |
| `SLACK-ADMIN-02` | `manualStatus` | manual |
| `SLACK-ADMIN-03` | `passStatus` | pass |
| `SLACK-ADMIN-03` | `warnStatus` | warn |
| `SLACK-ADMIN-03` | `failStatus` | fail |
| `SLACK-ADMIN-03` | `manualStatus` | manual |
| `SLACK-ADMIN-04` | `passStatus` | pass |
| `SLACK-ADMIN-04` | `warnStatus` | warn |
| `SLACK-ADMIN-04` | `failStatus` | fail |
| `SLACK-ADMIN-04` | `manualStatus` | manual |
| `SLACK-ADMIN-05` | `passStatus` | pass |
| `SLACK-ADMIN-05` | `warnStatus` | warn |
| `SLACK-ADMIN-05` | `failStatus` | fail |
| `SLACK-ADMIN-05` | `manualStatus` | manual |
| `SLACK-ADMIN-06` | `passStatus` | pass |
| `SLACK-ADMIN-06` | `warnStatus` | warn |
| `SLACK-ADMIN-06` | `failStatus` | fail |
| `SLACK-ADMIN-06` | `manualStatus` | manual |
| `SLACK-ADMIN-07` | `passStatus` | pass |
| `SLACK-ADMIN-07` | `warnStatus` | warn |
| `SLACK-ADMIN-07` | `failStatus` | fail |
| `SLACK-ADMIN-07` | `manualStatus` | manual |
| `SLACK-ADMIN-08` | `passStatus` | pass |
| `SLACK-ADMIN-08` | `warnStatus` | warn |
| `SLACK-ADMIN-08` | `failStatus` | fail |
| `SLACK-ADMIN-08` | `manualStatus` | manual |
| `SLACK-ADMIN-09` | `passStatus` | pass |
| `SLACK-ADMIN-09` | `warnStatus` | warn |
| `SLACK-ADMIN-09` | `failStatus` | fail |
| `SLACK-ADMIN-09` | `manualStatus` | manual |
| `SLACK-APP-01` | `passStatus` | pass |
| `SLACK-APP-01` | `warnStatus` | warn |
| `SLACK-APP-01` | `failStatus` | fail |
| `SLACK-APP-01` | `manualStatus` | manual |
| `SLACK-APP-02` | `passStatus` | pass |
| `SLACK-APP-02` | `warnStatus` | warn |
| `SLACK-APP-02` | `failStatus` | fail |
| `SLACK-APP-02` | `manualStatus` | manual |
| `SLACK-APP-03` | `passStatus` | pass |
| `SLACK-APP-03` | `warnStatus` | warn |
| `SLACK-APP-03` | `failStatus` | fail |
| `SLACK-APP-03` | `manualStatus` | manual |
| `SLACK-APP-04` | `passStatus` | pass |
| `SLACK-APP-04` | `warnStatus` | warn |
| `SLACK-APP-04` | `failStatus` | fail |
| `SLACK-APP-04` | `manualStatus` | manual |
| `SLACK-APP-05` | `passStatus` | pass |
| `SLACK-APP-05` | `warnStatus` | warn |
| `SLACK-APP-05` | `failStatus` | fail |
| `SLACK-APP-05` | `manualStatus` | manual |
| `SLACK-APP-06` | `passStatus` | pass |
| `SLACK-APP-06` | `warnStatus` | warn |
| `SLACK-APP-06` | `failStatus` | fail |
| `SLACK-APP-06` | `manualStatus` | manual |
| `SLACK-APP-07` | `passStatus` | pass |
| `SLACK-APP-07` | `warnStatus` | warn |
| `SLACK-APP-07` | `failStatus` | fail |
| `SLACK-APP-07` | `manualStatus` | manual |
| `SLACK-CHAN-01` | `passStatus` | pass |
| `SLACK-CHAN-01` | `warnStatus` | warn |
| `SLACK-CHAN-01` | `failStatus` | fail |
| `SLACK-CHAN-01` | `manualStatus` | manual |
| `SLACK-CHAN-02` | `passStatus` | pass |
| `SLACK-CHAN-02` | `warnStatus` | warn |
| `SLACK-CHAN-02` | `failStatus` | fail |
| `SLACK-CHAN-02` | `manualStatus` | manual |
| `SLACK-CHAN-03` | `passStatus` | pass |
| `SLACK-CHAN-03` | `warnStatus` | warn |
| `SLACK-CHAN-03` | `failStatus` | fail |
| `SLACK-CHAN-03` | `manualStatus` | manual |
| `SLACK-CHAN-04` | `passStatus` | pass |
| `SLACK-CHAN-04` | `warnStatus` | warn |
| `SLACK-CHAN-04` | `failStatus` | fail |
| `SLACK-CHAN-04` | `manualStatus` | manual |
| `SLACK-CHAN-05` | `passStatus` | pass |
| `SLACK-CHAN-05` | `warnStatus` | warn |
| `SLACK-CHAN-05` | `failStatus` | fail |
| `SLACK-CHAN-05` | `manualStatus` | manual |
| `SLACK-MON-01` | `passStatus` | pass |
| `SLACK-MON-01` | `warnStatus` | warn |
| `SLACK-MON-01` | `failStatus` | fail |
| `SLACK-MON-01` | `manualStatus` | manual |
| `SLACK-MON-02` | `passStatus` | pass |
| `SLACK-MON-02` | `warnStatus` | warn |
| `SLACK-MON-02` | `failStatus` | fail |
| `SLACK-MON-02` | `manualStatus` | manual |
| `SLACK-MON-03` | `passStatus` | pass |
| `SLACK-MON-03` | `warnStatus` | warn |
| `SLACK-MON-03` | `failStatus` | fail |
| `SLACK-MON-03` | `manualStatus` | manual |
| `SLACK-MON-04` | `passStatus` | pass |
| `SLACK-MON-04` | `warnStatus` | warn |
| `SLACK-MON-04` | `failStatus` | fail |
| `SLACK-MON-04` | `manualStatus` | manual |
| `SLACK-MON-05` | `passStatus` | pass |
| `SLACK-MON-05` | `warnStatus` | warn |
| `SLACK-MON-05` | `failStatus` | fail |
| `SLACK-MON-05` | `manualStatus` | manual |
| `SLACK-MON-06` | `passStatus` | pass |
| `SLACK-MON-06` | `warnStatus` | warn |
| `SLACK-MON-06` | `failStatus` | fail |
| `SLACK-MON-06` | `manualStatus` | manual |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `SLACK-ID-01` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ID-01` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ID-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ID-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ID-02` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ID-02` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ID-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ID-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ID-03` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ID-03` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ID-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ID-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ID-04` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ID-04` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ID-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ID-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ID-05` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ID-05` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ID-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ID-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ADMIN-01` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ADMIN-01` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ADMIN-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ADMIN-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ADMIN-02` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ADMIN-02` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ADMIN-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ADMIN-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ADMIN-03` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ADMIN-03` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ADMIN-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ADMIN-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ADMIN-04` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ADMIN-04` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ADMIN-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ADMIN-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ADMIN-05` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ADMIN-05` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ADMIN-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ADMIN-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ADMIN-06` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ADMIN-06` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ADMIN-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ADMIN-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ADMIN-07` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ADMIN-07` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ADMIN-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ADMIN-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ADMIN-08` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ADMIN-08` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ADMIN-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ADMIN-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-ADMIN-09` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-ADMIN-09` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-ADMIN-09` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-ADMIN-09` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-APP-01` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-APP-01` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-APP-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-APP-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-APP-02` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-APP-02` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-APP-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-APP-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-APP-03` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-APP-03` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-APP-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-APP-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-APP-04` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-APP-04` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-APP-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-APP-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-APP-05` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-APP-05` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-APP-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-APP-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-APP-06` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-APP-06` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-APP-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-APP-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-APP-07` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-APP-07` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-APP-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-APP-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-CHAN-01` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-CHAN-01` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-CHAN-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-CHAN-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-CHAN-02` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-CHAN-02` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-CHAN-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-CHAN-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-CHAN-03` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-CHAN-03` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-CHAN-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-CHAN-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-CHAN-04` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-CHAN-04` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-CHAN-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-CHAN-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-CHAN-05` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-CHAN-05` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-CHAN-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-CHAN-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-MON-01` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-MON-01` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-MON-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-MON-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-MON-02` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-MON-02` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-MON-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-MON-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-MON-03` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-MON-03` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-MON-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-MON-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-MON-04` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-MON-04` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-MON-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-MON-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-MON-05` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-MON-05` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-MON-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-MON-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SLACK-MON-06` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SLACK-MON-06` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SLACK-MON-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SLACK-MON-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | SSO enforcement | - | - | - | - | - | - | - | - |
| 2 | MFA enrollment | - | - | - | - | - | - | - | - |
| 3 | Session duration limits | - | - | - | - | - | - | - | - |
| 4 | Session idle timeout | - | - | - | - | - | - | - | - |
| 5 | Mobile session controls | - | - | - | - | - | - | - | - |
| 6 | File upload restrictions | - | - | - | - | - | - | - | - |
| 7 | External sharing monitoring | - | - | - | - | - | - | - | - |
| 8 | Information barriers | - | - | - | - | - | - | - | - |
| 9 | Restricted app policy | - | - | - | - | - | - | - | - |
| 10 | Custom and sensitive-scope apps | - | - | - | - | - | - | - | - |
| 11 | DLP and Discovery evidence | - | - | - | - | - | - | - | - |
| 12 | Channel retention overrides | - | - | - | - | - | - | - | - |
| 13 | SIEM streaming evidence | - | - | - | - | - | - | - | - |
| 14 | Workspace admin inventory | - | - | - | - | - | - | - | - |
| 15 | Guest account inventory | - | - | - | - | - | - | - | - |
| 16 | Email domain restrictions | - | - | - | - | - | - | - | - |
| 17 | Workspace discoverability | - | - | - | - | - | - | - | - |
| 18 | Channel posting restrictions | - | - | - | - | - | - | - | - |
| 19 | Custom emoji governance | - | - | - | - | - | - | - | - |
| 20 | External email ingestion | - | - | - | - | - | - | - | - |
| 21 | Link previews and URL unfurling | - | - | - | - | - | - | - | - |
| 22 | SCIM provisioning coverage | - | - | - | - | - | - | - | - |
| 23 | Deactivated user visibility | - | - | - | - | - | - | - | - |
| 24 | Workspace analytics access | - | - | - | - | - | - | - | - |
| 25 | Token rotation and revocation | - | - | - | - | - | - | - | - |

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

Sensitive fields and values: token, scimToken, authorization, cookie, webhook_url

Credential formats: xoxb, xoxp, xoxe, and xapp token families, SCIM bearer tokens, webhook path secrets

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `users` | `id`, `deleted`, `is_admin`, `is_owner`, `is_restricted`, `has_2fa`, `has_sso` |
| `admin-users` | `id`, `team_id`, `email`, `is_admin`, `is_owner` |
| `admin-apps` | `app_id`, `name`, `scopes`, `is_internal` |
| `scim-users` | `id`, `userName`, `active`, `groups` |
| `audit-logs` | `id`, `date_create`, `action`, `actor`, `entity`, `context` |

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

Archive pairing: Create slack-audit.zip beside the allocated slack-audit directory, applying the same suffix to both.
