---
slug: "zendesk-sec-inspector"
name: "Zendesk Security Inspector"
vendor: "Zendesk"
category: "customer-support"
language: "language-neutral"
status: "generated"
version: "1.0.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# Zendesk Security Inspector

Portable contract for the shipped Zendesk authentication, access-control, data-protection, and integration assessments.

## Purpose

Assess Zendesk Support authentication, team-member access, data protection, auditability, application, brand, and external-delivery posture.

## Design guidance

Use only current API-token or OAuth authentication. Keep admin and Enterprise plan gates explicit, and do not infer HIPAA, anonymous-ticket, or attachment-type settings from nearby account fields when the public API lacks a decisive read.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- Cursor pagination is preferred and offset pagination is retained defensively; both deduplicate stable record IDs and mark cap, repeated-link, and inconsistent-total exits partial.
- Admin-only, Enterprise-only, and plan-gated reads produce explicit manual findings with endpoint and evidence instructions; forbidden evidence never becomes an empty pass.
- HIPAA mode, allowed attachment types, and anonymous-ticket posture have no decisive published read field and remain manual.
- Guide, Talk, Chat, Sell, and real-tenant validation remain outside the shipped scope.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `zendesk_check_access` | Validate read-only Zendesk Support API access across account settings, team members, custom roles, groups, audit logs, OAuth clients and tokens, apps, brands, webhooks, targets, triggers, automations, sharing agreements, and suspended tickets, reporting which admin-only surfaces the credential cannot read. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zendesk_assess_authentication` | Assess Zendesk authentication controls (spec controls 1-5 and 21) from the admin-only Security Settings endpoint plus documented user flags: SSO enforcement, account-level two-factor enforcement and per-agent enrollment, team member password policy, IP restrictions, session expiration, and end-user authentication methods. Forbidden endpoints render as manual findings naming the Admin Center evidence. | `ZD-01`, `ZD-02`, `ZD-03`, `ZD-04`, `ZD-05`, `ZD-21` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zendesk_assess_access_control` | Assess Zendesk access control (spec controls 6-8, 13, 14): least-privilege custom roles, admin count and dormant admins, group segmentation, API token exposure with token creation and deletion events enumerated from the audit log, and OAuth client scope and token hygiene, with partial or truncated inventories downgraded instead of passing. | `ZD-06`, `ZD-07`, `ZD-08`, `ZD-13`, `ZD-14` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zendesk_assess_data_protection` | Assess Zendesk audit logging and data protection (spec controls 9-12, 18-20): audit log availability and retention (Enterprise), HIPAA mode, active deletion schedules by object plus redaction permissions, authenticated attachment downloads, attachment limits, and suspended ticket backlog age. | `ZD-09`, `ZD-10`, `ZD-11`, `ZD-12`, `ZD-18`, `ZD-19`, `ZD-20` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zendesk_assess_integrations` | Assess Zendesk apps, brands, and external communications (spec controls 15-17, 22-25): marketplace and private app inventories, sandbox provisioning, cross-brand help center consistency, sharing agreements, https-only targets and webhooks, and trigger or automation actions that send ticket data externally. | `ZD-15`, `ZD-16`, `ZD-17`, `ZD-22`, `ZD-23`, `ZD-24`, `ZD-25` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zendesk_export_audit_bundle` | Export a Zendesk audit bundle with raw API snapshots (core_data/), normalized findings (analysis/), an executive summary, a unified compliance matrix, per-framework reports (compliance/), a QUICK_REFERENCE.md, an _errors.log when collection was partial, and a paired .zip archive. Reruns allocate a new directory instead of overwriting. | `ZD-01`, `ZD-02`, `ZD-03`, `ZD-04`, `ZD-05`, `ZD-06`, `ZD-07`, `ZD-08`, `ZD-09`, `ZD-10`, `ZD-11`, `ZD-12`, `ZD-13`, `ZD-14`, `ZD-15`, `ZD-16`, `ZD-17`, `ZD-18`, `ZD-19`, `ZD-20`, `ZD-21`, `ZD-22`, `ZD-23`, `ZD-24`, `ZD-25` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `zendesk_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `subdomain` | string | no | Zendesk subdomain (the {subdomain} in https://{subdomain}.zendesk.com). Defaults to ZENDESK_SUBDOMAIN or the config file. |
| `email` | string | no | Email of the admin or agent that owns the API token. Defaults to ZENDESK_EMAIL. |
| `api_token` | string | no | Zendesk API token used with email as Basic auth ({email}/token:{api_token}). Defaults to ZENDESK_API_TOKEN. |
| `oauth_token` | string | no | Zendesk OAuth access token (Bearer). Defaults to ZENDESK_OAUTH_TOKEN. Preferred over API tokens, which Zendesk is retiring. |
| `base_url` | string | no | API base URL override. Defaults to https://{subdomain}.zendesk.com/api/v2. |
| `config_file` | string | no | JSON config file with subdomain, email, api_token, or oauth_token keys. Defaults to ZENDESK_CONFIG_FILE or ~/.zendesk/config.json. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |

#### `zendesk_assess_authentication`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `subdomain` | string | no | Zendesk subdomain (the {subdomain} in https://{subdomain}.zendesk.com). Defaults to ZENDESK_SUBDOMAIN or the config file. |
| `email` | string | no | Email of the admin or agent that owns the API token. Defaults to ZENDESK_EMAIL. |
| `api_token` | string | no | Zendesk API token used with email as Basic auth ({email}/token:{api_token}). Defaults to ZENDESK_API_TOKEN. |
| `oauth_token` | string | no | Zendesk OAuth access token (Bearer). Defaults to ZENDESK_OAUTH_TOKEN. Preferred over API tokens, which Zendesk is retiring. |
| `base_url` | string | no | API base URL override. Defaults to https://{subdomain}.zendesk.com/api/v2. |
| `config_file` | string | no | JSON config file with subdomain, email, api_token, or oauth_token keys. Defaults to ZENDESK_CONFIG_FILE or ~/.zendesk/config.json. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `admin_threshold` | number | no | Maximum acceptable number of admins before failing control 7. Defaults to 5. |
| `suspended_ticket_age_days` | number | no | Suspended tickets older than this many days are flagged. Defaults to 30. |
| `stale_days` | number | no | Days without sign-in or token use before an admin or token counts as dormant. Defaults to 90. |
| `retention_days` | number | no | Required audit log retention in days. Defaults to 365. |
| `session_timeout_minutes` | number | no | Maximum acceptable team member inactivity timeout in minutes for control 5. Defaults to 480. |
| `max_items` | number | no | Maximum items to page through per inventory before recording truncation. Defaults to 2000. |

#### `zendesk_assess_access_control`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `subdomain` | string | no | Zendesk subdomain (the {subdomain} in https://{subdomain}.zendesk.com). Defaults to ZENDESK_SUBDOMAIN or the config file. |
| `email` | string | no | Email of the admin or agent that owns the API token. Defaults to ZENDESK_EMAIL. |
| `api_token` | string | no | Zendesk API token used with email as Basic auth ({email}/token:{api_token}). Defaults to ZENDESK_API_TOKEN. |
| `oauth_token` | string | no | Zendesk OAuth access token (Bearer). Defaults to ZENDESK_OAUTH_TOKEN. Preferred over API tokens, which Zendesk is retiring. |
| `base_url` | string | no | API base URL override. Defaults to https://{subdomain}.zendesk.com/api/v2. |
| `config_file` | string | no | JSON config file with subdomain, email, api_token, or oauth_token keys. Defaults to ZENDESK_CONFIG_FILE or ~/.zendesk/config.json. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `admin_threshold` | number | no | Maximum acceptable number of admins before failing control 7. Defaults to 5. |
| `suspended_ticket_age_days` | number | no | Suspended tickets older than this many days are flagged. Defaults to 30. |
| `stale_days` | number | no | Days without sign-in or token use before an admin or token counts as dormant. Defaults to 90. |
| `retention_days` | number | no | Required audit log retention in days. Defaults to 365. |
| `session_timeout_minutes` | number | no | Maximum acceptable team member inactivity timeout in minutes for control 5. Defaults to 480. |
| `max_items` | number | no | Maximum items to page through per inventory before recording truncation. Defaults to 2000. |

#### `zendesk_assess_data_protection`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `subdomain` | string | no | Zendesk subdomain (the {subdomain} in https://{subdomain}.zendesk.com). Defaults to ZENDESK_SUBDOMAIN or the config file. |
| `email` | string | no | Email of the admin or agent that owns the API token. Defaults to ZENDESK_EMAIL. |
| `api_token` | string | no | Zendesk API token used with email as Basic auth ({email}/token:{api_token}). Defaults to ZENDESK_API_TOKEN. |
| `oauth_token` | string | no | Zendesk OAuth access token (Bearer). Defaults to ZENDESK_OAUTH_TOKEN. Preferred over API tokens, which Zendesk is retiring. |
| `base_url` | string | no | API base URL override. Defaults to https://{subdomain}.zendesk.com/api/v2. |
| `config_file` | string | no | JSON config file with subdomain, email, api_token, or oauth_token keys. Defaults to ZENDESK_CONFIG_FILE or ~/.zendesk/config.json. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `admin_threshold` | number | no | Maximum acceptable number of admins before failing control 7. Defaults to 5. |
| `suspended_ticket_age_days` | number | no | Suspended tickets older than this many days are flagged. Defaults to 30. |
| `stale_days` | number | no | Days without sign-in or token use before an admin or token counts as dormant. Defaults to 90. |
| `retention_days` | number | no | Required audit log retention in days. Defaults to 365. |
| `session_timeout_minutes` | number | no | Maximum acceptable team member inactivity timeout in minutes for control 5. Defaults to 480. |
| `max_items` | number | no | Maximum items to page through per inventory before recording truncation. Defaults to 2000. |

#### `zendesk_assess_integrations`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `subdomain` | string | no | Zendesk subdomain (the {subdomain} in https://{subdomain}.zendesk.com). Defaults to ZENDESK_SUBDOMAIN or the config file. |
| `email` | string | no | Email of the admin or agent that owns the API token. Defaults to ZENDESK_EMAIL. |
| `api_token` | string | no | Zendesk API token used with email as Basic auth ({email}/token:{api_token}). Defaults to ZENDESK_API_TOKEN. |
| `oauth_token` | string | no | Zendesk OAuth access token (Bearer). Defaults to ZENDESK_OAUTH_TOKEN. Preferred over API tokens, which Zendesk is retiring. |
| `base_url` | string | no | API base URL override. Defaults to https://{subdomain}.zendesk.com/api/v2. |
| `config_file` | string | no | JSON config file with subdomain, email, api_token, or oauth_token keys. Defaults to ZENDESK_CONFIG_FILE or ~/.zendesk/config.json. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `admin_threshold` | number | no | Maximum acceptable number of admins before failing control 7. Defaults to 5. |
| `suspended_ticket_age_days` | number | no | Suspended tickets older than this many days are flagged. Defaults to 30. |
| `stale_days` | number | no | Days without sign-in or token use before an admin or token counts as dormant. Defaults to 90. |
| `retention_days` | number | no | Required audit log retention in days. Defaults to 365. |
| `session_timeout_minutes` | number | no | Maximum acceptable team member inactivity timeout in minutes for control 5. Defaults to 480. |
| `max_items` | number | no | Maximum items to page through per inventory before recording truncation. Defaults to 2000. |

#### `zendesk_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `subdomain` | string | no | Zendesk subdomain (the {subdomain} in https://{subdomain}.zendesk.com). Defaults to ZENDESK_SUBDOMAIN or the config file. |
| `email` | string | no | Email of the admin or agent that owns the API token. Defaults to ZENDESK_EMAIL. |
| `api_token` | string | no | Zendesk API token used with email as Basic auth ({email}/token:{api_token}). Defaults to ZENDESK_API_TOKEN. |
| `oauth_token` | string | no | Zendesk OAuth access token (Bearer). Defaults to ZENDESK_OAUTH_TOKEN. Preferred over API tokens, which Zendesk is retiring. |
| `base_url` | string | no | API base URL override. Defaults to https://{subdomain}.zendesk.com/api/v2. |
| `config_file` | string | no | JSON config file with subdomain, email, api_token, or oauth_token keys. Defaults to ZENDESK_CONFIG_FILE or ~/.zendesk/config.json. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `admin_threshold` | number | no | Maximum acceptable number of admins before failing control 7. Defaults to 5. |
| `suspended_ticket_age_days` | number | no | Suspended tickets older than this many days are flagged. Defaults to 30. |
| `stale_days` | number | no | Days without sign-in or token use before an admin or token counts as dormant. Defaults to 90. |
| `retention_days` | number | no | Required audit log retention in days. Defaults to 365. |
| `session_timeout_minutes` | number | no | Maximum acceptable team member inactivity timeout in minutes for control 5. Defaults to 480. |
| `max_items` | number | no | Maximum items to page through per inventory before recording truncation. Defaults to 2000. |
| `output_dir` | string | no | Output root. Defaults to ./export/zendesk. |


## Authentication

Supported modes:

- API token with email Basic authentication
- OAuth bearer token

Credential precedence, highest first:

1. Explicit OAuth token
2. Explicit API token and email
3. Explicit config file
4. ZENDESK_* environment variables

Environment variables: `ZENDESK_SUBDOMAIN`, `ZENDESK_EMAIL`, `ZENDESK_API_TOKEN`, `ZENDESK_OAUTH_TOKEN`, `ZENDESK_CONFIG_FILE`

Configuration locations: ~/.zendesk/config.json

Credential and deployment variants: Zendesk subdomain or explicit same-origin API base URL

Configuration fields: `subdomain`, `email`, `apiToken`, `oauthToken`, `baseUrl`, `timeoutMs`

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| role | `Zendesk administrator API access` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `Enterprise audit-log and custom-role entitlements` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `OAuth read scope` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `security-settings` | HTTP | `GET /api/v2/security_settings` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sso`, `two_factor_authentication`, `password_policy`, `ip_restrictions`, `session_expiration` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/account-configuration/security_settings/) |
| `users` | HTTP | `GET /api/v2/users` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `email`, `role`, `custom_role_id`, `active`, `suspended`, `last_login_at` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/users/users/) |
| `audit-logs` | HTTP | `GET /api/v2/audit_logs` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `created_at`, `action`, `source_type`, `source_id`, `actor_id` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/account-configuration/audit_logs/) |
| `deletion-schedules` | HTTP | `GET /api/v2/deletion_schedules` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `title`, `status`, `object_type`, `retention_period` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/account-configuration/data-deletion-schedules/) |
| `apps-and-webhooks` | HTTP | `GET /api/v2/apps/installations` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `app_id`, `enabled`, `settings`, `url` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/apps/apps/) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `security-settings` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `security-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `security-settings` | response | A JSON object or list containing only the documented sso, two_factor_authentication, password_policy, ip_restrictions, session_expiration members consumed by verdicts. | yes |
| `users` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `users` | response | A JSON object or list containing only the documented id, email, role, custom_role_id, active, suspended, last_login_at members consumed by verdicts. | yes |
| `audit-logs` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `audit-logs` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `audit-logs` | response | A JSON object or list containing only the documented id, created_at, action, source_type, source_id, actor_id members consumed by verdicts. | yes |
| `deletion-schedules` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `deletion-schedules` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `deletion-schedules` | response | A JSON object or list containing only the documented id, title, status, object_type, retention_period members consumed by verdicts. | yes |
| `apps-and-webhooks` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `apps-and-webhooks` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `apps-and-webhooks` | response | A JSON object or list containing only the documented id, app_id, enabled, settings, url members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `meta.has_more`, `links.next`, `next_page`, `count` | 100 | 2000 | none | Cursor exhaustion or offset count equality proves completeness; missing or larger totals keep the dataset partial. | has_more false or no next page; Declared total reached; Configured item cap; Repeated next link; Empty page with continuation; Rejected cross-origin next link |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Zendesk Security Inspector | 400 requests/minute on Team and 700 requests/minute on Professional or Enterprise by default | `Retry-After`, `X-Rate-Limit`, `X-Rate-Limit-Remaining` | 429, 500, 502, 503, 504 | Honor bounded Retry-After and retry transient failures; expose exhausted reads without copying response bodies. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | SSO enforcement enabled | ZD-01 | Evaluate the ordered first-match rules for ZD-01 below. |
| 2 | Two-factor authentication required for agents | ZD-02 | Evaluate the ordered first-match rules for ZD-02 below. |
| 3 | Password policy meets complexity requirements | ZD-03 | Evaluate the ordered first-match rules for ZD-03 below. |
| 4 | IP restrictions configured for agent access | ZD-04 | Evaluate the ordered first-match rules for ZD-04 below. |
| 5 | Session timeout configured and reasonable | ZD-05 | Evaluate the ordered first-match rules for ZD-05 below. |
| 6 | Agent roles follow least privilege | ZD-06 | Evaluate the ordered first-match rules for ZD-06 below. |
| 7 | No excessive admin accounts | ZD-07 | Evaluate the ordered first-match rules for ZD-07 below. |
| 8 | Group-based access controls configured | ZD-08 | Evaluate the ordered first-match rules for ZD-08 below. |
| 9 | Audit logging enabled and accessible | ZD-09 | Evaluate the ordered first-match rules for ZD-09 below. |
| 10 | Audit log retention meets compliance requirements | ZD-10 | Evaluate the ordered first-match rules for ZD-10 below. |
| 11 | HIPAA compliance mode enabled when applicable | ZD-11 | Evaluate the ordered first-match rules for ZD-11 below. |
| 12 | Data deletion and redaction policies configured | ZD-12 | Evaluate the ordered first-match rules for ZD-12 below. |
| 13 | API tokens are minimal and reviewed | ZD-13 | Evaluate the ordered first-match rules for ZD-13 below. |
| 14 | OAuth application permissions are scoped | ZD-14 | Evaluate the ordered first-match rules for ZD-14 below. |
| 15 | Marketplace apps reviewed for permissions | ZD-15 | Evaluate the ordered first-match rules for ZD-15 below. |
| 16 | Private and custom apps have appropriate scope | ZD-16 | Evaluate the ordered first-match rules for ZD-16 below. |
| 17 | Sandbox environment used for testing | ZD-17 | Evaluate the ordered first-match rules for ZD-17 below. |
| 18 | Authenticated attachment downloads configured | ZD-18 | Evaluate the ordered first-match rules for ZD-18 below. |
| 19 | File attachment restrictions configured | ZD-19 | Evaluate the ordered first-match rules for ZD-19 below. |
| 20 | Suspended ticket handling automated | ZD-20 | Evaluate the ordered first-match rules for ZD-20 below. |
| 21 | End-user authentication required | ZD-21 | Evaluate the ordered first-match rules for ZD-21 below. |
| 22 | Brand security settings consistent | ZD-22 | Evaluate the ordered first-match rules for ZD-22 below. |
| 23 | External sharing agreements reviewed | ZD-23 | Evaluate the ordered first-match rules for ZD-23 below. |
| 24 | External notification targets use HTTPS | ZD-24 | Evaluate the ordered first-match rules for ZD-24 below. |
| 25 | Triggers and automations do not send data to external URLs | ZD-25 | Evaluate the ordered first-match rules for ZD-25 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `ZD-01` | critical | `zendesk_assess_authentication` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for SSO enforcement enabled; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for SSO enforcement enabled, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of SSO enforcement enabled; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for SSO enforcement enabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-02` | critical | `zendesk_assess_authentication` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Two-factor authentication required for agents; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Two-factor authentication required for agents, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Two-factor authentication required for agents; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Two-factor authentication required for agents is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-03` | high | `zendesk_assess_authentication` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Password policy meets complexity requirements; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Password policy meets complexity requirements, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Password policy meets complexity requirements; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Password policy meets complexity requirements is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-04` | high | `zendesk_assess_authentication` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for IP restrictions configured for agent access; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for IP restrictions configured for agent access, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of IP restrictions configured for agent access; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for IP restrictions configured for agent access is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-05` | medium | `zendesk_assess_authentication` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Session timeout configured and reasonable; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Session timeout configured and reasonable, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Session timeout configured and reasonable; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Session timeout configured and reasonable is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-06` | critical | `zendesk_assess_access_control` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Agent roles follow least privilege; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Agent roles follow least privilege, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Agent roles follow least privilege; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Agent roles follow least privilege is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-07` | high | `zendesk_assess_access_control` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for No excessive admin accounts; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for No excessive admin accounts, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of No excessive admin accounts; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for No excessive admin accounts is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-08` | medium | `zendesk_assess_access_control` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Group-based access controls configured; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Group-based access controls configured, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Group-based access controls configured; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Group-based access controls configured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-09` | high | `zendesk_assess_data_protection` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Audit logging enabled and accessible; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Audit logging enabled and accessible, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Audit logging enabled and accessible; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Audit logging enabled and accessible is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-10` | medium | `zendesk_assess_data_protection` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Audit log retention meets compliance requirements; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Audit log retention meets compliance requirements, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Audit log retention meets compliance requirements; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Audit log retention meets compliance requirements is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-11` | critical | `zendesk_assess_data_protection` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for HIPAA compliance mode enabled when applicable; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for HIPAA compliance mode enabled when applicable, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of HIPAA compliance mode enabled when applicable; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for HIPAA compliance mode enabled when applicable is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-12` | high | `zendesk_assess_data_protection` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Data deletion and redaction policies configured; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Data deletion and redaction policies configured, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Data deletion and redaction policies configured; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Data deletion and redaction policies configured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-13` | high | `zendesk_assess_access_control` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for API tokens are minimal and reviewed; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for API tokens are minimal and reviewed, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of API tokens are minimal and reviewed; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for API tokens are minimal and reviewed is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-14` | high | `zendesk_assess_access_control` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for OAuth application permissions are scoped; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for OAuth application permissions are scoped, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of OAuth application permissions are scoped; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for OAuth application permissions are scoped is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-15` | medium | `zendesk_assess_integrations` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Marketplace apps reviewed for permissions; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Marketplace apps reviewed for permissions, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Marketplace apps reviewed for permissions; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Marketplace apps reviewed for permissions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-16` | medium | `zendesk_assess_integrations` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Private and custom apps have appropriate scope; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Private and custom apps have appropriate scope, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Private and custom apps have appropriate scope; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Private and custom apps have appropriate scope is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-17` | medium | `zendesk_assess_integrations` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Sandbox environment used for testing; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Sandbox environment used for testing, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Sandbox environment used for testing; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Sandbox environment used for testing is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-18` | medium | `zendesk_assess_data_protection` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Authenticated attachment downloads configured; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Authenticated attachment downloads configured, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Authenticated attachment downloads configured; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Authenticated attachment downloads configured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-19` | medium | `zendesk_assess_data_protection` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for File attachment restrictions configured; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for File attachment restrictions configured, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of File attachment restrictions configured; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for File attachment restrictions configured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-20` | medium | `zendesk_assess_data_protection` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Suspended ticket handling automated; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Suspended ticket handling automated, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Suspended ticket handling automated; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Suspended ticket handling automated is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-21` | high | `zendesk_assess_authentication` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for End-user authentication required; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for End-user authentication required, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of End-user authentication required; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for End-user authentication required is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-22` | medium | `zendesk_assess_integrations` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Brand security settings consistent; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Brand security settings consistent, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Brand security settings consistent; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Brand security settings consistent is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-23` | medium | `zendesk_assess_integrations` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for External sharing agreements reviewed; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for External sharing agreements reviewed, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of External sharing agreements reviewed; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for External sharing agreements reviewed is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-24` | high | `zendesk_assess_integrations` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for External notification targets use HTTPS; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for External notification targets use HTTPS, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of External notification targets use HTTPS; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for External notification targets use HTTPS is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-25` | high | `zendesk_assess_integrations` | `security-settings`, `users`, `audit-logs`, `deletion-schedules`, `apps-and-webhooks` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Triggers and automations do not send data to external URLs; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Triggers and automations do not send data to external URLs, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Triggers and automations do not send data to external URLs; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Triggers and automations do not send data to external URLs is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `ZD-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-06` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-06` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-06` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-06` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-07` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-07` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-07` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-07` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-08` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-08` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-08` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-08` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-09` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-09` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-09` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-09` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-10` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-10` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-10` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-10` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-11` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-11` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-11` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-11` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-12` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-12` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-12` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-12` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-13` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-13` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-13` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-13` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-14` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-14` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-14` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-14` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-15` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-15` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-15` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-15` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-16` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-16` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-16` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-16` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-17` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-17` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-17` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-17` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-18` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-18` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-18` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-18` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-19` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-19` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-19` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-19` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-20` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-20` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-20` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-20` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-21` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-21` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-21` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-21` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-22` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-22` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-22` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-22` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-23` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-23` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-23` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-23` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-24` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-24` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-24` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-24` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `ZD-25` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `ZD-25` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `ZD-25` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `ZD-25` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `ZD-01` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-02` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-03` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-04` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-05` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-06` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-07` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-08` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-09` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-10` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-11` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-12` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-13` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-14` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-15` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-16` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-17` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-18` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-19` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-20` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-21` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-22` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-23` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-24` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `ZD-25` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `ZD-01` | `passStatus` | pass |
| `ZD-01` | `warnStatus` | warn |
| `ZD-01` | `failStatus` | fail |
| `ZD-01` | `manualStatus` | manual |
| `ZD-02` | `passStatus` | pass |
| `ZD-02` | `warnStatus` | warn |
| `ZD-02` | `failStatus` | fail |
| `ZD-02` | `manualStatus` | manual |
| `ZD-03` | `passStatus` | pass |
| `ZD-03` | `warnStatus` | warn |
| `ZD-03` | `failStatus` | fail |
| `ZD-03` | `manualStatus` | manual |
| `ZD-04` | `passStatus` | pass |
| `ZD-04` | `warnStatus` | warn |
| `ZD-04` | `failStatus` | fail |
| `ZD-04` | `manualStatus` | manual |
| `ZD-05` | `passStatus` | pass |
| `ZD-05` | `warnStatus` | warn |
| `ZD-05` | `failStatus` | fail |
| `ZD-05` | `manualStatus` | manual |
| `ZD-06` | `passStatus` | pass |
| `ZD-06` | `warnStatus` | warn |
| `ZD-06` | `failStatus` | fail |
| `ZD-06` | `manualStatus` | manual |
| `ZD-07` | `passStatus` | pass |
| `ZD-07` | `warnStatus` | warn |
| `ZD-07` | `failStatus` | fail |
| `ZD-07` | `manualStatus` | manual |
| `ZD-08` | `passStatus` | pass |
| `ZD-08` | `warnStatus` | warn |
| `ZD-08` | `failStatus` | fail |
| `ZD-08` | `manualStatus` | manual |
| `ZD-09` | `passStatus` | pass |
| `ZD-09` | `warnStatus` | warn |
| `ZD-09` | `failStatus` | fail |
| `ZD-09` | `manualStatus` | manual |
| `ZD-10` | `passStatus` | pass |
| `ZD-10` | `warnStatus` | warn |
| `ZD-10` | `failStatus` | fail |
| `ZD-10` | `manualStatus` | manual |
| `ZD-11` | `passStatus` | pass |
| `ZD-11` | `warnStatus` | warn |
| `ZD-11` | `failStatus` | fail |
| `ZD-11` | `manualStatus` | manual |
| `ZD-12` | `passStatus` | pass |
| `ZD-12` | `warnStatus` | warn |
| `ZD-12` | `failStatus` | fail |
| `ZD-12` | `manualStatus` | manual |
| `ZD-13` | `passStatus` | pass |
| `ZD-13` | `warnStatus` | warn |
| `ZD-13` | `failStatus` | fail |
| `ZD-13` | `manualStatus` | manual |
| `ZD-14` | `passStatus` | pass |
| `ZD-14` | `warnStatus` | warn |
| `ZD-14` | `failStatus` | fail |
| `ZD-14` | `manualStatus` | manual |
| `ZD-15` | `passStatus` | pass |
| `ZD-15` | `warnStatus` | warn |
| `ZD-15` | `failStatus` | fail |
| `ZD-15` | `manualStatus` | manual |
| `ZD-16` | `passStatus` | pass |
| `ZD-16` | `warnStatus` | warn |
| `ZD-16` | `failStatus` | fail |
| `ZD-16` | `manualStatus` | manual |
| `ZD-17` | `passStatus` | pass |
| `ZD-17` | `warnStatus` | warn |
| `ZD-17` | `failStatus` | fail |
| `ZD-17` | `manualStatus` | manual |
| `ZD-18` | `passStatus` | pass |
| `ZD-18` | `warnStatus` | warn |
| `ZD-18` | `failStatus` | fail |
| `ZD-18` | `manualStatus` | manual |
| `ZD-19` | `passStatus` | pass |
| `ZD-19` | `warnStatus` | warn |
| `ZD-19` | `failStatus` | fail |
| `ZD-19` | `manualStatus` | manual |
| `ZD-20` | `passStatus` | pass |
| `ZD-20` | `warnStatus` | warn |
| `ZD-20` | `failStatus` | fail |
| `ZD-20` | `manualStatus` | manual |
| `ZD-21` | `passStatus` | pass |
| `ZD-21` | `warnStatus` | warn |
| `ZD-21` | `failStatus` | fail |
| `ZD-21` | `manualStatus` | manual |
| `ZD-22` | `passStatus` | pass |
| `ZD-22` | `warnStatus` | warn |
| `ZD-22` | `failStatus` | fail |
| `ZD-22` | `manualStatus` | manual |
| `ZD-23` | `passStatus` | pass |
| `ZD-23` | `warnStatus` | warn |
| `ZD-23` | `failStatus` | fail |
| `ZD-23` | `manualStatus` | manual |
| `ZD-24` | `passStatus` | pass |
| `ZD-24` | `warnStatus` | warn |
| `ZD-24` | `failStatus` | fail |
| `ZD-24` | `manualStatus` | manual |
| `ZD-25` | `passStatus` | pass |
| `ZD-25` | `warnStatus` | warn |
| `ZD-25` | `failStatus` | fail |
| `ZD-25` | `manualStatus` | manual |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `ZD-01` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-01` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-02` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-02` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-03` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-03` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-04` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-04` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-05` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-05` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-06` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-06` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-07` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-07` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-08` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-08` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-09` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-09` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-09` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-09` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-10` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-10` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-10` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-10` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-11` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-11` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-11` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-11` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-12` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-12` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-12` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-12` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-13` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-13` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-13` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-13` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-14` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-14` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-14` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-14` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-15` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-15` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-15` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-15` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-16` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-16` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-16` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-16` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-17` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-17` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-17` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-17` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-18` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-18` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-18` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-18` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-19` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-19` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-19` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-19` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-20` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-20` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-20` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-20` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-21` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-21` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-21` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-21` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-22` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-22` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-22` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-22` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-23` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-23` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-23` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-23` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-24` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-24` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-24` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-24` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-25` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-25` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-25` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-25` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | SSO enforcement enabled | - | - | - | - | - | - | - | - |
| 2 | Two-factor authentication required for agents | - | - | - | - | - | - | - | - |
| 3 | Password policy meets complexity requirements | - | - | - | - | - | - | - | - |
| 4 | IP restrictions configured for agent access | - | - | - | - | - | - | - | - |
| 5 | Session timeout configured and reasonable | - | - | - | - | - | - | - | - |
| 6 | Agent roles follow least privilege | - | - | - | - | - | - | - | - |
| 7 | No excessive admin accounts | - | - | - | - | - | - | - | - |
| 8 | Group-based access controls configured | - | - | - | - | - | - | - | - |
| 9 | Audit logging enabled and accessible | - | - | - | - | - | - | - | - |
| 10 | Audit log retention meets compliance requirements | - | - | - | - | - | - | - | - |
| 11 | HIPAA compliance mode enabled when applicable | - | - | - | - | - | - | - | - |
| 12 | Data deletion and redaction policies configured | - | - | - | - | - | - | - | - |
| 13 | API tokens are minimal and reviewed | - | - | - | - | - | - | - | - |
| 14 | OAuth application permissions are scoped | - | - | - | - | - | - | - | - |
| 15 | Marketplace apps reviewed for permissions | - | - | - | - | - | - | - | - |
| 16 | Private and custom apps have appropriate scope | - | - | - | - | - | - | - | - |
| 17 | Sandbox environment used for testing | - | - | - | - | - | - | - | - |
| 18 | Authenticated attachment downloads configured | - | - | - | - | - | - | - | - |
| 19 | File attachment restrictions configured | - | - | - | - | - | - | - | - |
| 20 | Suspended ticket handling automated | - | - | - | - | - | - | - | - |
| 21 | End-user authentication required | - | - | - | - | - | - | - | - |
| 22 | Brand security settings consistent | - | - | - | - | - | - | - | - |
| 23 | External sharing agreements reviewed | - | - | - | - | - | - | - | - |
| 24 | External notification targets use HTTPS | - | - | - | - | - | - | - | - |
| 25 | Triggers and automations do not send data to external URLs | - | - | - | - | - | - | - | - |

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

Sensitive fields and values: api_token, oauth_token, authorization, cookie, email, webhook_url

Credential formats: Zendesk API tokens, OAuth bearer tokens, Basic authorization values, webhook path secrets

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `security-settings` | `sso`, `two_factor_authentication`, `password_policy`, `ip_restrictions`, `session_expiration` |
| `users` | `id`, `email`, `role`, `custom_role_id`, `active`, `suspended`, `last_login_at` |
| `audit-logs` | `id`, `created_at`, `action`, `source_type`, `source_id`, `actor_id` |
| `deletion-schedules` | `id`, `title`, `status`, `object_type`, `retention_period` |
| `apps-and-webhooks` | `id`, `app_id`, `enabled`, `settings`, `url` |

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

Archive pairing: Create zendesk-audit.zip beside the allocated zendesk-audit directory, applying the same suffix to both.
