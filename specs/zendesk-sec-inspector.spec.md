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
| role | `Zendesk agent` | `current-user`, `team-members`, `groups`, `group-memberships` |  |
| role | `Zendesk administrator` | `current-user`, `account-settings`, `security-settings`, `team-members`, `groups`, `group-memberships`, `deletion-schedules`, `oauth-clients`, `oauth-tokens`, `app-installations`, `owned-apps`, `brands`, `webhooks`, `targets`, `triggers`, `automations`, `sharing-agreements`, `suspended-tickets` | Individual endpoint and plan entitlements still apply. |
| plan | `Zendesk Enterprise audit-log and custom-role entitlements` | `custom-roles`, `audit-logs-recent`, `audit-log-oldest`, `api-token-audit-logs` |  |
| oauth-scope | `read` | `current-user`, `account-settings`, `security-settings`, `team-members`, `custom-roles`, `groups`, `group-memberships`, `audit-logs-recent`, `audit-log-oldest`, `api-token-audit-logs`, `deletion-schedules`, `oauth-clients`, `oauth-tokens`, `app-installations`, `owned-apps`, `brands`, `webhooks`, `targets`, `triggers`, `automations`, `sharing-agreements`, `suspended-tickets` | Used only for OAuth bearer authentication; API-token Basic authentication has no OAuth scope. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `current-user` | HTTP | `GET /api/v2/users/me` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `user.id`, `user.email`, `user.role` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `account-settings` | HTTP | `GET /api/v2/account/settings` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `settings.api`, `settings.tickets`, `settings.attachments`, `settings.sandbox` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `security-settings` | HTTP | `GET /api/v2/security_settings` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `security_settings.authentication`, `security_settings.ip`, `security_settings.session_expiration`, `security_settings.mobile_session_expiration` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `team-members` | HTTP | `GET /api/v2/users?role[]=agent&role[]=admin` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `users.id`, `users.email`, `users.role`, `users.custom_role_id`, `users.active`, `users.suspended`, `users.last_login_at`, `users.two_factor_auth_enabled`, `users.restricted_agent` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `custom-roles` | HTTP | `GET /api/v2/custom_roles` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `custom_roles.id`, `custom_roles.name`, `custom_roles.configuration`, `custom_roles.team_member_count` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `groups` | HTTP | `GET /api/v2/groups` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `groups.id`, `groups.name`, `groups.deleted` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `group-memberships` | HTTP | `GET /api/v2/group_memberships` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `group_memberships.id`, `group_memberships.group_id`, `group_memberships.user_id` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `audit-logs-recent` | HTTP | `GET /api/v2/audit_logs?sort=-created_at` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `audit_logs.id`, `audit_logs.created_at`, `audit_logs.action`, `audit_logs.source_type`, `audit_logs.source_id`, `audit_logs.actor_id` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `audit-log-oldest` | HTTP | `GET /api/v2/audit_logs?sort=created_at&page[size]=1` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `audit_logs.id`, `audit_logs.created_at` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `api-token-audit-logs` | HTTP | `GET /api/v2/audit_logs?filter[source_type]=apitoken&sort=-created_at` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `audit_logs.id`, `audit_logs.created_at`, `audit_logs.action`, `audit_logs.source_type`, `audit_logs.source_id`, `audit_logs.source_label` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `deletion-schedules` | HTTP | `GET /api/v2/deletion_schedules` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `deletion_schedules.id`, `deletion_schedules.title`, `deletion_schedules.object`, `deletion_schedules.active`, `deletion_schedules.default`, `deletion_schedules.conditions`, `deletion_schedules.updated_at` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `oauth-clients` | HTTP | `GET /api/v2/oauth/clients` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `clients.id`, `clients.name`, `clients.allowed_scopes`, `clients.redirect_uri`, `clients.public` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `oauth-tokens` | HTTP | `GET /api/v2/oauth/tokens?all=true` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `tokens.id`, `tokens.client_id`, `tokens.user_id`, `tokens.scopes`, `tokens.expires_at`, `tokens.used_at` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `app-installations` | HTTP | `GET /api/v2/apps/installations` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `installations.id`, `installations.app_id`, `installations.enabled`, `installations.settings`, `installations.product`, `installations.role_restrictions`, `installations.group_restrictions` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `owned-apps` | HTTP | `GET /api/v2/apps/owned` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `apps.id`, `apps.name`, `apps.deprecated`, `apps.obsolete` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `brands` | HTTP | `GET /api/v2/brands` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `brands.id`, `brands.name`, `brands.active`, `brands.has_help_center` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `webhooks` | HTTP | `GET /api/v2/webhooks` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `webhooks.id`, `webhooks.name`, `webhooks.active`, `webhooks.endpoint`, `webhooks.http_method`, `webhooks.authentication` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `targets` | HTTP | `GET /api/v2/targets` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `targets.id`, `targets.title`, `targets.active`, `targets.type`, `targets.target_url` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `triggers` | HTTP | `GET /api/v2/triggers` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `triggers.id`, `triggers.title`, `triggers.active`, `triggers.actions` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `automations` | HTTP | `GET /api/v2/automations` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `automations.id`, `automations.title`, `automations.active`, `automations.actions` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `sharing-agreements` | HTTP | `GET /api/v2/sharing_agreements` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sharing_agreements.id`, `sharing_agreements.name`, `sharing_agreements.status` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |
| `suspended-tickets` | HTTP | `GET /api/v2/suspended_tickets?sort_by=created_at&sort_order=asc` | Zendesk Support API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `suspended_tickets.id`, `suspended_tickets.created_at`, `suspended_tickets.subject`, `suspended_tickets.cause` | [Official documentation](https://developer.zendesk.com/api-reference/ticketing/) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `current-user` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `current-user` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `current-user` | response | A JSON object or list containing only the documented user.id, user.email, user.role members consumed by verdicts. | yes |
| `account-settings` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `account-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `account-settings` | response | A JSON object or list containing only the documented settings.api, settings.tickets, settings.attachments, settings.sandbox members consumed by verdicts. | yes |
| `security-settings` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `security-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `security-settings` | response | A JSON object or list containing only the documented security_settings.authentication, security_settings.ip, security_settings.session_expiration, security_settings.mobile_session_expiration members consumed by verdicts. | yes |
| `team-members` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `team-members` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `team-members` | response | A JSON object or list containing only the documented users.id, users.email, users.role, users.custom_role_id, users.active, users.suspended, users.last_login_at, users.two_factor_auth_enabled, users.restricted_agent members consumed by verdicts. | yes |
| `custom-roles` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `custom-roles` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `custom-roles` | response | A JSON object or list containing only the documented custom_roles.id, custom_roles.name, custom_roles.configuration, custom_roles.team_member_count members consumed by verdicts. | yes |
| `groups` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `groups` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `groups` | response | A JSON object or list containing only the documented groups.id, groups.name, groups.deleted members consumed by verdicts. | yes |
| `group-memberships` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `group-memberships` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `group-memberships` | response | A JSON object or list containing only the documented group_memberships.id, group_memberships.group_id, group_memberships.user_id members consumed by verdicts. | yes |
| `audit-logs-recent` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `audit-logs-recent` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `audit-logs-recent` | response | A JSON object or list containing only the documented audit_logs.id, audit_logs.created_at, audit_logs.action, audit_logs.source_type, audit_logs.source_id, audit_logs.actor_id members consumed by verdicts. | yes |
| `audit-log-oldest` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `audit-log-oldest` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `audit-log-oldest` | response | A JSON object or list containing only the documented audit_logs.id, audit_logs.created_at members consumed by verdicts. | yes |
| `api-token-audit-logs` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `api-token-audit-logs` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `api-token-audit-logs` | response | A JSON object or list containing only the documented audit_logs.id, audit_logs.created_at, audit_logs.action, audit_logs.source_type, audit_logs.source_id, audit_logs.source_label members consumed by verdicts. | yes |
| `deletion-schedules` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `deletion-schedules` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `deletion-schedules` | response | A JSON object or list containing only the documented deletion_schedules.id, deletion_schedules.title, deletion_schedules.object, deletion_schedules.active, deletion_schedules.default, deletion_schedules.conditions, deletion_schedules.updated_at members consumed by verdicts. | yes |
| `oauth-clients` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `oauth-clients` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `oauth-clients` | response | A JSON object or list containing only the documented clients.id, clients.name, clients.allowed_scopes, clients.redirect_uri, clients.public members consumed by verdicts. | yes |
| `oauth-tokens` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `oauth-tokens` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `oauth-tokens` | response | A JSON object or list containing only the documented tokens.id, tokens.client_id, tokens.user_id, tokens.scopes, tokens.expires_at, tokens.used_at members consumed by verdicts. | yes |
| `app-installations` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `app-installations` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `app-installations` | response | A JSON object or list containing only the documented installations.id, installations.app_id, installations.enabled, installations.settings, installations.product, installations.role_restrictions, installations.group_restrictions members consumed by verdicts. | yes |
| `owned-apps` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `owned-apps` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `owned-apps` | response | A JSON object or list containing only the documented apps.id, apps.name, apps.deprecated, apps.obsolete members consumed by verdicts. | yes |
| `brands` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `brands` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `brands` | response | A JSON object or list containing only the documented brands.id, brands.name, brands.active, brands.has_help_center members consumed by verdicts. | yes |
| `webhooks` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `webhooks` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `webhooks` | response | A JSON object or list containing only the documented webhooks.id, webhooks.name, webhooks.active, webhooks.endpoint, webhooks.http_method, webhooks.authentication members consumed by verdicts. | yes |
| `targets` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `targets` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `targets` | response | A JSON object or list containing only the documented targets.id, targets.title, targets.active, targets.type, targets.target_url members consumed by verdicts. | yes |
| `triggers` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `triggers` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `triggers` | response | A JSON object or list containing only the documented triggers.id, triggers.title, triggers.active, triggers.actions members consumed by verdicts. | yes |
| `automations` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `automations` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `automations` | response | A JSON object or list containing only the documented automations.id, automations.title, automations.active, automations.actions members consumed by verdicts. | yes |
| `sharing-agreements` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `sharing-agreements` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `sharing-agreements` | response | A JSON object or list containing only the documented sharing_agreements.id, sharing_agreements.name, sharing_agreements.status members consumed by verdicts. | yes |
| `suspended-tickets` | client | Use the configured Zendesk Support API origin; never follow a server link to a different origin. | yes |
| `suspended-tickets` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `suspended-tickets` | response | A JSON object or list containing only the documented suspended_tickets.id, suspended_tickets.created_at, suspended_tickets.subject, suspended_tickets.cause members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `team-members`, `groups`, `group-memberships`, `audit-logs-recent`, `api-token-audit-logs`, `oauth-clients`, `oauth-tokens`, `brands`, `webhooks`, `triggers`, `automations`, `suspended-tickets` | `meta.has_more`, `links.next`, `next_page`, `count` | 100 | 2000 | 100 | Cursor exhaustion proves completeness; count is retained as a boundary check when supplied. | has_more false or no next page; Declared total reached; Configured item cap; Repeated next link; Empty page with continuation; Rejected cross-origin next link |
| `custom-roles`, `deletion-schedules`, `app-installations`, `owned-apps`, `targets`, `sharing-agreements` | `next_page`, `count`, `page`, `per_page` | 100 | 2000 | 100 | A null next_page or equality with a stable count proves completeness; missing or larger totals keep the dataset partial. | No next_page; Declared count reached; Configured item cap; Page cap; Repeated next_page; Empty page with continuation; Rejected cross-origin next link |

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
| `ZD-01` | critical | `zendesk_assess_authentication` | `security-settings` | `security_settings.authentication`, `security_settings.ip`, `security_settings.session_expiration`, `security_settings.mobile_session_expiration`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when team-member SSO is enforced, Zendesk password login is disabled, and at least one SSO method is enabled; warn when SSO is enforced without a method or while password login remains enabled; and fail when SSO is not enforced. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when team-member SSO is enforced, Zendesk password login is disabled, and at least one SSO method is enabled; warn when SSO is enforced without a method or while password login remains enabled; and fail when SSO is not enforced. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when team-member SSO is enforced, Zendesk password login is disabled, and at least one SSO method is enabled; warn when SSO is enforced without a method or while password login remains enabled; and fail when SSO is not enforced. | The required evidence for SSO enforcement enabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-02` | critical | `zendesk_assess_authentication` | `security-settings`, `team-members` | `security_settings.authentication`, `security_settings.ip`, `security_settings.session_expiration`, `security_settings.mobile_session_expiration`, `users.id`, `users.email`, `users.role`, `users.custom_role_id`, `users.active`, `users.suspended`, `users.last_login_at`, `users.two_factor_auth_enabled`, `users.restricted_agent`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any active team member explicitly lacks 2FA or account enforcement is disabled without enforced SSO, pass when enforcement is enabled and every member in a complete inventory reports 2FA enabled, warn for missing enrollment flags or partial coverage, and manual when MFA depends on the identity provider. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any active team member explicitly lacks 2FA or account enforcement is disabled without enforced SSO, pass when enforcement is enabled and every member in a complete inventory reports 2FA enabled, warn for missing enrollment flags or partial coverage, and manual when MFA depends on the identity provider. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any active team member explicitly lacks 2FA or account enforcement is disabled without enforced SSO, pass when enforcement is enabled and every member in a complete inventory reports 2FA enabled, warn for missing enrollment flags or partial coverage, and manual when MFA depends on the identity provider. | The required evidence for Two-factor authentication required for agents is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-03` | high | `zendesk_assess_authentication` | `security-settings` | `security_settings.authentication`, `security_settings.ip`, `security_settings.session_expiration`, `security_settings.mobile_session_expiration`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass for the Recommended preset or a Custom policy with length at least 12, complexity at least two, mixed case, at most ten failed attempts, email-local-part rejection, and history at least five or unlimited; warn for High or a deficient Custom policy, and fail for every lower preset. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass for the Recommended preset or a Custom policy with length at least 12, complexity at least two, mixed case, at most ten failed attempts, email-local-part rejection, and history at least five or unlimited; warn for High or a deficient Custom policy, and fail for every lower preset. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass for the Recommended preset or a Custom policy with length at least 12, complexity at least two, mixed case, at most ten failed attempts, email-local-part rejection, and history at least five or unlimited; warn for High or a deficient Custom policy, and fail for every lower preset. | The required evidence for Password policy meets complexity requirements is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-04` | high | `zendesk_assess_authentication` | `security-settings` | `security_settings.authentication`, `security_settings.ip`, `security_settings.session_expiration`, `security_settings.mobile_session_expiration`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when IP restriction is enabled with at least one range, warn when enabled with no range, and fail when disabled. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when IP restriction is enabled with at least one range, warn when enabled with no range, and fail when disabled. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when IP restriction is enabled with at least one range, warn when enabled with no range, and fail when disabled. | The required evidence for IP restrictions configured for agent access is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-05` | medium | `zendesk_assess_authentication` | `security-settings` | `security_settings.authentication`, `security_settings.ip`, `security_settings.session_expiration`, `security_settings.mobile_session_expiration`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when positive agent and applicable mobile inactivity timeouts are at or below the configured threshold, fail when the agent timeout is zero or above three times the threshold, and warn for every other threshold violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when positive agent and applicable mobile inactivity timeouts are at or below the configured threshold, fail when the agent timeout is zero or above three times the threshold, and warn for every other threshold violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when positive agent and applicable mobile inactivity timeouts are at or below the configured threshold, fail when the agent timeout is zero or above three times the threshold, and warn for every other threshold violation. | The required evidence for Session timeout configured and reasonable is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-06` | critical | `zendesk_assess_access_control` | `team-members`, `custom-roles` | `users.id`, `users.email`, `users.role`, `users.custom_role_id`, `users.active`, `users.suspended`, `users.last_login_at`, `users.two_factor_auth_enabled`, `users.restricted_agent`, `custom_roles.id`, `custom_roles.name`, `custom_roles.configuration`, `custom_roles.team_member_count`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any populated custom role grants administrator-equivalent permissions, warn for partial inventories, unassigned administrator-equivalent roles, or an all-unrestricted agent population, and pass when complete role and team inventories show none. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any populated custom role grants administrator-equivalent permissions, warn for partial inventories, unassigned administrator-equivalent roles, or an all-unrestricted agent population, and pass when complete role and team inventories show none. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any populated custom role grants administrator-equivalent permissions, warn for partial inventories, unassigned administrator-equivalent roles, or an all-unrestricted agent population, and pass when complete role and team inventories show none. | The required evidence for Agent roles follow least privilege is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-07` | high | `zendesk_assess_access_control` | `team-members` | `users.id`, `users.email`, `users.role`, `users.custom_role_id`, `users.active`, `users.suspended`, `users.last_login_at`, `users.two_factor_auth_enabled`, `users.restricted_agent`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when active administrators exceed the configured threshold, warn when any administrator is stale, undated, or the inventory is partial, and pass when the non-empty complete inventory is within the threshold and all administrators are recent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when active administrators exceed the configured threshold, warn when any administrator is stale, undated, or the inventory is partial, and pass when the non-empty complete inventory is within the threshold and all administrators are recent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when active administrators exceed the configured threshold, warn when any administrator is stale, undated, or the inventory is partial, and pass when the non-empty complete inventory is within the threshold and all administrators are recent. | The required evidence for No excessive admin accounts is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-08` | medium | `zendesk_assess_access_control` | `groups`, `group-memberships` | `groups.id`, `groups.name`, `groups.deleted`, `group_memberships.id`, `group_memberships.group_id`, `group_memberships.user_id`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when complete inventories contain more than one group and at least one membership, and warn when only one group exists, no membership exists, or either inventory is truncated. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when complete inventories contain more than one group and at least one membership, and warn when only one group exists, no membership exists, or either inventory is truncated. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when complete inventories contain more than one group and at least one membership, and warn when only one group exists, no membership exists, or either inventory is truncated. | The required evidence for Group-based access controls configured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-09` | high | `zendesk_assess_data_protection` | `audit-logs-recent` | `audit_logs.id`, `audit_logs.created_at`, `audit_logs.action`, `audit_logs.source_type`, `audit_logs.source_id`, `audit_logs.actor_id`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the recent audit-log endpoint returns at least one entry and fills or cleanly completes its 25-entry sample, warn when paging cuts that sample short, and manual when the endpoint is unavailable or a completed sample is unexpectedly empty. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the recent audit-log endpoint returns at least one entry and fills or cleanly completes its 25-entry sample, warn when paging cuts that sample short, and manual when the endpoint is unavailable or a completed sample is unexpectedly empty. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the recent audit-log endpoint returns at least one entry and fills or cleanly completes its 25-entry sample, warn when paging cuts that sample short, and manual when the endpoint is unavailable or a completed sample is unexpectedly empty. | The required evidence for Audit logging enabled and accessible is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-10` | medium | `zendesk_assess_data_protection` | `audit-log-oldest` | `audit_logs.id`, `audit_logs.created_at`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the dated oldest audit entry is at least the configured retention age and warn when it is younger; an absent or undated oldest entry is manual. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the dated oldest audit entry is at least the configured retention age and warn when it is younger; an absent or undated oldest entry is manual. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the dated oldest audit entry is at least the configured retention age and warn when it is younger; an absent or undated oldest entry is manual. | The required evidence for Audit log retention meets compliance requirements is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-11` | critical | `zendesk_assess_data_protection` | `account-settings`, `security-settings` | `settings.api`, `settings.tickets`, `settings.attachments`, `settings.sandbox`, `security_settings.authentication`, `security_settings.ip`, `security_settings.session_expiration`, `security_settings.mobile_session_expiration`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: always return manual because the published Account Settings and Security Settings APIs expose no HIPAA or Advanced Data Privacy and Protection field. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: always return manual because the published Account Settings and Security Settings APIs expose no HIPAA or Advanced Data Privacy and Protection field. | Complete readable evidence satisfies the violation branch, which has first-match precedence: always return manual because the published Account Settings and Security Settings APIs expose no HIPAA or Advanced Data Privacy and Protection field. | The required evidence for HIPAA compliance mode enabled when applicable is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-12` | high | `zendesk_assess_data_protection` | `deletion-schedules`, `account-settings`, `custom-roles` | `deletion_schedules.id`, `deletion_schedules.title`, `deletion_schedules.object`, `deletion_schedules.active`, `deletion_schedules.default`, `deletion_schedules.conditions`, `deletion_schedules.updated_at`, `settings.api`, `settings.tickets`, `settings.attachments`, `settings.sandbox`, `custom_roles.id`, `custom_roles.name`, `custom_roles.configuration`, `custom_roles.team_member_count`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when a complete deletion-schedule inventory is empty or has no active schedule, pass when it has a conditioned active ticket schedule and all companion evidence is complete, and warn for truncation, no active ticket schedule, or any active schedule without conditions. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when a complete deletion-schedule inventory is empty or has no active schedule, pass when it has a conditioned active ticket schedule and all companion evidence is complete, and warn for truncation, no active ticket schedule, or any active schedule without conditions. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when a complete deletion-schedule inventory is empty or has no active schedule, pass when it has a conditioned active ticket schedule and all companion evidence is complete, and warn for truncation, no active ticket schedule, or any active schedule without conditions. | The required evidence for Data deletion and redaction policies configured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-13` | high | `zendesk_assess_access_control` | `account-settings`, `api-token-audit-logs` | `settings.api`, `settings.tickets`, `settings.attachments`, `settings.sandbox`, `audit_logs.id`, `audit_logs.created_at`, `audit_logs.action`, `audit_logs.source_type`, `audit_logs.source_id`, `audit_logs.source_label`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when API-token authentication is disabled and audit evidence is complete, warn when it is enabled but the event history shows no outstanding token, and manual when enabled tokens remain or account settings or token history are unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when API-token authentication is disabled and audit evidence is complete, warn when it is enabled but the event history shows no outstanding token, and manual when enabled tokens remain or account settings or token history are unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when API-token authentication is disabled and audit evidence is complete, warn when it is enabled but the event history shows no outstanding token, and manual when enabled tokens remain or account settings or token history are unavailable. | The required evidence for API tokens are minimal and reviewed is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-14` | high | `zendesk_assess_access_control` | `oauth-clients`, `oauth-tokens` | `clients.id`, `clients.name`, `clients.allowed_scopes`, `clients.redirect_uri`, `clients.public`, `tokens.id`, `tokens.client_id`, `tokens.user_id`, `tokens.scopes`, `tokens.expires_at`, `tokens.used_at`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any OAuth client is unscoped or has a non-local HTTP redirect, pass when complete client and token inventories are empty or all clients are scoped with HTTPS redirects and every token is expiring and recently used, and warn for public, privileged, non-expiring, stale, undated, hidden, partial, or unreadable token evidence. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any OAuth client is unscoped or has a non-local HTTP redirect, pass when complete client and token inventories are empty or all clients are scoped with HTTPS redirects and every token is expiring and recently used, and warn for public, privileged, non-expiring, stale, undated, hidden, partial, or unreadable token evidence. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any OAuth client is unscoped or has a non-local HTTP redirect, pass when complete client and token inventories are empty or all clients are scoped with HTTPS redirects and every token is expiring and recently used, and warn for public, privileged, non-expiring, stale, undated, hidden, partial, or unreadable token evidence. | The required evidence for OAuth application permissions are scoped is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-15` | medium | `zendesk_assess_integrations` | `app-installations`, `owned-apps` | `installations.id`, `installations.app_id`, `installations.enabled`, `installations.settings`, `installations.product`, `installations.role_restrictions`, `installations.group_restrictions`, `apps.id`, `apps.name`, `apps.deprecated`, `apps.obsolete`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when complete installation and owned-app inventories prove no installed apps, warn when the installation inventory truncates before its first app, and manual when any installation exists because the API does not prove that marketplace permissions were reviewed. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when complete installation and owned-app inventories prove no installed apps, warn when the installation inventory truncates before its first app, and manual when any installation exists because the API does not prove that marketplace permissions were reviewed. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when complete installation and owned-app inventories prove no installed apps, warn when the installation inventory truncates before its first app, and manual when any installation exists because the API does not prove that marketplace permissions were reviewed. | The required evidence for Marketplace apps reviewed for permissions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-16` | medium | `zendesk_assess_integrations` | `owned-apps` | `apps.id`, `apps.name`, `apps.deprecated`, `apps.obsolete`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete owned-app inventory is empty, warn when any owned app is deprecated or obsolete or the inventory truncates before its first app, and manual for other non-empty inventories because manifest scope review is not automated. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete owned-app inventory is empty, warn when any owned app is deprecated or obsolete or the inventory truncates before its first app, and manual for other non-empty inventories because manifest scope review is not automated. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete owned-app inventory is empty, warn when any owned app is deprecated or obsolete or the inventory truncates before its first app, and manual for other non-empty inventories because manifest scope review is not automated. | The required evidence for Private and custom apps have appropriate scope is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-17` | medium | `zendesk_assess_integrations` | `account-settings` | `settings.api`, `settings.tickets`, `settings.attachments`, `settings.sandbox`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when account settings report the sandbox feature enabled, warn when disabled, and manual when the flag is absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when account settings report the sandbox feature enabled, warn when disabled, and manual when the flag is absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when account settings report the sandbox feature enabled, warn when disabled, and manual when the flag is absent. | The required evidence for Sandbox environment used for testing is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-18` | medium | `zendesk_assess_data_protection` | `account-settings` | `settings.api`, `settings.tickets`, `settings.attachments`, `settings.sandbox`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when authenticated attachment downloads are enabled and every listed CDN host uses HTTPS, warn when authentication is enabled but any CDN host is insecure, and fail when authenticated downloads are disabled. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when authenticated attachment downloads are enabled and every listed CDN host uses HTTPS, warn when authentication is enabled but any CDN host is insecure, and fail when authenticated downloads are disabled. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when authenticated attachment downloads are enabled and every listed CDN host uses HTTPS, warn when authentication is enabled but any CDN host is insecure, and fail when authenticated downloads are disabled. | The required evidence for Authenticated attachment downloads configured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-19` | medium | `zendesk_assess_data_protection` | `account-settings` | `settings.api`, `settings.tickets`, `settings.attachments`, `settings.sandbox`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: always return manual because the API exposes attachment size and email-attachment posture but not allowed file types or malicious-attachment detection. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: always return manual because the API exposes attachment size and email-attachment posture but not allowed file types or malicious-attachment detection. | Complete readable evidence satisfies the violation branch, which has first-match precedence: always return manual because the API exposes attachment size and email-attachment posture but not allowed file types or malicious-attachment detection. | The required evidence for File attachment restrictions configured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-20` | medium | `zendesk_assess_data_protection` | `suspended-tickets` | `suspended_tickets.id`, `suspended_tickets.created_at`, `suspended_tickets.subject`, `suspended_tickets.cause`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete suspended-ticket queue is empty or every queued ticket is dated and newer than the configured age, and warn for stale, undated, or partial queue evidence. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete suspended-ticket queue is empty or every queued ticket is dated and newer than the configured age, and warn for stale, undated, or partial queue evidence. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete suspended-ticket queue is empty or every queued ticket is dated and newer than the configured age, and warn for stale, undated, or partial queue evidence. | The required evidence for Suspended ticket handling automated is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-21` | high | `zendesk_assess_authentication` | `security-settings`, `account-settings` | `security_settings.authentication`, `security_settings.ip`, `security_settings.session_expiration`, `security_settings.mobile_session_expiration`, `settings.api`, `settings.tickets`, `settings.attachments`, `settings.sandbox`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when end users have enforced SSO with a method, password login under Recommended or High, or SSO-only login; warn for enforced SSO without a method or a weaker password preset, fail when no login method exists, and keep anonymous-ticket submission as a named manual limitation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when end users have enforced SSO with a method, password login under Recommended or High, or SSO-only login; warn for enforced SSO without a method or a weaker password preset, fail when no login method exists, and keep anonymous-ticket submission as a named manual limitation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when end users have enforced SSO with a method, password login under Recommended or High, or SSO-only login; warn for enforced SSO without a method or a weaker password preset, fail when no login method exists, and keep anonymous-ticket submission as a named manual limitation. | The required evidence for End-user authentication required is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-22` | medium | `zendesk_assess_integrations` | `brands` | `brands.id`, `brands.name`, `brands.active`, `brands.has_help_center`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when an administrator reads every active brand and all have one known help-center state, warn for a non-admin view, truncation, or mixed or unknown states, and manual when no brand is visible. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when an administrator reads every active brand and all have one known help-center state, warn for a non-admin view, truncation, or mixed or unknown states, and manual when no brand is visible. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when an administrator reads every active brand and all have one known help-center state, warn for a non-admin view, truncation, or mixed or unknown states, and manual when no brand is visible. | The required evidence for Brand security settings consistent is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-23` | medium | `zendesk_assess_integrations` | `sharing-agreements` | `sharing_agreements.id`, `sharing_agreements.name`, `sharing_agreements.status`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete sharing-agreement inventory is empty, warn when any agreement is failed, ssl_error, or configuration_error or the inventory truncates before its first record, and manual when accepted or pending external agreements require business review. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete sharing-agreement inventory is empty, warn when any agreement is failed, ssl_error, or configuration_error or the inventory truncates before its first record, and manual when accepted or pending external agreements require business review. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete sharing-agreement inventory is empty, warn when any agreement is failed, ssl_error, or configuration_error or the inventory truncates before its first record, and manual when accepted or pending external agreements require business review. | The required evidence for External sharing agreements reviewed is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-24` | high | `zendesk_assess_integrations` | `targets`, `webhooks` | `targets.id`, `targets.title`, `targets.active`, `targets.type`, `targets.target_url`, `webhooks.id`, `webhooks.name`, `webhooks.active`, `webhooks.endpoint`, `webhooks.http_method`, `webhooks.authentication`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any active target or webhook uses a non-HTTPS endpoint, pass when complete readable inventories contain no active destination or every destination is HTTPS and every webhook has authentication, and warn for missing, partial, or unauthenticated destination evidence. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any active target or webhook uses a non-HTTPS endpoint, pass when complete readable inventories contain no active destination or every destination is HTTPS and every webhook has authentication, and warn for missing, partial, or unauthenticated destination evidence. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any active target or webhook uses a non-HTTPS endpoint, pass when complete readable inventories contain no active destination or every destination is HTTPS and every webhook has authentication, and warn for missing, partial, or unauthenticated destination evidence. | The required evidence for External notification targets use HTTPS is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZD-25` | high | `zendesk_assess_integrations` | `triggers`, `automations`, `targets`, `webhooks` | `triggers.id`, `triggers.title`, `triggers.active`, `triggers.actions`, `automations.id`, `automations.title`, `automations.active`, `automations.actions`, `targets.id`, `targets.title`, `targets.active`, `targets.type`, `targets.target_url`, `webhooks.id`, `webhooks.name`, `webhooks.active`, `webhooks.endpoint`, `webhooks.http_method`, `webhooks.authentication`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any active trigger or automation sends ticket data to an HTTP destination, pass when the complete non-empty rule inventory has no external notification action and destination lookups are complete, warn for external actions or partial evidence, and manual when no active rule is visible or either rule inventory is unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any active trigger or automation sends ticket data to an HTTP destination, pass when the complete non-empty rule inventory has no external notification action and destination lookups are complete, warn for external actions or partial evidence, and manual when no active rule is visible or either rule inventory is unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any active trigger or automation sends ticket data to an HTTP destination, pass when the complete non-empty rule inventory has no external notification action and destination lookups are complete, warn for external actions or partial evidence, and manual when no active rule is visible or either rule inventory is unavailable. | The required evidence for Triggers and automations do not send data to external URLs is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `ZD-01` | 1 | fail | `zd_01_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-01` | 2 | manual | any of (`zd_01_required_evidence_readable` equals false; not (`zd_01_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-01` | 3 | warn | any of (`zd_01_warning_matches` equals true; `zd_01_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-01` | 4 | pass | all of (`zd_01_compliant_matches` equals true; `zd_01_required_evidence_readable` equals true; `zd_01_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-01` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-02` | 1 | fail | `zd_02_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-02` | 2 | manual | any of (`zd_02_required_evidence_readable` equals false; not (`zd_02_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-02` | 3 | warn | any of (`zd_02_warning_matches` equals true; `zd_02_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-02` | 4 | pass | all of (`zd_02_compliant_matches` equals true; `zd_02_required_evidence_readable` equals true; `zd_02_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-02` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-03` | 1 | fail | `zd_03_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-03` | 2 | manual | any of (`zd_03_required_evidence_readable` equals false; not (`zd_03_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-03` | 3 | warn | any of (`zd_03_warning_matches` equals true; `zd_03_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-03` | 4 | pass | all of (`zd_03_compliant_matches` equals true; `zd_03_required_evidence_readable` equals true; `zd_03_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-03` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-04` | 1 | fail | `zd_04_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-04` | 2 | manual | any of (`zd_04_required_evidence_readable` equals false; not (`zd_04_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-04` | 3 | warn | any of (`zd_04_warning_matches` equals true; `zd_04_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-04` | 4 | pass | all of (`zd_04_compliant_matches` equals true; `zd_04_required_evidence_readable` equals true; `zd_04_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-04` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-05` | 1 | fail | `zd_05_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-05` | 2 | manual | any of (`zd_05_required_evidence_readable` equals false; not (`zd_05_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-05` | 3 | warn | any of (`zd_05_warning_matches` equals true; `zd_05_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-05` | 4 | pass | all of (`zd_05_compliant_matches` equals true; `zd_05_required_evidence_readable` equals true; `zd_05_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-05` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-06` | 1 | fail | `zd_06_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-06` | 2 | manual | any of (`zd_06_required_evidence_readable` equals false; not (`zd_06_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-06` | 3 | warn | any of (`zd_06_warning_matches` equals true; `zd_06_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-06` | 4 | pass | all of (`zd_06_compliant_matches` equals true; `zd_06_required_evidence_readable` equals true; `zd_06_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-06` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-07` | 1 | fail | `zd_07_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-07` | 2 | manual | any of (`zd_07_required_evidence_readable` equals false; not (`zd_07_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-07` | 3 | warn | any of (`zd_07_warning_matches` equals true; `zd_07_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-07` | 4 | pass | all of (`zd_07_compliant_matches` equals true; `zd_07_required_evidence_readable` equals true; `zd_07_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-07` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-08` | 1 | manual | any of (`zd_08_required_evidence_readable` equals false; not (`zd_08_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-08` | 2 | warn | any of (`zd_08_warning_matches` equals true; `zd_08_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-08` | 3 | pass | all of (`zd_08_compliant_matches` equals true; `zd_08_required_evidence_readable` equals true; `zd_08_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-08` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-09` | 1 | manual | any of (`zd_09_required_evidence_readable` equals false; not (`zd_09_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-09` | 2 | warn | any of (`zd_09_warning_matches` equals true; `zd_09_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-09` | 3 | pass | all of (`zd_09_compliant_matches` equals true; `zd_09_required_evidence_readable` equals true; `zd_09_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-09` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-10` | 1 | manual | any of (`zd_10_required_evidence_readable` equals false; not (`zd_10_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-10` | 2 | warn | any of (`zd_10_warning_matches` equals true; `zd_10_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-10` | 3 | pass | all of (`zd_10_compliant_matches` equals true; `zd_10_required_evidence_readable` equals true; `zd_10_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-10` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-11` | 1 | manual | any of (`zd_11_required_evidence_readable` equals false; not (`zd_11_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-11` | 2 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-12` | 1 | fail | `zd_12_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-12` | 2 | manual | any of (`zd_12_required_evidence_readable` equals false; not (`zd_12_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-12` | 3 | warn | any of (`zd_12_warning_matches` equals true; `zd_12_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-12` | 4 | pass | all of (`zd_12_compliant_matches` equals true; `zd_12_required_evidence_readable` equals true; `zd_12_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-12` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-13` | 1 | manual | any of (`zd_13_required_evidence_readable` equals false; not (`zd_13_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-13` | 2 | warn | any of (`zd_13_warning_matches` equals true; `zd_13_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-13` | 3 | pass | all of (`zd_13_compliant_matches` equals true; `zd_13_required_evidence_readable` equals true; `zd_13_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-13` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-14` | 1 | fail | `zd_14_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-14` | 2 | manual | any of (`zd_14_required_evidence_readable` equals false; not (`zd_14_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-14` | 3 | warn | any of (`zd_14_warning_matches` equals true; `zd_14_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-14` | 4 | pass | all of (`zd_14_compliant_matches` equals true; `zd_14_required_evidence_readable` equals true; `zd_14_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-14` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-15` | 1 | manual | any of (`zd_15_required_evidence_readable` equals false; not (`zd_15_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-15` | 2 | warn | any of (`zd_15_warning_matches` equals true; `zd_15_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-15` | 3 | pass | all of (`zd_15_compliant_matches` equals true; `zd_15_required_evidence_readable` equals true; `zd_15_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-15` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-16` | 1 | manual | any of (`zd_16_required_evidence_readable` equals false; not (`zd_16_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-16` | 2 | warn | any of (`zd_16_warning_matches` equals true; `zd_16_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-16` | 3 | pass | all of (`zd_16_compliant_matches` equals true; `zd_16_required_evidence_readable` equals true; `zd_16_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-16` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-17` | 1 | manual | any of (`zd_17_required_evidence_readable` equals false; not (`zd_17_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-17` | 2 | warn | any of (`zd_17_warning_matches` equals true; `zd_17_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-17` | 3 | pass | all of (`zd_17_compliant_matches` equals true; `zd_17_required_evidence_readable` equals true; `zd_17_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-17` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-18` | 1 | fail | `zd_18_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-18` | 2 | manual | any of (`zd_18_required_evidence_readable` equals false; not (`zd_18_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-18` | 3 | warn | any of (`zd_18_warning_matches` equals true; `zd_18_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-18` | 4 | pass | all of (`zd_18_compliant_matches` equals true; `zd_18_required_evidence_readable` equals true; `zd_18_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-18` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-19` | 1 | manual | any of (`zd_19_required_evidence_readable` equals false; not (`zd_19_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-19` | 2 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-20` | 1 | manual | any of (`zd_20_required_evidence_readable` equals false; not (`zd_20_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-20` | 2 | warn | any of (`zd_20_warning_matches` equals true; `zd_20_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-20` | 3 | pass | all of (`zd_20_compliant_matches` equals true; `zd_20_required_evidence_readable` equals true; `zd_20_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-20` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-21` | 1 | fail | `zd_21_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-21` | 2 | manual | any of (`zd_21_required_evidence_readable` equals false; not (`zd_21_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-21` | 3 | warn | any of (`zd_21_warning_matches` equals true; `zd_21_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-21` | 4 | pass | all of (`zd_21_compliant_matches` equals true; `zd_21_required_evidence_readable` equals true; `zd_21_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-21` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-22` | 1 | manual | any of (`zd_22_required_evidence_readable` equals false; not (`zd_22_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-22` | 2 | warn | any of (`zd_22_warning_matches` equals true; `zd_22_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-22` | 3 | pass | all of (`zd_22_compliant_matches` equals true; `zd_22_required_evidence_readable` equals true; `zd_22_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-22` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-23` | 1 | manual | any of (`zd_23_required_evidence_readable` equals false; not (`zd_23_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-23` | 2 | warn | any of (`zd_23_warning_matches` equals true; `zd_23_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-23` | 3 | pass | all of (`zd_23_compliant_matches` equals true; `zd_23_required_evidence_readable` equals true; `zd_23_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-23` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-24` | 1 | fail | `zd_24_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-24` | 2 | manual | any of (`zd_24_required_evidence_readable` equals false; not (`zd_24_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-24` | 3 | warn | any of (`zd_24_warning_matches` equals true; `zd_24_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-24` | 4 | pass | all of (`zd_24_compliant_matches` equals true; `zd_24_required_evidence_readable` equals true; `zd_24_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-24` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `ZD-25` | 1 | fail | `zd_25_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `ZD-25` | 2 | manual | any of (`zd_25_required_evidence_readable` equals false; not (`zd_25_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `ZD-25` | 3 | warn | any of (`zd_25_warning_matches` equals true; `zd_25_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `ZD-25` | 4 | pass | all of (`zd_25_compliant_matches` equals true; `zd_25_required_evidence_readable` equals true; `zd_25_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `ZD-25` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `ZD-01` | `zd_01_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-01 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-01` | `zd_01_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-01` | `zd_01_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when team-member SSO is enforced, Zendesk password login is disabled, and at least one SSO method is enabled; warn when SSO is enforced without a method or while password login remains enabled; and fail when SSO is not enforced. |
| `ZD-01` | `zd_01_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when team-member SSO is enforced, Zendesk password login is disabled, and at least one SSO method is enabled; warn when SSO is enforced without a method or while password login remains enabled; and fail when SSO is not enforced. |
| `ZD-01` | `zd_01_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when team-member SSO is enforced, Zendesk password login is disabled, and at least one SSO method is enabled; warn when SSO is enforced without a method or while password login remains enabled; and fail when SSO is not enforced. |
| `ZD-02` | `zd_02_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-02 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-02` | `zd_02_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-02` | `zd_02_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any active team member explicitly lacks 2FA or account enforcement is disabled without enforced SSO, pass when enforcement is enabled and every member in a complete inventory reports 2FA enabled, warn for missing enrollment flags or partial coverage, and manual when MFA depends on the identity provider. |
| `ZD-02` | `zd_02_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any active team member explicitly lacks 2FA or account enforcement is disabled without enforced SSO, pass when enforcement is enabled and every member in a complete inventory reports 2FA enabled, warn for missing enrollment flags or partial coverage, and manual when MFA depends on the identity provider. |
| `ZD-02` | `zd_02_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any active team member explicitly lacks 2FA or account enforcement is disabled without enforced SSO, pass when enforcement is enabled and every member in a complete inventory reports 2FA enabled, warn for missing enrollment flags or partial coverage, and manual when MFA depends on the identity provider. |
| `ZD-03` | `zd_03_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-03 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-03` | `zd_03_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-03` | `zd_03_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass for the Recommended preset or a Custom policy with length at least 12, complexity at least two, mixed case, at most ten failed attempts, email-local-part rejection, and history at least five or unlimited; warn for High or a deficient Custom policy, and fail for every lower preset. |
| `ZD-03` | `zd_03_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass for the Recommended preset or a Custom policy with length at least 12, complexity at least two, mixed case, at most ten failed attempts, email-local-part rejection, and history at least five or unlimited; warn for High or a deficient Custom policy, and fail for every lower preset. |
| `ZD-03` | `zd_03_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass for the Recommended preset or a Custom policy with length at least 12, complexity at least two, mixed case, at most ten failed attempts, email-local-part rejection, and history at least five or unlimited; warn for High or a deficient Custom policy, and fail for every lower preset. |
| `ZD-04` | `zd_04_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-04 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-04` | `zd_04_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-04` | `zd_04_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when IP restriction is enabled with at least one range, warn when enabled with no range, and fail when disabled. |
| `ZD-04` | `zd_04_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when IP restriction is enabled with at least one range, warn when enabled with no range, and fail when disabled. |
| `ZD-04` | `zd_04_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when IP restriction is enabled with at least one range, warn when enabled with no range, and fail when disabled. |
| `ZD-05` | `zd_05_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-05 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-05` | `zd_05_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-05` | `zd_05_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when positive agent and applicable mobile inactivity timeouts are at or below the configured threshold, fail when the agent timeout is zero or above three times the threshold, and warn for every other threshold violation. |
| `ZD-05` | `zd_05_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when positive agent and applicable mobile inactivity timeouts are at or below the configured threshold, fail when the agent timeout is zero or above three times the threshold, and warn for every other threshold violation. |
| `ZD-05` | `zd_05_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when positive agent and applicable mobile inactivity timeouts are at or below the configured threshold, fail when the agent timeout is zero or above three times the threshold, and warn for every other threshold violation. |
| `ZD-06` | `zd_06_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-06 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-06` | `zd_06_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-06` | `zd_06_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any populated custom role grants administrator-equivalent permissions, warn for partial inventories, unassigned administrator-equivalent roles, or an all-unrestricted agent population, and pass when complete role and team inventories show none. |
| `ZD-06` | `zd_06_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any populated custom role grants administrator-equivalent permissions, warn for partial inventories, unassigned administrator-equivalent roles, or an all-unrestricted agent population, and pass when complete role and team inventories show none. |
| `ZD-06` | `zd_06_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any populated custom role grants administrator-equivalent permissions, warn for partial inventories, unassigned administrator-equivalent roles, or an all-unrestricted agent population, and pass when complete role and team inventories show none. |
| `ZD-07` | `zd_07_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-07 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-07` | `zd_07_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-07` | `zd_07_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when active administrators exceed the configured threshold, warn when any administrator is stale, undated, or the inventory is partial, and pass when the non-empty complete inventory is within the threshold and all administrators are recent. |
| `ZD-07` | `zd_07_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when active administrators exceed the configured threshold, warn when any administrator is stale, undated, or the inventory is partial, and pass when the non-empty complete inventory is within the threshold and all administrators are recent. |
| `ZD-07` | `zd_07_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when active administrators exceed the configured threshold, warn when any administrator is stale, undated, or the inventory is partial, and pass when the non-empty complete inventory is within the threshold and all administrators are recent. |
| `ZD-08` | `zd_08_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-08 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-08` | `zd_08_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-08` | `zd_08_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when complete inventories contain more than one group and at least one membership, and warn when only one group exists, no membership exists, or either inventory is truncated. |
| `ZD-08` | `zd_08_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when complete inventories contain more than one group and at least one membership, and warn when only one group exists, no membership exists, or either inventory is truncated. |
| `ZD-08` | `zd_08_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when complete inventories contain more than one group and at least one membership, and warn when only one group exists, no membership exists, or either inventory is truncated. |
| `ZD-09` | `zd_09_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-09 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-09` | `zd_09_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-09` | `zd_09_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the recent audit-log endpoint returns at least one entry and fills or cleanly completes its 25-entry sample, warn when paging cuts that sample short, and manual when the endpoint is unavailable or a completed sample is unexpectedly empty. |
| `ZD-09` | `zd_09_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the recent audit-log endpoint returns at least one entry and fills or cleanly completes its 25-entry sample, warn when paging cuts that sample short, and manual when the endpoint is unavailable or a completed sample is unexpectedly empty. |
| `ZD-09` | `zd_09_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the recent audit-log endpoint returns at least one entry and fills or cleanly completes its 25-entry sample, warn when paging cuts that sample short, and manual when the endpoint is unavailable or a completed sample is unexpectedly empty. |
| `ZD-10` | `zd_10_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-10 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-10` | `zd_10_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-10` | `zd_10_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the dated oldest audit entry is at least the configured retention age and warn when it is younger; an absent or undated oldest entry is manual. |
| `ZD-10` | `zd_10_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the dated oldest audit entry is at least the configured retention age and warn when it is younger; an absent or undated oldest entry is manual. |
| `ZD-10` | `zd_10_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the dated oldest audit entry is at least the configured retention age and warn when it is younger; an absent or undated oldest entry is manual. |
| `ZD-11` | `zd_11_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-11 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-11` | `zd_11_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-11` | `zd_11_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: always return manual because the published Account Settings and Security Settings APIs expose no HIPAA or Advanced Data Privacy and Protection field. |
| `ZD-11` | `zd_11_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: always return manual because the published Account Settings and Security Settings APIs expose no HIPAA or Advanced Data Privacy and Protection field. |
| `ZD-11` | `zd_11_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: always return manual because the published Account Settings and Security Settings APIs expose no HIPAA or Advanced Data Privacy and Protection field. |
| `ZD-12` | `zd_12_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-12 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-12` | `zd_12_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-12` | `zd_12_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when a complete deletion-schedule inventory is empty or has no active schedule, pass when it has a conditioned active ticket schedule and all companion evidence is complete, and warn for truncation, no active ticket schedule, or any active schedule without conditions. |
| `ZD-12` | `zd_12_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when a complete deletion-schedule inventory is empty or has no active schedule, pass when it has a conditioned active ticket schedule and all companion evidence is complete, and warn for truncation, no active ticket schedule, or any active schedule without conditions. |
| `ZD-12` | `zd_12_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when a complete deletion-schedule inventory is empty or has no active schedule, pass when it has a conditioned active ticket schedule and all companion evidence is complete, and warn for truncation, no active ticket schedule, or any active schedule without conditions. |
| `ZD-13` | `zd_13_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-13 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-13` | `zd_13_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-13` | `zd_13_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when API-token authentication is disabled and audit evidence is complete, warn when it is enabled but the event history shows no outstanding token, and manual when enabled tokens remain or account settings or token history are unavailable. |
| `ZD-13` | `zd_13_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when API-token authentication is disabled and audit evidence is complete, warn when it is enabled but the event history shows no outstanding token, and manual when enabled tokens remain or account settings or token history are unavailable. |
| `ZD-13` | `zd_13_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when API-token authentication is disabled and audit evidence is complete, warn when it is enabled but the event history shows no outstanding token, and manual when enabled tokens remain or account settings or token history are unavailable. |
| `ZD-14` | `zd_14_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-14 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-14` | `zd_14_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-14` | `zd_14_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any OAuth client is unscoped or has a non-local HTTP redirect, pass when complete client and token inventories are empty or all clients are scoped with HTTPS redirects and every token is expiring and recently used, and warn for public, privileged, non-expiring, stale, undated, hidden, partial, or unreadable token evidence. |
| `ZD-14` | `zd_14_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any OAuth client is unscoped or has a non-local HTTP redirect, pass when complete client and token inventories are empty or all clients are scoped with HTTPS redirects and every token is expiring and recently used, and warn for public, privileged, non-expiring, stale, undated, hidden, partial, or unreadable token evidence. |
| `ZD-14` | `zd_14_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any OAuth client is unscoped or has a non-local HTTP redirect, pass when complete client and token inventories are empty or all clients are scoped with HTTPS redirects and every token is expiring and recently used, and warn for public, privileged, non-expiring, stale, undated, hidden, partial, or unreadable token evidence. |
| `ZD-15` | `zd_15_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-15 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-15` | `zd_15_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-15` | `zd_15_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when complete installation and owned-app inventories prove no installed apps, warn when the installation inventory truncates before its first app, and manual when any installation exists because the API does not prove that marketplace permissions were reviewed. |
| `ZD-15` | `zd_15_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when complete installation and owned-app inventories prove no installed apps, warn when the installation inventory truncates before its first app, and manual when any installation exists because the API does not prove that marketplace permissions were reviewed. |
| `ZD-15` | `zd_15_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when complete installation and owned-app inventories prove no installed apps, warn when the installation inventory truncates before its first app, and manual when any installation exists because the API does not prove that marketplace permissions were reviewed. |
| `ZD-16` | `zd_16_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-16 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-16` | `zd_16_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-16` | `zd_16_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the complete owned-app inventory is empty, warn when any owned app is deprecated or obsolete or the inventory truncates before its first app, and manual for other non-empty inventories because manifest scope review is not automated. |
| `ZD-16` | `zd_16_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the complete owned-app inventory is empty, warn when any owned app is deprecated or obsolete or the inventory truncates before its first app, and manual for other non-empty inventories because manifest scope review is not automated. |
| `ZD-16` | `zd_16_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the complete owned-app inventory is empty, warn when any owned app is deprecated or obsolete or the inventory truncates before its first app, and manual for other non-empty inventories because manifest scope review is not automated. |
| `ZD-17` | `zd_17_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-17 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-17` | `zd_17_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-17` | `zd_17_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when account settings report the sandbox feature enabled, warn when disabled, and manual when the flag is absent. |
| `ZD-17` | `zd_17_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when account settings report the sandbox feature enabled, warn when disabled, and manual when the flag is absent. |
| `ZD-17` | `zd_17_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when account settings report the sandbox feature enabled, warn when disabled, and manual when the flag is absent. |
| `ZD-18` | `zd_18_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-18 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-18` | `zd_18_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-18` | `zd_18_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when authenticated attachment downloads are enabled and every listed CDN host uses HTTPS, warn when authentication is enabled but any CDN host is insecure, and fail when authenticated downloads are disabled. |
| `ZD-18` | `zd_18_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when authenticated attachment downloads are enabled and every listed CDN host uses HTTPS, warn when authentication is enabled but any CDN host is insecure, and fail when authenticated downloads are disabled. |
| `ZD-18` | `zd_18_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when authenticated attachment downloads are enabled and every listed CDN host uses HTTPS, warn when authentication is enabled but any CDN host is insecure, and fail when authenticated downloads are disabled. |
| `ZD-19` | `zd_19_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-19 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-19` | `zd_19_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-19` | `zd_19_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: always return manual because the API exposes attachment size and email-attachment posture but not allowed file types or malicious-attachment detection. |
| `ZD-19` | `zd_19_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: always return manual because the API exposes attachment size and email-attachment posture but not allowed file types or malicious-attachment detection. |
| `ZD-19` | `zd_19_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: always return manual because the API exposes attachment size and email-attachment posture but not allowed file types or malicious-attachment detection. |
| `ZD-20` | `zd_20_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-20 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-20` | `zd_20_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-20` | `zd_20_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the complete suspended-ticket queue is empty or every queued ticket is dated and newer than the configured age, and warn for stale, undated, or partial queue evidence. |
| `ZD-20` | `zd_20_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the complete suspended-ticket queue is empty or every queued ticket is dated and newer than the configured age, and warn for stale, undated, or partial queue evidence. |
| `ZD-20` | `zd_20_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the complete suspended-ticket queue is empty or every queued ticket is dated and newer than the configured age, and warn for stale, undated, or partial queue evidence. |
| `ZD-21` | `zd_21_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-21 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-21` | `zd_21_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-21` | `zd_21_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when end users have enforced SSO with a method, password login under Recommended or High, or SSO-only login; warn for enforced SSO without a method or a weaker password preset, fail when no login method exists, and keep anonymous-ticket submission as a named manual limitation. |
| `ZD-21` | `zd_21_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when end users have enforced SSO with a method, password login under Recommended or High, or SSO-only login; warn for enforced SSO without a method or a weaker password preset, fail when no login method exists, and keep anonymous-ticket submission as a named manual limitation. |
| `ZD-21` | `zd_21_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when end users have enforced SSO with a method, password login under Recommended or High, or SSO-only login; warn for enforced SSO without a method or a weaker password preset, fail when no login method exists, and keep anonymous-ticket submission as a named manual limitation. |
| `ZD-22` | `zd_22_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-22 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-22` | `zd_22_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-22` | `zd_22_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when an administrator reads every active brand and all have one known help-center state, warn for a non-admin view, truncation, or mixed or unknown states, and manual when no brand is visible. |
| `ZD-22` | `zd_22_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when an administrator reads every active brand and all have one known help-center state, warn for a non-admin view, truncation, or mixed or unknown states, and manual when no brand is visible. |
| `ZD-22` | `zd_22_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when an administrator reads every active brand and all have one known help-center state, warn for a non-admin view, truncation, or mixed or unknown states, and manual when no brand is visible. |
| `ZD-23` | `zd_23_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-23 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-23` | `zd_23_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-23` | `zd_23_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the complete sharing-agreement inventory is empty, warn when any agreement is failed, ssl_error, or configuration_error or the inventory truncates before its first record, and manual when accepted or pending external agreements require business review. |
| `ZD-23` | `zd_23_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the complete sharing-agreement inventory is empty, warn when any agreement is failed, ssl_error, or configuration_error or the inventory truncates before its first record, and manual when accepted or pending external agreements require business review. |
| `ZD-23` | `zd_23_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the complete sharing-agreement inventory is empty, warn when any agreement is failed, ssl_error, or configuration_error or the inventory truncates before its first record, and manual when accepted or pending external agreements require business review. |
| `ZD-24` | `zd_24_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-24 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-24` | `zd_24_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-24` | `zd_24_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any active target or webhook uses a non-HTTPS endpoint, pass when complete readable inventories contain no active destination or every destination is HTTPS and every webhook has authentication, and warn for missing, partial, or unauthenticated destination evidence. |
| `ZD-24` | `zd_24_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any active target or webhook uses a non-HTTPS endpoint, pass when complete readable inventories contain no active destination or every destination is HTTPS and every webhook has authentication, and warn for missing, partial, or unauthenticated destination evidence. |
| `ZD-24` | `zd_24_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any active target or webhook uses a non-HTTPS endpoint, pass when complete readable inventories contain no active destination or every destination is HTTPS and every webhook has authentication, and warn for missing, partial, or unauthenticated destination evidence. |
| `ZD-25` | `zd_25_required_evidence_readable` | From the declared source surfaces, set true only when every value required by ZD-25 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `ZD-25` | `zd_25_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `ZD-25` | `zd_25_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any active trigger or automation sends ticket data to an HTTP destination, pass when the complete non-empty rule inventory has no external notification action and destination lookups are complete, warn for external actions or partial evidence, and manual when no active rule is visible or either rule inventory is unavailable. |
| `ZD-25` | `zd_25_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any active trigger or automation sends ticket data to an HTTP destination, pass when the complete non-empty rule inventory has no external notification action and destination lookups are complete, warn for external actions or partial evidence, and manual when no active rule is visible or either rule inventory is unavailable. |
| `ZD-25` | `zd_25_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any active trigger or automation sends ticket data to an HTTP destination, pass when the complete non-empty rule inventory has no external notification action and destination lookups are complete, warn for external actions or partial evidence, and manual when no active rule is visible or either rule inventory is unavailable. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `ZD-01` | `requiredEvidenceReadable` | true |
| `ZD-01` | `requiredEvidenceComplete` | true |
| `ZD-02` | `requiredEvidenceReadable` | true |
| `ZD-02` | `requiredEvidenceComplete` | true |
| `ZD-03` | `requiredEvidenceReadable` | true |
| `ZD-03` | `requiredEvidenceComplete` | true |
| `ZD-04` | `requiredEvidenceReadable` | true |
| `ZD-04` | `requiredEvidenceComplete` | true |
| `ZD-05` | `requiredEvidenceReadable` | true |
| `ZD-05` | `requiredEvidenceComplete` | true |
| `ZD-06` | `requiredEvidenceReadable` | true |
| `ZD-06` | `requiredEvidenceComplete` | true |
| `ZD-07` | `requiredEvidenceReadable` | true |
| `ZD-07` | `requiredEvidenceComplete` | true |
| `ZD-08` | `requiredEvidenceReadable` | true |
| `ZD-08` | `requiredEvidenceComplete` | true |
| `ZD-09` | `requiredEvidenceReadable` | true |
| `ZD-09` | `requiredEvidenceComplete` | true |
| `ZD-10` | `requiredEvidenceReadable` | true |
| `ZD-10` | `requiredEvidenceComplete` | true |
| `ZD-11` | `requiredEvidenceReadable` | true |
| `ZD-11` | `requiredEvidenceComplete` | true |
| `ZD-12` | `requiredEvidenceReadable` | true |
| `ZD-12` | `requiredEvidenceComplete` | true |
| `ZD-13` | `requiredEvidenceReadable` | true |
| `ZD-13` | `requiredEvidenceComplete` | true |
| `ZD-14` | `requiredEvidenceReadable` | true |
| `ZD-14` | `requiredEvidenceComplete` | true |
| `ZD-15` | `requiredEvidenceReadable` | true |
| `ZD-15` | `requiredEvidenceComplete` | true |
| `ZD-16` | `requiredEvidenceReadable` | true |
| `ZD-16` | `requiredEvidenceComplete` | true |
| `ZD-17` | `requiredEvidenceReadable` | true |
| `ZD-17` | `requiredEvidenceComplete` | true |
| `ZD-18` | `requiredEvidenceReadable` | true |
| `ZD-18` | `requiredEvidenceComplete` | true |
| `ZD-19` | `requiredEvidenceReadable` | true |
| `ZD-19` | `requiredEvidenceComplete` | true |
| `ZD-20` | `requiredEvidenceReadable` | true |
| `ZD-20` | `requiredEvidenceComplete` | true |
| `ZD-21` | `requiredEvidenceReadable` | true |
| `ZD-21` | `requiredEvidenceComplete` | true |
| `ZD-22` | `requiredEvidenceReadable` | true |
| `ZD-22` | `requiredEvidenceComplete` | true |
| `ZD-23` | `requiredEvidenceReadable` | true |
| `ZD-23` | `requiredEvidenceComplete` | true |
| `ZD-24` | `requiredEvidenceReadable` | true |
| `ZD-24` | `requiredEvidenceComplete` | true |
| `ZD-25` | `requiredEvidenceReadable` | true |
| `ZD-25` | `requiredEvidenceComplete` | true |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `ZD-01` | compliant | All required source reads are complete and this derivation returns pass: return pass when team-member SSO is enforced, Zendesk password login is disabled, and at least one SSO method is enabled; warn when SSO is enforced without a method or while password login remains enabled; and fail when SSO is not enforced. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when team-member SSO is enforced, Zendesk password login is disabled, and at least one SSO method is enabled; warn when SSO is enforced without a method or while password login remains enabled; and fail when SSO is not enforced. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-02` | compliant | All required source reads are complete and this derivation returns pass: return fail when any active team member explicitly lacks 2FA or account enforcement is disabled without enforced SSO, pass when enforcement is enabled and every member in a complete inventory reports 2FA enabled, warn for missing enrollment flags or partial coverage, and manual when MFA depends on the identity provider. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any active team member explicitly lacks 2FA or account enforcement is disabled without enforced SSO, pass when enforcement is enabled and every member in a complete inventory reports 2FA enabled, warn for missing enrollment flags or partial coverage, and manual when MFA depends on the identity provider. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-03` | compliant | All required source reads are complete and this derivation returns pass: return pass for the Recommended preset or a Custom policy with length at least 12, complexity at least two, mixed case, at most ten failed attempts, email-local-part rejection, and history at least five or unlimited; warn for High or a deficient Custom policy, and fail for every lower preset. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass for the Recommended preset or a Custom policy with length at least 12, complexity at least two, mixed case, at most ten failed attempts, email-local-part rejection, and history at least five or unlimited; warn for High or a deficient Custom policy, and fail for every lower preset. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-04` | compliant | All required source reads are complete and this derivation returns pass: return pass when IP restriction is enabled with at least one range, warn when enabled with no range, and fail when disabled. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when IP restriction is enabled with at least one range, warn when enabled with no range, and fail when disabled. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-05` | compliant | All required source reads are complete and this derivation returns pass: return pass when positive agent and applicable mobile inactivity timeouts are at or below the configured threshold, fail when the agent timeout is zero or above three times the threshold, and warn for every other threshold violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when positive agent and applicable mobile inactivity timeouts are at or below the configured threshold, fail when the agent timeout is zero or above three times the threshold, and warn for every other threshold violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-06` | compliant | All required source reads are complete and this derivation returns pass: return fail when any populated custom role grants administrator-equivalent permissions, warn for partial inventories, unassigned administrator-equivalent roles, or an all-unrestricted agent population, and pass when complete role and team inventories show none. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any populated custom role grants administrator-equivalent permissions, warn for partial inventories, unassigned administrator-equivalent roles, or an all-unrestricted agent population, and pass when complete role and team inventories show none. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-07` | compliant | All required source reads are complete and this derivation returns pass: return fail when active administrators exceed the configured threshold, warn when any administrator is stale, undated, or the inventory is partial, and pass when the non-empty complete inventory is within the threshold and all administrators are recent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when active administrators exceed the configured threshold, warn when any administrator is stale, undated, or the inventory is partial, and pass when the non-empty complete inventory is within the threshold and all administrators are recent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-08` | compliant | All required source reads are complete and this derivation returns pass: return pass when complete inventories contain more than one group and at least one membership, and warn when only one group exists, no membership exists, or either inventory is truncated. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-08` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when complete inventories contain more than one group and at least one membership, and warn when only one group exists, no membership exists, or either inventory is truncated. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-09` | compliant | All required source reads are complete and this derivation returns pass: return pass when the recent audit-log endpoint returns at least one entry and fills or cleanly completes its 25-entry sample, warn when paging cuts that sample short, and manual when the endpoint is unavailable or a completed sample is unexpectedly empty. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-09` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the recent audit-log endpoint returns at least one entry and fills or cleanly completes its 25-entry sample, warn when paging cuts that sample short, and manual when the endpoint is unavailable or a completed sample is unexpectedly empty. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-09` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-09` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-10` | compliant | All required source reads are complete and this derivation returns pass: return pass when the dated oldest audit entry is at least the configured retention age and warn when it is younger; an absent or undated oldest entry is manual. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-10` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the dated oldest audit entry is at least the configured retention age and warn when it is younger; an absent or undated oldest entry is manual. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-10` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-10` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-11` | compliant | All required source reads are complete and this derivation returns pass: always return manual because the published Account Settings and Security Settings APIs expose no HIPAA or Advanced Data Privacy and Protection field. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-11` | noncompliant | A complete source read satisfies the fail branch of this derivation: always return manual because the published Account Settings and Security Settings APIs expose no HIPAA or Advanced Data Privacy and Protection field. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-11` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-11` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-12` | compliant | All required source reads are complete and this derivation returns pass: return fail when a complete deletion-schedule inventory is empty or has no active schedule, pass when it has a conditioned active ticket schedule and all companion evidence is complete, and warn for truncation, no active ticket schedule, or any active schedule without conditions. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-12` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when a complete deletion-schedule inventory is empty or has no active schedule, pass when it has a conditioned active ticket schedule and all companion evidence is complete, and warn for truncation, no active ticket schedule, or any active schedule without conditions. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-12` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-12` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-13` | compliant | All required source reads are complete and this derivation returns pass: return pass when API-token authentication is disabled and audit evidence is complete, warn when it is enabled but the event history shows no outstanding token, and manual when enabled tokens remain or account settings or token history are unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-13` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when API-token authentication is disabled and audit evidence is complete, warn when it is enabled but the event history shows no outstanding token, and manual when enabled tokens remain or account settings or token history are unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-13` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-13` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-14` | compliant | All required source reads are complete and this derivation returns pass: return fail when any OAuth client is unscoped or has a non-local HTTP redirect, pass when complete client and token inventories are empty or all clients are scoped with HTTPS redirects and every token is expiring and recently used, and warn for public, privileged, non-expiring, stale, undated, hidden, partial, or unreadable token evidence. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-14` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any OAuth client is unscoped or has a non-local HTTP redirect, pass when complete client and token inventories are empty or all clients are scoped with HTTPS redirects and every token is expiring and recently used, and warn for public, privileged, non-expiring, stale, undated, hidden, partial, or unreadable token evidence. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-14` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-14` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-15` | compliant | All required source reads are complete and this derivation returns pass: return pass when complete installation and owned-app inventories prove no installed apps, warn when the installation inventory truncates before its first app, and manual when any installation exists because the API does not prove that marketplace permissions were reviewed. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-15` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when complete installation and owned-app inventories prove no installed apps, warn when the installation inventory truncates before its first app, and manual when any installation exists because the API does not prove that marketplace permissions were reviewed. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-15` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-15` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-16` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete owned-app inventory is empty, warn when any owned app is deprecated or obsolete or the inventory truncates before its first app, and manual for other non-empty inventories because manifest scope review is not automated. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-16` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete owned-app inventory is empty, warn when any owned app is deprecated or obsolete or the inventory truncates before its first app, and manual for other non-empty inventories because manifest scope review is not automated. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-16` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-16` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-17` | compliant | All required source reads are complete and this derivation returns pass: return pass when account settings report the sandbox feature enabled, warn when disabled, and manual when the flag is absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-17` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when account settings report the sandbox feature enabled, warn when disabled, and manual when the flag is absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-17` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-17` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-18` | compliant | All required source reads are complete and this derivation returns pass: return pass when authenticated attachment downloads are enabled and every listed CDN host uses HTTPS, warn when authentication is enabled but any CDN host is insecure, and fail when authenticated downloads are disabled. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-18` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when authenticated attachment downloads are enabled and every listed CDN host uses HTTPS, warn when authentication is enabled but any CDN host is insecure, and fail when authenticated downloads are disabled. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-18` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-18` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-19` | compliant | All required source reads are complete and this derivation returns pass: always return manual because the API exposes attachment size and email-attachment posture but not allowed file types or malicious-attachment detection. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-19` | noncompliant | A complete source read satisfies the fail branch of this derivation: always return manual because the API exposes attachment size and email-attachment posture but not allowed file types or malicious-attachment detection. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-19` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-19` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-20` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete suspended-ticket queue is empty or every queued ticket is dated and newer than the configured age, and warn for stale, undated, or partial queue evidence. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-20` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete suspended-ticket queue is empty or every queued ticket is dated and newer than the configured age, and warn for stale, undated, or partial queue evidence. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-20` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-20` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-21` | compliant | All required source reads are complete and this derivation returns pass: return pass when end users have enforced SSO with a method, password login under Recommended or High, or SSO-only login; warn for enforced SSO without a method or a weaker password preset, fail when no login method exists, and keep anonymous-ticket submission as a named manual limitation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-21` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when end users have enforced SSO with a method, password login under Recommended or High, or SSO-only login; warn for enforced SSO without a method or a weaker password preset, fail when no login method exists, and keep anonymous-ticket submission as a named manual limitation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-21` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-21` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-22` | compliant | All required source reads are complete and this derivation returns pass: return pass when an administrator reads every active brand and all have one known help-center state, warn for a non-admin view, truncation, or mixed or unknown states, and manual when no brand is visible. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-22` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when an administrator reads every active brand and all have one known help-center state, warn for a non-admin view, truncation, or mixed or unknown states, and manual when no brand is visible. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-22` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-22` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-23` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete sharing-agreement inventory is empty, warn when any agreement is failed, ssl_error, or configuration_error or the inventory truncates before its first record, and manual when accepted or pending external agreements require business review. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-23` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete sharing-agreement inventory is empty, warn when any agreement is failed, ssl_error, or configuration_error or the inventory truncates before its first record, and manual when accepted or pending external agreements require business review. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-23` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-23` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-24` | compliant | All required source reads are complete and this derivation returns pass: return fail when any active target or webhook uses a non-HTTPS endpoint, pass when complete readable inventories contain no active destination or every destination is HTTPS and every webhook has authentication, and warn for missing, partial, or unauthenticated destination evidence. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-24` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any active target or webhook uses a non-HTTPS endpoint, pass when complete readable inventories contain no active destination or every destination is HTTPS and every webhook has authentication, and warn for missing, partial, or unauthenticated destination evidence. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-24` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-24` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZD-25` | compliant | All required source reads are complete and this derivation returns pass: return fail when any active trigger or automation sends ticket data to an HTTP destination, pass when the complete non-empty rule inventory has no external notification action and destination lookups are complete, warn for external actions or partial evidence, and manual when no active rule is visible or either rule inventory is unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZD-25` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any active trigger or automation sends ticket data to an HTTP destination, pass when the complete non-empty rule inventory has no external notification action and destination lookups are complete, warn for external actions or partial evidence, and manual when no active rule is visible or either rule inventory is unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZD-25` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZD-25` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | SSO enforcement enabled | IA-2 | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 2 | Two-factor authentication required for agents | IA-2(1) | IA.L2-3.5.3 | CC6.1 | 4.5 | 8.3.2 | SRG-APP-000149 | ISM-1401 | 8.2.2 |
| 3 | Password policy meets complexity requirements | IA-5(1) | IA.L2-3.5.7 | CC6.1 | 5.1 | 8.2.3 | SRG-APP-000164 | ISM-0421 | 8.2.3 |
| 4 | IP restrictions configured for agent access | SC-7 | SC.L2-3.13.6 | CC6.6 | 4.4 | 1.3.2 | SRG-APP-000383 | ISM-1284 | 10.2.2 |
| 5 | Session timeout configured and reasonable | AC-12 | AC.L2-3.1.10 | CC6.1 | 5.6 | 8.1.8 | SRG-APP-000295 | ISM-1164 | 8.3.1 |
| 6 | Agent roles follow least privilege | AC-6(1) | AC.L2-3.1.5 | CC6.3 | 6.1 | 7.1.1 | SRG-APP-000340 | ISM-1508 | 8.1.2 |
| 7 | No excessive admin accounts | AC-6(5) | AC.L2-3.1.5 | CC6.3 | 6.2 | 7.1.2 | SRG-APP-000340 | ISM-1508 | 8.1.3 |
| 8 | Group-based access controls configured | AC-3 | AC.L2-3.1.2 | CC6.1 | 6.1 | 7.1.1 | SRG-APP-000033 | ISM-1508 | 8.1.1 |
| 9 | Audit logging enabled and accessible | AU-2 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.1 | SRG-APP-000089 | ISM-0580 | 12.1.1 |
| 10 | Audit log retention meets compliance requirements | AU-11 | AU.L2-3.3.1 | CC7.2 | 8.3 | 10.7 | SRG-APP-000515 | ISM-0859 | 12.1.2 |
| 11 | HIPAA compliance mode enabled when applicable | SC-28 | SC.L2-3.13.16 | CC6.1 | 14.7 | 3.4 | SRG-APP-000231 | ISM-0457 | 10.1.2 |
| 12 | Data deletion and redaction policies configured | SI-12 | MP.L2-3.8.3 | CC6.5 | 3.1 | 3.1 | SRG-APP-000504 | ISM-0261 | 7.1.1 |
| 13 | API tokens are minimal and reviewed | IA-5(1) | IA.L2-3.5.10 | CC6.1 | 4.4 | 8.2.4 | SRG-APP-000174 | ISM-1557 | 8.2.4 |
| 14 | OAuth application permissions are scoped | AC-6 | AC.L2-3.1.1 | CC6.3 | 6.1 | 7.1.1 | SRG-APP-000033 | ISM-1508 | 8.1.1 |
| 15 | Marketplace apps reviewed for permissions | CM-7 | CM.L2-3.4.7 | CC6.6 | 13.5 | 2.2.2 | SRG-APP-000141 | ISM-1284 | 6.1.1 |
| 16 | Private and custom apps have appropriate scope | CM-7 | CM.L2-3.4.7 | CC6.6 | 13.5 | 2.2.2 | SRG-APP-000141 | ISM-1284 | 6.1.1 |
| 17 | Sandbox environment used for testing | CM-3 | CM.L2-3.4.3 | CC8.1 | 2.3 | 6.4.1 | SRG-APP-000128 | ISM-1211 | 6.2.1 |
| 18 | Authenticated attachment downloads configured | SC-8 | SC.L2-3.13.1 | CC6.7 | 14.4 | 4.1 | SRG-APP-000439 | ISM-0487 | 10.1.1 |
| 19 | File attachment restrictions configured | SC-7 | SC.L2-3.13.6 | CC6.6 | 13.1 | 1.3.1 | SRG-APP-000383 | ISM-1284 | 10.2.1 |
| 20 | Suspended ticket handling automated | SI-4 | SI.L2-3.14.6 | CC7.2 | 8.5 | 10.6.1 | SRG-APP-000095 | ISM-0580 | 12.1.3 |
| 21 | End-user authentication required | IA-2 | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 22 | Brand security settings consistent | CM-2 | CM.L2-3.4.1 | CC6.1 | 2.1 | 2.2 | SRG-APP-000128 | ISM-1211 | 6.1.1 |
| 23 | External sharing agreements reviewed | AC-4 | AC.L2-3.1.3 | CC6.6 | 13.4 | 7.1.2 | SRG-APP-000039 | ISM-1284 | 8.1.3 |
| 24 | External notification targets use HTTPS | SC-8(1) | SC.L2-3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0487 | 10.1.1 |
| 25 | Triggers and automations do not send data to external URLs | AC-4 | AC.L2-3.1.3 | CC6.6 | 13.4 | 1.3.4 | SRG-APP-000039 | ISM-1284 | 8.1.3 |

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
| `current-user` | `user.id`, `user.email`, `user.role` |
| `account-settings` | `settings.api`, `settings.tickets`, `settings.attachments`, `settings.sandbox` |
| `security-settings` | `security_settings.authentication`, `security_settings.ip`, `security_settings.session_expiration`, `security_settings.mobile_session_expiration` |
| `team-members` | `users.id`, `users.email`, `users.role`, `users.custom_role_id`, `users.active`, `users.suspended`, `users.last_login_at`, `users.two_factor_auth_enabled`, `users.restricted_agent` |
| `custom-roles` | `custom_roles.id`, `custom_roles.name`, `custom_roles.configuration`, `custom_roles.team_member_count` |
| `groups` | `groups.id`, `groups.name`, `groups.deleted` |
| `group-memberships` | `group_memberships.id`, `group_memberships.group_id`, `group_memberships.user_id` |
| `audit-logs-recent` | `audit_logs.id`, `audit_logs.created_at`, `audit_logs.action`, `audit_logs.source_type`, `audit_logs.source_id`, `audit_logs.actor_id` |
| `audit-log-oldest` | `audit_logs.id`, `audit_logs.created_at` |
| `api-token-audit-logs` | `audit_logs.id`, `audit_logs.created_at`, `audit_logs.action`, `audit_logs.source_type`, `audit_logs.source_id`, `audit_logs.source_label` |
| `deletion-schedules` | `deletion_schedules.id`, `deletion_schedules.title`, `deletion_schedules.object`, `deletion_schedules.active`, `deletion_schedules.default`, `deletion_schedules.conditions`, `deletion_schedules.updated_at` |
| `oauth-clients` | `clients.id`, `clients.name`, `clients.allowed_scopes`, `clients.redirect_uri`, `clients.public` |
| `oauth-tokens` | `tokens.id`, `tokens.client_id`, `tokens.user_id`, `tokens.scopes`, `tokens.expires_at`, `tokens.used_at` |
| `app-installations` | `installations.id`, `installations.app_id`, `installations.enabled`, `installations.settings`, `installations.product`, `installations.role_restrictions`, `installations.group_restrictions` |
| `owned-apps` | `apps.id`, `apps.name`, `apps.deprecated`, `apps.obsolete` |
| `brands` | `brands.id`, `brands.name`, `brands.active`, `brands.has_help_center` |
| `webhooks` | `webhooks.id`, `webhooks.name`, `webhooks.active`, `webhooks.endpoint`, `webhooks.http_method`, `webhooks.authentication` |
| `targets` | `targets.id`, `targets.title`, `targets.active`, `targets.type`, `targets.target_url` |
| `triggers` | `triggers.id`, `triggers.title`, `triggers.active`, `triggers.actions` |
| `automations` | `automations.id`, `automations.title`, `automations.active`, `automations.actions` |
| `sharing-agreements` | `sharing_agreements.id`, `sharing_agreements.name`, `sharing_agreements.status` |
| `suspended-tickets` | `suspended_tickets.id`, `suspended_tickets.created_at`, `suspended_tickets.subject`, `suspended_tickets.cause` |

## Export layout

Required paths:

- `metadata.json`
- `QUICK_REFERENCE.md`
- `core_data/access_check.json`
- `core_data/current_user.json`
- `core_data/account_settings.json`
- `core_data/security_settings.json`
- `core_data/team_members.json`
- `core_data/custom_roles.json`
- `core_data/groups.json`
- `core_data/group_memberships.json`
- `core_data/oauth_clients.json`
- `core_data/oauth_tokens.json`
- `core_data/api_token_audit_logs.json`
- `core_data/audit_logs_recent.json`
- `core_data/audit_log_oldest.json`
- `core_data/deletion_schedules.json`
- `core_data/suspended_tickets.json`
- `core_data/app_installations.json`
- `core_data/owned_apps.json`
- `core_data/brands.json`
- `core_data/sharing_agreements.json`
- `core_data/targets.json`
- `core_data/webhooks.json`
- `core_data/triggers.json`
- `core_data/automations.json`
- `analysis/authentication.json`
- `analysis/access-control.json`
- `analysis/data-protection.json`
- `analysis/integrations.json`
- `analysis/findings.json`
- `compliance/executive_summary.md`
- `compliance/unified_compliance_matrix.md`
- `compliance/fedramp_compliance_report.md`
- `compliance/cmmc_compliance_report.md`
- `compliance/soc2_compliance_report.md`
- `compliance/cis_compliance_report.md`
- `compliance/pci_dss_compliance_report.md`
- `compliance/disa_stig_compliance_report.md`
- `compliance/irap_compliance_report.md`
- `compliance/ismap_compliance_report.md`

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `metadata.json` | json | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `QUICK_REFERENCE.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `core_data/access_check.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/current_user.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/account_settings.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/security_settings.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/team_members.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/custom_roles.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/groups.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/group_memberships.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/oauth_clients.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/oauth_tokens.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/api_token_audit_logs.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/audit_logs_recent.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/audit_log_oldest.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/deletion_schedules.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/suspended_tickets.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/app_installations.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/owned_apps.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/brands.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sharing_agreements.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/targets.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/webhooks.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/triggers.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/automations.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/authentication.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/access-control.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/data-protection.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/integrations.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/findings.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `compliance/executive_summary.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/unified_compliance_matrix.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/fedramp_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cmmc_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/soc2_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cis_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/pci_dss_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/disa_stig_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/irap_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/ismap_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
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

Overwrite policy: Allocate a new {subdomain}-zendesk-audit-bundle directory with a numeric suffix when needed; never overwrite a prior directory.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Write a sibling zip named from the exact allocated bundle-directory path plus .zip.
