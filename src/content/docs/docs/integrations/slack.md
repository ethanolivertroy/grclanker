---
title: Slack
description: Read-only Slack Enterprise Grid security inspector covering identity, admin access, integrations, channel governance, monitoring, and evidence export.
---

The Slack tool family inspects a Slack Enterprise Grid organization (or a single workspace when only a workspace token is available) against the 25 controls in `specs/slack-sec-inspector.spec.md`. Every method call is read-only, and every field the tools read is traceable to a public Slack reference page listed in the method table below.

## Setup and authentication

| Variable | Purpose |
|----------|---------|
| `SLACK_USER_TOKEN` | Org-level user token (`xoxp-`) from an app installed on the whole Enterprise org. Required for every `admin.*` and Audit Logs method. |
| `SLACK_BOT_TOKEN` | Optional bot token (`xoxb-`). Used only for methods whose reference page lists bot tokens (`auth.test`, `users.list`, `team.preferences.list`). Admin methods are refused locally with `not_allowed_token_type` when only a bot token is present. |
| `SLACK_SCIM_TOKEN` | SCIM bearer token (Business+ or Enterprise Grid). Enables provisioning and lifecycle checks. |
| `SLACK_ORG_ID` | Enterprise Grid org ID (`E...`). Passed as `enterprise_id` to the app inventory methods. |
| `SLACK_CONFIG_FILE` | Optional JSON file with `user_token`, `bot_token`, `scim_token`, and `org_id`. Defaults to `~/.config/grclanker/slack.json` when present. Arguments override environment variables, which override the file. A file that cannot be read reports `Unable to read Slack config file <path> (<code>)` with only the system error code (for example `EISDIR` or `EACCES`); a file that is not valid JSON reports a fixed `Unable to parse Slack config file <path>: the file is not valid JSON` message, so neither the file contents nor a library message can appear in the error. |

Required user-token scopes: `admin.teams:read`, `admin.users:read`, `admin.apps:read`, `admin.barriers:read`, `admin.conversations:read`, `admin.analytics:read` (optional probe), `auditlogs:read`, `users:read`, and `team.preferences:read`. The Admin API and Audit Logs API require an Enterprise Grid plan; an `ok:false` response of `not_allowed_token_type`, `missing_scope`, `not_an_enterprise`, or `feature_not_enabled` is rendered as a manual finding that names the cause, never as an empty or passing result.

Multi-inventory findings: a finding that compares two inventories demotes below pass when any of them is unreadable, even if the primary inventory is complete. `SLACK-ADMIN-08` compares emoji uploaders with the admin roster built from `admin.users.list`, `admin.teams.list`, and `admin.teams.admins.list`; if any workspace's admin list is unreadable the roster is incomplete, the finding caps at `warn` (`manual` when every workspace is unreadable), no upload is classified as non-admin, and the summary names the endpoint and workspace ids. `SLACK-APP-06` caps at `warn` when `auth.test` fails, because the workspace the preference applies to cannot be identified. `SLACK-CHAN-02` derives its announcement channel set from the channel search, so a denied `#general` is reported as unreadable rather than missing. Counts and lists derived from an unreadable inventory are rendered as `null` beside a `*_status` field (for example `workspace_id: null` with `workspace_id_status`, `non_admin_uploads: null` with `non_admin_uploads_status`), never as `0`, `[]`, or a placeholder, in findings and in the per-area summaries alike. The same applies to reads that were never issued because their input inventory failed or was empty (for example `admin.users.session.getSettings` without a readable `admin.users.list`, `admin.teams.admins.list` without `admin.teams.list`, the per-channel preference and retention reads without a channel search, SCIM `/Users` without `/ServiceProviderConfig`): the count is `null` and the status reads `not collected: <upstream> was unreadable (<reason>), so <read> was not called`.

Rate limits: the client honors `429` responses by sleeping for the `Retry-After` value (capped at 60 seconds) and retrying twice. Pagination follows `response_metadata.next_cursor` (or the top-level `next_cursor` on `admin.conversations.search`) up to each method's documented `limit` maximum. Every early exit is recorded as truncation and demotes the dependent verdict to `warn`: an item cap (`user_limit`, `workspace_limit`, `app_limit`, `channel_limit`, or a page that carried more items than the cap allowed), the page cap of 50 requests per list, a cursor that returns an empty page, a missing SCIM `totalResults`, or an audit log page that ends with a `next_cursor`. The name-keyed `admin.emoji.list` map follows the same rules: an empty page with a cursor outstanding stops the listing as a stalled cursor and `SLACK-ADMIN-08` states the truncation instead of reporting no custom emoji. The finding summary states seen versus total and the reason, for example `2 seen of unknown total (partial view, item limit reached)`.

Credential hygiene: every Web API, SCIM, and Audit Logs response is redacted when it is parsed, before any verdict logic or bundle file sees it. Fields named like credentials (`token`, `secret`, `password`, `webhook`, `signing`, `private_key`, `api_key`, `authorization`, `cookie`, `credential`) keep their name and receive the value `[REDACTED]`; Slack token shapes (`xoxb-`, `xoxp-`, `xoxe-`, `xapp-`), `hooks.slack.com` webhook URLs, `Bearer` headers, and credential query parameters are replaced inside any string, including JSON error bodies (`error`, `response_metadata.messages`, SCIM `detail`). Error strings pass through one scrub, `redactErrorText`, at the point they are created (the `SlackApiError` constructor and the helpers that turn a thrown error into a finding summary, an errors entry, or the tool error text), which adds header- and assignment-style credentials (`Cookie`, `Authorization`, `X-Api-Key`, `session_id`, `client_secret`, and similar names followed by `:` or `=`); a response body that is not a JSON object (an HTML error page from a proxy or gateway, plain text) is never quoted in an error string at all and is described instead as `non-JSON text/html body (N characters) withheld` beside the HTTP status and endpoint. A vendor error code copied from a body is pattern-validated like every other code: Slack's documented snake_case `error` values (and the scope lists in `needed` and `provided`, the code list in `warning`) render verbatim, anything of another shape (for example a token) renders the fixed `UnknownError`, and a JSON error body is never echoed. The fields read from an error body are chosen by the API that was called, not by the fields the body happens to carry: a Web API or Audit Logs body renders only `error`, `needed`, `provided`, and `warning`, so a `detail`, `status`, or `scimType` a gateway adds beside them is dropped; a SCIM body renders only when it carries the SCIM 2.0 error schema (`schemas` naming `urn:ietf:params:scim:api:messages:2.0:Error`, RFC 7644 section 3.12), and then only its documented `status` (validated integer), `scimType` (documented keyword, identifier, or urn, else dropped), and `detail` (scrubbed and cut); a SCIM body without that schema is withheld, and undocumented fields such as `code` or `response_metadata.messages` are dropped. `token_type` and `token_kinds` are kept because they describe a token without carrying one. The scrub is name- and shape-based, so ordinary-looking data (user names, channel names, email addresses, IDs, timestamps) is preserved by design; only credential-named fields and credential-shaped values are replaced. Configured token values shorter than 8 characters are not scrubbed by exact match, so a degenerate token cannot blank unrelated text.

## Tools

| Tool | What it does |
|------|--------------|
| `slack_check_access` | Calls `auth.test` and probes 15 surfaces (workspaces, users, admin users, approved and restricted apps, barriers, channels, emoji, team preferences, Audit Logs, SCIM). |
| `slack_assess_identity` | MFA enrollment (`has_2fa`), guest inventory, SCIM provisioning coverage, lifecycle alignment, deactivated user visibility. |
| `slack_assess_admin_access` | Admin inventory, SSO coverage (`has_sso`), session duration, idle timeout, discoverability, mobile session controls, email domain restrictions, custom emoji governance, analytics access. |
| `slack_assess_integrations` | Approved and restricted app inventories, internal and sensitive-scope apps, information barriers, DLP and Discovery evidence, file upload restrictions (`team.preferences.list`), token rotation. |
| `slack_assess_channel_governance` | Slack Connect exposure, posting restrictions on general and org default channels, channel retention overrides, external email ingestion, link previews. |
| `slack_assess_monitoring` | Audit Logs access, recency, security event visibility, schema visibility, external sharing monitoring, SIEM streaming evidence. |
| `slack_export_audit_bundle` | Runs everything and writes the evidence bundle described below. |

## Status semantics

- `pass`: documented evidence was read completely and is compliant.
- `warn`: compliant on the seen data, but the inventory was partial or empty, or items need review.
- `fail`: documented evidence shows a gap.
- `manual`: the API cannot prove the control. The summary names the cause (method, missing scope or plan, or the reference page proving the setting is absent) and the evidence a human must collect.

Empty inventories never pass by default. The only exceptions, stated in the finding summary, are `SLACK-ID-02` (no guests in a complete inventory) and `SLACK-CHAN-01` (no externally shared channels in a complete search).

## Control coverage

| Spec control | Tool | Finding | Status semantics |
|--------------|------|---------|------------------|
| 1 SSO enforcement | admin_access | `SLACK-ADMIN-02` | fail when any active user has `has_sso=false`; pass only on a complete inventory. The org "require SSO" toggle is not API-readable and is noted in the summary. |
| 2 Two-factor authentication | identity | `SLACK-ID-01` | fail when any active human has `has_2fa=false`; users without the flag are bucketed and cap the result at warn. |
| 3 Session duration limits | admin_access | `SLACK-ADMIN-03` | `admin.users.session.getSettings` durations compared with `max_session_hours`; users in `no_settings_applied` inherit an org default the API does not expose. |
| 4 Session idle timeout | admin_access | `SLACK-ADMIN-04` | manual: only `duration` and `desktop_app_browser_quit` are documented. |
| 5 Mobile session controls | admin_access | `SLACK-ADMIN-06` | manual with the same citation; reports `desktop_app_browser_quit` coverage as evidence. |
| 6 File upload restrictions | integrations | `SLACK-APP-06` | `disable_file_uploads` from `team.preferences.list`: `disallow_all` and `type:owner,type:admin` pass, `type:regular` warns (only guests excluded), `allow_all` fails, an undocumented value warns, a missing field or unreadable method is manual. A pass is downgraded to warn when the org has more than one workspace or the workspace inventory is partial, because the method reads only the token's workspace. |
| 7 External sharing controls | channel_governance, monitoring | `SLACK-CHAN-01`, `SLACK-MON-05` | Connect exposure from `is_ext_shared` channels; `external_shared_channel_*` actions from the audit log (documented action names only). |
| 8 Information barriers | integrations | `SLACK-APP-04` | pass when barriers exist and the list is complete; empty is warn. |
| 9 App management policy | integrations | `SLACK-APP-01`, `SLACK-APP-02` | inventories from `approved_apps` and `restricted_apps`; empty is warn. |
| 10 Custom app restrictions | integrations | `SLACK-APP-03` | warn on `is_internal`, `is_app_directory_approved=false`, or `is_sensitive` scopes. |
| 11 DLP policy configuration | integrations | `SLACK-APP-05` | manual: the Discovery API has no public reference page and no `discovery.*` method appears in the methods index (https://docs.slack.dev/reference/methods), so entitlement and DLP scanning status are collected from the DLP partner. |
| 12 Channel retention policies | channel_governance | `SLACK-CHAN-03` | fail when a channel override is below `min_retention_days`; the workspace default is not API-readable. |
| 13 Audit log streaming | monitoring | `SLACK-MON-01` to `SLACK-MON-04`, `SLACK-MON-06` | API access and recency are automated; SIEM streaming is manual. |
| 14 Admin role inventory | admin_access | `SLACK-ADMIN-01` | `admin_ids` per workspace compared with `max_workspace_admins`. |
| 15 Guest account controls | identity | `SLACK-ID-02` | `is_restricted` or `is_ultra_restricted` users. |
| 16 Email domain restrictions | admin_access | `SLACK-ADMIN-07` | fail when `team.email_domain` is empty. |
| 17 Workspace discoverability | admin_access | `SLACK-ADMIN-05` | fail when `discoverability=open` on `admin.teams.list`. |
| 18 Channel posting restrictions | channel_governance | `SLACK-CHAN-02` | `prefs.who_can_post.type` on general and org default channels must contain only the documented admin or owner spellings (`admin`, `admins`, `owner`, `owners`), or list explicit users. |
| 19 Custom emoji restrictions | admin_access | `SLACK-ADMIN-08` | fail when any emoji `uploaded_by` is not an admin or owner. |
| 20 External email ingestion | channel_governance | `SLACK-CHAN-04` | manual: no documented read. |
| 21 Link previews and URL unfurling | channel_governance | `SLACK-CHAN-05` | manual: no documented read. |
| 22 SCIM provisioning status | identity | `SLACK-ID-03` | pass when `/ServiceProviderConfig` is readable and `/Users` returns provisioned users completely. |
| 23 Deactivated user audit | identity | `SLACK-ID-04`, `SLACK-ID-05` | SCIM-active users deactivated in Slack fail. |
| 24 Workspace analytics access | admin_access | `SLACK-ADMIN-09` | manual: `admin.analytics.getFile` is a capability probe only; a `200` with `Content-type: application/gzip` is a successful probe (the file is never downloaded) and an `ok:false` JSON body is the failure path. |
| 25 Token rotation and revocation | integrations | `SLACK-APP-07` | manual with `auth.test` identity and token format evidence. |

Coverage: 25 of 25 spec controls are represented; 17 are automated and 8 are manual by design (controls 4, 5, 11, 13, 20, 21, 24, 25).

## Framework mappings

Every finding carries the FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP references from the spec mapping table. The export bundle writes one report per framework under `compliance/`.

## Export bundle

`slack_export_audit_bundle` allocates `export/slack/<org>-audit`, then `-2`, `-3` on reruns, and never overwrites a prior bundle. The zip is named after the allocated directory. Layout:

- `core_data/`: `access.json` plus per-area snapshots (redacted at collection time; the configured tokens and any credential-shaped value are replaced with `[REDACTED]` again when each file is written, so the zip inherits the redaction)
- `analysis/findings.json` and per-area summaries
- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, and `fedramp.md`, `cmmc.md`, `soc-2.md`, `cis.md`, `pci-dss.md`, `stig.md`, `irap.md`, `ismap.md`
- `reports/<area>.md`, `QUICK_REFERENCE.md`, `README.md`, `metadata.json`
- `_errors.log` only when collection partially failed

## Live smoke

```bash
npm --prefix cli run test:slack:live
```

The script prints a skip message and exits 0 when no token is configured; otherwise it runs `slack_check_access` and every assess tool.

## Method table

| Method | Reference | Fields read |
|--------|-----------|-------------|
| `auth.test` (POST, user or bot) | https://api.slack.com/methods/auth.test | `url`, `team`, `team_id`, `user`, `user_id`, `enterprise_id`, `is_enterprise_install` |
| `users.list` (GET, user or bot, `limit`, `cursor`, `team_id`) | https://api.slack.com/methods/users.list | `members[].id`, `name`, `deleted`, `is_bot`, `is_app_user`, `is_restricted`, `is_ultra_restricted`, `has_2fa`, `profile.email` |
| `admin.teams.list` (POST, `limit` max 1000) | https://api.slack.com/methods/admin.teams.list | `teams[].id`, `name`, `discoverability` |
| `admin.teams.settings.info` (POST, `team_id`) | https://api.slack.com/methods/admin.teams.settings.info | `team.email_domain` |
| `admin.teams.admins.list` (GET, `team_id`, `limit` max 1000) | https://api.slack.com/methods/admin.teams.admins.list | `admin_ids[]` |
| `admin.users.list` (POST, `limit`, `cursor`) | https://api.slack.com/methods/admin.users.list | `users[].id`, `username`, `is_active`, `is_admin`, `is_owner`, `is_primary_owner`, `is_bot`, `has_sso` |
| `admin.users.session.getSettings` (POST, `user_ids`) | https://api.slack.com/methods/admin.users.session.getSettings | `session_settings[].user_id`, `duration`, `desktop_app_browser_quit`, `no_settings_applied[]` |
| `admin.apps.approved.list` (GET, `limit` max 1000, `enterprise_id`) | https://api.slack.com/methods/admin.apps.approved.list | `approved_apps[].app.id`, `name`, `is_internal`, `is_app_directory_approved`, `developer_type`, `scopes[].name`, `is_sensitive` |
| `admin.apps.restricted.list` (GET, `limit` max 1000, `enterprise_id`) | https://api.slack.com/methods/admin.apps.restricted.list | `restricted_apps[]` with the same shape |
| `admin.barriers.list` (GET, `limit` max 1000) | https://api.slack.com/methods/admin.barriers.list | `barriers[].id`, `primary_usergroup.name`, `restricted_subjects` |
| `admin.conversations.search` (POST, `limit` max 20, top-level `next_cursor`, `total_count`, `search_channel_types`) | https://api.slack.com/methods/admin.conversations.search | `conversations[].id`, `name`, `is_private`, `is_general`, `is_org_default`, `is_org_mandatory`, `is_ext_shared`, `connected_team_ids`, `pending_connected_team_ids` |
| `admin.conversations.getConversationPrefs` (POST, `channel_id`) | https://api.slack.com/methods/admin.conversations.getConversationPrefs | `prefs.who_can_post.type`, `prefs.who_can_post.user` |
| `admin.conversations.getCustomRetention` (POST, `channel_id`) | https://api.slack.com/methods/admin.conversations.getCustomRetention | `is_policy_enabled`, `duration_days` |
| `admin.emoji.list` (GET, `limit` max 1000) | https://api.slack.com/methods/admin.emoji.list | `emoji.<name>.uploaded_by`, `date_created` |
| `admin.analytics.getFile` (GET, `type=public_channel`, `metadata_only=true`) | https://api.slack.com/methods/admin.analytics.getFile | capability probe only: `Content-type` header (`application/gzip` success, `application/json` with `ok:false` failure); the body is not downloaded |
| `team.preferences.list` (POST, bot or user token, `team.preferences:read`) | https://docs.slack.dev/reference/methods/team.preferences.list | `disable_file_uploads` |
| Audit Logs `GET /logs` (`limit`, `oldest`) and `GET /schemas` | https://docs.slack.dev/admins/audit-logs-api/ | `entries[].date_create`, `action`, `response_metadata.next_cursor`, `schemas[]` |
| Audit Logs action names matched by `SLACK-MON-03` and `SLACK-MON-05` | https://docs.slack.dev/reference/audit-logs-api/methods-actions-reference | `user_login`, `user_logout`, `app_installed`, `app_approved`, `app_restricted`, `role_change_to_admin`, `pref.sso_setting_changed`, `pref.two_factor_auth_changed`, `user_deactivated`; `external_shared_channel_connected`, `external_shared_channel_reconnected`, `external_shared_channel_disconnected`, `external_shared_channel_disconnect_and_archived`, `external_shared_channel_invite_created`, `external_shared_channel_invite_accepted`, `external_shared_channel_invite_approved`, `external_shared_channel_invite_declined`, `external_shared_channel_invite_expired`, `external_shared_channel_invite_revoked`, `external_shared_channel_invite_auto_revoked`, `external_shared_channel_access_upgraded` |
| SCIM `GET /Users` (`startIndex`, `count`), `GET /Groups`, `GET /ServiceProviderConfig` | https://docs.slack.dev/admins/scim-api/ | `totalResults`, `Resources[].userName`, `emails[]`, `active` |

## Limitations

- The TUI, `--controls`, and SARIF surfaces described in the spec are not part of this CLI pass.
- Org-level policy toggles (SSO required, session default, Slack Connect permission, retention default, email ingestion, link previews, analytics roles, emoji upload permission) are not exposed by any documented read method; the corresponding findings report the evidence that is readable and name the manual artifact to collect. File upload permission is the exception: `team.preferences.list` documents `disable_file_uploads` for the token's workspace.
- The Discovery API is not publicly documented (no reference page and no `discovery.*` method in the methods index), so Discovery entitlement and DLP scanning status are never read.
- `admin.conversations.restrictAccess.listGroups` (IDP group channel restrictions) and guest expiration dates from `admin.users.list only_guests=true` are deferred.
