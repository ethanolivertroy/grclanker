---
title: Zoom
description: Read-only Zoom account inspection for identity posture, collaboration governance, meeting security, and audit bundle export.
---

The Zoom integration inspects a Zoom Workplace or Zoom for Government account through the public Zoom REST API v2 and renders the 25 controls in `specs/zoom-sec-inspector.spec.md` as pass, warn, fail, or manual findings with FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP mappings. Every request is a read; the tools never change account settings.

## What it inspects

- Identity posture: SSO enforcement, blocked personal and social sign-in methods, admin two-factor authentication, managed (associated) domain verification, admin privilege concentration, session inactivity timeouts, and the vanity URL control (manual).
- Collaboration governance: trusted domains, in-meeting file transfer, cloud recording auto-delete retention, Zoom Phone recording policies, admin operation log recency, IM group restrictions, external contact restrictions, and Team Chat encryption (manual).
- Meeting security: passcode enforcement and account lock, waiting room, host-only screen sharing, local recording, end-to-end encryption, join-link passcode embedding, PMI usage, authenticated join, data center regions, and the recording consent disclaimer, each checked for group-level overrides.

Account settings are collected once per run from `GET /accounts/{accountId}/settings` (default view plus the documented `option` views `security`, `meeting_authentication`, and `meeting_security`) and `GET /accounts/{accountId}/lock_settings` (default view plus `option=meeting_security`), merged into a single nested settings object. Controls that require enforcement read the matching `lock_settings` key and report a compliant but unlocked setting as warn.

## Setup and authentication

1. In the Zoom App Marketplace, create a Server-to-Server OAuth app ([Zoom S2S OAuth guide](https://developers.zoom.us/docs/internal-apps/s2s-oauth/)). User-level OAuth and the deprecated JWT app type are not supported.
2. Add the read scopes listed in the endpoint table below. Classic scopes: `account:read:admin`, `user:read:admin`, `role:read:admin`, `group:read:admin`, `report:read:admin`, `imgroup:read:admin`, and `phone:read:admin` (only if Zoom Phone is licensed). Granular equivalents are listed per endpoint.
3. Activate the app and copy the Account ID, Client ID, and Client Secret.
4. Provide credentials through any of the following, resolved in this order: tool arguments, environment variables, then a JSON config file.

| Source | Keys |
|--------|------|
| Tool arguments | `account_id`, `client_id`, `client_secret` (or `token`), `base_url`, `oauth_base_url`, `timeout_seconds`, `config_file` |
| Environment | `ZOOM_ACCOUNT_ID`, `ZOOM_CLIENT_ID`, `ZOOM_CLIENT_SECRET` (or `ZOOM_TOKEN`), `ZOOM_BASE_URL`, `ZOOM_OAUTH_BASE_URL`, `ZOOM_TIMEOUT`, `ZOOM_CONFIG_FILE` |
| Config file | `ZOOM_CONFIG_FILE` or `config_file`, then `./.zoom.json`, `./.grclanker-zoom.json`, `~/.zoom.json`, `~/.grclanker-zoom.json`, `~/.config/grclanker/zoom.json` |

Config file example (`~/.zoom.json`):

```json
{
  "account_id": "q6gBJVO5TzexKYTb_I2rpg",
  "client_id": "abc123",
  "client_secret": "secret",
  "base_url": "https://api.zoom.us/v2"
}
```

The client exchanges the credentials for a bearer token at `{oauth_base_url}/oauth/token` with `grant_type=account_credentials`, refreshes it before expiry, and sends `Authorization: Bearer` on every call. For Zoom for Government set `base_url` to `https://api.zoomgov.com/v2`; the OAuth host is derived from it unless `oauth_base_url` is set. A pre-issued token can be supplied with `ZOOM_TOKEN` instead of the client credentials.

Pagination follows the [documented `next_page_token` contract](https://developers.zoom.us/docs/api/rest/pagination/) and runs to completion or records truncation when a caller limit stops it (users default 1000, groups 50, operation logs 300, role members 3000). `429` responses are retried up to three times honoring `Retry-After` ([rate limits](https://developers.zoom.us/docs/api/rest/rate-limits/)), capped at 30 seconds per wait.

## Tools

| Tool | Purpose | Notable arguments |
|------|---------|-------------------|
| `zoom_check_access` | Verifies every audit surface (settings and lock settings per option view, users, roles, groups, operation logs, IM groups, managed and trusted domains, Zoom Phone settings) and reports readable, not readable (with the 403 or error cause), or not configured. `healthy` requires the settings, users, roles, and groups surfaces. | auth arguments |
| `zoom_assess_identity` | ZOOM-ID-01 to ZOOM-ID-07. | `user_limit` (default 1000), `max_admins` (default 10), `max_session_inactivity_minutes` (default 120) |
| `zoom_assess_collaboration_governance` | ZOOM-COLLAB-01 to ZOOM-COLLAB-08. | `max_recording_retention_days` (default 120), `operation_log_limit` (default 300, over a fixed 30-day window), `group_limit` (default 50) |
| `zoom_assess_meeting_security` | ZOOM-MTG-01 to ZOOM-MTG-10 with group override detection. | `group_limit` (default 50) |
| `zoom_export_audit_bundle` | Runs all three assessments and writes the shared bundle layout plus a zip. | `output_dir` (default `./export/zoom`) plus the assessment arguments |

### Bundle layout

```
<accountId>-audit-bundle[-2, -3, ...]/
  core_data/            raw snapshots per endpoint (bearer tokens redacted)
  analysis/             findings.json plus identity, collaboration, and meeting summaries
  compliance/           executive_summary.md, unified_compliance_matrix.md, one report per framework
  QUICK_REFERENCE.md
  _errors.log           only when collection partially failed
<accountId>-audit-bundle[-N].zip
```

Reruns allocate `-2`, `-3`, and so on; a prior bundle is never overwritten, and the zip name always derives from the allocated directory. Output paths are resolved through `resolveSecureOutputPath`, which rejects traversal outside the output root and symlinked parents.

## Control coverage

Status semantics for every finding: `pass` means the documented setting is compliant and, where the control requires enforcement, locked with no sampled group override; `warn` means compliant but unlocked, overridden by a sampled group, judged on a partial inventory, or only provable for items carrying a date; `fail` means the documented value is non-compliant; `manual` means the surface was denied or errored, the documented key was absent from the response, the inventory was empty where emptiness is not compliant, or the API does not expose the setting (with the reference page cited in the summary).

| # | Spec control | Tool | Finding | Verdict basis |
|---|--------------|------|---------|---------------|
| 1 | Meeting password enforcement enabled | meeting_security | ZOOM-MTG-01 | `schedule_meeting.require_password_for_scheduling_new_meetings` true |
| 2 | Waiting room enabled by default | meeting_security | ZOOM-MTG-02 | `meeting_security.waiting_room` true and locked |
| 3 | Screen sharing restricted to host only | meeting_security | ZOOM-MTG-03 | `in_meeting.screen_sharing` with `in_meeting.who_can_share_screen` = `host` |
| 4 | Recording consent notification enabled | meeting_security | ZOOM-MTG-10 | `recording.recording_notification_for_zoom_client.disclaimer_to_participants` names all participants (deprecated `recording.recording_disclaimer` as fallback) |
| 5 | SSO enforcement for all users | identity | ZOOM-ID-01 | every listed user has `login_types` containing 101 (SSO); users without `login_types` are bucketed and cap at warn |
| 6 | Two-factor authentication for admins | identity | ZOOM-ID-02, ZOOM-ID-04 | `security.sign_in_with_two_factor_auth` = `all`, or `sign_in_with_two_factor_auth_roles` covering every admin role; admin count within `max_admins` |
| 7 | End-to-end encryption available and default | meeting_security | ZOOM-MTG-05 | `meeting_security.end_to_end_encrypted_meetings` true and `meeting_security.encryption_type` = `e2ee` |
| 8 | Chat encryption enabled | collaboration_governance | ZOOM-COLLAB-08 | manual: no account-level Team Chat encryption setting is documented |
| 9 | File transfer in meetings restricted | collaboration_governance | ZOOM-COLLAB-02 | `in_meeting.file_transfer` false and locked |
| 10 | Cloud recording auto-delete policy configured | collaboration_governance | ZOOM-COLLAB-03 | `recording.auto_delete_cmr` true |
| 11 | Auto-delete days within retention policy | collaboration_governance | ZOOM-COLLAB-03 | `recording.auto_delete_cmr_days` within `max_recording_retention_days`, locked |
| 12 | External contacts restricted | collaboration_governance | ZOOM-COLLAB-07, ZOOM-COLLAB-01 | `chat.allow_users_to_add_contacts` and `chat.allow_users_to_chat_with_others` disabled or `selected_option` 2, 3, or 4; trusted domains explicitly named |
| 13 | Vanity URL configured and secured | identity | ZOOM-ID-07 | manual: no account vanity URL field is documented |
| 14 | Managed domains verified | identity | ZOOM-ID-03 | every `domains[].status` = `verified` with `total_records` matching |
| 15 | IM group restrictions enforced | collaboration_governance | ZOOM-COLLAB-06 | every IM group `type` is `normal` or `restricted` (no `shared` or undocumented type) and no group sets `search_by_ma_account` |
| 16 | Sign-in methods restricted | identity | ZOOM-ID-05 | no user `login_types` code in 0, 1, 24, 27 (Facebook, Google, Apple, Microsoft) |
| 17 | Session timeout within policy | identity | ZOOM-ID-06 | `security.sign_again_period_for_inactivity_on_client` and `_on_web` present and within `max_session_inactivity_minutes` |
| 18 | Data routing control enabled | meeting_security | ZOOM-MTG-09 | `in_meeting.custom_data_center_regions` true with a non-empty `in_meeting.data_center_regions`, locked |
| 19 | Zoom Phone recording policies enforced | collaboration_governance | ZOOM-COLLAB-04 | `auto_call_recording.enable` and `locked` with `ad_hoc_call_recording` disabled or locked |
| 20 | Local recording disabled or restricted | meeting_security | ZOOM-MTG-04 | `recording.local_recording` false and locked |
| 21 | Meeting password locked at account level | meeting_security | ZOOM-MTG-01 | `lock_settings.schedule_meeting.require_password_for_scheduling_new_meetings` true |
| 22 | Embed password in join link disabled | meeting_security | ZOOM-MTG-06 | `schedule_meeting.embed_password_in_join_link` false and locked |
| 23 | Only authenticated users can join | meeting_security | ZOOM-MTG-08 | `meeting_authentication` true (option view) and locked |
| 24 | Admin operation log retention verified | collaboration_governance | ZOOM-COLLAB-05 | entries with a parseable `time` inside the `operation_log_days` window; undated entries cap at warn |
| 25 | PMI usage restricted | meeting_security | ZOOM-MTG-07 | `schedule_meeting.personal_meeting` false, or `use_pmi_for_scheduled_meetings` and `use_pmi_for_instant_meetings` false and locked |

Coverage: 25 of 25 spec controls have a finding; 23 are automatable and 2 (controls 8 and 13) are manual by design with the reference page proving the absence cited in the finding summary.

## Framework mappings

Each finding carries the mapping row for its spec controls across FedRAMP (NIST 800-53), CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP, taken from section 5 of the spec. The bundle writes `compliance/unified_compliance_matrix.md` with all eight columns and one `compliance/<framework>.md` report per framework listing the framework reference, the spec control, the findings, and their status.

## Live smoke test

```bash
npm --prefix cli run test:zoom:live
```

The script prints a skip message and exits 0 when no Zoom credentials or config file are present. With credentials it runs `zoom_check_access` and all three assessments against the real account and stops with a non-zero exit if the core surfaces are not readable.

## Limitations and manual controls

- Control 8 (chat encryption): the account settings reference documents no Team Chat encryption setting under the `chat` object; encryption indicators exist only as per-message metadata in the Team Chat API. Confirm Advanced Chat Encryption in the admin portal.
- Control 13 (vanity URL): the account settings reference exposes no account vanity URL field; only per-user personal meeting room URLs (`vanity_url` on `GET /users/{userId}`) are documented. Review the account profile in the admin portal.
- Zoom Phone (control 19): `GET /phone/account_settings` requires a Zoom Phone license; without it the finding is manual and names the requirement.
- Managed and trusted domains use master-account granular scopes (`account:read:managed_domains:master`, `account:read:trusted_domains:master`); a sub-account credential renders those findings manual.
- Group override detection samples up to `group_limit` groups; when the group inventory is truncated the affected findings downgrade to warn and say so.
- User-level OAuth flows, JWT apps, and SARIF, CSV, and HTML reporters are out of scope for this integration.

## Endpoints

| Endpoint | Reference | Scopes (classic / granular) | Constraints honored | Fields read |
|----------|-----------|-----------------------------|---------------------|-------------|
| `POST {oauth_base_url}/oauth/token` | [Server-to-Server OAuth](https://developers.zoom.us/docs/internal-apps/s2s-oauth/) | n/a | `grant_type=account_credentials`, basic auth with client id and secret | `access_token`, `expires_in` |
| `GET /users/me` | [Get a user](https://developers.zoom.us/docs/api/users/#tag/users/GET/users/{userId}) | `user:read:admin` / `user:read:user:admin` | none | `id`, `email`, `first_name` |
| `GET /accounts/{accountId}/settings` | [Get account settings](https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/settings) | `account:read:admin` / `account:read:settings:admin`, `account:read:settings:master` | `option` in `security`, `meeting_authentication`, `meeting_security` | `schedule_meeting.*`, `in_meeting.*`, `recording.*`, `chat.*`, `security.*`, `meeting_security.*`, `meeting_authentication`, `authentication_options` |
| `GET /accounts/{accountId}/lock_settings` | [Get locked settings](https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/lock_settings) | `account:read:admin` / `account:read:lock_settings:master` | `option=meeting_security` | lock booleans under `schedule_meeting`, `in_meeting`, `recording`, `chat`, `meeting_security` |
| `GET /accounts/{accountId}/managed_domains` | [Get managed domains](https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/managed_domains) | `account:read:admin` / `account:read:managed_domains:master` | not paginated; `total_records` compared to the list | `domains[].domain`, `domains[].status`, `total_records` |
| `GET /accounts/{accountId}/trusted_domains` | [Get trusted domains](https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/trusted_domains) | `account:read:admin` / `account:read:trusted_domains:master` | not paginated | `trusted_domains[]` |
| `GET /users` | [List users](https://developers.zoom.us/docs/api/users/#tag/users/GET/users) | `user:read:admin` / `user:read:list_users:admin` | `page_size` max 2000, `next_page_token`, default `status=active` | `users[].id`, `email`, `type`, `status`, `login_types`, `total_records` |
| `GET /roles` | [List roles](https://developers.zoom.us/docs/api/accounts/#tag/roles/GET/roles) | `role:read:admin` / `role:read:list_roles:admin` | none | `roles[].id`, `name`, `total_members` |
| `GET /roles/{roleId}/members` | [List role members](https://developers.zoom.us/docs/api/accounts/#tag/roles/GET/roles/{roleId}/members) | `role:read:admin` / `role:read:list_members:admin` | `page_size` max 300, `next_page_token` | `members[].id`, `email`, `total_records` |
| `GET /groups` | [List groups](https://developers.zoom.us/docs/api/users/#tag/groups/GET/groups) | `group:read:admin` / `group:read:list_groups:admin` | `page_size` max 300, `next_page_token` | `groups[].id`, `name`, `total_members`, `total_records` |
| `GET /groups/{groupId}/settings` | [Get group settings](https://developers.zoom.us/docs/api/users/#tag/groups/GET/groups/{groupId}/settings) | `group:read:admin` / `group:read:settings:admin` | `option=meeting_security` | the same setting paths as the account, for override detection |
| `GET /groups/{groupId}/lock_settings` | [Get group locked settings](https://developers.zoom.us/docs/api/users/#tag/groups/GET/groups/{groupId}/lock_settings) | `group:read:admin` / `group:read:lock_settings:admin` | `option=meeting_security` | group lock booleans |
| `GET /report/operationlogs` | [Get operation logs report](https://developers.zoom.us/docs/api/meetings/#tag/reports/GET/report/operationlogs) | `report:read:admin` / `report:read:operation_logs:admin` | `from` and `to` (yyyy-mm-dd) required, `page_size` max 300, `next_page_token` | `operation_logs[].time`, `action`, `category_type`, `operator`, `operation_detail` |
| `GET /im/groups` | [List IM groups](https://developers.zoom.us/docs/api/team-chat/#tag/im-groups/GET/im/groups) | `imgroup:read:admin` / `contact_group:read:list_groups:admin` | not paginated; `total_records` compared to the list | `groups[].id`, `name`, `type`, `total_members`, `search_by_account`, `search_by_domain`, `search_by_ma_account` |
| `GET /phone/account_settings` | [Get account phone settings](https://developers.zoom.us/docs/api/phone/#tag/accounts/GET/phone/account_settings) | `phone:read:admin` / `phone:read:list_account_settings:admin` | `setting_types=auto_call_recording,ad_hoc_call_recording` | `auto_call_recording.enable`, `locked`, `locked_by`, `recording_calls`; `ad_hoc_call_recording.enable`, `locked`, `locked_by` |
