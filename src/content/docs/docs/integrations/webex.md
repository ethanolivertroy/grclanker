---
title: Webex
description: Read-only Cisco Webex security inspector covering identity, collaboration governance, meeting and hybrid posture, and an audit bundle export.
---

The Webex integration inspects a Cisco Webex organization through the public REST API at `https://webexapis.com/v1`. It is read-only, maps every finding to the 25 controls in `specs/webex-sec-inspector.spec.md`, and never writes credentials into its output.

## What it inspects

- Identity: Compliance Officer assignment, administrator concentration, bot account inventory, guest account inventory, plus manual evidence prompts for SSO, admin MFA, and bot approval.
- Collaboration governance: space classification, webhook HTTPS and signing secrets, license utilization, admin audit visibility, plus manual prompts for external communications, file sharing and DLP, recording governance, and eDiscovery or legal hold.
- Meeting and hybrid security: per-site lobby (join before host), meeting password, and guest access defaults from the site common settings API, hybrid connector health, plus manual prompts for E2EE and SRTP defaults, virtual background policy, and device firmware posture (with inventory evidence).

## Setup and authentication

Token types, detected from `GET /people/me` (`type` is `person`, `bot`, or `appuser`):

- Admin user token or integration token: reads admin surfaces when the authorizing user holds an admin role and the scopes below.
- Service App token: machine account authorized by a Full Administrator in Control Hub; supports the refresh flow below.
- Bot token: cannot read admin surfaces. `webex_check_access` marks those surfaces `manual` and every admin-only control renders `manual` naming the token type.

Scopes for full coverage: `spark-admin:people_read`, `spark-admin:organizations_read`, `spark-admin:roles_read`, `spark-admin:licenses_read`, `spark-admin:devices_read`, `spark-admin:hybrid_clusters_read`, `spark-admin:workspaces_read`, `spark-compliance:events_read`, `spark-compliance:recordings_read`, `audit:events_read`, `meeting:admin_config_read`, `meeting:schedules_read`, `meeting:preferences_read`, `guest-issuer:read`, `spark:rooms_read`, and `spark:webhooks_read`. Compliance scopes require the Compliance Officer role; `meeting:admin_config_read` requires a site administrator.

Configuration precedence: tool arguments, then environment variables, then a config file.

| Source | Keys |
|--------|------|
| Environment | `WEBEX_TOKEN`, `WEBEX_ORG_ID`, `WEBEX_CLIENT_ID`, `WEBEX_CLIENT_SECRET`, `WEBEX_REFRESH_TOKEN`, `WEBEX_API_BASE_URL`, `WEBEX_TIMEOUT`, `WEBEX_CONFIG_FILE` |
| Config file | `~/.config/webex-sec-inspector/config.json`, `config.yaml`, or `config.yml` with `token`, `org_id`, `client_id`, `client_secret`, `refresh_token`, `base_url`, `timeout_seconds` |

The default config locations are optional, but a path given explicitly through `config_file` or `WEBEX_CONFIG_FILE` must exist; a missing one is reported as `Webex config file not found: <path>` rather than silently skipped. A file that cannot be read or parsed is reported as `Unable to read Webex config file <path> (<code>)` with only the system error code (for example `EACCES` or `EISDIR`), or `Unable to parse Webex config file: invalid YAML in <path> at line <n>` (or `invalid JSON in <path>`) with the line number taken only from the parser's structured position. The parser's own message is never included, because the YAML parser quotes the offending source line, which for a malformed `token:` line is the credential itself, and `JSON.parse` quotes a window of the source.

Refresh flow: when `client_id`, `client_secret`, and `refresh_token` are present and no token is, the client posts `grant_type=refresh_token` to `POST /access_token` (the integration and Service App token flow documented on the [integrations](https://developer.webex.com/docs/integrations) and [Service Apps](https://developer.webex.com/docs/service-apps) pages) and uses the returned `access_token`. Tokens, secrets, passwords, and host PINs are redacted from every bundle file.

Bundle hygiene: `core_data/` never holds a raw response. Each surface is projected to a per-surface allowlist of the documented fields the findings read (the "Fields read" column below plus the identifiers that make a row citable), so an undocumented or newly added property is dropped before anything is written. On top of that, secret-named keys are replaced with `[REDACTED]` and URL-valued fields keep host and path only: the recording `downloadUrl` and `playbackUrl` lose their `RCID` access token, the meeting `webLink` loses its `MTID` join token, webhook `targetUrl` values lose any query string, and `;pwd=` parameters are removed from SIP URIs. The same rules apply to the zip, which is built from the written directory.

Error hygiene: error strings follow the same rule, because they travel further than data (the errors array, `_errors.log`, `core_data/access.json`, every `*_status` object, finding summaries, and the reports). A response body is never copied into an error string: a JSON error contributes only its documented `message`, `errors[].description`, `error`, and `error_description` fields, and a non-JSON body such as an HTML gateway page is described only as `non-JSON error body (<content type>; <bytes> bytes)` next to the status and endpoint. Every error string is then scrubbed once, at the point it is created (`scrubErrorText` in the `WebexApiError` constructor, in the surface collectors, and on the config loader's fixed messages), stripping the query string and fragment of any URL embedded anywhere in the text and redacting credential-shaped fragments such as `Bearer <value>`, `session=<value>`, or `X-Api-Key: <value>`, so no consumer downstream can receive an unscrubbed error.

Deviation: the spec names `config.toml`; JSON or YAML is accepted instead so no TOML dependency is added.

## Tools

| Tool | Purpose |
|------|---------|
| `webex_check_access` | Probes every surface, reports token type, org selection, readable counts, truncation, and the missing scopes. |
| `webex_assess_identity` | WEBEX-ID-01 to WEBEX-ID-07. |
| `webex_assess_collaboration_governance` | WEBEX-COLLAB-01 to WEBEX-COLLAB-08. |
| `webex_assess_meeting_hybrid_security` | WEBEX-MTG-01 to WEBEX-MTG-07. |
| `webex_export_audit_bundle` | Writes `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log` on partial failure, and a zip named after the allocated directory; reruns allocate `-2`, `-3` and never overwrite. |

## Status semantics

- `pass`: the documented field supporting the control was read for the complete visible population.
- `warn`: the population was truncated, partially visible (bot token), undated, or above a review threshold.
- `fail`: a documented field shows the control unmet.
- `manual`: the endpoint was denied or errored, the population was empty where emptiness is inconclusive, a documented field was absent from the response, or the setting is only visible in Control Hub. The summary names the cause and the evidence to collect.

Site-level findings (WEBEX-MTG-02, WEBEX-MTG-03, WEBEX-MTG-06) read `GET /admin/meeting/config/commonSettings?siteUrl=` once per site listed by `GET /meetingPreferences/sites`. The verdict is the worst site; a passing verdict downgrades to `warn` when any site was denied, the site list was truncated, or no site could be listed (in which case only the administrator's preferred site is evaluated).

## Control coverage

| Spec control | Tool | Finding | Status semantics |
|--------------|------|---------|------------------|
| 1 SSO enforcement | identity | WEBEX-ID-01 | manual: Organizations API exposes no SSO field |
| 2 Admin MFA | identity | WEBEX-ID-02 | manual: `mfaEnabled` exists only in the PATCH schema of `/identity/organizations/{orgId}/authenticationConfig`, no documented GET; admin list attached |
| 3 Compliance Officer role | identity | WEBEX-ID-03 | pass/fail/warn from `/people` roles and `/roles` names |
| 4 External communications | collaboration | WEBEX-COLLAB-01 | manual: no documented endpoint |
| 5 File sharing restrictions | collaboration | WEBEX-COLLAB-02 | manual: Control Hub setting |
| 6 Recording storage | collaboration | WEBEX-COLLAB-03 | manual: no storage field; recordings inventoried |
| 7 Recording retention | collaboration | WEBEX-COLLAB-03 | manual: no retention field |
| 8 E2E meeting encryption | meeting-hybrid | WEBEX-MTG-01 | manual: no encryption field in meeting preferences, common settings, or session types |
| 9 Meeting lobby | meeting-hybrid | WEBEX-MTG-02 | pass/warn/fail/manual per site from `securityOptions.joinBeforeHost`, `audioBeforeHost`, `unlistAllMeetings`; sampled `unlockedMeetingJoinSecurity` attached |
| 10 Meeting password | meeting-hybrid | WEBEX-MTG-06 | pass/warn/fail/manual per site from `securityOptions.requireStrongPassword` and `passwordCriteria.minLength` (threshold 8); sampled `password` attached |
| 11 eDiscovery and legal hold | collaboration | WEBEX-COLLAB-08 | manual: eDiscovery is a Control Hub report; events readability attached |
| 12 Data retention policy | collaboration | WEBEX-COLLAB-03 | manual: Control Hub setting |
| 13 Guest access | meeting-hybrid, identity | WEBEX-MTG-03, WEBEX-ID-07 | policy pass/fail/manual per site from `securityOptions.requireLoginBeforeAccess`; inventory pass/warn from `type = appuser` and `GET /guests/count` |
| 14 Space classification | collaboration | WEBEX-COLLAB-04 | pass/fail/warn from `classificationId` on visible rooms |
| 15 Hybrid cluster health | meeting-hybrid | WEBEX-MTG-04 | pass/fail/warn from connector `status` |
| 16 Hybrid connector status | meeting-hybrid | WEBEX-MTG-04 | pass/fail/warn from connector `status` |
| 17 Device firmware | meeting-hybrid | WEBEX-MTG-05 | manual: no end-of-life field; `software` versions and `upgradeChannel` values inventoried |
| 18 Unmanaged devices | meeting-hybrid | WEBEX-MTG-05 | manual: no blocking policy field; `personId` and `managedBy` inventoried |
| 19 Bot management | identity | WEBEX-ID-05, WEBEX-ID-06 | inventory pass/warn from `type = bot`; approval manual |
| 20 Webhook HTTPS and secret | collaboration | WEBEX-COLLAB-05 | pass/fail/warn from `targetUrl` and `secret` on visible webhooks |
| 21 Messaging DLP | collaboration | WEBEX-COLLAB-02 | manual: DLP is an Events API integration |
| 22 SRTP calling encryption | meeting-hybrid | WEBEX-MTG-01 | manual, folded: no calling SRTP setting in the public API |
| 23 Virtual background | meeting-hybrid | WEBEX-MTG-07 | manual: no field in common settings, meeting preferences, or session types |
| 24 License utilization | collaboration | WEBEX-COLLAB-06 | pass/warn from `totalUnits` and `consumedUnits` |
| 25 Admin audit logging | collaboration, identity | WEBEX-COLLAB-07, WEBEX-ID-04 | audit pass/warn from `/adminAudit/events` over 30 days; admin concentration pass/warn from `/people` roles against `max_admins` (evidence for the role review, not an MFA verdict) |

Automatable controls: 3, 9, 10, 13, 14, 15, 16, 19 (inventory), 20, 24, 25. All 25 controls have a finding; 22 findings in total.

## Framework mappings

Every finding carries the spec section 5 mappings for FedRAMP / NIST 800-53, CMMC, SOC 2, CIS Controls, PCI-DSS, DISA STIG, IRAP / ISM, and ISMAP. The bundle writes one report per framework under `compliance/`.

## Live smoke

```bash
npm --prefix cli run test:webex:live
```

The script skips with exit code 0 when no `WEBEX_TOKEN`, refresh credential trio, or config file is present. Otherwise it runs `webex_check_access` and all three assess tools.

## Limitations and manual controls

- `GET /rooms`, `GET /webhooks`, and `GET /meetings` list only what the authenticated identity can see; findings state this and downgrade to `warn` under a bot token.
- `GET /people` returns 400 for non-admin tokens without a filter; that renders as manual, not empty.
- `GET /admin/meeting/config/commonSettings` needs a site administrator with `meeting:admin_config_read`; `GET /guests/count` needs `guest-issuer:read`.
- A finding that reads more than one inventory cannot pass while any of them is unreadable: WEBEX-ID-07 caps at `warn` when `GET /guests/count` is denied, WEBEX-MTG-02 and WEBEX-MTG-06 cap at `warn` when `GET /meetings` or `GET /meetingPreferences` is denied, and WEBEX-COLLAB-04, WEBEX-COLLAB-05, WEBEX-MTG-02, WEBEX-MTG-03, and WEBEX-MTG-06 cap at `warn` when `GET /people/me` is unreadable (the bot-token partial view cannot be excluded). Each summary names the unreadable endpoint, and counts derived from it render as `null` beside a `*_status` object rather than `0` or `[]`. The same null rule applies to manual findings whose evidence is derived from more than one inventory: WEBEX-ID-02 renders `admin_users` and `admin_count` as `null` and names the denied endpoint when either `GET /people` or `GET /roles` is unreadable (the administrator list needs both), and WEBEX-ID-06 asserts no bot count when `GET /people` is unreadable.
- Events older than 90 days require Pro Pack for Control Hub.
- Pagination follows `Link rel="next"` for at most 1000 pages per listing; both the item limit and the page ceiling report `truncated: true`, and evidence lists capped at 25 or 50 entries carry a matching `*_count` total.
- SARIF, CSV, and HTML reporters from the spec are out of scope for this pass.

## Endpoints

Every canonical reference URL of the form `https://developer.webex.com/docs/api/v1/<category>/<page>` answers 302 to a category-prefixed page (`/admin/docs`, `/meeting/docs`, `/calling/docs`, `/messaging/docs`) whose server-rendered HTML embeds the OpenAPI 3.0.3 schema for every endpoint in that category, so `curl -L` fetches it without a browser. The links below are those redirect targets, and every field in the table was checked against the embedded schema.

| Endpoint | Fields read | Documentation |
|----------|-------------|---------------|
| `POST /access_token` | `access_token` | [Integrations](https://developer.webex.com/docs/integrations), [Service Apps](https://developer.webex.com/docs/service-apps) |
| `GET /people/me` | `id`, `displayName`, `emails`, `type` | [Get My Own Details](https://developer.webex.com/admin/docs/api/v1/people/get-my-own-details) |
| `GET /people?orgId&max` | `id`, `displayName`, `emails`, `roles`, `type` (`person`, `bot`, `appuser`), `created` | [List People](https://developer.webex.com/admin/docs/api/v1/people/list-people) |
| `GET /organizations` | `id`, `displayName` | [List Organizations](https://developer.webex.com/admin/docs/api/v1/organizations/list-organizations) |
| `GET /organizations/{orgId}` | `id`, `displayName`, `created` | [Get Organization Details](https://developer.webex.com/admin/docs/api/v1/organizations/get-organization-details) |
| `GET /roles` | `id`, `name` | [List Roles](https://developer.webex.com/admin/docs/api/v1/roles/list-roles) |
| `GET /licenses?orgId` | `totalUnits`, `consumedUnits` | [List Licenses](https://developer.webex.com/admin/docs/api/v1/licenses/list-licenses) |
| `GET /guests/count` | bare numeric body | [Get Guest Count](https://developer.webex.com/admin/docs/api/v1/guest-management/get-guest-count) |
| `GET /events?max` | count, `created` | [List Events](https://developer.webex.com/admin/docs/api/v1/events/list-events), [Compliance guide](https://developer.webex.com/docs/api/guides/compliance) |
| `GET /adminAudit/events?orgId&from&to&max` | `created` | [List Admin Audit Events](https://developer.webex.com/admin/docs/api/v1/admin-audit-events/list-admin-audit-events) |
| `GET /admin/recordings?max` | `status` | [List Recordings For an Admin or Compliance Officer](https://developer.webex.com/admin/docs/api/v1/recordings/list-recordings-for-an-admin-or-compliance-officer) |
| `GET /meetings?max` | `password`, `unlockedMeetingJoinSecurity` | [List Meetings](https://developer.webex.com/meeting/docs/api/v1/meetings/list-meetings) |
| `GET /meetingPreferences` | `personalMeetingRoom.enabledAutoLock`, `sites[].siteUrl` | [Get Meeting Preference Details](https://developer.webex.com/meeting/docs/api/v1/meeting-preferences/get-meeting-preference-details) |
| `GET /meetingPreferences/sites` | `sites[].siteUrl` | [Get Site List](https://developer.webex.com/meeting/docs/api/v1/meeting-preferences/get-site-list) |
| `GET /admin/meeting/config/commonSettings?siteUrl` | `securityOptions.joinBeforeHost`, `audioBeforeHost`, `unlistAllMeetings`, `requireLoginBeforeAccess`, `requireStrongPassword`, `passwordCriteria.minLength`, `mixedCase`, `minNumeric`, `minAlpha`, `minSpecial`, `disallowDynamicWebText`, `disallowList` | [Get Meeting Common Settings Configuration](https://developer.webex.com/meeting/docs/api/v1/site/get-meeting-common-settings-configuration) |
| `GET /hybrid/clusters?orgId` | `id`, `name` | [List Hybrid Clusters](https://developer.webex.com/admin/docs/api/v1/hybrid-clusters/list-hybrid-clusters) |
| `GET /hybrid/connectors?orgId` | `id`, `type`, `status`, `version`, `created` | [List Hybrid Connectors](https://developer.webex.com/admin/docs/api/v1/hybrid-connectors/list-hybrid-connectors) |
| `GET /devices?orgId&max` | `software`, `upgradeChannel`, `managedBy`, `personId`, `workspaceId` | [List Devices](https://developer.webex.com/calling/docs/api/v1/devices/list-devices) |
| `GET /workspaces?orgId&max` | count | [List Workspaces](https://developer.webex.com/calling/docs/api/v1/workspaces/list-workspaces) |
| `GET /rooms?max` | `id`, `title`, `classificationId` | [List Rooms](https://developer.webex.com/messaging/docs/api/v1/rooms/list-rooms) |
| `GET /webhooks?max` | `id`, `name`, `targetUrl`, `secret`, `status` | [List Webhooks](https://developer.webex.com/meeting/docs/api/v1/webhooks/list-webhooks) |

Not read, cited as proof of absence: [Update Organization Authentication Configuration Settings](https://developer.webex.com/admin/docs/api/v1/identity-organization/update-organization-authentication-configuration-settings) is the only page documenting `mfaEnabled`, and it is a PATCH; [Session Types](https://developer.webex.com/meeting/docs/api/v1/session-types) returns `id`, `shortName`, `siteUrl`, `name`, and `type` with no encryption or virtual background field.

`max` is sent only to the endpoints whose reference documents it (`/people`, `/events`, `/adminAudit/events`, `/admin/recordings`, `/meetings`, `/devices`, `/workspaces`, `/rooms`, `/webhooks`), within each documented ceiling. Pagination follows the RFC 5988 `Link` header with `rel="next"` until absent and reports truncation when an item limit stops early; 429 responses honor `Retry-After` (both on the [basics](https://developer.webex.com/docs/api/basics) page).
