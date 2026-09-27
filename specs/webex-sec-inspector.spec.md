---
slug: "webex-sec-inspector"
name: "Webex Security Inspector"
vendor: "Cisco"
category: "saas-collaboration"
language: "language-neutral"
status: "generated"
version: "2.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from `cli/extensions/grc-tools/webex.spec.ts` and registered tool definitions by `npm --prefix cli run sync:integration-specs`. Edit the metadata or narrative source, not this file.

# Webex Security Inspector

Read-only Webex organization posture inspection across identity, collaboration governance, meetings, hybrid services, and devices.

## Purpose

Webex Security Inspector gives auditors a read-only, evidence-based view of a Webex organization's identity, collaboration, meeting, hybrid-service, and device posture. It combines the settings that Webex exposes through documented read interfaces with explicit manual evidence requests for settings that remain available only in Control Hub.

## Rationale

Webex security evidence is split across organization, meeting, messaging, calling, and compliance surfaces. Token type, tenant plan, delegated scopes, and per-site configuration all affect what a collector can see. A portable implementation must preserve that uncertainty instead of treating an inaccessible or credential-scoped view as a compliant empty tenant.

The contract favors documented reads over guessed fields or write interfaces. This is especially important for SSO, organization-wide MFA, data loss prevention, calling encryption, device blocking, and other controls whose administrative state is not exposed by a public read operation.

## Non-goals

- Changing Webex settings or issuing any administrative write request
- Claiming complete organization coverage from bot-scoped rooms or webhooks
- Replacing reviewer judgment for settings that have no documented read interface
- Providing a general Webex administration client
- Reproducing a particular programming language, package layout, or command-line framework

## Portable implementation guidance

Keep the API client, evidence projection, verdict evaluation, and bundle writer as separable concerns. Preserve the relationship between a finding and every source it depends on, including the token-type probe and the site list. Assess each meeting site independently before combining results. When Webex returns a credential-scoped inventory, state that scope in the evidence even if every visible record is compliant.

## Shared integration contract

This specification requires [shared integration contract version 1.0](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Tools

| Tool | Purpose | Finding IDs |
|---|---|---|
| `webex_check_access` | Validate read-only Webex access across people, organizations, roles, licenses, recordings, events, admin audit, hybrid, devices, workspaces, rooms, webhooks, meetings, site common settings, and guest count, and report the token type. | None |
| `webex_assess_identity` | Assess Webex identity posture across SSO enforcement, admin MFA, Compliance Officer assignment, administrative privilege concentration, bot inventory, bot approval state, and guest account inventory. | `WEBEX-ID-01`, `WEBEX-ID-02`, `WEBEX-ID-03`, `WEBEX-ID-04`, `WEBEX-ID-05`, `WEBEX-ID-06`, `WEBEX-ID-07` |
| `webex_assess_collaboration_governance` | Assess Webex collaboration governance across external communications, file sharing and DLP, recording governance, space classification, webhook security, license utilization, admin audit visibility, and eDiscovery capability. | `WEBEX-COLLAB-01`, `WEBEX-COLLAB-02`, `WEBEX-COLLAB-03`, `WEBEX-COLLAB-04`, `WEBEX-COLLAB-05`, `WEBEX-COLLAB-06`, `WEBEX-COLLAB-07`, `WEBEX-COLLAB-08` |
| `webex_assess_meeting_hybrid_security` | Assess Webex meeting and hybrid security across encryption defaults, per-site lobby, password, and guest access settings from the site common settings API, virtual background policy, hybrid connector health, and device inventory posture. | `WEBEX-MTG-01`, `WEBEX-MTG-02`, `WEBEX-MTG-03`, `WEBEX-MTG-04`, `WEBEX-MTG-05`, `WEBEX-MTG-06`, `WEBEX-MTG-07` |
| `webex_export_audit_bundle` | Export a Webex audit bundle with field-allowlisted, redacted core_data snapshots (URL query strings such as recording RCID and meeting MTID stripped), analysis JSON, compliance reports per framework, a quick reference, and a zip archive named after the allocated output directory. | `WEBEX-ID-01`, `WEBEX-ID-02`, `WEBEX-ID-03`, `WEBEX-ID-04`, `WEBEX-ID-05`, `WEBEX-ID-06`, `WEBEX-ID-07`, `WEBEX-COLLAB-01`, `WEBEX-COLLAB-02`, `WEBEX-COLLAB-03`, `WEBEX-COLLAB-04`, `WEBEX-COLLAB-05`, `WEBEX-COLLAB-06`, `WEBEX-COLLAB-07`, `WEBEX-COLLAB-08`, `WEBEX-MTG-01`, `WEBEX-MTG-02`, `WEBEX-MTG-03`, `WEBEX-MTG-04`, `WEBEX-MTG-05`, `WEBEX-MTG-06`, `WEBEX-MTG-07` |

### Parameters

#### `webex_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Webex access token. Defaults to WEBEX_TOKEN, then the config file. |
| `client_id` | string | no | Integration or Service App client ID for the refresh_token grant. Defaults to WEBEX_CLIENT_ID. |
| `client_secret` | string | no | Integration or Service App client secret. Defaults to WEBEX_CLIENT_SECRET. |
| `refresh_token` | string | no | Integration or Service App refresh token. Defaults to WEBEX_REFRESH_TOKEN. |
| `config_file` | string | no | Config file path. Defaults to WEBEX_CONFIG_FILE, then ~/.config/webex-sec-inspector/config.{json,yaml,yml}. |
| `org_id` | string | no | Webex organization ID. Defaults to WEBEX_ORG_ID or auto-detect when only one org is visible. |
| `base_url` | string | no | Webex API base URL. Defaults to https://webexapis.com/v1. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |

#### `webex_assess_identity`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Webex access token. Defaults to WEBEX_TOKEN, then the config file. |
| `client_id` | string | no | Integration or Service App client ID for the refresh_token grant. Defaults to WEBEX_CLIENT_ID. |
| `client_secret` | string | no | Integration or Service App client secret. Defaults to WEBEX_CLIENT_SECRET. |
| `refresh_token` | string | no | Integration or Service App refresh token. Defaults to WEBEX_REFRESH_TOKEN. |
| `config_file` | string | no | Config file path. Defaults to WEBEX_CONFIG_FILE, then ~/.config/webex-sec-inspector/config.{json,yaml,yml}. |
| `org_id` | string | no | Webex organization ID. Defaults to WEBEX_ORG_ID or auto-detect when only one org is visible. |
| `base_url` | string | no | Webex API base URL. Defaults to https://webexapis.com/v1. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `people_limit` | number | no | Maximum people to inspect. Defaults to 1000. |
| `max_admins` | number | no | Maximum acceptable admin users before warning. Defaults to 10. |

#### `webex_assess_collaboration_governance`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Webex access token. Defaults to WEBEX_TOKEN, then the config file. |
| `client_id` | string | no | Integration or Service App client ID for the refresh_token grant. Defaults to WEBEX_CLIENT_ID. |
| `client_secret` | string | no | Integration or Service App client secret. Defaults to WEBEX_CLIENT_SECRET. |
| `refresh_token` | string | no | Integration or Service App refresh token. Defaults to WEBEX_REFRESH_TOKEN. |
| `config_file` | string | no | Config file path. Defaults to WEBEX_CONFIG_FILE, then ~/.config/webex-sec-inspector/config.{json,yaml,yml}. |
| `org_id` | string | no | Webex organization ID. Defaults to WEBEX_ORG_ID or auto-detect when only one org is visible. |
| `base_url` | string | no | Webex API base URL. Defaults to https://webexapis.com/v1. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `event_limit` | number | no | Maximum events to inspect. Defaults to 500. |
| `recording_limit` | number | no | Maximum recordings to inspect. Defaults to 200. |
| `webhook_limit` | number | no | Maximum webhooks to inspect. Defaults to 200. |
| `license_limit` | number | no | Maximum licenses to inspect. Defaults to 200. |
| `room_limit` | number | no | Maximum rooms to inspect. Defaults to 500. |

#### `webex_assess_meeting_hybrid_security`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Webex access token. Defaults to WEBEX_TOKEN, then the config file. |
| `client_id` | string | no | Integration or Service App client ID for the refresh_token grant. Defaults to WEBEX_CLIENT_ID. |
| `client_secret` | string | no | Integration or Service App client secret. Defaults to WEBEX_CLIENT_SECRET. |
| `refresh_token` | string | no | Integration or Service App refresh token. Defaults to WEBEX_REFRESH_TOKEN. |
| `config_file` | string | no | Config file path. Defaults to WEBEX_CONFIG_FILE, then ~/.config/webex-sec-inspector/config.{json,yaml,yml}. |
| `org_id` | string | no | Webex organization ID. Defaults to WEBEX_ORG_ID or auto-detect when only one org is visible. |
| `base_url` | string | no | Webex API base URL. Defaults to https://webexapis.com/v1. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `meeting_limit` | number | no | Maximum meetings to inspect. Defaults to 200. |
| `device_limit` | number | no | Maximum devices to inspect. Defaults to 500. |

#### `webex_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `token` | string | no | Webex access token. Defaults to WEBEX_TOKEN, then the config file. |
| `client_id` | string | no | Integration or Service App client ID for the refresh_token grant. Defaults to WEBEX_CLIENT_ID. |
| `client_secret` | string | no | Integration or Service App client secret. Defaults to WEBEX_CLIENT_SECRET. |
| `refresh_token` | string | no | Integration or Service App refresh token. Defaults to WEBEX_REFRESH_TOKEN. |
| `config_file` | string | no | Config file path. Defaults to WEBEX_CONFIG_FILE, then ~/.config/webex-sec-inspector/config.{json,yaml,yml}. |
| `org_id` | string | no | Webex organization ID. Defaults to WEBEX_ORG_ID or auto-detect when only one org is visible. |
| `base_url` | string | no | Webex API base URL. Defaults to https://webexapis.com/v1. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `output_dir` | string | no | Output root. Defaults to ./export/webex. |
| `people_limit` | number | no | Maximum people to inspect. Defaults to 1000. |
| `max_admins` | number | no | Maximum acceptable admin users before warning. Defaults to 10. |
| `event_limit` | number | no | Maximum events to inspect. Defaults to 500. |
| `recording_limit` | number | no | Maximum recordings to inspect. Defaults to 200. |
| `webhook_limit` | number | no | Maximum webhooks to inspect. Defaults to 200. |
| `license_limit` | number | no | Maximum licenses to inspect. Defaults to 200. |
| `room_limit` | number | no | Maximum rooms to inspect. Defaults to 500. |
| `meeting_limit` | number | no | Maximum meetings to inspect. Defaults to 200. |
| `device_limit` | number | no | Maximum devices to inspect. Defaults to 500. |


## Authentication

Supported modes:

- Existing OAuth access token
- OAuth refresh-token exchange for an integration or service application

Credential precedence, highest first:

1. Explicit tool arguments
2. Environment variables
3. Configured file
4. Default user configuration file

Environment variables: `WEBEX_TOKEN`, `WEBEX_CLIENT_ID`, `WEBEX_CLIENT_SECRET`, `WEBEX_REFRESH_TOKEN`, `WEBEX_ORG_ID`, `WEBEX_BASE_URL`, `WEBEX_CONFIG_FILE`

Configuration locations: Path named by WEBEX_CONFIG_FILE, ~/.config/webex-sec-inspector/config.json, ~/.config/webex-sec-inspector/config.yaml, ~/.config/webex-sec-inspector/config.yml

Credential and deployment variants: Person token, Guest token, Bot token, Integration token, Service application token

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| oauth-scope | `spark-admin:people_read` | `people`, `me` |  |
| oauth-scope | `spark-admin:organizations_read` | `organizations`, `organization` |  |
| oauth-scope | `spark-admin:roles_read` | `roles` |  |
| oauth-scope | `spark-admin:licenses_read` | `licenses` |  |
| oauth-scope | `spark-admin:devices_read` | `devices`, `workspaces` |  |
| oauth-scope | `spark-admin:hybrid_clusters_read` | `hybrid-clusters`, `hybrid-connectors` |  |
| oauth-scope | `spark-compliance:events_read` | `events`, `admin-audit-events` |  |
| oauth-scope | `meeting:admin_schedule_read` | `meetings` |  |
| oauth-scope | `meeting:admin_recordings_read` | `admin-recordings` |  |
| oauth-scope | `meeting:admin_preferences_read` | `meeting-preferences`, `meeting-sites`, `meeting-common-settings` |  |
| plan | `Webex Pro Pack` | `events`, `admin-audit-events` | Some compliance and longer-retention evidence depends on the tenant plan. |

## API surfaces

| ID | Interface | Read operation | Service | Intent | Fields consumed | Reference |
|---|---|---|---|---|---|---|
| `me` | HTTP | `GET /people/me` | https://webexapis.com/v1 | auth-only | `id`, `displayName`, `emails`, `type`, `roles`, `orgId`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/people/get-my-own-details) |
| `organizations` | HTTP | `GET /organizations` | https://webexapis.com/v1 | read | `id`, `displayName`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/organizations/list-organizations) |
| `organization` | HTTP | `GET /organizations/{orgId}` | https://webexapis.com/v1 | read | `id`, `displayName`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/organizations/get-organization-details) |
| `people` | HTTP | `GET /people` | https://webexapis.com/v1 | read | `id`, `displayName`, `emails`, `type`, `roles`, `orgId`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/people/list-people) |
| `roles` | HTTP | `GET /roles` | https://webexapis.com/v1 | read | `id`, `name` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/roles/list-roles) |
| `licenses` | HTTP | `GET /licenses` | https://webexapis.com/v1 | read | `id`, `name`, `totalUnits`, `consumedUnits`, `subscriptionId`, `siteUrl`, `siteType` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/licenses/list-licenses) |
| `events` | HTTP | `GET /events` | https://webexapis.com/v1 | read | `id`, `resource`, `type`, `actorId`, `actorOrgId`, `orgId`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/events/list-events) |
| `admin-audit-events` | HTTP | `GET /adminAudit/events` | https://webexapis.com/v1 | read | `id`, `actorId`, `actorOrgId`, `targetOrgId`, `created`, `data.eventCategory`, `data.eventDescription`, `data.actionText`, `data.actorEmail`, `data.actorName`, `data.adminRoles`, `data.targetType`, `data.targetName` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/admin-audit-events/list-admin-audit-events) |
| `admin-recordings` | HTTP | `GET /admin/recordings` | https://webexapis.com/v1 | read | `id`, `meetingId`, `topic`, `createTime`, `timeRecorded`, `hostEmail`, `siteUrl`, `downloadUrl`, `playbackUrl`, `format`, `serviceType`, `durationSeconds`, `sizeBytes`, `status` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/recordings/list-recordings-for-an-admin-or-compliance-officer) |
| `guest-count` | HTTP | `GET /guests/count` | https://webexapis.com/v1 | read | `count` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/guest-management/get-guest-count) |
| `hybrid-clusters` | HTTP | `GET /hybrid/clusters` | https://webexapis.com/v1 | read | `id`, `name`, `orgId`, `resourceGroupId` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/hybrid-clusters/list-hybrid-clusters) |
| `hybrid-connectors` | HTTP | `GET /hybrid/connectors` | https://webexapis.com/v1 | read | `id`, `orgId`, `hybridClusterId`, `hostname`, `type`, `version`, `status`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/hybrid-connectors/list-hybrid-connectors) |
| `meetings` | HTTP | `GET /meetings` | https://webexapis.com/v1 | read | `id`, `title`, `meetingType`, `state`, `start`, `end`, `hostEmail`, `siteUrl`, `webLink`, `password`, `unlockedMeetingJoinSecurity`, `enabledJoinBeforeHost`, `joinBeforeHostMinutes`, `enableAutomaticLock`, `automaticLockMinutes`, `publicMeeting` | [Official documentation](https://developer.webex.com/meeting/docs/api/v1/meetings/list-meetings) |
| `meeting-preferences` | HTTP | `GET /meetingPreferences` | https://webexapis.com/v1 | read | `personalMeetingRoom.enabledAutoLock`, `personalMeetingRoom.autoLockMinutes`, `personalMeetingRoom.notifyHost`, `personalMeetingRoom.supportCoHost`, `personalMeetingRoom.supportAnyoneAsCoHost`, `personalMeetingRoom.allowFirstUserToBeCoHost`, `personalMeetingRoom.allowAuthenticatedDevices`, `audio.defaultAudioType`, `audio.enabledGlobalCallIn`, `audio.enabledTollFree`, `audio.enabledAutoConnection`, `schedulingOptions.enabledJoinBeforeHost`, `schedulingOptions.joinBeforeHostMinutes`, `schedulingOptions.enabledAutoShareRecording`, `schedulingOptions.enabledWebexAssistantByDefault`, `sites.siteUrl`, `sites.default` | [Official documentation](https://developer.webex.com/meeting/docs/api/v1/meeting-preferences/get-meeting-preference-details) |
| `meeting-sites` | HTTP | `GET /meetingPreferences/sites` | https://webexapis.com/v1 | read | `siteUrl`, `default` | [Official documentation](https://developer.webex.com/meeting/docs/api/v1/meeting-preferences/get-site-list) |
| `meeting-common-settings` | HTTP | `GET /admin/meeting/config/commonSettings` | https://webexapis.com/v1 | read | `siteUrl`, `securityOptions.joinBeforeHost`, `securityOptions.audioBeforeHost`, `securityOptions.firstAttendeeAsPresenter`, `securityOptions.unlistAllMeetings`, `securityOptions.requireLoginBeforeAccess`, `securityOptions.allowMobileScreenCapture`, `securityOptions.requireStrongPassword`, `securityOptions.passwordCriteria.mixedCase`, `securityOptions.passwordCriteria.minLength`, `securityOptions.passwordCriteria.minNumeric`, `securityOptions.passwordCriteria.minAlpha`, `securityOptions.passwordCriteria.minSpecial`, `securityOptions.passwordCriteria.disallowDynamicWebText`, `securityOptions.passwordCriteria.disallowList`, `securityOptions.passwordCriteria.disallowValues` | [Official documentation](https://developer.webex.com/meeting/docs/api/v1/site/get-meeting-common-settings-configuration) |
| `devices` | HTTP | `GET /devices` | https://webexapis.com/v1 | read | `id`, `displayName`, `workspaceId`, `personId`, `orgId`, `product`, `type`, `software`, `upgradeChannel`, `connectionStatus`, `managedBy`, `created` | [Official documentation](https://developer.webex.com/calling/docs/api/v1/devices/list-devices) |
| `workspaces` | HTTP | `GET /workspaces` | https://webexapis.com/v1 | read | `id`, `displayName`, `type`, `orgId`, `created` | [Official documentation](https://developer.webex.com/calling/docs/api/v1/workspaces/list-workspaces) |
| `rooms` | HTTP | `GET /rooms` | https://webexapis.com/v1 | read | `id`, `title`, `type`, `isLocked`, `isPublic`, `classificationId`, `teamId`, `ownerId`, `created`, `lastActivity` | [Official documentation](https://developer.webex.com/messaging/docs/api/v1/rooms/list-rooms) |
| `webhooks` | HTTP | `GET /webhooks` | https://webexapis.com/v1 | read | `id`, `name`, `targetUrl`, `resource`, `event`, `secret`, `status`, `ownedBy`, `created` | [Official documentation](https://developer.webex.com/meeting/docs/api/v1/webhooks/list-webhooks) |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `people`, `licenses`, `events`, `admin-audit-events`, `admin-recordings`, `hybrid-clusters`, `hybrid-connectors`, `meetings`, `meeting-sites`, `devices`, `workspaces`, `rooms`, `webhooks` | `Link header rel=next` | service default | caller limit | 1000 | The service does not provide a dependable total for these walks; report items seen and whether exhaustion was proven. | No next link; Configured item cap; Page cap; Repeated next link; Empty page with next link; Rejected cross-origin or userinfo-bearing next link |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Webex REST API | Not published | `Retry-After` | 429 | Retry at most 2 times, cap each Retry-After delay at 30000 milliseconds, then report the surface unreadable. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | SSO enforcement | WEBEX-ID-01 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 2 | Admin MFA | WEBEX-ID-02 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 3 | Compliance officer role | WEBEX-ID-03 | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| 4 | External communications | WEBEX-COLLAB-01 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 5 | File sharing restrictions | WEBEX-COLLAB-02 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 6 | Recording storage control | WEBEX-COLLAB-03 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 7 | Recording retention | WEBEX-COLLAB-03 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 8 | End-to-end meeting encryption | WEBEX-MTG-01 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 9 | Meeting lobby controls | WEBEX-MTG-02 | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| 10 | Meeting password required | WEBEX-MTG-06 | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| 11 | eDiscovery and legal hold | WEBEX-COLLAB-08 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 12 | Data retention policy | WEBEX-COLLAB-03 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 13 | Guest access restrictions | WEBEX-ID-07, WEBEX-MTG-03 | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| 14 | Space classification | WEBEX-COLLAB-04 | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| 15 | Hybrid cluster health | WEBEX-MTG-04 | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| 16 | Hybrid connector status | WEBEX-MTG-04 | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| 17 | Device firmware currency | WEBEX-MTG-05 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 18 | Unmanaged device blocking | WEBEX-MTG-05 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 19 | Bot management | WEBEX-ID-05, WEBEX-ID-06 | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 20 | Webhook transport and signing | WEBEX-COLLAB-05 | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| 21 | Messaging data loss prevention | WEBEX-COLLAB-02 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 22 | Calling encryption | WEBEX-MTG-01 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 23 | Virtual background policy | WEBEX-MTG-07 | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| 24 | License utilization | WEBEX-COLLAB-06 | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| 25 | Admin activity audit | WEBEX-ID-04, WEBEX-COLLAB-07 | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |

### Finding criteria

| Finding | Severity | Owning tool | Sources | Pass | Warn | Fail | Manual |
|---|---|---|---|---|---|---|---|
| `WEBEX-ID-01` | critical | `webex_assess_identity` | `organization` | Not emitted automatically. A reviewer may record pass only after examining the named administrative evidence. | Readable supporting inventory is incomplete or indicates that manual review is still required. | Not emitted automatically unless a documented read surface directly proves noncompliance. | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| `WEBEX-ID-02` | critical | `webex_assess_identity` | `people`, `roles` | Not emitted automatically. A reviewer may record pass only after examining the named administrative evidence. | Readable supporting inventory is incomplete or indicates that manual review is still required. | Not emitted automatically unless a documented read surface directly proves noncompliance. | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| `WEBEX-ID-03` | high | `webex_assess_identity` | `people`, `roles` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-ID-04` | medium | `webex_assess_identity` | `people`, `roles` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-ID-05` | medium | `webex_assess_identity` | `people` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-ID-06` | medium | `webex_assess_identity` | `people` | Not emitted automatically. A reviewer may record pass only after examining the named administrative evidence. | Readable supporting inventory is incomplete or indicates that manual review is still required. | Not emitted automatically unless a documented read surface directly proves noncompliance. | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| `WEBEX-ID-07` | medium | `webex_assess_identity` | `people`, `guest-count` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-COLLAB-01` | high | `webex_assess_collaboration_governance` | `organization` | Not emitted automatically. A reviewer may record pass only after examining the named administrative evidence. | Readable supporting inventory is incomplete or indicates that manual review is still required. | Not emitted automatically unless a documented read surface directly proves noncompliance. | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| `WEBEX-COLLAB-02` | high | `webex_assess_collaboration_governance` | `events` | Not emitted automatically. A reviewer may record pass only after examining the named administrative evidence. | Readable supporting inventory is incomplete or indicates that manual review is still required. | Not emitted automatically unless a documented read surface directly proves noncompliance. | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| `WEBEX-COLLAB-03` | medium | `webex_assess_collaboration_governance` | `admin-recordings` | Not emitted automatically. A reviewer may record pass only after examining the named administrative evidence. | Readable supporting inventory is incomplete or indicates that manual review is still required. | Not emitted automatically unless a documented read surface directly proves noncompliance. | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| `WEBEX-COLLAB-04` | medium | `webex_assess_collaboration_governance` | `rooms`, `me` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-COLLAB-05` | high | `webex_assess_collaboration_governance` | `webhooks`, `me` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-COLLAB-06` | low | `webex_assess_collaboration_governance` | `licenses` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-COLLAB-07` | high | `webex_assess_collaboration_governance` | `admin-audit-events` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-COLLAB-08` | high | `webex_assess_collaboration_governance` | `events` | Not emitted automatically. A reviewer may record pass only after examining the named administrative evidence. | Readable supporting inventory is incomplete or indicates that manual review is still required. | Not emitted automatically unless a documented read surface directly proves noncompliance. | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| `WEBEX-MTG-01` | high | `webex_assess_meeting_hybrid_security` | `meeting-preferences`, `meeting-common-settings` | Not emitted automatically. A reviewer may record pass only after examining the named administrative evidence. | Readable supporting inventory is incomplete or indicates that manual review is still required. | Not emitted automatically unless a documented read surface directly proves noncompliance. | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| `WEBEX-MTG-02` | high | `webex_assess_meeting_hybrid_security` | `meeting-sites`, `meeting-common-settings`, `meetings`, `meeting-preferences`, `me` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-MTG-03` | medium | `webex_assess_meeting_hybrid_security` | `meeting-sites`, `meeting-common-settings`, `me` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-MTG-04` | high | `webex_assess_meeting_hybrid_security` | `hybrid-clusters`, `hybrid-connectors` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-MTG-05` | high | `webex_assess_meeting_hybrid_security` | `devices`, `workspaces` | Not emitted automatically. A reviewer may record pass only after examining the named administrative evidence. | Readable supporting inventory is incomplete or indicates that manual review is still required. | Not emitted automatically unless a documented read surface directly proves noncompliance. | Collect the administrative evidence named by the finding because no documented read interface settles the control. |
| `WEBEX-MTG-06` | high | `webex_assess_meeting_hybrid_security` | `meeting-sites`, `meeting-common-settings`, `meetings`, `meeting-preferences`, `me` | Every required source is complete and the observed settings satisfy the check. | The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance. | Complete readable evidence proves that the required setting is absent or noncompliant. | A required source is unreadable, denied, not requested, or not exposed by a documented read interface. |
| `WEBEX-MTG-07` | low | `webex_assess_meeting_hybrid_security` | `meeting-common-settings` | Not emitted automatically. A reviewer may record pass only after examining the named administrative evidence. | Readable supporting inventory is incomplete or indicates that manual review is still required. | Not emitted automatically unless a documented read surface directly proves noncompliance. | Collect the administrative evidence named by the finding because no documented read interface settles the control. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | SSO enforcement | IA-2(1) | L2 3.5.3 | CC6.1 | 16.2 | 8.4.1 | SRG-APP-000148 | ISM-1546 | CPS-7.1 |
| 2 | Admin MFA | IA-2(2) | L2 3.5.3 | CC6.1 | 16.3 | 8.4.2 | SRG-APP-000149 | ISM-1401 | CPS-7.2 |
| 3 | Compliance officer role | AU-1 | L2 3.3.2 | CC7.2 | 8.1 | 12.5.2 | SRG-APP-000516 | ISM-0042 | CPS-12.1 |
| 4 | External communications | AC-4 | L2 3.1.3 | CC6.6 | 13.4 | 1.3.7 | SRG-APP-000100 | ISM-1528 | CPS-11.1 |
| 5 | File sharing restrictions | AC-4(1) | L2 3.1.3 | CC6.7 | 13.4 | 1.3.7 | SRG-APP-000100 | ISM-0947 | CPS-11.2 |
| 6 | Recording storage control | SC-28 | L2 3.13.16 | CC6.7 | 14.8 | 3.4.1 | SRG-APP-000428 | ISM-0457 | CPS-11.3 |
| 7 | Recording retention | SI-12 | L2 3.8.9 | CC6.5 | 14.8 | 3.1 | SRG-APP-000504 | ISM-0859 | CPS-12.2 |
| 8 | End-to-end meeting encryption | SC-8(1) | L2 3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0484 | CPS-11.4 |
| 9 | Meeting lobby controls | AC-3 | L2 3.1.1 | CC6.1 | 16.7 | 7.1.3 | SRG-APP-000033 | ISM-1506 | CPS-8.1 |
| 10 | Meeting password required | IA-5 | L2 3.5.7 | CC6.1 | 16.5 | 8.2.3 | SRG-APP-000170 | ISM-1557 | CPS-7.3 |
| 11 | eDiscovery and legal hold | AU-11 | L2 3.3.1 | CC7.3 | 8.3 | 10.7 | SRG-APP-000515 | ISM-0859 | CPS-12.3 |
| 12 | Data retention policy | SI-12 | L2 3.8.9 | CC6.5 | 14.8 | 3.1 | SRG-APP-000504 | ISM-0859 | CPS-12.4 |
| 13 | Guest access restrictions | AC-14 | L2 3.1.1 | CC6.1 | 16.7 | 7.1.3 | SRG-APP-000033 | ISM-1506 | CPS-8.2 |
| 14 | Space classification | AC-16 | L2 3.13.12 | CC6.7 | 14.1 | 9.6.1 | SRG-APP-000311 | ISM-0271 | CPS-11.5 |
| 15 | Hybrid cluster health | CM-8 | L2 3.4.1 | CC6.8 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1409 | CPS-10.1 |
| 16 | Hybrid connector status | SI-4 | L2 3.14.6 | CC7.1 | 1.1 | 10.6 | SRG-APP-000516 | ISM-0576 | CPS-12.5 |
| 17 | Device firmware currency | SI-2 | L2 3.14.1 | CC7.1 | 7.4 | 6.2 | SRG-APP-000456 | ISM-1143 | CPS-13.1 |
| 18 | Unmanaged device blocking | CM-8(3) | L2 3.4.1 | CC6.8 | 1.4 | 9.7.1 | SRG-APP-000383 | ISM-1482 | CPS-10.2 |
| 19 | Bot management | CM-7 | L2 3.4.6 | CC6.8 | 4.8 | 2.2.2 | SRG-APP-000141 | ISM-1407 | CPS-10.3 |
| 20 | Webhook transport and signing | SC-8(1) | L2 3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0484 | CPS-11.6 |
| 21 | Messaging data loss prevention | SC-7(8) | L2 3.13.1 | CC6.7 | 13.4 | 1.3.7 | SRG-APP-000516 | ISM-0947 | CPS-11.7 |
| 22 | Calling encryption | SC-8 | L2 3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000439 | ISM-0484 | CPS-11.8 |
| 23 | Virtual background policy | AC-3 | L2 3.1.1 | CC6.1 | - | - | SRG-APP-000033 | - | - |
| 24 | License utilization | CM-8 | L2 3.4.1 | CC6.8 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1409 | CPS-10.4 |
| 25 | Admin activity audit | AU-12 | L2 3.3.1 | CC7.2 | 8.5 | 10.2.2 | SRG-APP-000507 | ISM-0580 | CPS-12.6 |

## Collection states

| State | Required rendering |
|---|---|
| complete | The requested surface was read to proven exhaustion. |
| truncated | The surface returned data, but a cap or pagination anomaly prevented proven exhaustion. |
| unreadable | The request failed or the response did not match the documented shape. |
| denied | The service refused the request; record the endpoint and observed status without treating the inventory as empty. |
| not requested | A dependent request was never issued because its parent inventory was unreadable; name the parent and invent no status. |
| not configured | The surface requires tenant or organization context that was not configured or discoverable. |

## Integration-specific scrubbing

Shared contract version: 1.0.

Sensitive fields and values: token, client_secret, refresh_token, password, secret, targetUrl query, downloadUrl query, playbackUrl query, webLink query

Credential formats: Bearer credentials, OAuth client secrets, Refresh tokens, Webhook signing secrets, Meeting passwords, Credential-bearing URL parameters

Reviewed benign exceptions: Documented resource identifiers, Organization identifiers, Site host names

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `me` | `id`, `displayName`, `emails`, `type`, `roles`, `orgId`, `created` |
| `organizations` | `id`, `displayName`, `created` |
| `organization` | `id`, `displayName`, `created` |
| `people` | `id`, `displayName`, `emails`, `type`, `roles`, `orgId`, `created` |
| `roles` | `id`, `name` |
| `guest_count` | `count` |
| `licenses` | `id`, `name`, `totalUnits`, `consumedUnits`, `subscriptionId`, `siteUrl`, `siteType` |
| `events` | `id`, `resource`, `type`, `actorId`, `actorOrgId`, `orgId`, `created` |
| `admin_audit_events` | `id`, `actorId`, `actorOrgId`, `targetOrgId`, `created`, `data.eventCategory`, `data.eventDescription`, `data.actionText`, `data.actorEmail`, `data.actorName`, `data.adminRoles`, `data.targetType`, `data.targetName` |
| `admin_recordings` | `id`, `meetingId`, `topic`, `createTime`, `timeRecorded`, `hostEmail`, `siteUrl`, `downloadUrl`, `playbackUrl`, `format`, `serviceType`, `durationSeconds`, `sizeBytes`, `status` |
| `rooms` | `id`, `title`, `type`, `isLocked`, `isPublic`, `classificationId`, `teamId`, `ownerId`, `created`, `lastActivity` |
| `webhooks` | `id`, `name`, `targetUrl`, `resource`, `event`, `secret`, `status`, `ownedBy`, `created` |
| `meeting_preferences` | `personalMeetingRoom.enabledAutoLock`, `personalMeetingRoom.autoLockMinutes`, `personalMeetingRoom.notifyHost`, `personalMeetingRoom.supportCoHost`, `personalMeetingRoom.supportAnyoneAsCoHost`, `personalMeetingRoom.allowFirstUserToBeCoHost`, `personalMeetingRoom.allowAuthenticatedDevices`, `audio.defaultAudioType`, `audio.enabledGlobalCallIn`, `audio.enabledTollFree`, `audio.enabledAutoConnection`, `schedulingOptions.enabledJoinBeforeHost`, `schedulingOptions.joinBeforeHostMinutes`, `schedulingOptions.enabledAutoShareRecording`, `schedulingOptions.enabledWebexAssistantByDefault`, `sites.siteUrl`, `sites.default` |
| `meeting_sites` | `siteUrl`, `default` |
| `meeting_common_settings` | `siteUrl`, `securityOptions.joinBeforeHost`, `securityOptions.audioBeforeHost`, `securityOptions.firstAttendeeAsPresenter`, `securityOptions.unlistAllMeetings`, `securityOptions.requireLoginBeforeAccess`, `securityOptions.allowMobileScreenCapture`, `securityOptions.requireStrongPassword`, `securityOptions.passwordCriteria.mixedCase`, `securityOptions.passwordCriteria.minLength`, `securityOptions.passwordCriteria.minNumeric`, `securityOptions.passwordCriteria.minAlpha`, `securityOptions.passwordCriteria.minSpecial`, `securityOptions.passwordCriteria.disallowDynamicWebText`, `securityOptions.passwordCriteria.disallowList`, `securityOptions.passwordCriteria.disallowValues` |
| `meetings` | `id`, `title`, `meetingType`, `state`, `start`, `end`, `hostEmail`, `siteUrl`, `webLink`, `password`, `unlockedMeetingJoinSecurity`, `enabledJoinBeforeHost`, `joinBeforeHostMinutes`, `enableAutomaticLock`, `automaticLockMinutes`, `publicMeeting` |
| `hybrid_clusters` | `id`, `name`, `orgId`, `resourceGroupId` |
| `hybrid_connectors` | `id`, `orgId`, `hybridClusterId`, `hostname`, `type`, `version`, `status`, `created` |
| `devices` | `id`, `displayName`, `workspaceId`, `personId`, `orgId`, `product`, `type`, `software`, `upgradeChannel`, `connectionStatus`, `managedBy`, `created` |
| `workspaces` | `id`, `displayName`, `type`, `orgId`, `created` |

## Export layout

Required paths:

- `QUICK_REFERENCE.md`
- `metadata.json`
- `core_data/access.json`
- `core_data/{category}/{surface}.json`
- `analysis/{category}.json`
- `analysis/findings.json`
- `compliance/executive_summary.md`
- `compliance/unified_compliance_matrix.md`
- `compliance/{framework}/{report}.md`

Conditional paths:

- `_errors.log`

Overwrite policy: Allocate a new suffixed bundle directory on every rerun; never replace an earlier bundle.

Path safety: Reject traversal, output roots outside the configured parent, symlink roots, and symlinked parent directories.

Archive pairing: Write a zip archive beside the bundle directory using the exact allocated directory name plus .zip.
