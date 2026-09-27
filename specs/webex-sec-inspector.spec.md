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
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

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

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `webex_check_access` | Validate read-only Webex access across people, organizations, roles, licenses, recordings, events, admin audit, hybrid, devices, workspaces, rooms, webhooks, meetings, site common settings, and guest count, and report the token type. | None | Text table plus structured fields {tool, status, orgId?, tokenType, adminCapable, surfaces, notes, recommendedNextStep}. |
| `webex_assess_identity` | Assess Webex identity posture across SSO enforcement, admin MFA, Compliance Officer assignment, administrative privilege concentration, bot inventory, bot approval state, and guest account inventory. | `WEBEX-ID-01`, `WEBEX-ID-02`, `WEBEX-ID-03`, `WEBEX-ID-04`, `WEBEX-ID-05`, `WEBEX-ID-06`, `WEBEX-ID-07` | Text summary/table plus structured fields {tool, title, category, summary, findings, errors, rawData}. |
| `webex_assess_collaboration_governance` | Assess Webex collaboration governance across external communications, file sharing and DLP, recording governance, space classification, webhook security, license utilization, admin audit visibility, and eDiscovery capability. | `WEBEX-COLLAB-01`, `WEBEX-COLLAB-02`, `WEBEX-COLLAB-03`, `WEBEX-COLLAB-04`, `WEBEX-COLLAB-05`, `WEBEX-COLLAB-06`, `WEBEX-COLLAB-07`, `WEBEX-COLLAB-08` | Text summary/table plus structured fields {tool, title, category, summary, findings, errors, rawData}. |
| `webex_assess_meeting_hybrid_security` | Assess Webex meeting and hybrid security across encryption defaults, per-site lobby, password, and guest access settings from the site common settings API, virtual background policy, hybrid connector health, and device inventory posture. | `WEBEX-MTG-01`, `WEBEX-MTG-02`, `WEBEX-MTG-03`, `WEBEX-MTG-04`, `WEBEX-MTG-05`, `WEBEX-MTG-06`, `WEBEX-MTG-07` | Text summary/table plus structured fields {tool, title, category, summary, findings, errors, rawData}. |
| `webex_export_audit_bundle` | Export a Webex audit bundle with field-allowlisted, redacted core_data snapshots (URL query strings such as recording RCID and meeting MTID stripped), analysis JSON, compliance reports per framework, a quick reference, and a zip archive named after the allocated output directory. | `WEBEX-ID-01`, `WEBEX-ID-02`, `WEBEX-ID-03`, `WEBEX-ID-04`, `WEBEX-ID-05`, `WEBEX-ID-06`, `WEBEX-ID-07`, `WEBEX-COLLAB-01`, `WEBEX-COLLAB-02`, `WEBEX-COLLAB-03`, `WEBEX-COLLAB-04`, `WEBEX-COLLAB-05`, `WEBEX-COLLAB-06`, `WEBEX-COLLAB-07`, `WEBEX-COLLAB-08`, `WEBEX-MTG-01`, `WEBEX-MTG-02`, `WEBEX-MTG-03`, `WEBEX-MTG-04`, `WEBEX-MTG-05`, `WEBEX-MTG-06`, `WEBEX-MTG-07` | Text export receipt plus structured fields {tool, output_dir, zip_path, finding_count, file_count, error_count}. |

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

Environment variables: `WEBEX_TOKEN`, `WEBEX_CLIENT_ID`, `WEBEX_CLIENT_SECRET`, `WEBEX_REFRESH_TOKEN`, `WEBEX_ORG_ID`, `WEBEX_API_BASE_URL`, `WEBEX_TIMEOUT`, `WEBEX_CONFIG_FILE`

Configuration locations: Path named by WEBEX_CONFIG_FILE, ~/.config/webex-sec-inspector/config.json, ~/.config/webex-sec-inspector/config.yaml, ~/.config/webex-sec-inspector/config.yml

Credential and deployment variants: Person token, Guest token, Bot token, Integration token, Service application token

Configuration fields: `token`, `client_id`, `client_secret`, `refresh_token`, `org_id`, `base_url`, `timeout_seconds`

Malformed configuration: Reject unreadable, invalid, or non-object JSON/YAML with a fixed Webex configuration error. Never include parser text, source text, or credential values.

Credential refresh: POST /access_token with application/x-www-form-urlencoded grant_type=refresh_token, client_id, client_secret and refresh_token; require a JSON access_token.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| oauth-scope | `spark:people_read` | `me` |  |
| oauth-scope | `spark-admin:people_read` | `people` |  |
| oauth-scope | `spark-admin:organizations_read` | `organizations`, `organization` |  |
| oauth-scope | `spark-admin:roles_read` | `roles` |  |
| oauth-scope | `spark-admin:licenses_read` | `licenses` |  |
| oauth-scope | `spark-admin:devices_read` | `devices` |  |
| oauth-scope | `spark-admin:workspaces_read` | `workspaces` |  |
| oauth-scope | `spark-admin:hybrid_clusters_read` | `hybrid-clusters`, `hybrid-connectors` |  |
| oauth-scope | `spark-compliance:events_read` | `events` |  |
| oauth-scope | `audit:events_read` | `admin-audit-events` |  |
| oauth-scope | `meeting:schedules_read or meeting:admin_schedule_read` | `meetings` |  |
| oauth-scope | `spark-compliance:recordings_read` | `admin-recordings` |  |
| oauth-scope | `guest-issuer:read` | `guest-count` |  |
| oauth-scope | `meeting:preferences_read or meeting:admin_preferences_read` | `meeting-preferences`, `meeting-sites` |  |
| oauth-scope | `meeting:admin_config_read` | `meeting-common-settings` |  |
| oauth-scope | `spark:rooms_read` | `rooms` |  |
| oauth-scope | `spark:webhooks_read` | `webhooks` |  |
| plan | `Webex Pro Pack` | `events`, `admin-audit-events` | Some compliance and longer-retention evidence depends on the tenant plan. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `token-refresh` | HTTP | `POST /access_token` | https://webexapis.com/v1 | N/A | auth-only | Authentication only. The access token is never exported. | `access_token` | [Official documentation](https://developer.webex.com/docs/integrations) |
| `me` | HTTP | `GET /people/me` | https://webexapis.com/v1 | N/A | auth-only | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `displayName`, `emails`, `type`, `roles`, `orgId`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/people/get-my-own-details) |
| `organizations` | HTTP | `GET /organizations` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `displayName`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/organizations/list-organizations) |
| `organization` | HTTP | `GET /organizations/{orgId}` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `displayName`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/organizations/get-organization-details) |
| `people` | HTTP | `GET /people` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `displayName`, `emails`, `type`, `roles`, `orgId`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/people/list-people) |
| `roles` | HTTP | `GET /roles` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `name` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/roles/list-roles) |
| `licenses` | HTTP | `GET /licenses` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `name`, `totalUnits`, `consumedUnits`, `subscriptionId`, `siteUrl`, `siteType` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/licenses/list-licenses) |
| `events` | HTTP | `GET /events` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `resource`, `type`, `actorId`, `actorOrgId`, `orgId`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/events/list-events) |
| `admin-audit-events` | HTTP | `GET /adminAudit/events` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `actorId`, `actorOrgId`, `targetOrgId`, `created`, `data.eventCategory`, `data.eventDescription`, `data.actionText`, `data.actorEmail`, `data.actorName`, `data.adminRoles`, `data.targetType`, `data.targetName` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/admin-audit-events/list-admin-audit-events) |
| `admin-recordings` | HTTP | `GET /admin/recordings` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `meetingId`, `topic`, `createTime`, `timeRecorded`, `hostEmail`, `siteUrl`, `downloadUrl`, `playbackUrl`, `format`, `serviceType`, `durationSeconds`, `sizeBytes`, `status` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/recordings/list-recordings-for-an-admin-or-compliance-officer) |
| `guest-count` | HTTP | `GET /guests/count` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `count` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/guest-management/get-guest-count) |
| `hybrid-clusters` | HTTP | `GET /hybrid/clusters` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `name`, `orgId`, `resourceGroupId` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/hybrid-clusters/list-hybrid-clusters) |
| `hybrid-connectors` | HTTP | `GET /hybrid/connectors` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `orgId`, `hybridClusterId`, `hostname`, `type`, `version`, `status`, `created` | [Official documentation](https://developer.webex.com/admin/docs/api/v1/hybrid-connectors/list-hybrid-connectors) |
| `meetings` | HTTP | `GET /meetings` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `title`, `meetingType`, `state`, `start`, `end`, `hostEmail`, `siteUrl`, `webLink`, `password`, `unlockedMeetingJoinSecurity`, `enabledJoinBeforeHost`, `joinBeforeHostMinutes`, `enableAutomaticLock`, `automaticLockMinutes`, `publicMeeting` | [Official documentation](https://developer.webex.com/meeting/docs/api/v1/meetings/list-meetings) |
| `meeting-preferences` | HTTP | `GET /meetingPreferences` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `personalMeetingRoom.enabledAutoLock`, `personalMeetingRoom.autoLockMinutes`, `personalMeetingRoom.notifyHost`, `personalMeetingRoom.supportCoHost`, `personalMeetingRoom.supportAnyoneAsCoHost`, `personalMeetingRoom.allowFirstUserToBeCoHost`, `personalMeetingRoom.allowAuthenticatedDevices`, `audio.defaultAudioType`, `audio.enabledGlobalCallIn`, `audio.enabledTollFree`, `audio.enabledAutoConnection`, `schedulingOptions.enabledJoinBeforeHost`, `schedulingOptions.joinBeforeHostMinutes`, `schedulingOptions.enabledAutoShareRecording`, `schedulingOptions.enabledWebexAssistantByDefault`, `sites.siteUrl`, `sites.default` | [Official documentation](https://developer.webex.com/meeting/docs/api/v1/meeting-preferences/get-meeting-preference-details) |
| `meeting-sites` | HTTP | `GET /meetingPreferences/sites` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `siteUrl`, `default` | [Official documentation](https://developer.webex.com/meeting/docs/api/v1/meeting-preferences/get-site-list) |
| `meeting-common-settings` | HTTP | `GET /admin/meeting/config/commonSettings` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `siteUrl`, `securityOptions.joinBeforeHost`, `securityOptions.audioBeforeHost`, `securityOptions.firstAttendeeAsPresenter`, `securityOptions.unlistAllMeetings`, `securityOptions.requireLoginBeforeAccess`, `securityOptions.allowMobileScreenCapture`, `securityOptions.requireStrongPassword`, `securityOptions.passwordCriteria.mixedCase`, `securityOptions.passwordCriteria.minLength`, `securityOptions.passwordCriteria.minNumeric`, `securityOptions.passwordCriteria.minAlpha`, `securityOptions.passwordCriteria.minSpecial`, `securityOptions.passwordCriteria.disallowDynamicWebText`, `securityOptions.passwordCriteria.disallowList`, `securityOptions.passwordCriteria.disallowValues` | [Official documentation](https://developer.webex.com/meeting/docs/api/v1/site/get-meeting-common-settings-configuration) |
| `devices` | HTTP | `GET /devices` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `displayName`, `workspaceId`, `personId`, `orgId`, `product`, `type`, `software`, `upgradeChannel`, `connectionStatus`, `managedBy`, `created` | [Official documentation](https://developer.webex.com/calling/docs/api/v1/devices/list-devices) |
| `workspaces` | HTTP | `GET /workspaces` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `displayName`, `type`, `orgId`, `created` | [Official documentation](https://developer.webex.com/calling/docs/api/v1/workspaces/list-workspaces) |
| `rooms` | HTTP | `GET /rooms` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `title`, `type`, `isLocked`, `isPublic`, `classificationId`, `teamId`, `ownerId`, `created`, `lastActivity` | [Official documentation](https://developer.webex.com/messaging/docs/api/v1/rooms/list-rooms) |
| `webhooks` | HTTP | `GET /webhooks` | https://webexapis.com/v1 | N/A | read | Fields name the normalized record written under core_data after allowlist projection and secret scrubbing. | `id`, `name`, `targetUrl`, `resource`, `event`, `secret`, `status`, `ownedBy`, `created` | [Official documentation](https://developer.webex.com/meeting/docs/api/v1/webhooks/list-webhooks) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `token-refresh` | client | The configured Webex API origin. | yes |
| `token-refresh` | headers | Content-Type: application/x-www-form-urlencoded; Accept: application/json | yes |
| `token-refresh` | response | JSON object containing a nonempty access_token string. | yes |
| `token-refresh` | form-body:grant_type | refresh_token | yes |
| `token-refresh` | form-body:client_id | Configured client identifier | yes |
| `token-refresh` | form-body:client_secret | Configured client secret | yes |
| `token-refresh` | form-body:refresh_token | Configured refresh token | yes |
| `me` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `me` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `me` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `organizations` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `organizations` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `organizations` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `organization` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `organization` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `organization` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `organization` | path:orgId | URL-encoded organization identifier | yes |
| `people` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `people` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `people` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `people` | query:orgId | Configured organization identifier; Only when org_id is configured. | no |
| `people` | query:max | 100; Sent on every page for this surface. | no |
| `roles` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `roles` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `roles` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `licenses` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `licenses` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `licenses` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `licenses` | query:orgId | Configured organization identifier; Only when org_id is configured. | no |
| `events` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `events` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `events` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `events` | query:max | 100; Sent on every page for this surface. | no |
| `admin-audit-events` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `admin-audit-events` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `admin-audit-events` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `admin-audit-events` | query:orgId | Resolved organization identifier | yes |
| `admin-audit-events` | query:from | Current time minus 30 days, ISO 8601 | yes |
| `admin-audit-events` | query:to | Current time, ISO 8601 | yes |
| `admin-audit-events` | query:max | 200; Sent on every page for this surface. | no |
| `admin-recordings` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `admin-recordings` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `admin-recordings` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `admin-recordings` | query:max | 100; Sent on every page for this surface. | no |
| `guest-count` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `guest-count` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `guest-count` | response | A bare decimal count in text/plain or a JSON object containing one numeric value. | yes |
| `hybrid-clusters` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `hybrid-clusters` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `hybrid-clusters` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `hybrid-clusters` | query:orgId | Configured organization identifier; Only when org_id is configured. | no |
| `hybrid-connectors` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `hybrid-connectors` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `hybrid-connectors` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `hybrid-connectors` | query:orgId | Configured organization identifier; Only when org_id is configured. | no |
| `meetings` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `meetings` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `meetings` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `meetings` | query:max | 100; Sent on every page for this surface. | no |
| `meeting-preferences` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `meeting-preferences` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `meeting-preferences` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `meeting-sites` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `meeting-sites` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `meeting-sites` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `meeting-common-settings` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `meeting-common-settings` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `meeting-common-settings` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `meeting-common-settings` | query:siteUrl | One site URL from meeting-sites; Once per listed site; omit only for the preferred-site fallback. | no |
| `devices` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `devices` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `devices` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `devices` | query:orgId | Configured organization identifier; Only when org_id is configured. | no |
| `devices` | query:max | 100; Sent on every page for this surface. | no |
| `workspaces` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `workspaces` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `workspaces` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `workspaces` | query:orgId | Configured organization identifier; Only when org_id is configured. | no |
| `workspaces` | query:max | 100; Sent on every page for this surface. | no |
| `rooms` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `rooms` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `rooms` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `rooms` | query:max | 100; Sent on every page for this surface. | no |
| `webhooks` | client | The configured Webex API origin; there is no regional client selection. | yes |
| `webhooks` | headers | Accept: application/json; Authorization: Bearer <access token> | yes |
| `webhooks` | response | JSON object; list operations read the items array and also accept a top-level array. | yes |
| `webhooks` | query:max | 100; Sent on every page for this surface. | no |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `organizations`, `people`, `roles`, `licenses`, `events`, `admin-audit-events`, `admin-recordings`, `hybrid-clusters`, `hybrid-connectors`, `meetings`, `meeting-sites`, `devices`, `workspaces`, `rooms`, `webhooks` | `Link header rel=next` | service default | caller limit | 1000 | The service does not provide a dependable total for these walks; report items seen and whether exhaustion was proven. | No next link; Configured item cap; Page cap; Repeated next link; Empty page with next link; Rejected cross-origin or userinfo-bearing next link |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Webex REST API | Not published | `Retry-After` | 429 | Retry at most 2 times, cap each Retry-After delay at 30000 milliseconds, then report the surface unreadable. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | SSO enforcement | WEBEX-ID-01 | Export Control Hub Organization Settings > Authentication showing SSO enabled; the Organizations read exposes only id, displayName, and created. |
| 2 | Admin MFA | WEBEX-ID-02 | Export Control Hub Organization Settings > Authentication and the administrator list with MFA status for every administrator; the only documented mfaEnabled shape is on a write request and People has no MFA field. |
| 3 | Compliance officer role | WEBEX-ID-03 | People or roles is unreadable, or GET /people returns zero people; export the Control Hub Users list filtered to Compliance Officer. |
| 4 | External communications | WEBEX-COLLAB-01 | Export Control Hub Messaging external communication allow-list settings; no documented read endpoint exposes the policy. |
| 5 | File sharing restrictions | WEBEX-COLLAB-02 | Export Control Hub file-sharing controls and DLP or CASB integration evidence; Events is supporting inventory only and exposes no policy-state field. |
| 6 | Recording storage control | WEBEX-COLLAB-03 | Export Control Hub recording and messaging retention and storage settings; the admin recordings read exposes recordings but no retention or storage-location policy. |
| 7 | Recording retention | WEBEX-COLLAB-03 | Export Control Hub recording and messaging retention and storage settings; the admin recordings read exposes recordings but no retention or storage-location policy. |
| 8 | End-to-end meeting encryption | WEBEX-MTG-01 | Export the Control Hub meeting session type showing end-to-end encryption and the calling security configuration showing SRTP; the documented reads expose neither setting. |
| 9 | Meeting lobby controls | WEBEX-MTG-02 | No site common settings are readable or any site omits joinBeforeHost; collect each site's Control Hub Common Settings > Security page. |
| 10 | Meeting password required | WEBEX-MTG-06 | No site common settings are readable or any site omits requireStrongPassword; collect each site's Control Hub Common Settings > Security page. |
| 11 | eDiscovery and legal hold | WEBEX-COLLAB-08 | Export Control Hub eDiscovery and legal-hold configuration; the public compliance guide exposes no read endpoint for configuration and events older than 90 days require Pro Pack. |
| 12 | Data retention policy | WEBEX-COLLAB-03 | Export Control Hub recording and messaging retention and storage settings; the admin recordings read exposes recordings but no retention or storage-location policy. |
| 13 | Guest access restrictions | WEBEX-ID-07, WEBEX-MTG-03 | GET /people is unreadable or returns zero people; export the Control Hub guest user list. No site common settings are readable or any site omits requireLoginBeforeAccess; collect each site's Control Hub Common Settings > Security page. |
| 14 | Space classification | WEBEX-COLLAB-04 | Rooms is unreadable or empty; export Control Hub space classification settings. |
| 15 | Hybrid cluster health | WEBEX-MTG-04 | Either inventory is unreadable, or both are empty and deployment applicability must be confirmed in Control Hub. |
| 16 | Hybrid connector status | WEBEX-MTG-04 | Either inventory is unreadable, or both are empty and deployment applicability must be confirmed in Control Hub. |
| 17 | Device firmware currency | WEBEX-MTG-05 | Compare inventoried software and upgrade channels with Cisco RoomOS lifecycle guidance and export the Control Hub device activation policy; documented device reads expose no end-of-life or blocking-policy field. |
| 18 | Unmanaged device blocking | WEBEX-MTG-05 | Compare inventoried software and upgrade channels with Cisco RoomOS lifecycle guidance and export the Control Hub device activation policy; documented device reads expose no end-of-life or blocking-policy field. |
| 19 | Bot management | WEBEX-ID-05, WEBEX-ID-06 | GET /people is unreadable or returns zero people; export Control Hub Apps > Bots. Export Control Hub Management > Apps bot management and reconcile it with WEBEX-ID-05; no documented read field exposes bot approval state. |
| 20 | Webhook transport and signing | WEBEX-COLLAB-05 | Webhooks is unreadable or empty; collect webhook inventories from every integration owner. |
| 21 | Messaging data loss prevention | WEBEX-COLLAB-02 | Export Control Hub file-sharing controls and DLP or CASB integration evidence; Events is supporting inventory only and exposes no policy-state field. |
| 22 | Calling encryption | WEBEX-MTG-01 | Export the Control Hub meeting session type showing end-to-end encryption and the calling security configuration showing SRTP; the documented reads expose neither setting. |
| 23 | Virtual background policy | WEBEX-MTG-07 | Export the Control Hub meeting settings page for virtual backgrounds; no field is exposed by meeting preferences, common settings, or session types. |
| 24 | License utilization | WEBEX-COLLAB-06 | Licenses is unreadable, empty, or has totalUnits equal to zero; export the Control Hub subscriptions and usage report. |
| 25 | Admin activity audit | WEBEX-ID-04, WEBEX-COLLAB-07 | People or roles is unreadable, or GET /people returns zero people; export the Control Hub administrator list. Organization context is unavailable or admin audit events is unreadable; export the Control Hub admin audit log. |

### Finding criteria

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass | Warn | Fail | Manual |
|---|---|---|---|---|---|---|---|---|
| `WEBEX-ID-01` | critical | `webex_assess_identity` | `organization` | `org_id`, `organization`, `citation` | No automatic pass is emitted. | No automatic warn is emitted unless supporting inventory is partial. | No automatic fail is emitted. | Export Control Hub Organization Settings > Authentication showing SSO enabled; the Organizations read exposes only id, displayName, and created. |
| `WEBEX-ID-02` | critical | `webex_assess_identity` | `people`, `roles` | `admin_users`, `admin_count`, `people_seen`, `people_truncated`, `denied_endpoint`, `inventory_status`, `citation`, `people_citation`, `roles_citation`, `token_type` | No automatic pass is emitted. | No automatic warn is emitted unless supporting inventory is partial. | No automatic fail is emitted. | Export Control Hub Organization Settings > Authentication and the administrator list with MFA status for every administrator; the only documented mfaEnabled shape is on a write request and People has no MFA field. |
| `WEBEX-ID-03` | high | `webex_assess_identity` | `people`, `roles` | `citation`, `token_type`, `people_seen`, `roles_seen`, `compliance_officers`, `compliance_officer_count`, `people_truncated` | People and roles are readable, the people population is nonempty and complete, and at least one human has a role whose name contains 'Compliance Officer' case-insensitively. | At least one Compliance Officer is visible, but the people listing is truncated. | People and roles are readable and the nonempty people population contains no Compliance Officer. | People or roles is unreadable, or GET /people returns zero people; export the Control Hub Users list filtered to Compliance Officer. |
| `WEBEX-ID-04` | medium | `webex_assess_identity` | `people`, `roles` | `token_type`, `people_seen`, `people_truncated`, `admin_users`, `admin_count`, `max_admins` | People and roles are readable and complete, at least one human has a role containing 'Administrator', and the administrator count is at most max_admins. | No administrator is visible, the people list is truncated, or administrator count exceeds max_admins; max_admins defaults to 10. | No fail verdict is emitted; concentration above the threshold requires review rather than proving noncompliance. | People or roles is unreadable, or GET /people returns zero people; export the Control Hub administrator list. |
| `WEBEX-ID-05` | medium | `webex_assess_identity` | `people` | `citation`, `token_type`, `people_seen`, `people_truncated`, `bots`, `bot_count` | GET /people is readable, nonempty and complete; inventory records every Person.type equal to 'bot'. | GET /people is readable and nonempty but truncated. | No fail verdict is emitted because bot presence is an inventory for comparison with the approved register. | GET /people is unreadable or returns zero people; export Control Hub Apps > Bots. |
| `WEBEX-ID-06` | medium | `webex_assess_identity` | `people` | `bot_count`, `people_status`, `citation` | No automatic pass is emitted. | No automatic warn is emitted unless supporting inventory is partial. | No automatic fail is emitted. | Export Control Hub Management > Apps bot management and reconcile it with WEBEX-ID-05; no documented read field exposes bot approval state. |
| `WEBEX-ID-07` | medium | `webex_assess_identity` | `people`, `guest-count` | `guests`, `guest_count_people`, `guest_count_api`, `guest_count_api_error`, `guest_count_api_status`, `people_seen`, `people_truncated`, `citation`, `guest_count_citation`, `token_type` | GET /people is readable, nonempty and complete, GET /guests/count is readable, and Person.type='appuser' records are inventoried for reconciliation with WEBEX-MTG-03. | The people listing is truncated or GET /guests/count is unreadable, so the otherwise complete inventory cannot pass. | No fail verdict is emitted because the inventory does not itself settle guest-access policy. | GET /people is unreadable or returns zero people; export the Control Hub guest user list. |
| `WEBEX-COLLAB-01` | high | `webex_assess_collaboration_governance` | `organization` | `org_id`, `citation` | No automatic pass is emitted. | No automatic warn is emitted unless supporting inventory is partial. | No automatic fail is emitted. | Export Control Hub Messaging external communication allow-list settings; no documented read endpoint exposes the policy. |
| `WEBEX-COLLAB-02` | high | `webex_assess_collaboration_governance` | `events` | `events_readable`, `events_seen`, `events_status`, `citation` | No automatic pass is emitted. | No automatic warn is emitted unless supporting inventory is partial. | No automatic fail is emitted. | Export Control Hub file-sharing controls and DLP or CASB integration evidence; Events is supporting inventory only and exposes no policy-state field. |
| `WEBEX-COLLAB-03` | medium | `webex_assess_collaboration_governance` | `admin-recordings` | `citation`, `token_type`, `recordings_seen`, `deleted_recordings`, `recordings_truncated` | No automatic pass is emitted. | No automatic warn is emitted unless supporting inventory is partial. | No automatic fail is emitted. | Export Control Hub recording and messaging retention and storage settings; the admin recordings read exposes recordings but no retention or storage-location policy. |
| `WEBEX-COLLAB-04` | medium | `webex_assess_collaboration_governance` | `rooms`, `me` | `citation`, `rooms_seen`, `rooms_truncated`, `rooms_without_classification`, `rooms_without_classification_count`, `token_type`, `token_probe_status` | Rooms is readable and nonempty, every visible room has classificationId, the listing is complete, and token type is verified as non-bot. | Every visible room has classificationId but the listing is truncated, the token is a bot, or GET /people/me cannot prove token type. | At least one visible room lacks classificationId. | Rooms is unreadable or empty; export Control Hub space classification settings. |
| `WEBEX-COLLAB-05` | high | `webex_assess_collaboration_governance` | `webhooks`, `me` | `citation`, `webhooks_seen`, `webhooks_truncated`, `inactive_webhooks`, `insecure_webhooks`, `insecure_webhooks_count`, `token_type`, `token_probe_status` | Webhooks is readable and nonempty, every visible webhook targetUrl starts with 'https://' and has a nonempty secret, the list is complete, and token type is verified as non-bot. | Every visible webhook is secure but the list is truncated, the token is a bot, or token type cannot be verified. | At least one visible webhook lacks an HTTPS targetUrl or a nonempty signing secret. | Webhooks is unreadable or empty; collect webhook inventories from every integration owner. |
| `WEBEX-COLLAB-06` | low | `webex_assess_collaboration_governance` | `licenses` | `citation`, `token_type`, `licenses_seen`, `licenses_truncated`, `total_units`, `consumed_units`, `unassigned_units` | Licenses is readable and complete, totalUnits is positive, and unassigned units divided by total units is at most 0.20. | The unassigned ratio exceeds 0.20 or the license listing is truncated. | No fail verdict is emitted; excess unassigned capacity is a review condition. | Licenses is unreadable, empty, or has totalUnits equal to zero; export the Control Hub subscriptions and usage report. |
| `WEBEX-COLLAB-07` | high | `webex_assess_collaboration_governance` | `admin-audit-events` | `citation`, `token_type`, `events_seen`, `events_with_dates`, `undated_events`, `window_days`, `events_truncated` | Admin audit events is readable, nonempty and complete for the last 30 days. | The read returns zero events or is truncated; confirm the log is populated and reviewed. | No fail verdict is emitted because an empty window needs reviewer confirmation. | Organization context is unavailable or admin audit events is unreadable; export the Control Hub admin audit log. |
| `WEBEX-COLLAB-08` | high | `webex_assess_collaboration_governance` | `events` | `events_readable`, `events_seen`, `events_truncated`, `events_status`, `citation` | No automatic pass is emitted. | No automatic warn is emitted unless supporting inventory is partial. | No automatic fail is emitted. | Export Control Hub eDiscovery and legal-hold configuration; the public compliance guide exposes no read endpoint for configuration and events older than 90 days require Pro Pack. |
| `WEBEX-MTG-01` | high | `webex_assess_meeting_hybrid_security` | `meeting-preferences`, `meeting-common-settings` | `meeting_preferences_readable`, `sites_seen`, `meeting_sites_status`, `citation` | No automatic pass is emitted. | No automatic warn is emitted unless supporting inventory is partial. | No automatic fail is emitted. | Export the Control Hub meeting session type showing end-to-end encryption and the calling security configuration showing SRTP; the documented reads expose neither setting. |
| `WEBEX-MTG-02` | high | `webex_assess_meeting_hybrid_security` | `meeting-sites`, `meeting-common-settings`, `meetings`, `meeting-preferences`, `me` | `sites`, `denied_sites`, `site_coverage_complete`, `site_list_status`, `citation`, `token_type`, `meetings_seen`, `meetings_truncated`, `meetings_status`, `sampled_allow_join_without_lobby`, `sampled_without_password`, `personal_meeting_room_auto_lock`, `meeting_preferences_status`, `token_probe_status`, `meetings_citation` | Every readable site reports joinBeforeHost=false, audioBeforeHost=false and unlistAllMeetings=true; the site list and all sites are complete; meetings, meeting preferences and token type are readable. | joinBeforeHost=false but audioBeforeHost is absent or unlistAllMeetings is not true, or otherwise-passing evidence has partial site or secondary coverage. | Any site reports joinBeforeHost=true or audioBeforeHost=true. | No site common settings are readable or any site omits joinBeforeHost; collect each site's Control Hub Common Settings > Security page. |
| `WEBEX-MTG-03` | medium | `webex_assess_meeting_hybrid_security` | `meeting-sites`, `meeting-common-settings`, `me` | `sites`, `denied_sites`, `site_coverage_complete`, `site_list_status`, `citation`, `token_type`, `token_probe_status` | Every readable site reports requireLoginBeforeAccess=true, site coverage is complete, and token type is readable. | All readable sites require login but site coverage or token-type evidence is partial. | Any readable site reports requireLoginBeforeAccess=false. | No site common settings are readable or any site omits requireLoginBeforeAccess; collect each site's Control Hub Common Settings > Security page. |
| `WEBEX-MTG-04` | high | `webex_assess_meeting_hybrid_security` | `hybrid-clusters`, `hybrid-connectors` | `citation`, `token_type`, `clusters_seen`, `connectors_seen`, `connector_versions`, `undated_connectors`, `non_operational`, `non_operational_count` | Both inventories are readable, at least one connector exists, every connector status equals 'operational', and neither listing is truncated. | Every connector is operational but either listing is truncated. | Clusters exist with no connectors, or any connector status is not 'operational'. | Either inventory is unreadable, or both are empty and deployment applicability must be confirmed in Control Hub. |
| `WEBEX-MTG-05` | high | `webex_assess_meeting_hybrid_security` | `devices`, `workspaces` | `citation`, `token_type`, `devices_seen`, `devices_truncated`, `personal_mode_devices`, `software_versions`, `software_version_count`, `upgrade_channels`, `upgrade_channel_count`, `devices_without_upgrade_channel`, `managed_by`, `workspaces_seen`, `workspaces_status` | No automatic pass is emitted. | No automatic warn is emitted unless supporting inventory is partial. | No automatic fail is emitted. | Compare inventoried software and upgrade channels with Cisco RoomOS lifecycle guidance and export the Control Hub device activation policy; documented device reads expose no end-of-life or blocking-policy field. |
| `WEBEX-MTG-06` | high | `webex_assess_meeting_hybrid_security` | `meeting-sites`, `meeting-common-settings`, `meetings`, `meeting-preferences`, `me` | `sites`, `denied_sites`, `site_coverage_complete`, `site_list_status`, `citation`, `token_type`, `meetings_seen`, `meetings_truncated`, `meetings_status`, `sampled_allow_join_without_lobby`, `sampled_without_password`, `personal_meeting_room_auto_lock`, `meeting_preferences_status`, `token_probe_status`, `meetings_citation` | Every readable site reports requireStrongPassword=true and passwordCriteria.minLength at least 8; site coverage and all secondary evidence are complete. | Strong passwords are required but minLength is absent or below 8, or otherwise-passing evidence has partial site or secondary coverage. | Any readable site reports requireStrongPassword=false. | No site common settings are readable or any site omits requireStrongPassword; collect each site's Control Hub Common Settings > Security page. |
| `WEBEX-MTG-07` | low | `webex_assess_meeting_hybrid_security` | `meeting-common-settings` | `citation` | No automatic pass is emitted. | No automatic warn is emitted unless supporting inventory is partial. | No automatic fail is emitted. | Export the Control Hub meeting settings page for virtual backgrounds; no field is exposed by meeting preferences, common settings, or session types. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `WEBEX-ID-03` | `roleNameContains` | compliance officer |
| `WEBEX-ID-04` | `administratorRoleContains` | administrator |
| `WEBEX-ID-04` | `defaultMaxAdmins` | 10 |
| `WEBEX-ID-05` | `botPersonType` | bot |
| `WEBEX-ID-07` | `guestPersonType` | appuser |
| `WEBEX-COLLAB-05` | `secureTargetPrefix` | https:// |
| `WEBEX-COLLAB-06` | `maximumUnassignedRatio` | 0.2 |
| `WEBEX-COLLAB-07` | `windowDays` | 30 |
| `WEBEX-MTG-02` | `joinBeforeHost` | false |
| `WEBEX-MTG-02` | `audioBeforeHost` | false |
| `WEBEX-MTG-02` | `unlistAllMeetings` | true |
| `WEBEX-MTG-03` | `requireLoginBeforeAccess` | true |
| `WEBEX-MTG-04` | `operationalStatus` | operational |
| `WEBEX-MTG-06` | `minimumLength` | 8 |

### Criterion examples

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `WEBEX-ID-01` | compliant | No automatic pass is emitted. | manual | The setting has no documented read interface, so compliant evidence remains manual. |
| `WEBEX-ID-01` | noncompliant | No automatic fail is emitted. | manual | The noncompliant predicate emits manual. |
| `WEBEX-ID-01` | partial | No automatic warn is emitted unless supporting inventory is partial. | manual | The partial case emits manual. |
| `WEBEX-ID-01` | unreadable | Export Control Hub Organization Settings > Authentication showing SSO enabled; the Organizations read exposes only id, displayName, and created. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-ID-02` | compliant | No automatic pass is emitted. | manual | The setting has no documented read interface, so compliant evidence remains manual. |
| `WEBEX-ID-02` | noncompliant | No automatic fail is emitted. | manual | The noncompliant predicate emits manual. |
| `WEBEX-ID-02` | partial | No automatic warn is emitted unless supporting inventory is partial. | manual | The partial case emits manual. |
| `WEBEX-ID-02` | unreadable | Export Control Hub Organization Settings > Authentication and the administrator list with MFA status for every administrator; the only documented mfaEnabled shape is on a write request and People has no MFA field. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-ID-03` | compliant | People and roles are readable, the people population is nonempty and complete, and at least one human has a role whose name contains 'Compliance Officer' case-insensitively. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-ID-03` | noncompliant | People and roles are readable and the nonempty people population contains no Compliance Officer. | fail | The noncompliant predicate emits fail. |
| `WEBEX-ID-03` | partial | At least one Compliance Officer is visible, but the people listing is truncated. | warn | The partial case emits warn. |
| `WEBEX-ID-03` | unreadable | People or roles is unreadable, or GET /people returns zero people; export the Control Hub Users list filtered to Compliance Officer. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-ID-04` | compliant | People and roles are readable and complete, at least one human has a role containing 'Administrator', and the administrator count is at most max_admins. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-ID-04` | noncompliant | No fail verdict is emitted; concentration above the threshold requires review rather than proving noncompliance. | warn | The noncompliant predicate emits warn. |
| `WEBEX-ID-04` | partial | No administrator is visible, the people list is truncated, or administrator count exceeds max_admins; max_admins defaults to 10. | warn | The partial case emits warn. |
| `WEBEX-ID-04` | unreadable | People or roles is unreadable, or GET /people returns zero people; export the Control Hub administrator list. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-ID-05` | compliant | GET /people is readable, nonempty and complete; inventory records every Person.type equal to 'bot'. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-ID-05` | noncompliant | No fail verdict is emitted because bot presence is an inventory for comparison with the approved register. | warn | The noncompliant predicate emits warn. |
| `WEBEX-ID-05` | partial | GET /people is readable and nonempty but truncated. | warn | The partial case emits warn. |
| `WEBEX-ID-05` | unreadable | GET /people is unreadable or returns zero people; export Control Hub Apps > Bots. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-ID-06` | compliant | No automatic pass is emitted. | manual | The setting has no documented read interface, so compliant evidence remains manual. |
| `WEBEX-ID-06` | noncompliant | No automatic fail is emitted. | manual | The noncompliant predicate emits manual. |
| `WEBEX-ID-06` | partial | No automatic warn is emitted unless supporting inventory is partial. | manual | The partial case emits manual. |
| `WEBEX-ID-06` | unreadable | Export Control Hub Management > Apps bot management and reconcile it with WEBEX-ID-05; no documented read field exposes bot approval state. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-ID-07` | compliant | GET /people is readable, nonempty and complete, GET /guests/count is readable, and Person.type='appuser' records are inventoried for reconciliation with WEBEX-MTG-03. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-ID-07` | noncompliant | No fail verdict is emitted because the inventory does not itself settle guest-access policy. | warn | The noncompliant predicate emits warn. |
| `WEBEX-ID-07` | partial | The people listing is truncated or GET /guests/count is unreadable, so the otherwise complete inventory cannot pass. | warn | The partial case emits warn. |
| `WEBEX-ID-07` | unreadable | GET /people is unreadable or returns zero people; export the Control Hub guest user list. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-COLLAB-01` | compliant | No automatic pass is emitted. | manual | The setting has no documented read interface, so compliant evidence remains manual. |
| `WEBEX-COLLAB-01` | noncompliant | No automatic fail is emitted. | manual | The noncompliant predicate emits manual. |
| `WEBEX-COLLAB-01` | partial | No automatic warn is emitted unless supporting inventory is partial. | manual | The partial case emits manual. |
| `WEBEX-COLLAB-01` | unreadable | Export Control Hub Messaging external communication allow-list settings; no documented read endpoint exposes the policy. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-COLLAB-02` | compliant | No automatic pass is emitted. | manual | The setting has no documented read interface, so compliant evidence remains manual. |
| `WEBEX-COLLAB-02` | noncompliant | No automatic fail is emitted. | manual | The noncompliant predicate emits manual. |
| `WEBEX-COLLAB-02` | partial | No automatic warn is emitted unless supporting inventory is partial. | manual | The partial case emits manual. |
| `WEBEX-COLLAB-02` | unreadable | Export Control Hub file-sharing controls and DLP or CASB integration evidence; Events is supporting inventory only and exposes no policy-state field. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-COLLAB-03` | compliant | No automatic pass is emitted. | manual | The setting has no documented read interface, so compliant evidence remains manual. |
| `WEBEX-COLLAB-03` | noncompliant | No automatic fail is emitted. | manual | The noncompliant predicate emits manual. |
| `WEBEX-COLLAB-03` | partial | No automatic warn is emitted unless supporting inventory is partial. | manual | The partial case emits manual. |
| `WEBEX-COLLAB-03` | unreadable | Export Control Hub recording and messaging retention and storage settings; the admin recordings read exposes recordings but no retention or storage-location policy. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-COLLAB-04` | compliant | Rooms is readable and nonempty, every visible room has classificationId, the listing is complete, and token type is verified as non-bot. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-COLLAB-04` | noncompliant | At least one visible room lacks classificationId. | fail | The noncompliant predicate emits fail. |
| `WEBEX-COLLAB-04` | partial | Every visible room has classificationId but the listing is truncated, the token is a bot, or GET /people/me cannot prove token type. | warn | The partial case emits warn. |
| `WEBEX-COLLAB-04` | unreadable | Rooms is unreadable or empty; export Control Hub space classification settings. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-COLLAB-05` | compliant | Webhooks is readable and nonempty, every visible webhook targetUrl starts with 'https://' and has a nonempty secret, the list is complete, and token type is verified as non-bot. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-COLLAB-05` | noncompliant | At least one visible webhook lacks an HTTPS targetUrl or a nonempty signing secret. | fail | The noncompliant predicate emits fail. |
| `WEBEX-COLLAB-05` | partial | Every visible webhook is secure but the list is truncated, the token is a bot, or token type cannot be verified. | warn | The partial case emits warn. |
| `WEBEX-COLLAB-05` | unreadable | Webhooks is unreadable or empty; collect webhook inventories from every integration owner. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-COLLAB-06` | compliant | Licenses is readable and complete, totalUnits is positive, and unassigned units divided by total units is at most 0.20. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-COLLAB-06` | noncompliant | No fail verdict is emitted; excess unassigned capacity is a review condition. | warn | The noncompliant predicate emits warn. |
| `WEBEX-COLLAB-06` | partial | The unassigned ratio exceeds 0.20 or the license listing is truncated. | warn | The partial case emits warn. |
| `WEBEX-COLLAB-06` | unreadable | Licenses is unreadable, empty, or has totalUnits equal to zero; export the Control Hub subscriptions and usage report. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-COLLAB-07` | compliant | Admin audit events is readable, nonempty and complete for the last 30 days. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-COLLAB-07` | noncompliant | No fail verdict is emitted because an empty window needs reviewer confirmation. | warn | The noncompliant predicate emits warn. |
| `WEBEX-COLLAB-07` | partial | The read returns zero events or is truncated; confirm the log is populated and reviewed. | warn | The partial case emits warn. |
| `WEBEX-COLLAB-07` | unreadable | Organization context is unavailable or admin audit events is unreadable; export the Control Hub admin audit log. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-COLLAB-08` | compliant | No automatic pass is emitted. | manual | The setting has no documented read interface, so compliant evidence remains manual. |
| `WEBEX-COLLAB-08` | noncompliant | No automatic fail is emitted. | manual | The noncompliant predicate emits manual. |
| `WEBEX-COLLAB-08` | partial | No automatic warn is emitted unless supporting inventory is partial. | manual | The partial case emits manual. |
| `WEBEX-COLLAB-08` | unreadable | Export Control Hub eDiscovery and legal-hold configuration; the public compliance guide exposes no read endpoint for configuration and events older than 90 days require Pro Pack. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-MTG-01` | compliant | No automatic pass is emitted. | manual | The setting has no documented read interface, so compliant evidence remains manual. |
| `WEBEX-MTG-01` | noncompliant | No automatic fail is emitted. | manual | The noncompliant predicate emits manual. |
| `WEBEX-MTG-01` | partial | No automatic warn is emitted unless supporting inventory is partial. | manual | The partial case emits manual. |
| `WEBEX-MTG-01` | unreadable | Export the Control Hub meeting session type showing end-to-end encryption and the calling security configuration showing SRTP; the documented reads expose neither setting. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-MTG-02` | compliant | Every readable site reports joinBeforeHost=false, audioBeforeHost=false and unlistAllMeetings=true; the site list and all sites are complete; meetings, meeting preferences and token type are readable. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-MTG-02` | noncompliant | Any site reports joinBeforeHost=true or audioBeforeHost=true. | fail | The noncompliant predicate emits fail. |
| `WEBEX-MTG-02` | partial | joinBeforeHost=false but audioBeforeHost is absent or unlistAllMeetings is not true, or otherwise-passing evidence has partial site or secondary coverage. | warn | The partial case emits warn. |
| `WEBEX-MTG-02` | unreadable | No site common settings are readable or any site omits joinBeforeHost; collect each site's Control Hub Common Settings > Security page. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-MTG-03` | compliant | Every readable site reports requireLoginBeforeAccess=true, site coverage is complete, and token type is readable. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-MTG-03` | noncompliant | Any readable site reports requireLoginBeforeAccess=false. | fail | The noncompliant predicate emits fail. |
| `WEBEX-MTG-03` | partial | All readable sites require login but site coverage or token-type evidence is partial. | warn | The partial case emits warn. |
| `WEBEX-MTG-03` | unreadable | No site common settings are readable or any site omits requireLoginBeforeAccess; collect each site's Control Hub Common Settings > Security page. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-MTG-04` | compliant | Both inventories are readable, at least one connector exists, every connector status equals 'operational', and neither listing is truncated. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-MTG-04` | noncompliant | Clusters exist with no connectors, or any connector status is not 'operational'. | fail | The noncompliant predicate emits fail. |
| `WEBEX-MTG-04` | partial | Every connector is operational but either listing is truncated. | warn | The partial case emits warn. |
| `WEBEX-MTG-04` | unreadable | Either inventory is unreadable, or both are empty and deployment applicability must be confirmed in Control Hub. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-MTG-05` | compliant | No automatic pass is emitted. | manual | The setting has no documented read interface, so compliant evidence remains manual. |
| `WEBEX-MTG-05` | noncompliant | No automatic fail is emitted. | manual | The noncompliant predicate emits manual. |
| `WEBEX-MTG-05` | partial | No automatic warn is emitted unless supporting inventory is partial. | manual | The partial case emits manual. |
| `WEBEX-MTG-05` | unreadable | Compare inventoried software and upgrade channels with Cisco RoomOS lifecycle guidance and export the Control Hub device activation policy; documented device reads expose no end-of-life or blocking-policy field. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-MTG-06` | compliant | Every readable site reports requireStrongPassword=true and passwordCriteria.minLength at least 8; site coverage and all secondary evidence are complete. | pass | Complete evidence satisfies the pass predicate. |
| `WEBEX-MTG-06` | noncompliant | Any readable site reports requireStrongPassword=false. | fail | The noncompliant predicate emits fail. |
| `WEBEX-MTG-06` | partial | Strong passwords are required but minLength is absent or below 8, or otherwise-passing evidence has partial site or secondary coverage. | warn | The partial case emits warn. |
| `WEBEX-MTG-06` | unreadable | No site common settings are readable or any site omits requireStrongPassword; collect each site's Control Hub Common Settings > Security page. | manual | The required source cannot be evaluated automatically. |
| `WEBEX-MTG-07` | compliant | No automatic pass is emitted. | manual | The setting has no documented read interface, so compliant evidence remains manual. |
| `WEBEX-MTG-07` | noncompliant | No automatic fail is emitted. | manual | The noncompliant predicate emits manual. |
| `WEBEX-MTG-07` | partial | No automatic warn is emitted unless supporting inventory is partial. | manual | The partial case emits manual. |
| `WEBEX-MTG-07` | unreadable | Export the Control Hub meeting settings page for virtual backgrounds; no field is exposed by meeting preferences, common settings, or session types. | manual | The required source cannot be evaluated automatically. |

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

Shared contract version: 1.1.

Projection stage: Each raw Webex object is allowlist-projected before it enters rawData or core_data. Sensitive keys are then redacted recursively, and every JSON write scrubs the complete value again.

Sensitive fields and values: token, client_secret, refresh_token, password, secret, targetUrl query, downloadUrl query, playbackUrl query, webLink query

Credential formats: Bearer credentials, OAuth client secrets, Refresh tokens, Webhook signing secrets, Meeting passwords, Credential-bearing URL parameters

Reviewed benign exceptions: Documented resource identifiers, Organization identifiers, Site host names

Integration-specific rules:

- A key containing token, secret, password, passcode, hostpin, hostkey, authorization, accesscode, activationcode, or credential is replaced with [REDACTED], except passwordCriteria, requireStrongPassword, and excludePassword policy objects.
- Authorization Bearer and Basic values, credential assignments, cookies, URL user information, URL query and fragment values, and SIP URI pwd/password/pin/passcode/token/secret parameters are replaced.
- Webhook targetUrl, recording downloadUrl/playbackUrl, meeting webLink, and other URL-valued exported strings retain scheme, host and path but lose query, fragment and user information.
- Configured token, client secret and refresh token values are removed from error text before status/length rendering; non-JSON bodies are represented only by media type and byte length.
- Projection retains password and secret fields only so their presence is represented as [REDACTED], never their value.

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

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `QUICK_REFERENCE.md` | markdown | Always | Heading, five bundle-orientation bullets, then a four-step recommended reading order. | UTF-8 with a trailing newline. |
| `metadata.json` | json | Always | Object: generated_at string, org_id string\|null, token_type person\|bot\|appuser\|unknown, source_chain string[], config_file basename\|string\|null. | Scrub recursively, then two-space JSON with insertion-order keys and one trailing newline. |
| `core_data/access.json` | json | Always | WebexAccessCheckResult record described below. | Scrub recursively, then two-space JSON with insertion-order keys and one trailing newline. |
| `core_data/{category}/{surface}.json` | json | For every collected assessment surface | Readable surface: projected object or array using that surface allowlist. Unreadable surface: {error: scrubbed string, status: number\|null}. | Project first, scrub recursively, then two-space JSON with one trailing newline. |
| `analysis/{category}.json` | json | For identity, collaboration-governance and meeting-hybrid-security | Object: title string, category string, summary object, findings WebexFinding[], errors string[]. | Scrub recursively, then two-space JSON with insertion-order keys and one trailing newline. |
| `analysis/findings.json` | json | Always | Array of WebexFinding records in assessment order: identity, collaboration governance, meeting/hybrid. | Scrub recursively, then two-space JSON with one trailing newline. |
| `compliance/executive_summary.md` | markdown | Always | Org and generated timestamp; Result Counts; Highest Priority Findings sorted by status rank and capped at 12; optional Partial Collection Warnings. | UTF-8 Markdown with one trailing newline. |
| `compliance/unified_compliance_matrix.md` | markdown | Always | Finding, spec control, uppercase status, then one column for each of eight frameworks. | UTF-8 Markdown table with one trailing newline. |
| `compliance/{framework}/{report}.md` | markdown | One file for every configured framework | Framework heading, mapped-finding count, then Requirement, Finding, Status, Title, Summary table. | UTF-8 Markdown with one trailing newline. |
| `_errors.log` | text | At least one assessment collection error exists | Deduplicated lines prefixed by assessment category, one error per line. | UTF-8 text with one final newline. |
| `{allocated-bundle-name}.zip` | zip | Always after directory files are complete | Archive contains every bundle file under relative paths with no enclosing bundle directory. | Zip archive paired to the exact allocated directory basename; credentials are scrubbed before files enter the archive. |

### Record schemas

#### WebexFinding

- `id:string`
- `control:number[]`
- `title:string`
- `severity:critical|high|medium|low|info`
- `status:pass|warn|fail|manual`
- `summary:string`
- `evidence?:object`
- `mappings:string[]`
- `frameworks:{fedramp,cmmc,soc2,cis,pci_dss,disa_stig,irap,ismap}:string[]`

#### WebexAssessment

- `title:string`
- `category:string`
- `summary:object`
- `findings:WebexFinding[]`
- `errors:string[]`
- `rawData:surface-name -> projected value or unreadable marker`

#### WebexAccessCheckResult

- `status:healthy|limited`
- `orgId?:string`
- `tokenType:person|bot|appuser|unknown`
- `adminCapable:boolean`
- `surfaces:WebexAccessSurface[]`
- `notes:string[]`
- `recommendedNextStep:string`

#### WebexAccessSurface

- `name:string`
- `endpoint:string`
- `doc:string`
- `status:readable|not_readable|not_configured|manual`
- `count?:number`
- `truncated?:boolean`
- `error?:string`

#### UnreadableSurface

- `error:scrubbed string`
- `status:number|null`

#### IdentitySummary

- `org_id`
- `token_type`
- `people_seen`
- `people_truncated`
- `admin_users`
- `compliance_officers`
- `bots`
- `guests`
- `inventory_status`
- `pass`
- `warn`
- `fail`
- `manual`

#### CollaborationGovernanceSummary

- `org_id`
- `token_type`
- `rooms_seen`
- `rooms_without_classification`
- `webhooks_seen`
- `insecure_webhooks`
- `recordings_seen`
- `admin_audit_events`
- `compliance_events`
- `unassigned_license_units`
- `total_license_units`
- `inventory_status`
- `pass`
- `warn`
- `fail`
- `manual`

#### MeetingHybridSecuritySummary

- `org_id`
- `token_type`
- `sites_evaluated`
- `sites_denied`
- `meetings_seen`
- `hybrid_clusters`
- `hybrid_connectors`
- `non_operational_connectors`
- `devices_seen`
- `workspaces_seen`
- `inventory_status`
- `pass`
- `warn`
- `fail`
- `manual`

JSON formatting: Before every JSON write, recursively scrub the complete value. Serialize with two-space indentation, preserve object insertion order, encode dates as ISO strings through normal JSON conversion, and append exactly one newline.

Overwrite policy: Allocate a new suffixed bundle directory on every rerun; never replace an earlier bundle.

Path safety: Reject traversal, output roots outside the configured parent, symlink roots, and symlinked parent directories.

Archive pairing: Write a zip archive beside the bundle directory using the exact allocated directory name plus .zip.
