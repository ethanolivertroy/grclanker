---
slug: "box-sec-inspector"
name: "Box Security Inspector"
vendor: "Box"
category: "collaboration-and-content"
language: "language-neutral"
status: "generated"
version: "1.0.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# Box Security Inspector

Portable contract for the shipped Box identity, sharing, governance, Shield, and monitoring assessments.

## Purpose

Audit Box enterprise identity, sharing, governance, retention, legal-hold, Shield, and event-monitoring posture with read-only Content API evidence.

## Design guidance

Treat settings marked unused by Box as unenforced, not compliant. Keep marker, offset, and event-stream completion semantics separate. Preserve Admin Console review where individual delegated permissions or policy details are not exposed by the API.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- Enterprise configuration categories can be returned but marked unused by Box; unused security settings never pass and render warning or manual evidence.
- Marker, offset, and event-stream walkers keep distinct completion rules, including repeated markers, empty pages, server totals, item caps, and stream-position exits.
- Five policy areas remain partly or wholly manual because the Box Content API does not expose a decisive read field; the runtime names Admin Console evidence.
- CSV, HTML, SARIF, TUI output, and several policy reads remain absent.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `box_check_access` | Validate read-only Box Content API access across the current principal, enterprise configuration, users, groups, enterprise events, device pins, retention and legal hold policies, Shield barriers and lists, collaboration allowlist, metadata and classification templates, and terms of service. Supports JWT, Client Credentials Grant, and OAuth 2.0 tokens. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `box_assess_identity_access` | Assess Box identity and access controls: SSO enforcement, 2FA for admins and all users, admin role minimization, co-admin scoping, password policy strength, session duration, IP allowlisting, and inactive user detection (spec controls 1, 2, 3, 17, 18, 21, 22, 23, 24). | `BOX-01`, `BOX-02`, `BOX-03`, `BOX-17`, `BOX-18`, `BOX-21`, `BOX-22`, `BOX-23`, `BOX-24` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `box_assess_sharing_collaboration` | Assess Box sharing and collaboration controls: external collaboration restrictions, allowlist audit, shared link defaults, expiration, password requirements, watermarking, app approval, and custom terms of service (spec controls 4, 5, 6, 7, 8, 9, 19, 20). | `BOX-04`, `BOX-05`, `BOX-06`, `BOX-07`, `BOX-08`, `BOX-09`, `BOX-19`, `BOX-20` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `box_assess_data_governance` | Assess Box data governance controls: device trust and pins, classification labels, retention policies, and legal hold policies (spec controls 10, 11, 12, 13). | `BOX-10`, `BOX-11`, `BOX-12`, `BOX-13` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `box_assess_shield_monitoring` | Assess Box Shield and monitoring controls: Shield smart access and threat detection rules, information barriers, enterprise event streaming, and content access monitoring (spec controls 14, 15, 16, 25). | `BOX-14`, `BOX-15`, `BOX-16`, `BOX-25` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `box_export_audit_bundle` | Export a Box audit package covering all 25 spec controls with raw API snapshots (core_data/), normalized findings (analysis/), executive summary, unified compliance matrix, per-framework reports for FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP (compliance/), a quick reference, an error log for partial collection, and a zip archive. | `BOX-01`, `BOX-02`, `BOX-03`, `BOX-04`, `BOX-05`, `BOX-06`, `BOX-07`, `BOX-08`, `BOX-09`, `BOX-10`, `BOX-11`, `BOX-12`, `BOX-13`, `BOX-14`, `BOX-15`, `BOX-16`, `BOX-17`, `BOX-18`, `BOX-19`, `BOX-20`, `BOX-21`, `BOX-22`, `BOX-23`, `BOX-24`, `BOX-25` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `box_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_method` | string | no | Box auth method: jwt, ccg, or oauth. Defaults to BOX_AUTH_METHOD or is inferred from the credentials provided. |
| `jwt_config_path` | string | no | Path to the Box JWT app config JSON downloaded from the Developer Console. Defaults to BOX_JWT_CONFIG_PATH. |
| `jwt_passphrase` | string | no | Passphrase for the encrypted JWT private key when it is not stored in the config file. Defaults to BOX_JWT_PASSPHRASE. |
| `client_id` | string | no | Box app client ID. Defaults to BOX_CLIENT_ID or the JWT config file. |
| `client_secret` | string | no | Box app client secret. Defaults to BOX_CLIENT_SECRET or the JWT config file. |
| `enterprise_id` | string | no | Box enterprise ID. Defaults to BOX_ENTERPRISE_ID, the JWT config file, or the authenticated user's enterprise. |
| `subject_type` | string | no | Token subject type for JWT and CCG: enterprise (service account, default) or user. Defaults to BOX_SUBJECT_TYPE. |
| `subject_id` | string | no | Token subject ID for JWT and CCG when subject_type is user. Defaults to BOX_SUBJECT_ID. |
| `access_token` | string | no | Pre-issued OAuth 2.0 access token. Defaults to BOX_ACCESS_TOKEN (also BOX_TOKEN or BOX_DEVELOPER_TOKEN). |
| `refresh_token` | string | no | OAuth 2.0 refresh token used with client_id and client_secret to renew the access token. Defaults to BOX_REFRESH_TOKEN. |
| `config_path` | string | no | Path to a YAML config file. Defaults to BOX_CONFIG_PATH or ~/.box-sec-inspector/config.yaml. |
| `base_url` | string | no | Box Content API base URL. Defaults to https://api.box.com/2.0. |
| `token_url` | string | no | Box OAuth 2.0 token endpoint. Defaults to https://api.box.com/oauth2/token. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses with backoff. Defaults to 3. |

#### `box_assess_identity_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_method` | string | no | Box auth method: jwt, ccg, or oauth. Defaults to BOX_AUTH_METHOD or is inferred from the credentials provided. |
| `jwt_config_path` | string | no | Path to the Box JWT app config JSON downloaded from the Developer Console. Defaults to BOX_JWT_CONFIG_PATH. |
| `jwt_passphrase` | string | no | Passphrase for the encrypted JWT private key when it is not stored in the config file. Defaults to BOX_JWT_PASSPHRASE. |
| `client_id` | string | no | Box app client ID. Defaults to BOX_CLIENT_ID or the JWT config file. |
| `client_secret` | string | no | Box app client secret. Defaults to BOX_CLIENT_SECRET or the JWT config file. |
| `enterprise_id` | string | no | Box enterprise ID. Defaults to BOX_ENTERPRISE_ID, the JWT config file, or the authenticated user's enterprise. |
| `subject_type` | string | no | Token subject type for JWT and CCG: enterprise (service account, default) or user. Defaults to BOX_SUBJECT_TYPE. |
| `subject_id` | string | no | Token subject ID for JWT and CCG when subject_type is user. Defaults to BOX_SUBJECT_ID. |
| `access_token` | string | no | Pre-issued OAuth 2.0 access token. Defaults to BOX_ACCESS_TOKEN (also BOX_TOKEN or BOX_DEVELOPER_TOKEN). |
| `refresh_token` | string | no | OAuth 2.0 refresh token used with client_id and client_secret to renew the access token. Defaults to BOX_REFRESH_TOKEN. |
| `config_path` | string | no | Path to a YAML config file. Defaults to BOX_CONFIG_PATH or ~/.box-sec-inspector/config.yaml. |
| `base_url` | string | no | Box Content API base URL. Defaults to https://api.box.com/2.0. |
| `token_url` | string | no | Box OAuth 2.0 token endpoint. Defaults to https://api.box.com/oauth2/token. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses with backoff. Defaults to 3. |
| `event_limit` | number | no | Maximum enterprise events to sample from the admin_logs stream. Defaults to 2000. |
| `lookback_days` | number | no | Event lookback window in days. Defaults to 90. |
| `user_limit` | number | no | Maximum enterprise users to inspect. Defaults to 1000. |
| `max_admins` | number | no | Maximum acceptable admin plus co-admin accounts before warning. Defaults to 10. |
| `min_password_length` | number | no | Minimum password length expected for a passing result. Defaults to 12. |
| `max_session_hours` | number | no | Maximum acceptable session duration in hours. Defaults to 24. |

#### `box_assess_sharing_collaboration`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_method` | string | no | Box auth method: jwt, ccg, or oauth. Defaults to BOX_AUTH_METHOD or is inferred from the credentials provided. |
| `jwt_config_path` | string | no | Path to the Box JWT app config JSON downloaded from the Developer Console. Defaults to BOX_JWT_CONFIG_PATH. |
| `jwt_passphrase` | string | no | Passphrase for the encrypted JWT private key when it is not stored in the config file. Defaults to BOX_JWT_PASSPHRASE. |
| `client_id` | string | no | Box app client ID. Defaults to BOX_CLIENT_ID or the JWT config file. |
| `client_secret` | string | no | Box app client secret. Defaults to BOX_CLIENT_SECRET or the JWT config file. |
| `enterprise_id` | string | no | Box enterprise ID. Defaults to BOX_ENTERPRISE_ID, the JWT config file, or the authenticated user's enterprise. |
| `subject_type` | string | no | Token subject type for JWT and CCG: enterprise (service account, default) or user. Defaults to BOX_SUBJECT_TYPE. |
| `subject_id` | string | no | Token subject ID for JWT and CCG when subject_type is user. Defaults to BOX_SUBJECT_ID. |
| `access_token` | string | no | Pre-issued OAuth 2.0 access token. Defaults to BOX_ACCESS_TOKEN (also BOX_TOKEN or BOX_DEVELOPER_TOKEN). |
| `refresh_token` | string | no | OAuth 2.0 refresh token used with client_id and client_secret to renew the access token. Defaults to BOX_REFRESH_TOKEN. |
| `config_path` | string | no | Path to a YAML config file. Defaults to BOX_CONFIG_PATH or ~/.box-sec-inspector/config.yaml. |
| `base_url` | string | no | Box Content API base URL. Defaults to https://api.box.com/2.0. |
| `token_url` | string | no | Box OAuth 2.0 token endpoint. Defaults to https://api.box.com/oauth2/token. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses with backoff. Defaults to 3. |
| `event_limit` | number | no | Maximum enterprise events to sample from the admin_logs stream. Defaults to 2000. |
| `lookback_days` | number | no | Event lookback window in days. Defaults to 90. |
| `stale_allowlist_days` | number | no | Age in days after which a collaboration allowlist entry is flagged for review. Defaults to 365. |
| `list_limit` | number | no | Maximum records to inspect per paginated list (collaboration allowlist entries and exempt users, device pins, policies, and assignments). A list that hits the cap while Box reports more records is marked truncated and downgrades dependent findings to warn. Defaults to 500. |

#### `box_assess_data_governance`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_method` | string | no | Box auth method: jwt, ccg, or oauth. Defaults to BOX_AUTH_METHOD or is inferred from the credentials provided. |
| `jwt_config_path` | string | no | Path to the Box JWT app config JSON downloaded from the Developer Console. Defaults to BOX_JWT_CONFIG_PATH. |
| `jwt_passphrase` | string | no | Passphrase for the encrypted JWT private key when it is not stored in the config file. Defaults to BOX_JWT_PASSPHRASE. |
| `client_id` | string | no | Box app client ID. Defaults to BOX_CLIENT_ID or the JWT config file. |
| `client_secret` | string | no | Box app client secret. Defaults to BOX_CLIENT_SECRET or the JWT config file. |
| `enterprise_id` | string | no | Box enterprise ID. Defaults to BOX_ENTERPRISE_ID, the JWT config file, or the authenticated user's enterprise. |
| `subject_type` | string | no | Token subject type for JWT and CCG: enterprise (service account, default) or user. Defaults to BOX_SUBJECT_TYPE. |
| `subject_id` | string | no | Token subject ID for JWT and CCG when subject_type is user. Defaults to BOX_SUBJECT_ID. |
| `access_token` | string | no | Pre-issued OAuth 2.0 access token. Defaults to BOX_ACCESS_TOKEN (also BOX_TOKEN or BOX_DEVELOPER_TOKEN). |
| `refresh_token` | string | no | OAuth 2.0 refresh token used with client_id and client_secret to renew the access token. Defaults to BOX_REFRESH_TOKEN. |
| `config_path` | string | no | Path to a YAML config file. Defaults to BOX_CONFIG_PATH or ~/.box-sec-inspector/config.yaml. |
| `base_url` | string | no | Box Content API base URL. Defaults to https://api.box.com/2.0. |
| `token_url` | string | no | Box OAuth 2.0 token endpoint. Defaults to https://api.box.com/oauth2/token. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses with backoff. Defaults to 3. |
| `list_limit` | number | no | Maximum records to inspect per paginated list (collaboration allowlist entries and exempt users, device pins, policies, and assignments). A list that hits the cap while Box reports more records is marked truncated and downgrades dependent findings to warn. Defaults to 500. |

#### `box_assess_shield_monitoring`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_method` | string | no | Box auth method: jwt, ccg, or oauth. Defaults to BOX_AUTH_METHOD or is inferred from the credentials provided. |
| `jwt_config_path` | string | no | Path to the Box JWT app config JSON downloaded from the Developer Console. Defaults to BOX_JWT_CONFIG_PATH. |
| `jwt_passphrase` | string | no | Passphrase for the encrypted JWT private key when it is not stored in the config file. Defaults to BOX_JWT_PASSPHRASE. |
| `client_id` | string | no | Box app client ID. Defaults to BOX_CLIENT_ID or the JWT config file. |
| `client_secret` | string | no | Box app client secret. Defaults to BOX_CLIENT_SECRET or the JWT config file. |
| `enterprise_id` | string | no | Box enterprise ID. Defaults to BOX_ENTERPRISE_ID, the JWT config file, or the authenticated user's enterprise. |
| `subject_type` | string | no | Token subject type for JWT and CCG: enterprise (service account, default) or user. Defaults to BOX_SUBJECT_TYPE. |
| `subject_id` | string | no | Token subject ID for JWT and CCG when subject_type is user. Defaults to BOX_SUBJECT_ID. |
| `access_token` | string | no | Pre-issued OAuth 2.0 access token. Defaults to BOX_ACCESS_TOKEN (also BOX_TOKEN or BOX_DEVELOPER_TOKEN). |
| `refresh_token` | string | no | OAuth 2.0 refresh token used with client_id and client_secret to renew the access token. Defaults to BOX_REFRESH_TOKEN. |
| `config_path` | string | no | Path to a YAML config file. Defaults to BOX_CONFIG_PATH or ~/.box-sec-inspector/config.yaml. |
| `base_url` | string | no | Box Content API base URL. Defaults to https://api.box.com/2.0. |
| `token_url` | string | no | Box OAuth 2.0 token endpoint. Defaults to https://api.box.com/oauth2/token. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses with backoff. Defaults to 3. |
| `event_limit` | number | no | Maximum enterprise events to sample from the admin_logs stream. Defaults to 2000. |
| `lookback_days` | number | no | Event lookback window in days. Defaults to 90. |

#### `box_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `auth_method` | string | no | Box auth method: jwt, ccg, or oauth. Defaults to BOX_AUTH_METHOD or is inferred from the credentials provided. |
| `jwt_config_path` | string | no | Path to the Box JWT app config JSON downloaded from the Developer Console. Defaults to BOX_JWT_CONFIG_PATH. |
| `jwt_passphrase` | string | no | Passphrase for the encrypted JWT private key when it is not stored in the config file. Defaults to BOX_JWT_PASSPHRASE. |
| `client_id` | string | no | Box app client ID. Defaults to BOX_CLIENT_ID or the JWT config file. |
| `client_secret` | string | no | Box app client secret. Defaults to BOX_CLIENT_SECRET or the JWT config file. |
| `enterprise_id` | string | no | Box enterprise ID. Defaults to BOX_ENTERPRISE_ID, the JWT config file, or the authenticated user's enterprise. |
| `subject_type` | string | no | Token subject type for JWT and CCG: enterprise (service account, default) or user. Defaults to BOX_SUBJECT_TYPE. |
| `subject_id` | string | no | Token subject ID for JWT and CCG when subject_type is user. Defaults to BOX_SUBJECT_ID. |
| `access_token` | string | no | Pre-issued OAuth 2.0 access token. Defaults to BOX_ACCESS_TOKEN (also BOX_TOKEN or BOX_DEVELOPER_TOKEN). |
| `refresh_token` | string | no | OAuth 2.0 refresh token used with client_id and client_secret to renew the access token. Defaults to BOX_REFRESH_TOKEN. |
| `config_path` | string | no | Path to a YAML config file. Defaults to BOX_CONFIG_PATH or ~/.box-sec-inspector/config.yaml. |
| `base_url` | string | no | Box Content API base URL. Defaults to https://api.box.com/2.0. |
| `token_url` | string | no | Box OAuth 2.0 token endpoint. Defaults to https://api.box.com/oauth2/token. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses with backoff. Defaults to 3. |
| `event_limit` | number | no | Maximum enterprise events to sample from the admin_logs stream. Defaults to 2000. |
| `lookback_days` | number | no | Event lookback window in days. Defaults to 90. |
| `user_limit` | number | no | Maximum enterprise users to inspect. Defaults to 1000. |
| `max_admins` | number | no | Maximum acceptable admin plus co-admin accounts before warning. Defaults to 10. |
| `min_password_length` | number | no | Minimum password length expected for a passing result. Defaults to 12. |
| `max_session_hours` | number | no | Maximum acceptable session duration in hours. Defaults to 24. |
| `stale_allowlist_days` | number | no | Age in days after which a collaboration allowlist entry is flagged for review. Defaults to 365. |
| `list_limit` | number | no | Maximum records to inspect per paginated list (collaboration allowlist entries and exempt users, device pins, policies, and assignments). A list that hits the cap while Box reports more records is marked truncated and downgrades dependent findings to warn. Defaults to 500. |
| `output_dir` | string | no | Output root. Defaults to ./export/box. |


## Authentication

Supported modes:

- JWT server authentication
- Client Credentials Grant
- OAuth refresh token
- Explicit access token

Credential precedence, highest first:

1. Explicit arguments
2. Explicit config path
3. Box inspector config
4. BOX_* environment variables

Environment variables: `BOX_CLIENT_ID`, `BOX_CLIENT_SECRET`, `BOX_ENTERPRISE_ID`, `BOX_ACCESS_TOKEN`, `BOX_REFRESH_TOKEN`, `BOX_JWT_CONFIG`

Configuration locations: ~/.box-sec-inspector/config.yaml

Credential and deployment variants: Enterprise or user subject, JWT RS256, RS384, or RS512 assertion

Configuration fields: `clientId`, `clientSecret`, `enterpriseId`, `subjectType`, `subjectId`, `accessToken`, `refreshToken`, `jwt`

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

Credential refresh: POST https://api.box.com/oauth2/token using the selected JWT, client_credentials, or refresh_token grant.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| role | `Box application scopes and enterprise authorization for users, groups, events, governance, and enterprise configuration` | `current-user`, `enterprise-configuration`, `users`, `groups`, `events`, `device-pinners`, `retention-policies`, `retention-assignments`, `legal-hold-policies`, `legal-hold-assignments`, `shield-barriers`, `shield-barrier-segments`, `shield-lists`, `allowlist-entries`, `allowlist-exempt-targets`, `metadata-templates`, `classification-template`, `terms-of-service` |  |
| license | `Box Governance entitlement` | `retention-policies`, `retention-assignments`, `legal-hold-policies`, `legal-hold-assignments` |  |
| license | `Box Shield entitlement` | `shield-barriers`, `shield-barrier-segments`, `shield-lists` |  |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `current-user` | HTTP | `GET /2.0/users/me` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `enterprise-configuration` | HTTP | `GET /2.0/enterprise_configurations/{enterpriseId}` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `users` | HTTP | `GET /2.0/users` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `groups` | HTTP | `GET /2.0/groups` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `events` | HTTP | `GET /2.0/events` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `device-pinners` | HTTP | `GET /2.0/enterprises/{enterpriseId}/device_pinners` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `retention-policies` | HTTP | `GET /2.0/retention_policies` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `retention-assignments` | HTTP | `GET /2.0/retention_policies/{policyId}/assignments` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `legal-hold-policies` | HTTP | `GET /2.0/legal_hold_policies` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `legal-hold-assignments` | HTTP | `GET /2.0/legal_hold_policy_assignments` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `shield-barriers` | HTTP | `GET /2.0/shield_information_barriers` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `shield-barrier-segments` | HTTP | `GET /2.0/shield_information_barrier_segments` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `shield-lists` | HTTP | `GET /2.0/shield_lists` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `allowlist-entries` | HTTP | `GET /2.0/collaboration_whitelist_entries` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `allowlist-exempt-targets` | HTTP | `GET /2.0/collaboration_whitelist_exempt_targets` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `metadata-templates` | HTTP | `GET /2.0/metadata_templates/enterprise` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `classification-template` | HTTP | `GET /2.0/metadata_templates/enterprise/securityClassification-6VMVochwUWo/schema` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |
| `terms-of-service` | HTTP | `GET /2.0/terms_of_services` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `projected fields consumed by the corresponding runtime assessment` | [Official documentation](https://developer.box.com/reference/) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `current-user` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `current-user` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `current-user` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `enterprise-configuration` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `enterprise-configuration` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `enterprise-configuration` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `users` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `users` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `groups` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `groups` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `groups` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `events` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `events` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `events` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `device-pinners` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `device-pinners` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `device-pinners` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `retention-policies` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `retention-policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `retention-policies` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `retention-assignments` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `retention-assignments` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `retention-assignments` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `legal-hold-policies` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `legal-hold-policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `legal-hold-policies` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `legal-hold-assignments` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `legal-hold-assignments` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `legal-hold-assignments` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `shield-barriers` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `shield-barriers` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `shield-barriers` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `shield-barrier-segments` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `shield-barrier-segments` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `shield-barrier-segments` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `shield-lists` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `shield-lists` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `shield-lists` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `allowlist-entries` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `allowlist-entries` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `allowlist-entries` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `allowlist-exempt-targets` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `allowlist-exempt-targets` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `allowlist-exempt-targets` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `metadata-templates` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `metadata-templates` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `metadata-templates` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `classification-template` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `classification-template` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `classification-template` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |
| `terms-of-service` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `terms-of-service` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `terms-of-service` | response | A JSON object or list containing only the documented projected fields consumed by the corresponding runtime assessment members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `users`, `device-pinners`, `retention-policies`, `retention-assignments`, `legal-hold-policies`, `legal-hold-assignments`, `shield-barriers`, `shield-barrier-segments`, `allowlist-entries`, `allowlist-exempt-targets`, `metadata-templates` | `next_marker` | 1000 | caller limit | none | Completion requires next_marker exhaustion; a cap with a remaining marker is incomplete. | No next_marker; Configured record cap; Repeated marker; Empty page with marker |
| `groups` | `offset`, `limit`, `total_count` | 1000 | caller limit | none | total_count is authoritative; seen below total is incomplete. | Seen reaches total; Configured cap; Offset fails to advance; Empty page before total |
| `events` | `next_stream_position`, `stream_position` | 500 | caller limit | none | The event stream has no total; the walker requires an empty page and advancing stream positions. | Empty page; Configured event cap; Repeated position; Fresh position adds no unseen event; Page budget |
| `shield-lists`, `terms-of-service`, `current-user`, `enterprise-configuration`, `classification-template` | None | service default | caller limit | none | Single request; a successful response is complete. | Single response |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Box Security Inspector | Box rate limits vary by endpoint, user, and enterprise | `Retry-After`, `X-Rate-Limit-Limit`, `X-Rate-Limit-Remaining` | 429, 500, 502, 503, 504 | Honor Retry-After up to 60 seconds and retry three times with bounded exponential delay. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | SSO enforcement | BOX-01 | Evaluate the ordered first-match rules for BOX-01 below. |
| 2 | 2FA for admins | BOX-02 | Evaluate the ordered first-match rules for BOX-02 below. |
| 3 | 2FA for all users | BOX-03 | Evaluate the ordered first-match rules for BOX-03 below. |
| 4 | External collaboration restrictions | BOX-04 | Evaluate the ordered first-match rules for BOX-04 below. |
| 5 | Collaboration allowlist audit | BOX-05 | Evaluate the ordered first-match rules for BOX-05 below. |
| 6 | Sharing link policies | BOX-06 | Evaluate the ordered first-match rules for BOX-06 below. |
| 7 | Shared link expiration | BOX-07 | Evaluate the ordered first-match rules for BOX-07 below. |
| 8 | Shared link password policy | BOX-08 | Evaluate the ordered first-match rules for BOX-08 below. |
| 9 | Watermarking enabled | BOX-09 | Evaluate the ordered first-match rules for BOX-09 below. |
| 10 | Device trust and pins | BOX-10 | Evaluate the ordered first-match rules for BOX-10 below. |
| 11 | Classification labels | BOX-11 | Evaluate the ordered first-match rules for BOX-11 below. |
| 12 | Retention policies | BOX-12 | Evaluate the ordered first-match rules for BOX-12 below. |
| 13 | Legal hold policies | BOX-13 | Evaluate the ordered first-match rules for BOX-13 below. |
| 14 | Shield smart access policies | BOX-14 | Evaluate the ordered first-match rules for BOX-14 below. |
| 15 | Shield information barriers | BOX-15 | Evaluate the ordered first-match rules for BOX-15 below. |
| 16 | Enterprise event streaming | BOX-16 | Evaluate the ordered first-match rules for BOX-16 below. |
| 17 | Admin role minimization | BOX-17 | Evaluate the ordered first-match rules for BOX-17 below. |
| 18 | Co-admin permission scoping | BOX-18 | Evaluate the ordered first-match rules for BOX-18 below. |
| 19 | App approval process | BOX-19 | Evaluate the ordered first-match rules for BOX-19 below. |
| 20 | Custom terms of service | BOX-20 | Evaluate the ordered first-match rules for BOX-20 below. |
| 21 | Password policy strength | BOX-21 | Evaluate the ordered first-match rules for BOX-21 below. |
| 22 | Session duration limits | BOX-22 | Evaluate the ordered first-match rules for BOX-22 below. |
| 23 | IP allowlisting | BOX-23 | Evaluate the ordered first-match rules for BOX-23 below. |
| 24 | Inactive user detection | BOX-24 | Evaluate the ordered first-match rules for BOX-24 below. |
| 25 | Content access monitoring | BOX-25 | Evaluate the ordered first-match rules for BOX-25 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `BOX-01` | critical | `box_assess_identity_access` | `enterprise-configuration` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when enterprise SSO is required and not in testing mode, warn when it is required but testing, unused, or not exposed, and fail when it is explicitly not required. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when enterprise SSO is required and not in testing mode, warn when it is required but testing, unused, or not exposed, and fail when it is explicitly not required. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when enterprise SSO is required and not in testing mode, warn when it is required but testing, unused, or not exposed, and fail when it is explicitly not required. | The required evidence for SSO enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-02` | critical | `box_assess_identity_access` | `enterprise-configuration`, `users` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when enterprise MFA is required but any admin or co-admin is exempt, pass when MFA is required and the complete privileged inventory has no exemption, warn for unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when both MFA and required SSO are disabled. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when enterprise MFA is required but any admin or co-admin is exempt, pass when MFA is required and the complete privileged inventory has no exemption, warn for unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when both MFA and required SSO are disabled. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when enterprise MFA is required but any admin or co-admin is exempt, pass when MFA is required and the complete privileged inventory has no exemption, warn for unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when both MFA and required SSO are disabled. | The required evidence for 2FA for admins is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-03` | high | `box_assess_identity_access` | `enterprise-configuration`, `users` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when enterprise MFA is required and the complete user inventory has no non-privileged exemption, warn for any exemption, unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when neither MFA nor required SSO is enforced. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when enterprise MFA is required and the complete user inventory has no non-privileged exemption, warn for any exemption, unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when neither MFA nor required SSO is enforced. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when enterprise MFA is required and the complete user inventory has no non-privileged exemption, warn for any exemption, unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when neither MFA nor required SSO is enforced. | The required evidence for 2FA for all users is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-04` | high | `box_assess_sharing_collaboration` | `enterprise-configuration`, `allowlist-entries` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when external collaboration is enterprise-only or allowlist-only with at least one readable entry, fail when unrestricted, and warn for unused, unknown, empty, unreadable, or truncated-before-first-entry allowlist evidence. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when external collaboration is enterprise-only or allowlist-only with at least one readable entry, fail when unrestricted, and warn for unused, unknown, empty, unreadable, or truncated-before-first-entry allowlist evidence. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when external collaboration is enterprise-only or allowlist-only with at least one readable entry, fail when unrestricted, and warn for unused, unknown, empty, unreadable, or truncated-before-first-entry allowlist evidence. | The required evidence for External collaboration restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-05` | medium | `box_assess_sharing_collaboration` | `enterprise-configuration`, `allowlist-entries`, `allowlist-exempt-targets` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any allowlist entry is a public consumer email domain, warn for truncation, stale or undated entries, exemptions, or an empty allowlist while allowlist-only mode is selected, and pass when complete entries are recent non-public domains without exemptions or no allowlist is required and none exists. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any allowlist entry is a public consumer email domain, warn for truncation, stale or undated entries, exemptions, or an empty allowlist while allowlist-only mode is selected, and pass when complete entries are recent non-public domains without exemptions or no allowlist is required and none exists. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any allowlist entry is a public consumer email domain, warn for truncation, stale or undated entries, exemptions, or an empty allowlist while allowlist-only mode is selected, and pass when complete entries are recent non-public domains without exemptions or no allowlist is required and none exists. | The required evidence for Collaboration allowlist audit is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-06` | high | `box_assess_sharing_collaboration` | `enterprise-configuration` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when shared links default to open access, pass when the default is restricted and open links are not offered, and warn when the default is restricted but open links remain available or the setting is unused or unrecognized. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when shared links default to open access, pass when the default is restricted and open links are not offered, and warn when the default is restricted but open links remain available or the setting is unused or unrecognized. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when shared links default to open access, pass when the default is restricted and open links are not offered, and warn when the default is restricted but open links remain available or the setting is unused or unrecognized. | The required evidence for Sharing link policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-07` | medium | `box_assess_sharing_collaboration` | `enterprise-configuration` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when mandatory expiration is enabled for all shared links, warn when only public links expire or the setting is unused or absent, and fail when mandatory expiration is explicitly disabled. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when mandatory expiration is enabled for all shared links, warn when only public links expire or the setting is unused or absent, and fail when mandatory expiration is explicitly disabled. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when mandatory expiration is enabled for all shared links, warn when only public links expire or the setting is unused or absent, and fail when mandatory expiration is explicitly disabled. | The required evidence for Shared link expiration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-08` | medium | `box_assess_sharing_collaboration` | None | `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: always return manual because the enterprise configuration API does not expose whether passwords are required for open shared links. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: always return manual because the enterprise configuration API does not expose whether passwords are required for open shared links. | Complete readable evidence satisfies the violation branch, which has first-match precedence: always return manual because the enterprise configuration API does not expose whether passwords are required for open shared links. | The required evidence for Shared link password policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-09` | medium | `box_assess_sharing_collaboration` | `enterprise-configuration` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when enterprise watermarking is enabled, fail when explicitly disabled, and warn when the flag is unused or absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when enterprise watermarking is enabled, fail when explicitly disabled, and warn when the flag is unused or absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when enterprise watermarking is enabled, fail when explicitly disabled, and warn when the flag is unused or absent. | The required evidence for Watermarking enabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-10` | medium | `box_assess_data_governance` | `device-pinners` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return warn when the complete device-pin inventory is empty and manual when pins exist because the API does not expose whether unpinned devices are blocked; a read that truncates before its first pin is also manual. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return warn when the complete device-pin inventory is empty and manual when pins exist because the API does not expose whether unpinned devices are blocked; a read that truncates before its first pin is also manual. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return warn when the complete device-pin inventory is empty and manual when pins exist because the API does not expose whether unpinned devices are blocked; a read that truncates before its first pin is also manual. | The required evidence for Device trust and pins is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-11` | medium | `box_assess_data_governance` | `classification-template`, `metadata-templates` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the classification template defines at least one label and fail when a readable template or a 404 proves that it defines none. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the classification template defines at least one label and fail when a readable template or a 404 proves that it defines none. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the classification template defines at least one label and fail when a readable template or a 404 proves that it defines none. | The required evidence for Classification labels is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-12` | medium | `box_assess_data_governance` | `retention-policies`, `retention-assignments` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when a complete retention-policy inventory has at least one active policy with visible assignments, warn when active policies lack assignments or any relevant inventory is truncated, and fail when a complete inventory has no active policy. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when a complete retention-policy inventory has at least one active policy with visible assignments, warn when active policies lack assignments or any relevant inventory is truncated, and fail when a complete inventory has no active policy. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when a complete retention-policy inventory has at least one active policy with visible assignments, warn when active policies lack assignments or any relevant inventory is truncated, and fail when a complete inventory has no active policy. | The required evidence for Retention policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-13` | medium | `box_assess_data_governance` | `legal-hold-policies`, `legal-hold-assignments` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when a complete legal-hold inventory has at least one active or applying policy with visible assignments, and warn when policies or assignments are incomplete, active holds lack assignments, no hold is active, or no hold exists. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when a complete legal-hold inventory has at least one active or applying policy with visible assignments, and warn when policies or assignments are incomplete, active holds lack assignments, no hold is active, or no hold exists. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when a complete legal-hold inventory has at least one active or applying policy with visible assignments, and warn when policies or assignments are incomplete, active holds lack assignments, no hold is active, or no hold exists. | The required evidence for Legal hold policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-14` | high | `box_assess_shield_monitoring` | `enterprise-configuration`, `shield-lists` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when at least one Shield smart-access or threat-detection rule is configured and fail when a readable complete Shield configuration has none. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when at least one Shield smart-access or threat-detection rule is configured and fail when a readable complete Shield configuration has none. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when at least one Shield smart-access or threat-detection rule is configured and fail when a readable complete Shield configuration has none. | The required evidence for Shield smart access policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-15` | medium | `box_assess_shield_monitoring` | `shield-barriers`, `shield-barrier-segments` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when at least one enabled information barrier has a visible segment, and warn when barriers or segments are incomplete, enabled barriers have no visible segment, no barrier is enabled, or no barrier exists. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when at least one enabled information barrier has a visible segment, and warn when barriers or segments are incomplete, enabled barriers have no visible segment, no barrier is enabled, or no barrier exists. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when at least one enabled information barrier has a visible segment, and warn when barriers or segments are incomplete, enabled barriers have no visible segment, no barrier is enabled, or no barrier exists. | The required evidence for Shield information barriers is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-16` | high | `box_assess_shield_monitoring` | `events` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the readable enterprise admin event stream contains at least one event in the lookback and warn when it contains none; this verdict proves stream readability only and does not prove SIEM consumption. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the readable enterprise admin event stream contains at least one event in the lookback and warn when it contains none; this verdict proves stream readability only and does not prove SIEM consumption. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the readable enterprise admin event stream contains at least one event in the lookback and warn when it contains none; this verdict proves stream readability only and does not prove SIEM consumption. | The required evidence for Enterprise event streaming is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-17` | high | `box_assess_identity_access` | `users` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return warn when the complete count of admins plus co-admins exceeds the configured maximum and pass when it is at or below that maximum. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return warn when the complete count of admins plus co-admins exceeds the configured maximum and pass when it is at or below that maximum. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return warn when the complete count of admins plus co-admins exceeds the configured maximum and pass when it is at or below that maximum. | The required evidence for Admin role minimization is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-18` | medium | `box_assess_identity_access` | `users` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete user inventory has no co-admin, warn when user evidence is partial, and manual when any co-admin exists because individual co-admin permissions are not exposed. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete user inventory has no co-admin, warn when user evidence is partial, and manual when any co-admin exists because individual co-admin permissions are not exposed. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete user inventory has no co-admin, warn when user evidence is partial, and manual when any co-admin exists because individual co-admin permissions are not exposed. | The required evidence for Co-admin permission scoping is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-19` | medium | `box_assess_sharing_collaboration` | `events`, `shield-lists` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: always return manual because app creation events and Shield integration lists do not expose the app approval policy. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: always return manual because app creation events and Shield integration lists do not expose the app approval policy. | Complete readable evidence satisfies the violation branch, which has first-match precedence: always return manual because app creation events and Shield integration lists do not expose the app approval policy. | The required evidence for App approval process is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-20` | medium | `box_assess_sharing_collaboration` | `terms-of-service` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when at least one managed-user custom terms record is enabled, fail when managed-user terms exist but are disabled, and fail when a complete terms inventory has no managed-user terms. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when at least one managed-user custom terms record is enabled, fail when managed-user terms exist but are disabled, and fail when a complete terms inventory has no managed-user terms. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when at least one managed-user custom terms record is enabled, fail when managed-user terms exist but are disabled, and fail when a complete terms inventory has no managed-user terms. | The required evidence for Custom terms of service is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-21` | high | `box_assess_identity_access` | `enterprise-configuration` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when minimum password length meets the configured target, weak-password prevention is enabled, and at least two of uppercase, numeric, and special-character minima are positive; warn when length is at least eight but any target is missed or the setting is unused or absent, and fail below eight. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when minimum password length meets the configured target, weak-password prevention is enabled, and at least two of uppercase, numeric, and special-character minima are positive; warn when length is at least eight but any target is missed or the setting is unused or absent, and fail below eight. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when minimum password length meets the configured target, weak-password prevention is enabled, and at least two of uppercase, numeric, and special-character minima are positive; warn when length is at least eight but any target is missed or the setting is unused or absent, and fail below eight. | The required evidence for Password policy strength is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-22` | medium | `box_assess_identity_access` | `enterprise-configuration` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when the base session duration or an enabled custom group duration exceeds the configured maximum, pass when every applicable duration is at or below it, and warn when a duration is unused, absent, or cannot be normalized. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when the base session duration or an enabled custom group duration exceeds the configured maximum, pass when every applicable duration is at or below it, and warn when a duration is unused, absent, or cannot be normalized. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when the base session duration or an enabled custom group duration exceeds the configured maximum, pass when every applicable duration is at or below it, and warn when a duration is unused, absent, or cannot be normalized. | The required evidence for Session duration limits is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-23` | medium | `box_assess_identity_access` | `shield-lists` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: always return manual because Shield IP lists do not expose whether enterprise sign-in or access-policy IP restrictions are enforced. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: always return manual because Shield IP lists do not expose whether enterprise sign-in or access-policy IP restrictions are enforced. | Complete readable evidence satisfies the violation branch, which has first-match precedence: always return manual because Shield IP lists do not expose whether enterprise sign-in or access-policy IP restrictions are enforced. | The required evidence for IP allowlisting is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-24` | medium | `box_assess_identity_access` | `users`, `events` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every active human user has a successful activity event in the lookback, fail when more than 25 percent lack one, and warn when at most 25 percent lack one, no active human user exists, or user or event coverage is incomplete. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every active human user has a successful activity event in the lookback, fail when more than 25 percent lack one, and warn when at most 25 percent lack one, no active human user exists, or user or event coverage is incomplete. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every active human user has a successful activity event in the lookback, fail when more than 25 percent lack one, and warn when at most 25 percent lack one, no active human user exists, or user or event coverage is incomplete. | The required evidence for Inactive user detection is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-25` | high | `box_assess_shield_monitoring` | `shield-lists`, `events` | `projected fields consumed by the corresponding runtime assessment`, `complete_source_counts` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when at least one Shield anomaly rule or Shield alert or block event exists, warn when one required source is unavailable, only ordinary access events exist, or the event window is incomplete, and fail when complete readable evidence has no anomaly rule, alert, block, or content-access event. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when at least one Shield anomaly rule or Shield alert or block event exists, warn when one required source is unavailable, only ordinary access events exist, or the event window is incomplete, and fail when complete readable evidence has no anomaly rule, alert, block, or content-access event. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when at least one Shield anomaly rule or Shield alert or block event exists, warn when one required source is unavailable, only ordinary access events exist, or the event window is incomplete, and fail when complete readable evidence has no anomaly rule, alert, block, or content-access event. | The required evidence for Content access monitoring is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `BOX-01` | 1 | fail | `box_01_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-01` | 2 | manual | any of (`box_01_required_evidence_readable` equals false; not (`box_01_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-01` | 3 | warn | any of (`box_01_warning_matches` equals true; `box_01_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-01` | 4 | pass | all of (`box_01_compliant_matches` equals true; `box_01_required_evidence_readable` equals true; `box_01_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-01` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-02` | 1 | fail | `box_02_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-02` | 2 | manual | any of (`box_02_required_evidence_readable` equals false; not (`box_02_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-02` | 3 | warn | any of (`box_02_warning_matches` equals true; `box_02_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-02` | 4 | pass | all of (`box_02_compliant_matches` equals true; `box_02_required_evidence_readable` equals true; `box_02_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-02` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-03` | 1 | fail | `box_03_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-03` | 2 | manual | any of (`box_03_required_evidence_readable` equals false; not (`box_03_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-03` | 3 | warn | any of (`box_03_warning_matches` equals true; `box_03_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-03` | 4 | pass | all of (`box_03_compliant_matches` equals true; `box_03_required_evidence_readable` equals true; `box_03_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-03` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-04` | 1 | fail | `box_04_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-04` | 2 | manual | any of (`box_04_required_evidence_readable` equals false; not (`box_04_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-04` | 3 | warn | any of (`box_04_warning_matches` equals true; `box_04_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-04` | 4 | pass | all of (`box_04_compliant_matches` equals true; `box_04_required_evidence_readable` equals true; `box_04_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-04` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-05` | 1 | fail | `box_05_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-05` | 2 | manual | any of (`box_05_required_evidence_readable` equals false; not (`box_05_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-05` | 3 | warn | any of (`box_05_warning_matches` equals true; `box_05_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-05` | 4 | pass | all of (`box_05_compliant_matches` equals true; `box_05_required_evidence_readable` equals true; `box_05_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-05` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-06` | 1 | fail | `box_06_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-06` | 2 | manual | any of (`box_06_required_evidence_readable` equals false; not (`box_06_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-06` | 3 | warn | any of (`box_06_warning_matches` equals true; `box_06_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-06` | 4 | pass | all of (`box_06_compliant_matches` equals true; `box_06_required_evidence_readable` equals true; `box_06_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-06` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-07` | 1 | fail | `box_07_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-07` | 2 | manual | any of (`box_07_required_evidence_readable` equals false; not (`box_07_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-07` | 3 | warn | any of (`box_07_warning_matches` equals true; `box_07_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-07` | 4 | pass | all of (`box_07_compliant_matches` equals true; `box_07_required_evidence_readable` equals true; `box_07_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-07` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-08` | 1 | manual | any of (`box_08_required_evidence_readable` equals false; not (`box_08_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-08` | 2 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-09` | 1 | fail | `box_09_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-09` | 2 | manual | any of (`box_09_required_evidence_readable` equals false; not (`box_09_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-09` | 3 | warn | any of (`box_09_warning_matches` equals true; `box_09_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-09` | 4 | pass | all of (`box_09_compliant_matches` equals true; `box_09_required_evidence_readable` equals true; `box_09_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-09` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-10` | 1 | manual | any of (`box_10_required_evidence_readable` equals false; not (`box_10_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-10` | 2 | warn | any of (`box_10_warning_matches` equals true; `box_10_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-10` | 3 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-11` | 1 | fail | `box_11_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-11` | 2 | manual | any of (`box_11_required_evidence_readable` equals false; not (`box_11_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-11` | 3 | pass | all of (`box_11_compliant_matches` equals true; `box_11_required_evidence_readable` equals true; `box_11_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-11` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-12` | 1 | fail | `box_12_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-12` | 2 | manual | any of (`box_12_required_evidence_readable` equals false; not (`box_12_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-12` | 3 | warn | any of (`box_12_warning_matches` equals true; `box_12_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-12` | 4 | pass | all of (`box_12_compliant_matches` equals true; `box_12_required_evidence_readable` equals true; `box_12_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-12` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-13` | 1 | manual | any of (`box_13_required_evidence_readable` equals false; not (`box_13_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-13` | 2 | warn | any of (`box_13_warning_matches` equals true; `box_13_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-13` | 3 | pass | all of (`box_13_compliant_matches` equals true; `box_13_required_evidence_readable` equals true; `box_13_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-13` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-14` | 1 | fail | `box_14_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-14` | 2 | manual | any of (`box_14_required_evidence_readable` equals false; not (`box_14_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-14` | 3 | pass | all of (`box_14_compliant_matches` equals true; `box_14_required_evidence_readable` equals true; `box_14_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-14` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-15` | 1 | manual | any of (`box_15_required_evidence_readable` equals false; not (`box_15_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-15` | 2 | warn | any of (`box_15_warning_matches` equals true; `box_15_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-15` | 3 | pass | all of (`box_15_compliant_matches` equals true; `box_15_required_evidence_readable` equals true; `box_15_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-15` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-16` | 1 | manual | any of (`box_16_required_evidence_readable` equals false; not (`box_16_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-16` | 2 | warn | any of (`box_16_warning_matches` equals true; `box_16_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-16` | 3 | pass | all of (`box_16_compliant_matches` equals true; `box_16_required_evidence_readable` equals true; `box_16_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-16` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-17` | 1 | manual | any of (`box_17_required_evidence_readable` equals false; not (`box_17_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-17` | 2 | warn | any of (`box_17_warning_matches` equals true; `box_17_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-17` | 3 | pass | all of (`box_17_compliant_matches` equals true; `box_17_required_evidence_readable` equals true; `box_17_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-17` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-18` | 1 | manual | any of (`box_18_required_evidence_readable` equals false; not (`box_18_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-18` | 2 | warn | any of (`box_18_warning_matches` equals true; `box_18_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-18` | 3 | pass | all of (`box_18_compliant_matches` equals true; `box_18_required_evidence_readable` equals true; `box_18_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-18` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-19` | 1 | manual | any of (`box_19_required_evidence_readable` equals false; not (`box_19_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-19` | 2 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-20` | 1 | fail | `box_20_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-20` | 2 | manual | any of (`box_20_required_evidence_readable` equals false; not (`box_20_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-20` | 3 | pass | all of (`box_20_compliant_matches` equals true; `box_20_required_evidence_readable` equals true; `box_20_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-20` | 4 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-21` | 1 | fail | `box_21_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-21` | 2 | manual | any of (`box_21_required_evidence_readable` equals false; not (`box_21_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-21` | 3 | warn | any of (`box_21_warning_matches` equals true; `box_21_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-21` | 4 | pass | all of (`box_21_compliant_matches` equals true; `box_21_required_evidence_readable` equals true; `box_21_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-21` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-22` | 1 | fail | `box_22_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-22` | 2 | manual | any of (`box_22_required_evidence_readable` equals false; not (`box_22_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-22` | 3 | warn | any of (`box_22_warning_matches` equals true; `box_22_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-22` | 4 | pass | all of (`box_22_compliant_matches` equals true; `box_22_required_evidence_readable` equals true; `box_22_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-22` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-23` | 1 | manual | any of (`box_23_required_evidence_readable` equals false; not (`box_23_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-23` | 2 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-24` | 1 | fail | `box_24_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-24` | 2 | manual | any of (`box_24_required_evidence_readable` equals false; not (`box_24_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-24` | 3 | warn | any of (`box_24_warning_matches` equals true; `box_24_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-24` | 4 | pass | all of (`box_24_compliant_matches` equals true; `box_24_required_evidence_readable` equals true; `box_24_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-24` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |
| `BOX-25` | 1 | fail | `box_25_failure_matches` equals true | A violation proved by readable evidence has first-match precedence over partial companion evidence. |
| `BOX-25` | 2 | manual | any of (`box_25_required_evidence_readable` equals false; not (`box_25_required_evidence_readable` is present and non-null)) | Missing, null, denied, unreadable, or never-requested required evidence cannot pass. |
| `BOX-25` | 3 | warn | any of (`box_25_warning_matches` equals true; `box_25_required_evidence_complete` equals false) | A review predicate or incomplete required inventory prevents pass. |
| `BOX-25` | 4 | pass | all of (`box_25_compliant_matches` equals true; `box_25_required_evidence_readable` equals true; `box_25_required_evidence_complete` equals true) | Pass requires the integration-specific compliant predicate and complete readable dependencies. |
| `BOX-25` | 5 | manual | always | Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `BOX-01` | `box_01_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-01 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-01` | `box_01_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-01` | `box_01_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when enterprise SSO is required and not in testing mode, warn when it is required but testing, unused, or not exposed, and fail when it is explicitly not required. |
| `BOX-01` | `box_01_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when enterprise SSO is required and not in testing mode, warn when it is required but testing, unused, or not exposed, and fail when it is explicitly not required. |
| `BOX-01` | `box_01_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when enterprise SSO is required and not in testing mode, warn when it is required but testing, unused, or not exposed, and fail when it is explicitly not required. |
| `BOX-02` | `box_02_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-02 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-02` | `box_02_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-02` | `box_02_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when enterprise MFA is required but any admin or co-admin is exempt, pass when MFA is required and the complete privileged inventory has no exemption, warn for unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when both MFA and required SSO are disabled. |
| `BOX-02` | `box_02_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when enterprise MFA is required but any admin or co-admin is exempt, pass when MFA is required and the complete privileged inventory has no exemption, warn for unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when both MFA and required SSO are disabled. |
| `BOX-02` | `box_02_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when enterprise MFA is required but any admin or co-admin is exempt, pass when MFA is required and the complete privileged inventory has no exemption, warn for unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when both MFA and required SSO are disabled. |
| `BOX-03` | `box_03_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-03 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-03` | `box_03_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-03` | `box_03_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when enterprise MFA is required and the complete user inventory has no non-privileged exemption, warn for any exemption, unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when neither MFA nor required SSO is enforced. |
| `BOX-03` | `box_03_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when enterprise MFA is required and the complete user inventory has no non-privileged exemption, warn for any exemption, unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when neither MFA nor required SSO is enforced. |
| `BOX-03` | `box_03_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when enterprise MFA is required and the complete user inventory has no non-privileged exemption, warn for any exemption, unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when neither MFA nor required SSO is enforced. |
| `BOX-04` | `box_04_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-04 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-04` | `box_04_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-04` | `box_04_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when external collaboration is enterprise-only or allowlist-only with at least one readable entry, fail when unrestricted, and warn for unused, unknown, empty, unreadable, or truncated-before-first-entry allowlist evidence. |
| `BOX-04` | `box_04_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when external collaboration is enterprise-only or allowlist-only with at least one readable entry, fail when unrestricted, and warn for unused, unknown, empty, unreadable, or truncated-before-first-entry allowlist evidence. |
| `BOX-04` | `box_04_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when external collaboration is enterprise-only or allowlist-only with at least one readable entry, fail when unrestricted, and warn for unused, unknown, empty, unreadable, or truncated-before-first-entry allowlist evidence. |
| `BOX-05` | `box_05_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-05 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-05` | `box_05_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-05` | `box_05_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when any allowlist entry is a public consumer email domain, warn for truncation, stale or undated entries, exemptions, or an empty allowlist while allowlist-only mode is selected, and pass when complete entries are recent non-public domains without exemptions or no allowlist is required and none exists. |
| `BOX-05` | `box_05_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when any allowlist entry is a public consumer email domain, warn for truncation, stale or undated entries, exemptions, or an empty allowlist while allowlist-only mode is selected, and pass when complete entries are recent non-public domains without exemptions or no allowlist is required and none exists. |
| `BOX-05` | `box_05_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when any allowlist entry is a public consumer email domain, warn for truncation, stale or undated entries, exemptions, or an empty allowlist while allowlist-only mode is selected, and pass when complete entries are recent non-public domains without exemptions or no allowlist is required and none exists. |
| `BOX-06` | `box_06_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-06 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-06` | `box_06_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-06` | `box_06_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when shared links default to open access, pass when the default is restricted and open links are not offered, and warn when the default is restricted but open links remain available or the setting is unused or unrecognized. |
| `BOX-06` | `box_06_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when shared links default to open access, pass when the default is restricted and open links are not offered, and warn when the default is restricted but open links remain available or the setting is unused or unrecognized. |
| `BOX-06` | `box_06_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when shared links default to open access, pass when the default is restricted and open links are not offered, and warn when the default is restricted but open links remain available or the setting is unused or unrecognized. |
| `BOX-07` | `box_07_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-07 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-07` | `box_07_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-07` | `box_07_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when mandatory expiration is enabled for all shared links, warn when only public links expire or the setting is unused or absent, and fail when mandatory expiration is explicitly disabled. |
| `BOX-07` | `box_07_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when mandatory expiration is enabled for all shared links, warn when only public links expire or the setting is unused or absent, and fail when mandatory expiration is explicitly disabled. |
| `BOX-07` | `box_07_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when mandatory expiration is enabled for all shared links, warn when only public links expire or the setting is unused or absent, and fail when mandatory expiration is explicitly disabled. |
| `BOX-08` | `box_08_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-08 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-08` | `box_08_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-08` | `box_08_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: always return manual because the enterprise configuration API does not expose whether passwords are required for open shared links. |
| `BOX-08` | `box_08_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: always return manual because the enterprise configuration API does not expose whether passwords are required for open shared links. |
| `BOX-08` | `box_08_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: always return manual because the enterprise configuration API does not expose whether passwords are required for open shared links. |
| `BOX-09` | `box_09_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-09 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-09` | `box_09_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-09` | `box_09_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when enterprise watermarking is enabled, fail when explicitly disabled, and warn when the flag is unused or absent. |
| `BOX-09` | `box_09_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when enterprise watermarking is enabled, fail when explicitly disabled, and warn when the flag is unused or absent. |
| `BOX-09` | `box_09_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when enterprise watermarking is enabled, fail when explicitly disabled, and warn when the flag is unused or absent. |
| `BOX-10` | `box_10_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-10 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-10` | `box_10_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-10` | `box_10_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return warn when the complete device-pin inventory is empty and manual when pins exist because the API does not expose whether unpinned devices are blocked; a read that truncates before its first pin is also manual. |
| `BOX-10` | `box_10_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return warn when the complete device-pin inventory is empty and manual when pins exist because the API does not expose whether unpinned devices are blocked; a read that truncates before its first pin is also manual. |
| `BOX-10` | `box_10_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return warn when the complete device-pin inventory is empty and manual when pins exist because the API does not expose whether unpinned devices are blocked; a read that truncates before its first pin is also manual. |
| `BOX-11` | `box_11_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-11 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-11` | `box_11_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-11` | `box_11_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the classification template defines at least one label and fail when a readable template or a 404 proves that it defines none. |
| `BOX-11` | `box_11_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the classification template defines at least one label and fail when a readable template or a 404 proves that it defines none. |
| `BOX-11` | `box_11_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the classification template defines at least one label and fail when a readable template or a 404 proves that it defines none. |
| `BOX-12` | `box_12_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-12 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-12` | `box_12_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-12` | `box_12_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when a complete retention-policy inventory has at least one active policy with visible assignments, warn when active policies lack assignments or any relevant inventory is truncated, and fail when a complete inventory has no active policy. |
| `BOX-12` | `box_12_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when a complete retention-policy inventory has at least one active policy with visible assignments, warn when active policies lack assignments or any relevant inventory is truncated, and fail when a complete inventory has no active policy. |
| `BOX-12` | `box_12_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when a complete retention-policy inventory has at least one active policy with visible assignments, warn when active policies lack assignments or any relevant inventory is truncated, and fail when a complete inventory has no active policy. |
| `BOX-13` | `box_13_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-13 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-13` | `box_13_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-13` | `box_13_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when a complete legal-hold inventory has at least one active or applying policy with visible assignments, and warn when policies or assignments are incomplete, active holds lack assignments, no hold is active, or no hold exists. |
| `BOX-13` | `box_13_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when a complete legal-hold inventory has at least one active or applying policy with visible assignments, and warn when policies or assignments are incomplete, active holds lack assignments, no hold is active, or no hold exists. |
| `BOX-13` | `box_13_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when a complete legal-hold inventory has at least one active or applying policy with visible assignments, and warn when policies or assignments are incomplete, active holds lack assignments, no hold is active, or no hold exists. |
| `BOX-14` | `box_14_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-14 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-14` | `box_14_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-14` | `box_14_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when at least one Shield smart-access or threat-detection rule is configured and fail when a readable complete Shield configuration has none. |
| `BOX-14` | `box_14_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when at least one Shield smart-access or threat-detection rule is configured and fail when a readable complete Shield configuration has none. |
| `BOX-14` | `box_14_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when at least one Shield smart-access or threat-detection rule is configured and fail when a readable complete Shield configuration has none. |
| `BOX-15` | `box_15_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-15 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-15` | `box_15_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-15` | `box_15_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when at least one enabled information barrier has a visible segment, and warn when barriers or segments are incomplete, enabled barriers have no visible segment, no barrier is enabled, or no barrier exists. |
| `BOX-15` | `box_15_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when at least one enabled information barrier has a visible segment, and warn when barriers or segments are incomplete, enabled barriers have no visible segment, no barrier is enabled, or no barrier exists. |
| `BOX-15` | `box_15_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when at least one enabled information barrier has a visible segment, and warn when barriers or segments are incomplete, enabled barriers have no visible segment, no barrier is enabled, or no barrier exists. |
| `BOX-16` | `box_16_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-16 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-16` | `box_16_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-16` | `box_16_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the readable enterprise admin event stream contains at least one event in the lookback and warn when it contains none; this verdict proves stream readability only and does not prove SIEM consumption. |
| `BOX-16` | `box_16_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the readable enterprise admin event stream contains at least one event in the lookback and warn when it contains none; this verdict proves stream readability only and does not prove SIEM consumption. |
| `BOX-16` | `box_16_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the readable enterprise admin event stream contains at least one event in the lookback and warn when it contains none; this verdict proves stream readability only and does not prove SIEM consumption. |
| `BOX-17` | `box_17_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-17 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-17` | `box_17_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-17` | `box_17_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return warn when the complete count of admins plus co-admins exceeds the configured maximum and pass when it is at or below that maximum. |
| `BOX-17` | `box_17_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return warn when the complete count of admins plus co-admins exceeds the configured maximum and pass when it is at or below that maximum. |
| `BOX-17` | `box_17_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return warn when the complete count of admins plus co-admins exceeds the configured maximum and pass when it is at or below that maximum. |
| `BOX-18` | `box_18_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-18 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-18` | `box_18_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-18` | `box_18_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when the complete user inventory has no co-admin, warn when user evidence is partial, and manual when any co-admin exists because individual co-admin permissions are not exposed. |
| `BOX-18` | `box_18_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when the complete user inventory has no co-admin, warn when user evidence is partial, and manual when any co-admin exists because individual co-admin permissions are not exposed. |
| `BOX-18` | `box_18_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when the complete user inventory has no co-admin, warn when user evidence is partial, and manual when any co-admin exists because individual co-admin permissions are not exposed. |
| `BOX-19` | `box_19_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-19 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-19` | `box_19_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-19` | `box_19_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: always return manual because app creation events and Shield integration lists do not expose the app approval policy. |
| `BOX-19` | `box_19_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: always return manual because app creation events and Shield integration lists do not expose the app approval policy. |
| `BOX-19` | `box_19_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: always return manual because app creation events and Shield integration lists do not expose the app approval policy. |
| `BOX-20` | `box_20_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-20 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-20` | `box_20_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-20` | `box_20_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when at least one managed-user custom terms record is enabled, fail when managed-user terms exist but are disabled, and fail when a complete terms inventory has no managed-user terms. |
| `BOX-20` | `box_20_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when at least one managed-user custom terms record is enabled, fail when managed-user terms exist but are disabled, and fail when a complete terms inventory has no managed-user terms. |
| `BOX-20` | `box_20_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when at least one managed-user custom terms record is enabled, fail when managed-user terms exist but are disabled, and fail when a complete terms inventory has no managed-user terms. |
| `BOX-21` | `box_21_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-21 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-21` | `box_21_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-21` | `box_21_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when minimum password length meets the configured target, weak-password prevention is enabled, and at least two of uppercase, numeric, and special-character minima are positive; warn when length is at least eight but any target is missed or the setting is unused or absent, and fail below eight. |
| `BOX-21` | `box_21_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when minimum password length meets the configured target, weak-password prevention is enabled, and at least two of uppercase, numeric, and special-character minima are positive; warn when length is at least eight but any target is missed or the setting is unused or absent, and fail below eight. |
| `BOX-21` | `box_21_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when minimum password length meets the configured target, weak-password prevention is enabled, and at least two of uppercase, numeric, and special-character minima are positive; warn when length is at least eight but any target is missed or the setting is unused or absent, and fail below eight. |
| `BOX-22` | `box_22_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-22 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-22` | `box_22_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-22` | `box_22_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return fail when the base session duration or an enabled custom group duration exceeds the configured maximum, pass when every applicable duration is at or below it, and warn when a duration is unused, absent, or cannot be normalized. |
| `BOX-22` | `box_22_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return fail when the base session duration or an enabled custom group duration exceeds the configured maximum, pass when every applicable duration is at or below it, and warn when a duration is unused, absent, or cannot be normalized. |
| `BOX-22` | `box_22_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return fail when the base session duration or an enabled custom group duration exceeds the configured maximum, pass when every applicable duration is at or below it, and warn when a duration is unused, absent, or cannot be normalized. |
| `BOX-23` | `box_23_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-23 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-23` | `box_23_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-23` | `box_23_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: always return manual because Shield IP lists do not expose whether enterprise sign-in or access-policy IP restrictions are enforced. |
| `BOX-23` | `box_23_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: always return manual because Shield IP lists do not expose whether enterprise sign-in or access-policy IP restrictions are enforced. |
| `BOX-23` | `box_23_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: always return manual because Shield IP lists do not expose whether enterprise sign-in or access-policy IP restrictions are enforced. |
| `BOX-24` | `box_24_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-24 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-24` | `box_24_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-24` | `box_24_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when every active human user has a successful activity event in the lookback, fail when more than 25 percent lack one, and warn when at most 25 percent lack one, no active human user exists, or user or event coverage is incomplete. |
| `BOX-24` | `box_24_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when every active human user has a successful activity event in the lookback, fail when more than 25 percent lack one, and warn when at most 25 percent lack one, no active human user exists, or user or event coverage is incomplete. |
| `BOX-24` | `box_24_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when every active human user has a successful activity event in the lookback, fail when more than 25 percent lack one, and warn when at most 25 percent lack one, no active human user exists, or user or event coverage is incomplete. |
| `BOX-25` | `box_25_required_evidence_readable` | From the declared source surfaces, set true only when every value required by BOX-25 was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false. |
| `BOX-25` | `box_25_required_evidence_complete` | From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false. |
| `BOX-25` | `box_25_failure_matches` | Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: return pass when at least one Shield anomaly rule or Shield alert or block event exists, warn when one required source is unavailable, only ordinary access events exist, or the event window is incomplete, and fail when complete readable evidence has no anomaly rule, alert, block, or content-access event. |
| `BOX-25` | `box_25_warning_matches` | Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: return pass when at least one Shield anomaly rule or Shield alert or block event exists, warn when one required source is unavailable, only ordinary access events exist, or the event window is incomplete, and fail when complete readable evidence has no anomaly rule, alert, block, or content-access event. |
| `BOX-25` | `box_25_compliant_matches` | Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: return pass when at least one Shield anomaly rule or Shield alert or block event exists, warn when one required source is unavailable, only ordinary access events exist, or the event window is incomplete, and fail when complete readable evidence has no anomaly rule, alert, block, or content-access event. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `BOX-01` | `requiredEvidenceReadable` | true |
| `BOX-01` | `requiredEvidenceComplete` | true |
| `BOX-02` | `requiredEvidenceReadable` | true |
| `BOX-02` | `requiredEvidenceComplete` | true |
| `BOX-03` | `requiredEvidenceReadable` | true |
| `BOX-03` | `requiredEvidenceComplete` | true |
| `BOX-04` | `requiredEvidenceReadable` | true |
| `BOX-04` | `requiredEvidenceComplete` | true |
| `BOX-05` | `requiredEvidenceReadable` | true |
| `BOX-05` | `requiredEvidenceComplete` | true |
| `BOX-06` | `requiredEvidenceReadable` | true |
| `BOX-06` | `requiredEvidenceComplete` | true |
| `BOX-07` | `requiredEvidenceReadable` | true |
| `BOX-07` | `requiredEvidenceComplete` | true |
| `BOX-08` | `requiredEvidenceReadable` | true |
| `BOX-08` | `requiredEvidenceComplete` | true |
| `BOX-09` | `requiredEvidenceReadable` | true |
| `BOX-09` | `requiredEvidenceComplete` | true |
| `BOX-10` | `requiredEvidenceReadable` | true |
| `BOX-10` | `requiredEvidenceComplete` | true |
| `BOX-11` | `requiredEvidenceReadable` | true |
| `BOX-11` | `requiredEvidenceComplete` | true |
| `BOX-12` | `requiredEvidenceReadable` | true |
| `BOX-12` | `requiredEvidenceComplete` | true |
| `BOX-13` | `requiredEvidenceReadable` | true |
| `BOX-13` | `requiredEvidenceComplete` | true |
| `BOX-14` | `requiredEvidenceReadable` | true |
| `BOX-14` | `requiredEvidenceComplete` | true |
| `BOX-15` | `requiredEvidenceReadable` | true |
| `BOX-15` | `requiredEvidenceComplete` | true |
| `BOX-16` | `requiredEvidenceReadable` | true |
| `BOX-16` | `requiredEvidenceComplete` | true |
| `BOX-17` | `requiredEvidenceReadable` | true |
| `BOX-17` | `requiredEvidenceComplete` | true |
| `BOX-18` | `requiredEvidenceReadable` | true |
| `BOX-18` | `requiredEvidenceComplete` | true |
| `BOX-19` | `requiredEvidenceReadable` | true |
| `BOX-19` | `requiredEvidenceComplete` | true |
| `BOX-20` | `requiredEvidenceReadable` | true |
| `BOX-20` | `requiredEvidenceComplete` | true |
| `BOX-21` | `requiredEvidenceReadable` | true |
| `BOX-21` | `requiredEvidenceComplete` | true |
| `BOX-22` | `requiredEvidenceReadable` | true |
| `BOX-22` | `requiredEvidenceComplete` | true |
| `BOX-23` | `requiredEvidenceReadable` | true |
| `BOX-23` | `requiredEvidenceComplete` | true |
| `BOX-24` | `requiredEvidenceReadable` | true |
| `BOX-24` | `requiredEvidenceComplete` | true |
| `BOX-25` | `requiredEvidenceReadable` | true |
| `BOX-25` | `requiredEvidenceComplete` | true |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `BOX-01` | compliant | All required source reads are complete and this derivation returns pass: return pass when enterprise SSO is required and not in testing mode, warn when it is required but testing, unused, or not exposed, and fail when it is explicitly not required. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when enterprise SSO is required and not in testing mode, warn when it is required but testing, unused, or not exposed, and fail when it is explicitly not required. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-02` | compliant | All required source reads are complete and this derivation returns pass: return fail when enterprise MFA is required but any admin or co-admin is exempt, pass when MFA is required and the complete privileged inventory has no exemption, warn for unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when both MFA and required SSO are disabled. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when enterprise MFA is required but any admin or co-admin is exempt, pass when MFA is required and the complete privileged inventory has no exemption, warn for unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when both MFA and required SSO are disabled. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-03` | compliant | All required source reads are complete and this derivation returns pass: return pass when enterprise MFA is required and the complete user inventory has no non-privileged exemption, warn for any exemption, unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when neither MFA nor required SSO is enforced. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when enterprise MFA is required and the complete user inventory has no non-privileged exemption, warn for any exemption, unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when neither MFA nor required SSO is enforced. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-04` | compliant | All required source reads are complete and this derivation returns pass: return pass when external collaboration is enterprise-only or allowlist-only with at least one readable entry, fail when unrestricted, and warn for unused, unknown, empty, unreadable, or truncated-before-first-entry allowlist evidence. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when external collaboration is enterprise-only or allowlist-only with at least one readable entry, fail when unrestricted, and warn for unused, unknown, empty, unreadable, or truncated-before-first-entry allowlist evidence. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-05` | compliant | All required source reads are complete and this derivation returns pass: return fail when any allowlist entry is a public consumer email domain, warn for truncation, stale or undated entries, exemptions, or an empty allowlist while allowlist-only mode is selected, and pass when complete entries are recent non-public domains without exemptions or no allowlist is required and none exists. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any allowlist entry is a public consumer email domain, warn for truncation, stale or undated entries, exemptions, or an empty allowlist while allowlist-only mode is selected, and pass when complete entries are recent non-public domains without exemptions or no allowlist is required and none exists. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-06` | compliant | All required source reads are complete and this derivation returns pass: return fail when shared links default to open access, pass when the default is restricted and open links are not offered, and warn when the default is restricted but open links remain available or the setting is unused or unrecognized. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when shared links default to open access, pass when the default is restricted and open links are not offered, and warn when the default is restricted but open links remain available or the setting is unused or unrecognized. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-07` | compliant | All required source reads are complete and this derivation returns pass: return pass when mandatory expiration is enabled for all shared links, warn when only public links expire or the setting is unused or absent, and fail when mandatory expiration is explicitly disabled. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when mandatory expiration is enabled for all shared links, warn when only public links expire or the setting is unused or absent, and fail when mandatory expiration is explicitly disabled. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-08` | compliant | All required source reads are complete and this derivation returns pass: always return manual because the enterprise configuration API does not expose whether passwords are required for open shared links. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-08` | noncompliant | A complete source read satisfies the fail branch of this derivation: always return manual because the enterprise configuration API does not expose whether passwords are required for open shared links. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-09` | compliant | All required source reads are complete and this derivation returns pass: return pass when enterprise watermarking is enabled, fail when explicitly disabled, and warn when the flag is unused or absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-09` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when enterprise watermarking is enabled, fail when explicitly disabled, and warn when the flag is unused or absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-09` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-09` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-10` | compliant | All required source reads are complete and this derivation returns pass: return warn when the complete device-pin inventory is empty and manual when pins exist because the API does not expose whether unpinned devices are blocked; a read that truncates before its first pin is also manual. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-10` | noncompliant | A complete source read satisfies the fail branch of this derivation: return warn when the complete device-pin inventory is empty and manual when pins exist because the API does not expose whether unpinned devices are blocked; a read that truncates before its first pin is also manual. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-10` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-10` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-11` | compliant | All required source reads are complete and this derivation returns pass: return pass when the classification template defines at least one label and fail when a readable template or a 404 proves that it defines none. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-11` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the classification template defines at least one label and fail when a readable template or a 404 proves that it defines none. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-11` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-11` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-12` | compliant | All required source reads are complete and this derivation returns pass: return pass when a complete retention-policy inventory has at least one active policy with visible assignments, warn when active policies lack assignments or any relevant inventory is truncated, and fail when a complete inventory has no active policy. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-12` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when a complete retention-policy inventory has at least one active policy with visible assignments, warn when active policies lack assignments or any relevant inventory is truncated, and fail when a complete inventory has no active policy. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-12` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-12` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-13` | compliant | All required source reads are complete and this derivation returns pass: return pass when a complete legal-hold inventory has at least one active or applying policy with visible assignments, and warn when policies or assignments are incomplete, active holds lack assignments, no hold is active, or no hold exists. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-13` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when a complete legal-hold inventory has at least one active or applying policy with visible assignments, and warn when policies or assignments are incomplete, active holds lack assignments, no hold is active, or no hold exists. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-13` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-13` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-14` | compliant | All required source reads are complete and this derivation returns pass: return pass when at least one Shield smart-access or threat-detection rule is configured and fail when a readable complete Shield configuration has none. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-14` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when at least one Shield smart-access or threat-detection rule is configured and fail when a readable complete Shield configuration has none. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-14` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-14` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-15` | compliant | All required source reads are complete and this derivation returns pass: return pass when at least one enabled information barrier has a visible segment, and warn when barriers or segments are incomplete, enabled barriers have no visible segment, no barrier is enabled, or no barrier exists. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-15` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when at least one enabled information barrier has a visible segment, and warn when barriers or segments are incomplete, enabled barriers have no visible segment, no barrier is enabled, or no barrier exists. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-15` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-15` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-16` | compliant | All required source reads are complete and this derivation returns pass: return pass when the readable enterprise admin event stream contains at least one event in the lookback and warn when it contains none; this verdict proves stream readability only and does not prove SIEM consumption. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-16` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the readable enterprise admin event stream contains at least one event in the lookback and warn when it contains none; this verdict proves stream readability only and does not prove SIEM consumption. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-16` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-16` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-17` | compliant | All required source reads are complete and this derivation returns pass: return warn when the complete count of admins plus co-admins exceeds the configured maximum and pass when it is at or below that maximum. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-17` | noncompliant | A complete source read satisfies the fail branch of this derivation: return warn when the complete count of admins plus co-admins exceeds the configured maximum and pass when it is at or below that maximum. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-17` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-17` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-18` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete user inventory has no co-admin, warn when user evidence is partial, and manual when any co-admin exists because individual co-admin permissions are not exposed. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-18` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete user inventory has no co-admin, warn when user evidence is partial, and manual when any co-admin exists because individual co-admin permissions are not exposed. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-18` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-18` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-19` | compliant | All required source reads are complete and this derivation returns pass: always return manual because app creation events and Shield integration lists do not expose the app approval policy. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-19` | noncompliant | A complete source read satisfies the fail branch of this derivation: always return manual because app creation events and Shield integration lists do not expose the app approval policy. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-19` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-19` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-20` | compliant | All required source reads are complete and this derivation returns pass: return pass when at least one managed-user custom terms record is enabled, fail when managed-user terms exist but are disabled, and fail when a complete terms inventory has no managed-user terms. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-20` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when at least one managed-user custom terms record is enabled, fail when managed-user terms exist but are disabled, and fail when a complete terms inventory has no managed-user terms. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-20` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-20` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-21` | compliant | All required source reads are complete and this derivation returns pass: return pass when minimum password length meets the configured target, weak-password prevention is enabled, and at least two of uppercase, numeric, and special-character minima are positive; warn when length is at least eight but any target is missed or the setting is unused or absent, and fail below eight. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-21` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when minimum password length meets the configured target, weak-password prevention is enabled, and at least two of uppercase, numeric, and special-character minima are positive; warn when length is at least eight but any target is missed or the setting is unused or absent, and fail below eight. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-21` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-21` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-22` | compliant | All required source reads are complete and this derivation returns pass: return fail when the base session duration or an enabled custom group duration exceeds the configured maximum, pass when every applicable duration is at or below it, and warn when a duration is unused, absent, or cannot be normalized. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-22` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when the base session duration or an enabled custom group duration exceeds the configured maximum, pass when every applicable duration is at or below it, and warn when a duration is unused, absent, or cannot be normalized. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-22` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-22` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-23` | compliant | All required source reads are complete and this derivation returns pass: always return manual because Shield IP lists do not expose whether enterprise sign-in or access-policy IP restrictions are enforced. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-23` | noncompliant | A complete source read satisfies the fail branch of this derivation: always return manual because Shield IP lists do not expose whether enterprise sign-in or access-policy IP restrictions are enforced. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-23` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-23` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-24` | compliant | All required source reads are complete and this derivation returns pass: return pass when every active human user has a successful activity event in the lookback, fail when more than 25 percent lack one, and warn when at most 25 percent lack one, no active human user exists, or user or event coverage is incomplete. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-24` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every active human user has a successful activity event in the lookback, fail when more than 25 percent lack one, and warn when at most 25 percent lack one, no active human user exists, or user or event coverage is incomplete. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-24` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-24` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `BOX-25` | compliant | All required source reads are complete and this derivation returns pass: return pass when at least one Shield anomaly rule or Shield alert or block event exists, warn when one required source is unavailable, only ordinary access events exist, or the event window is incomplete, and fail when complete readable evidence has no anomaly rule, alert, block, or content-access event. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-25` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when at least one Shield anomaly rule or Shield alert or block event exists, warn when one required source is unavailable, only ordinary access events exist, or the event window is incomplete, and fail when complete readable evidence has no anomaly rule, alert, block, or content-access event. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `BOX-25` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `BOX-25` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | SSO enforcement | IA-2 | AC.L2-3.1.1 | CC6.1 | 1.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | CPS-04 |
| 2 | 2FA for admins | IA-2(1) | IA.L2-3.5.3 | CC6.1 | 4.1 | 8.4.2 | SRG-APP-000149 | ISM-1401 | CPS-06 |
| 3 | 2FA for all users | IA-2(1) | IA.L2-3.5.3 | CC6.1 | 4.2 | 8.4.2 | SRG-APP-000149 | ISM-1401 | CPS-06 |
| 4 | External collaboration restrictions | AC-4 | AC.L2-3.1.3 | CC6.6 | 6.1 | 7.2.3 | SRG-APP-000039 | ISM-1148 | CPS-11 |
| 5 | Collaboration allowlist audit | AC-4 | AC.L2-3.1.3 | CC6.6 | 6.2 | 7.2.3 | SRG-APP-000039 | ISM-1148 | CPS-11 |
| 6 | Sharing link policies | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.3 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 7 | Shared link expiration | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.4 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 8 | Shared link password policy | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.5 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 9 | Watermarking enabled | SC-28 | SC.L2-3.13.16 | CC6.7 | 3.1 | 3.4 | SRG-APP-000231 | ISM-0457 | CPS-09 |
| 10 | Device trust and pins | IA-3 | IA.L2-3.5.1 | CC6.1 | 1.2 | 2.4 | SRG-APP-000158 | ISM-1482 | CPS-04 |
| 11 | Classification labels | MP-4 | MP.L2-3.8.5 | CC6.7 | 3.2 | 9.6.1 | SRG-APP-000231 | ISM-0272 | CPS-09 |
| 12 | Retention policies | AU-11 | AU.L2-3.3.1 | CC7.4 | 8.1 | 3.1 | SRG-APP-000515 | ISM-0859 | CPS-10 |
| 13 | Legal hold policies | AU-11 | AU.L2-3.3.1 | CC7.4 | 8.2 | 3.1 | SRG-APP-000515 | ISM-0859 | CPS-10 |
| 14 | Shield smart access policies | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.6 | 7.2.1 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 15 | Shield information barriers | AC-4 | AC.L2-3.1.3 | CC6.6 | 6.7 | 7.2.3 | SRG-APP-000039 | ISM-1148 | CPS-11 |
| 16 | Enterprise event streaming | AU-2 | AU.L2-3.3.1 | CC7.2 | 8.3 | 10.2.1 | SRG-APP-000089 | ISM-0580 | CPS-10 |
| 17 | Admin role minimization | AC-6(5) | AC.L2-3.1.5 | CC6.3 | 6.8 | 7.2.2 | SRG-APP-000340 | ISM-1507 | CPS-07 |
| 18 | Co-admin permission scoping | AC-6 | AC.L2-3.1.5 | CC6.3 | 6.9 | 7.2.2 | SRG-APP-000340 | ISM-0432 | CPS-07 |
| 19 | App approval process | CM-7(5) | CM.L2-3.4.8 | CC8.1 | 10.1 | 6.3.2 | SRG-APP-000386 | ISM-1490 | CPS-12 |
| 20 | Custom terms of service | PS-6 | AT.L2-3.2.1 | CC1.4 | 11.1 | 12.6.1 | SRG-APP-000516 | ISM-0252 | CPS-13 |
| 21 | Password policy strength | IA-5(1) | IA.L2-3.5.7 | CC6.1 | 5.1 | 8.3.6 | SRG-APP-000166 | ISM-0421 | CPS-05 |
| 22 | Session duration limits | AC-11 | AC.L2-3.1.10 | CC6.1 | 7.1 | 8.2.8 | SRG-APP-000190 | ISM-0853 | CPS-08 |
| 23 | IP allowlisting | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.1 | 1.3.2 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 24 | Inactive user detection | AC-2(3) | AC.L2-3.1.1 | CC6.2 | 7.2 | 8.1.4 | SRG-APP-000025 | ISM-1404 | CPS-07 |
| 25 | Content access monitoring | AU-6 | AU.L2-3.3.5 | CC7.2 | 8.4 | 10.6.1 | SRG-APP-000108 | ISM-0580 | CPS-10 |

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

Sensitive fields and values: client_secret, private_key, passphrase, access_token, refresh_token, authorization, login

Credential formats: Box OAuth access and refresh tokens, JWT private keys and passphrases, signed JWT assertions

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `current-user` | `projected fields consumed by the corresponding runtime assessment` |
| `enterprise-configuration` | `projected fields consumed by the corresponding runtime assessment` |
| `users` | `projected fields consumed by the corresponding runtime assessment` |
| `groups` | `projected fields consumed by the corresponding runtime assessment` |
| `events` | `projected fields consumed by the corresponding runtime assessment` |
| `device-pinners` | `projected fields consumed by the corresponding runtime assessment` |
| `retention-policies` | `projected fields consumed by the corresponding runtime assessment` |
| `retention-assignments` | `projected fields consumed by the corresponding runtime assessment` |
| `legal-hold-policies` | `projected fields consumed by the corresponding runtime assessment` |
| `legal-hold-assignments` | `projected fields consumed by the corresponding runtime assessment` |
| `shield-barriers` | `projected fields consumed by the corresponding runtime assessment` |
| `shield-barrier-segments` | `projected fields consumed by the corresponding runtime assessment` |
| `shield-lists` | `projected fields consumed by the corresponding runtime assessment` |
| `allowlist-entries` | `projected fields consumed by the corresponding runtime assessment` |
| `allowlist-exempt-targets` | `projected fields consumed by the corresponding runtime assessment` |
| `metadata-templates` | `projected fields consumed by the corresponding runtime assessment` |
| `classification-template` | `projected fields consumed by the corresponding runtime assessment` |
| `terms-of-service` | `projected fields consumed by the corresponding runtime assessment` |

## Export layout

Required paths:

- `core_data/access_check.json`
- `core_data/enterprise_configuration.json`
- `core_data/current_user.json`
- `core_data/users.json`
- `core_data/groups.json`
- `core_data/enterprise_events_activity.json`
- `core_data/enterprise_events_sharing.json`
- `core_data/enterprise_events_shield.json`
- `core_data/device_pinners.json`
- `core_data/classification_template.json`
- `core_data/metadata_templates.json`
- `core_data/retention_policies.json`
- `core_data/retention_policy_assignments.json`
- `core_data/legal_hold_policies.json`
- `core_data/legal_hold_policy_assignments.json`
- `core_data/shield_information_barriers.json`
- `core_data/shield_information_barrier_segments.json`
- `core_data/shield_lists.json`
- `core_data/collaboration_allowlist_entries.json`
- `core_data/collaboration_allowlist_exempt_targets.json`
- `core_data/terms_of_services.json`
- `core_data/collection_status.json`
- `analysis/identity_access.json`
- `analysis/sharing_collaboration.json`
- `analysis/data_governance.json`
- `analysis/shield_monitoring.json`
- `analysis/findings.json`
- `analysis/summary.json`
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
- `metadata.json`

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `core_data/access_check.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/enterprise_configuration.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/current_user.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/users.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/groups.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/enterprise_events_activity.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/enterprise_events_sharing.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/enterprise_events_shield.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/device_pinners.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/classification_template.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/metadata_templates.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/retention_policies.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/retention_policy_assignments.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/legal_hold_policies.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/legal_hold_policy_assignments.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/shield_information_barriers.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/shield_information_barrier_segments.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/shield_lists.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/collaboration_allowlist_entries.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/collaboration_allowlist_exempt_targets.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/terms_of_services.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/collection_status.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/identity_access.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/sharing_collaboration.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/data_governance.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/shield_monitoring.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/findings.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/summary.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `compliance/executive_summary.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/unified_compliance_matrix.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/fedramp/fedramp_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cmmc/cmmc_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/soc2/soc2_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cis/cis_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/pci_dss/pci_dss_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/disa_stig/stig_compliance_checklist.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/irap/irap_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/ismap/ismap_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `QUICK_REFERENCE.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `metadata.json` | json | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 JSON with two-space indentation and a trailing newline. |
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

Overwrite policy: Allocate a new <enterprise>-audit-bundle directory and numeric suffix without overwriting either directory or archive.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Create <allocated-directory>.zip beside the allocated enterprise audit directory.
