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
| role | `Box application access to enterprise users, groups, events, policies, legal holds, terms, and enterprise configuration` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `Box Shield or governance plan entitlements for gated surfaces` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `enterprise-users` | HTTP | `GET /2.0/users` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `login`, `role`, `status`, `is_exempt_from_login_verification`, `is_external_collab_restricted` | [Official documentation](https://developer.box.com/reference/get-users/) |
| `enterprise-config` | HTTP | `GET /2.0/enterprise/configuration` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `user_settings`, `security`, `content_and_sharing` | [Official documentation](https://developer.box.com/reference/get-enterprise-configuration/) |
| `enterprise-events` | HTTP | `GET /2.0/events` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `event_id`, `event_type`, `created_at`, `created_by`, `source`, `additional_details` | [Official documentation](https://developer.box.com/reference/get-events/) |
| `retention-policies` | HTTP | `GET /2.0/retention_policies` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `policy_name`, `policy_type`, `retention_length`, `status` | [Official documentation](https://developer.box.com/reference/get-retention-policies/) |
| `legal-hold-policies` | HTTP | `GET /2.0/legal_hold_policies` | Box Content API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `policy_name`, `status`, `created_at` | [Official documentation](https://developer.box.com/reference/get-legal-hold-policies/) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `enterprise-users` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `enterprise-users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `enterprise-users` | response | A JSON object or list containing only the documented id, login, role, status, is_exempt_from_login_verification, is_external_collab_restricted members consumed by verdicts. | yes |
| `enterprise-config` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `enterprise-config` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `enterprise-config` | response | A JSON object or list containing only the documented user_settings, security, content_and_sharing members consumed by verdicts. | yes |
| `enterprise-events` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `enterprise-events` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `enterprise-events` | response | A JSON object or list containing only the documented event_id, event_type, created_at, created_by, source, additional_details members consumed by verdicts. | yes |
| `retention-policies` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `retention-policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `retention-policies` | response | A JSON object or list containing only the documented id, policy_name, policy_type, retention_length, status members consumed by verdicts. | yes |
| `legal-hold-policies` | client | Use the configured Box Content API origin; never follow a server link to a different origin. | yes |
| `legal-hold-policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `legal-hold-policies` | response | A JSON object or list containing only the documented id, policy_name, status, created_at members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `next_marker`, `offset`, `total_count`, `next_stream_position` | 100 | caller limit | none | Offset totals and event stream positions are checked independently; a remaining marker or total above seen records is truncated. | No next marker or total reached; Configured item cap; Fixed assignment cap; Repeated marker or stream position; Empty page with continuation; Event page budget |

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
| `BOX-01` | critical | `box_assess_identity_access` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for SSO enforcement returns pass from complete, readable evidence. | The portable derivation for SSO enforcement returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for SSO enforcement returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for SSO enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-02` | critical | `box_assess_identity_access` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for 2FA for admins returns pass from complete, readable evidence. | The portable derivation for 2FA for admins returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for 2FA for admins returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for 2FA for admins is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-03` | high | `box_assess_identity_access` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for 2FA for all users returns pass from complete, readable evidence. | The portable derivation for 2FA for all users returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for 2FA for all users returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for 2FA for all users is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-04` | high | `box_assess_sharing_collaboration` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for External collaboration restrictions returns pass from complete, readable evidence. | The portable derivation for External collaboration restrictions returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for External collaboration restrictions returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for External collaboration restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-05` | medium | `box_assess_sharing_collaboration` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Collaboration allowlist audit returns pass from complete, readable evidence. | The portable derivation for Collaboration allowlist audit returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Collaboration allowlist audit returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Collaboration allowlist audit is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-06` | high | `box_assess_sharing_collaboration` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Sharing link policies returns pass from complete, readable evidence. | The portable derivation for Sharing link policies returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Sharing link policies returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Sharing link policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-07` | medium | `box_assess_sharing_collaboration` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Shared link expiration returns pass from complete, readable evidence. | The portable derivation for Shared link expiration returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Shared link expiration returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Shared link expiration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-08` | medium | `box_assess_sharing_collaboration` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Shared link password policy returns pass from complete, readable evidence. | The portable derivation for Shared link password policy returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Shared link password policy returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Shared link password policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-09` | medium | `box_assess_sharing_collaboration` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Watermarking enabled returns pass from complete, readable evidence. | The portable derivation for Watermarking enabled returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Watermarking enabled returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Watermarking enabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-10` | medium | `box_assess_data_governance` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Device trust and pins returns pass from complete, readable evidence. | The portable derivation for Device trust and pins returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Device trust and pins returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Device trust and pins is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-11` | medium | `box_assess_data_governance` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Classification labels returns pass from complete, readable evidence. | The portable derivation for Classification labels returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Classification labels returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Classification labels is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-12` | medium | `box_assess_data_governance` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Retention policies returns pass from complete, readable evidence. | The portable derivation for Retention policies returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Retention policies returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Retention policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-13` | medium | `box_assess_data_governance` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Legal hold policies returns pass from complete, readable evidence. | The portable derivation for Legal hold policies returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Legal hold policies returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Legal hold policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-14` | high | `box_assess_shield_monitoring` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Shield smart access policies returns pass from complete, readable evidence. | The portable derivation for Shield smart access policies returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Shield smart access policies returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Shield smart access policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-15` | medium | `box_assess_shield_monitoring` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Shield information barriers returns pass from complete, readable evidence. | The portable derivation for Shield information barriers returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Shield information barriers returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Shield information barriers is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-16` | high | `box_assess_shield_monitoring` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Enterprise event streaming returns pass from complete, readable evidence. | The portable derivation for Enterprise event streaming returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Enterprise event streaming returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Enterprise event streaming is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-17` | high | `box_assess_identity_access` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Admin role minimization returns pass from complete, readable evidence. | The portable derivation for Admin role minimization returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Admin role minimization returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Admin role minimization is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-18` | medium | `box_assess_identity_access` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Co-admin permission scoping returns pass from complete, readable evidence. | The portable derivation for Co-admin permission scoping returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Co-admin permission scoping returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Co-admin permission scoping is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-19` | medium | `box_assess_sharing_collaboration` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for App approval process returns pass from complete, readable evidence. | The portable derivation for App approval process returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for App approval process returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for App approval process is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-20` | medium | `box_assess_sharing_collaboration` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Custom terms of service returns pass from complete, readable evidence. | The portable derivation for Custom terms of service returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Custom terms of service returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Custom terms of service is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-21` | high | `box_assess_identity_access` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Password policy strength returns pass from complete, readable evidence. | The portable derivation for Password policy strength returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Password policy strength returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Password policy strength is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-22` | medium | `box_assess_identity_access` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Session duration limits returns pass from complete, readable evidence. | The portable derivation for Session duration limits returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Session duration limits returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Session duration limits is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-23` | medium | `box_assess_identity_access` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for IP allowlisting returns pass from complete, readable evidence. | The portable derivation for IP allowlisting returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for IP allowlisting returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for IP allowlisting is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-24` | medium | `box_assess_identity_access` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Inactive user detection returns pass from complete, readable evidence. | The portable derivation for Inactive user detection returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Inactive user detection returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Inactive user detection is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `BOX-25` | high | `box_assess_shield_monitoring` | `enterprise-users`, `enterprise-config`, `enterprise-events`, `retention-policies`, `legal-hold-policies` | `decision_status` | The portable derivation for Content access monitoring returns pass from complete, readable evidence. | The portable derivation for Content access monitoring returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Content access monitoring returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Content access monitoring is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `BOX-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-06` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-06` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-06` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-06` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-07` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-07` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-07` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-07` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-08` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-08` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-08` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-08` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-09` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-09` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-09` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-09` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-10` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-10` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-10` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-10` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-11` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-11` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-11` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-11` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-12` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-12` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-12` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-12` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-13` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-13` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-13` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-13` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-14` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-14` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-14` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-14` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-15` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-15` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-15` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-15` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-16` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-16` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-16` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-16` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-17` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-17` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-17` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-17` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-18` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-18` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-18` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-18` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-19` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-19` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-19` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-19` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-20` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-20` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-20` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-20` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-21` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-21` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-21` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-21` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-22` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-22` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-22` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-22` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-23` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-23` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-23` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-23` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-24` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-24` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-24` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-24` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `BOX-25` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `BOX-25` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `BOX-25` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `BOX-25` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `BOX-01` | `decision_status` | Using complete source cardinalities, return pass when enterprise SSO is required and not in testing mode, warn when it is required but testing, unused, or not exposed, and fail when it is explicitly not required. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-02` | `decision_status` | Using complete source cardinalities, return fail when enterprise MFA is required but any admin or co-admin is exempt, pass when MFA is required and the complete privileged inventory has no exemption, warn for unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when both MFA and required SSO are disabled. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-03` | `decision_status` | Using complete source cardinalities, return pass when enterprise MFA is required and the complete user inventory has no non-privileged exemption, warn for any exemption, unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when neither MFA nor required SSO is enforced. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-04` | `decision_status` | Using complete source cardinalities, return pass when external collaboration is enterprise-only or allowlist-only with at least one readable entry, fail when unrestricted, and warn for unused, unknown, empty, unreadable, or truncated-before-first-entry allowlist evidence. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-05` | `decision_status` | Using complete source cardinalities, return fail when any allowlist entry is a public consumer email domain, warn for truncation, stale or undated entries, exemptions, or an empty allowlist while allowlist-only mode is selected, and pass when complete entries are recent non-public domains without exemptions or no allowlist is required and none exists. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-06` | `decision_status` | Using complete source cardinalities, return fail when shared links default to open access, pass when the default is restricted and open links are not offered, and warn when the default is restricted but open links remain available or the setting is unused or unrecognized. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-07` | `decision_status` | Using complete source cardinalities, return pass when mandatory expiration is enabled for all shared links, warn when only public links expire or the setting is unused or absent, and fail when mandatory expiration is explicitly disabled. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-08` | `decision_status` | Using complete source cardinalities, always return manual because the enterprise configuration API does not expose whether passwords are required for open shared links. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-09` | `decision_status` | Using complete source cardinalities, return pass when enterprise watermarking is enabled, fail when explicitly disabled, and warn when the flag is unused or absent. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-10` | `decision_status` | Using complete source cardinalities, return warn when the complete device-pin inventory is empty and manual when pins exist because the API does not expose whether unpinned devices are blocked; a read that truncates before its first pin is also manual. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-11` | `decision_status` | Using complete source cardinalities, return pass when the classification template defines at least one label and fail when a readable template or a 404 proves that it defines none. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-12` | `decision_status` | Using complete source cardinalities, return pass when a complete retention-policy inventory has at least one active policy with visible assignments, warn when active policies lack assignments or any relevant inventory is truncated, and fail when a complete inventory has no active policy. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-13` | `decision_status` | Using complete source cardinalities, return pass when a complete legal-hold inventory has at least one active or applying policy with visible assignments, and warn when policies or assignments are incomplete, active holds lack assignments, no hold is active, or no hold exists. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-14` | `decision_status` | Using complete source cardinalities, return pass when at least one Shield smart-access or threat-detection rule is configured and fail when a readable complete Shield configuration has none. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-15` | `decision_status` | Using complete source cardinalities, return pass when at least one enabled information barrier has a visible segment, and warn when barriers or segments are incomplete, enabled barriers have no visible segment, no barrier is enabled, or no barrier exists. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-16` | `decision_status` | Using complete source cardinalities, return pass when the readable enterprise admin event stream contains at least one event in the lookback and warn when it contains none; this verdict proves stream readability only and does not prove SIEM consumption. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-17` | `decision_status` | Using complete source cardinalities, return warn when the complete count of admins plus co-admins exceeds the configured maximum and pass when it is at or below that maximum. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-18` | `decision_status` | Using complete source cardinalities, return pass when the complete user inventory has no co-admin and manual when any co-admin exists because individual co-admin permissions are not exposed. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-19` | `decision_status` | Using complete source cardinalities, always return manual because app creation events and Shield integration lists do not expose the app approval policy. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-20` | `decision_status` | Using complete source cardinalities, return pass when at least one managed-user custom terms record is enabled, fail when managed-user terms exist but are disabled, and fail when a complete terms inventory has no managed-user terms. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-21` | `decision_status` | Using complete source cardinalities, return pass when minimum password length meets the configured target, weak-password prevention is enabled, and at least two of uppercase, numeric, and special-character minima are positive; warn when length is at least eight but any target is missed or the setting is unused or absent, and fail below eight. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-22` | `decision_status` | Using complete source cardinalities, return fail when the base session duration or an enabled custom group duration exceeds the configured maximum, pass when every applicable duration is at or below it, and warn when a duration is unused, absent, or cannot be normalized. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-23` | `decision_status` | Using complete source cardinalities, always return manual because Shield IP lists do not expose whether enterprise sign-in or access-policy IP restrictions are enforced. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-24` | `decision_status` | Using complete source cardinalities, return pass when every active human user has a successful activity event in the lookback, fail when more than 25 percent lack one, and warn when at most 25 percent lack one, no active human user exists, or user or event coverage is incomplete. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `BOX-25` | `decision_status` | Using complete source cardinalities, return pass when at least one Shield anomaly rule or Shield alert or block event exists, warn when one required source is unavailable, only ordinary access events exist, or the event window is incomplete, and fail when complete readable evidence has no anomaly rule, alert, block, or content-access event. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `BOX-01` | `passStatus` | pass |
| `BOX-01` | `warnStatus` | warn |
| `BOX-01` | `failStatus` | fail |
| `BOX-01` | `manualStatus` | manual |
| `BOX-02` | `passStatus` | pass |
| `BOX-02` | `warnStatus` | warn |
| `BOX-02` | `failStatus` | fail |
| `BOX-02` | `manualStatus` | manual |
| `BOX-03` | `passStatus` | pass |
| `BOX-03` | `warnStatus` | warn |
| `BOX-03` | `failStatus` | fail |
| `BOX-03` | `manualStatus` | manual |
| `BOX-04` | `passStatus` | pass |
| `BOX-04` | `warnStatus` | warn |
| `BOX-04` | `failStatus` | fail |
| `BOX-04` | `manualStatus` | manual |
| `BOX-05` | `passStatus` | pass |
| `BOX-05` | `warnStatus` | warn |
| `BOX-05` | `failStatus` | fail |
| `BOX-05` | `manualStatus` | manual |
| `BOX-06` | `passStatus` | pass |
| `BOX-06` | `warnStatus` | warn |
| `BOX-06` | `failStatus` | fail |
| `BOX-06` | `manualStatus` | manual |
| `BOX-07` | `passStatus` | pass |
| `BOX-07` | `warnStatus` | warn |
| `BOX-07` | `failStatus` | fail |
| `BOX-07` | `manualStatus` | manual |
| `BOX-08` | `passStatus` | pass |
| `BOX-08` | `warnStatus` | warn |
| `BOX-08` | `failStatus` | fail |
| `BOX-08` | `manualStatus` | manual |
| `BOX-09` | `passStatus` | pass |
| `BOX-09` | `warnStatus` | warn |
| `BOX-09` | `failStatus` | fail |
| `BOX-09` | `manualStatus` | manual |
| `BOX-10` | `passStatus` | pass |
| `BOX-10` | `warnStatus` | warn |
| `BOX-10` | `failStatus` | fail |
| `BOX-10` | `manualStatus` | manual |
| `BOX-11` | `passStatus` | pass |
| `BOX-11` | `warnStatus` | warn |
| `BOX-11` | `failStatus` | fail |
| `BOX-11` | `manualStatus` | manual |
| `BOX-12` | `passStatus` | pass |
| `BOX-12` | `warnStatus` | warn |
| `BOX-12` | `failStatus` | fail |
| `BOX-12` | `manualStatus` | manual |
| `BOX-13` | `passStatus` | pass |
| `BOX-13` | `warnStatus` | warn |
| `BOX-13` | `failStatus` | fail |
| `BOX-13` | `manualStatus` | manual |
| `BOX-14` | `passStatus` | pass |
| `BOX-14` | `warnStatus` | warn |
| `BOX-14` | `failStatus` | fail |
| `BOX-14` | `manualStatus` | manual |
| `BOX-15` | `passStatus` | pass |
| `BOX-15` | `warnStatus` | warn |
| `BOX-15` | `failStatus` | fail |
| `BOX-15` | `manualStatus` | manual |
| `BOX-16` | `passStatus` | pass |
| `BOX-16` | `warnStatus` | warn |
| `BOX-16` | `failStatus` | fail |
| `BOX-16` | `manualStatus` | manual |
| `BOX-17` | `passStatus` | pass |
| `BOX-17` | `warnStatus` | warn |
| `BOX-17` | `failStatus` | fail |
| `BOX-17` | `manualStatus` | manual |
| `BOX-18` | `passStatus` | pass |
| `BOX-18` | `warnStatus` | warn |
| `BOX-18` | `failStatus` | fail |
| `BOX-18` | `manualStatus` | manual |
| `BOX-19` | `passStatus` | pass |
| `BOX-19` | `warnStatus` | warn |
| `BOX-19` | `failStatus` | fail |
| `BOX-19` | `manualStatus` | manual |
| `BOX-20` | `passStatus` | pass |
| `BOX-20` | `warnStatus` | warn |
| `BOX-20` | `failStatus` | fail |
| `BOX-20` | `manualStatus` | manual |
| `BOX-21` | `passStatus` | pass |
| `BOX-21` | `warnStatus` | warn |
| `BOX-21` | `failStatus` | fail |
| `BOX-21` | `manualStatus` | manual |
| `BOX-22` | `passStatus` | pass |
| `BOX-22` | `warnStatus` | warn |
| `BOX-22` | `failStatus` | fail |
| `BOX-22` | `manualStatus` | manual |
| `BOX-23` | `passStatus` | pass |
| `BOX-23` | `warnStatus` | warn |
| `BOX-23` | `failStatus` | fail |
| `BOX-23` | `manualStatus` | manual |
| `BOX-24` | `passStatus` | pass |
| `BOX-24` | `warnStatus` | warn |
| `BOX-24` | `failStatus` | fail |
| `BOX-24` | `manualStatus` | manual |
| `BOX-25` | `passStatus` | pass |
| `BOX-25` | `warnStatus` | warn |
| `BOX-25` | `failStatus` | fail |
| `BOX-25` | `manualStatus` | manual |

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
| `BOX-18` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete user inventory has no co-admin and manual when any co-admin exists because individual co-admin permissions are not exposed. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `BOX-18` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete user inventory has no co-admin and manual when any co-admin exists because individual co-admin permissions are not exposed. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
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
| 1 | SSO enforcement | - | - | - | - | - | - | - | - |
| 2 | 2FA for admins | - | - | - | - | - | - | - | - |
| 3 | 2FA for all users | - | - | - | - | - | - | - | - |
| 4 | External collaboration restrictions | - | - | - | - | - | - | - | - |
| 5 | Collaboration allowlist audit | - | - | - | - | - | - | - | - |
| 6 | Sharing link policies | - | - | - | - | - | - | - | - |
| 7 | Shared link expiration | - | - | - | - | - | - | - | - |
| 8 | Shared link password policy | - | - | - | - | - | - | - | - |
| 9 | Watermarking enabled | - | - | - | - | - | - | - | - |
| 10 | Device trust and pins | - | - | - | - | - | - | - | - |
| 11 | Classification labels | - | - | - | - | - | - | - | - |
| 12 | Retention policies | - | - | - | - | - | - | - | - |
| 13 | Legal hold policies | - | - | - | - | - | - | - | - |
| 14 | Shield smart access policies | - | - | - | - | - | - | - | - |
| 15 | Shield information barriers | - | - | - | - | - | - | - | - |
| 16 | Enterprise event streaming | - | - | - | - | - | - | - | - |
| 17 | Admin role minimization | - | - | - | - | - | - | - | - |
| 18 | Co-admin permission scoping | - | - | - | - | - | - | - | - |
| 19 | App approval process | - | - | - | - | - | - | - | - |
| 20 | Custom terms of service | - | - | - | - | - | - | - | - |
| 21 | Password policy strength | - | - | - | - | - | - | - | - |
| 22 | Session duration limits | - | - | - | - | - | - | - | - |
| 23 | IP allowlisting | - | - | - | - | - | - | - | - |
| 24 | Inactive user detection | - | - | - | - | - | - | - | - |
| 25 | Content access monitoring | - | - | - | - | - | - | - | - |

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
| `enterprise-users` | `id`, `login`, `role`, `status`, `is_exempt_from_login_verification`, `is_external_collab_restricted` |
| `enterprise-config` | `user_settings`, `security`, `content_and_sharing` |
| `enterprise-events` | `event_id`, `event_type`, `created_at`, `created_by`, `source`, `additional_details` |
| `retention-policies` | `id`, `policy_name`, `policy_type`, `retention_length`, `status` |
| `legal-hold-policies` | `id`, `policy_name`, `status`, `created_at` |

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

Archive pairing: Create box-audit.zip beside the allocated box-audit directory, applying the same suffix to both.
