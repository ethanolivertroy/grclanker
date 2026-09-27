---
slug: "salesforce-sec-inspector"
name: "Salesforce Security Inspector"
vendor: "Salesforce"
category: "crm-and-business-applications"
language: "language-neutral"
status: "generated"
version: "1.0.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# Salesforce Security Inspector

Portable contract for the shipped Salesforce platform, identity, data-protection, and monitoring assessments.

## Purpose

Inspect Salesforce organization security, identity permissions, data protection, and monitoring configuration through read-only REST, Tooling, and Metadata API evidence.

## Design guidance

Keep the three API surfaces and their permissions distinct. Population sanity checks are mandatory for user, profile, permission-set, and MFA conclusions. A zero-row response from a permission-limited view is unknown, not compliant.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- REST, Tooling SOQL, and synchronous Metadata API reads retain separate permission and pagination states; one readable surface does not substitute for another denied dependency.
- Profile and user verdicts require population sanity gates: zero standard users, unresolved sensitive profiles, row caps, or partial profile metadata cannot pass.
- SOQL nextRecordsUrl values are followed only on the configured Salesforce instance origin without user information; rejected links stop truncated.
- Interactive authorization code flow, geolocation baselines, and several policy surfaces are not read.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `salesforce_check_access` | Validate read-only Salesforce access across OAuth session, Organization, limits, Security Health Check, SecuritySettings metadata, users, profiles, permission sets, login history, setup audit trail, connected apps, and event log files, and report likely missing permissions. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `salesforce_assess_platform_security` | Assess Salesforce Health Check score, session timeout, password policy, trusted IP ranges, My Domain login policy, clickjack protection, and CSRF protection (controls 1, 2, 3, 5, 18, 19, 20) via the Tooling API and Metadata API readMetadata. | `SF-01`, `SF-02`, `SF-03`, `SF-05`, `SF-18`, `SF-19`, `SF-20` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `salesforce_assess_identity_access` | Assess Salesforce MFA enforcement and enrollment, login hour restrictions, API access controls, elevated permission sets and assignments, administrator profiles, and guest user access (controls 4, 6, 7, 9, 10, 13). | `SF-04`, `SF-06`, `SF-07`, `SF-09`, `SF-10`, `SF-13` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `salesforce_assess_data_protection` | Assess Salesforce field-level security on sensitive fields, organization-wide sharing defaults, Shield Platform Encryption tenant secrets, and certificate expiry (controls 8, 12, 16, 17). | `SF-08`, `SF-12`, `SF-16`, `SF-17` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `salesforce_assess_monitoring_integrations` | Assess Salesforce connected app OAuth policies and token usage, login history forensics, setup audit trail high-risk changes, and Event Monitoring availability (controls 11, 14, 15). | `SF-11`, `SF-14`, `SF-15` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `salesforce_export_audit_bundle` | Export a Salesforce audit package with projected and redacted API snapshots (core_data/, with not-collected markers for denied datasets), normalized findings (analysis/), executive summary, unified compliance matrix, per-framework reports (compliance/), QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a zip archive. | `SF-01`, `SF-02`, `SF-03`, `SF-04`, `SF-05`, `SF-06`, `SF-07`, `SF-08`, `SF-09`, `SF-10`, `SF-11`, `SF-12`, `SF-13`, `SF-14`, `SF-15`, `SF-16`, `SF-17`, `SF-18`, `SF-19`, `SF-20` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `salesforce_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance_url` | string | no | Salesforce instance or My Domain URL, for example https://acme.my.salesforce.com. Defaults to SF_INSTANCE_URL. |
| `login_url` | string | no | OAuth login host. Defaults to SF_LOGIN_URL, else https://test.salesforce.com for sandboxes or https://login.salesforce.com. |
| `username` | string | no | Salesforce username for JWT bearer or username-password flows. Defaults to SF_USERNAME. |
| `password` | string | no | Password for the username-password flow. Defaults to SF_PASSWORD. |
| `security_token` | string | no | Security token appended to the password. Defaults to SF_SECURITY_TOKEN. |
| `consumer_key` | string | no | Connected app consumer key (client_id). Defaults to SF_CONSUMER_KEY. |
| `consumer_secret` | string | no | Connected app consumer secret. Defaults to SF_CONSUMER_SECRET. |
| `private_key_file` | string | no | PEM private key path for the JWT bearer flow. Defaults to SF_PRIVATE_KEY_FILE. |
| `refresh_token` | string | no | OAuth refresh token from a prior authorization code grant. Defaults to SF_REFRESH_TOKEN. |
| `access_token` | string | no | Pre-issued access token (requires instance_url). Defaults to SF_ACCESS_TOKEN. |
| `credentials_file` | string | no | JSON credentials file with grant_type jwt-bearer, password, or authorization_code. Defaults to SF_CREDENTIALS_FILE. |
| `api_version` | string | no | Salesforce API version. Defaults to 64.0. |
| `sandbox` | boolean | no | Force the sandbox login host https://test.salesforce.com. Defaults to SF_SANDBOX or detection from the instance URL. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |

#### `salesforce_assess_platform_security`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance_url` | string | no | Salesforce instance or My Domain URL, for example https://acme.my.salesforce.com. Defaults to SF_INSTANCE_URL. |
| `login_url` | string | no | OAuth login host. Defaults to SF_LOGIN_URL, else https://test.salesforce.com for sandboxes or https://login.salesforce.com. |
| `username` | string | no | Salesforce username for JWT bearer or username-password flows. Defaults to SF_USERNAME. |
| `password` | string | no | Password for the username-password flow. Defaults to SF_PASSWORD. |
| `security_token` | string | no | Security token appended to the password. Defaults to SF_SECURITY_TOKEN. |
| `consumer_key` | string | no | Connected app consumer key (client_id). Defaults to SF_CONSUMER_KEY. |
| `consumer_secret` | string | no | Connected app consumer secret. Defaults to SF_CONSUMER_SECRET. |
| `private_key_file` | string | no | PEM private key path for the JWT bearer flow. Defaults to SF_PRIVATE_KEY_FILE. |
| `refresh_token` | string | no | OAuth refresh token from a prior authorization code grant. Defaults to SF_REFRESH_TOKEN. |
| `access_token` | string | no | Pre-issued access token (requires instance_url). Defaults to SF_ACCESS_TOKEN. |
| `credentials_file` | string | no | JSON credentials file with grant_type jwt-bearer, password, or authorization_code. Defaults to SF_CREDENTIALS_FILE. |
| `api_version` | string | no | Salesforce API version. Defaults to 64.0. |
| `sandbox` | boolean | no | Force the sandbox login host https://test.salesforce.com. Defaults to SF_SANDBOX or detection from the instance URL. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `record_limit` | number | no | Maximum records to read per SOQL query before recording truncation. Defaults to 2000. |

#### `salesforce_assess_identity_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance_url` | string | no | Salesforce instance or My Domain URL, for example https://acme.my.salesforce.com. Defaults to SF_INSTANCE_URL. |
| `login_url` | string | no | OAuth login host. Defaults to SF_LOGIN_URL, else https://test.salesforce.com for sandboxes or https://login.salesforce.com. |
| `username` | string | no | Salesforce username for JWT bearer or username-password flows. Defaults to SF_USERNAME. |
| `password` | string | no | Password for the username-password flow. Defaults to SF_PASSWORD. |
| `security_token` | string | no | Security token appended to the password. Defaults to SF_SECURITY_TOKEN. |
| `consumer_key` | string | no | Connected app consumer key (client_id). Defaults to SF_CONSUMER_KEY. |
| `consumer_secret` | string | no | Connected app consumer secret. Defaults to SF_CONSUMER_SECRET. |
| `private_key_file` | string | no | PEM private key path for the JWT bearer flow. Defaults to SF_PRIVATE_KEY_FILE. |
| `refresh_token` | string | no | OAuth refresh token from a prior authorization code grant. Defaults to SF_REFRESH_TOKEN. |
| `access_token` | string | no | Pre-issued access token (requires instance_url). Defaults to SF_ACCESS_TOKEN. |
| `credentials_file` | string | no | JSON credentials file with grant_type jwt-bearer, password, or authorization_code. Defaults to SF_CREDENTIALS_FILE. |
| `api_version` | string | no | Salesforce API version. Defaults to 64.0. |
| `sandbox` | boolean | no | Force the sandbox login host https://test.salesforce.com. Defaults to SF_SANDBOX or detection from the instance URL. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `record_limit` | number | no | Maximum records to read per SOQL query before recording truncation. Defaults to 2000. |
| `max_admins` | number | no | Maximum acceptable administrator-class users or elevated assignees before failing. Defaults to 5. |
| `stale_login_days` | number | no | Days without login after which an administrator is stale. Defaults to 90. |

#### `salesforce_assess_data_protection`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance_url` | string | no | Salesforce instance or My Domain URL, for example https://acme.my.salesforce.com. Defaults to SF_INSTANCE_URL. |
| `login_url` | string | no | OAuth login host. Defaults to SF_LOGIN_URL, else https://test.salesforce.com for sandboxes or https://login.salesforce.com. |
| `username` | string | no | Salesforce username for JWT bearer or username-password flows. Defaults to SF_USERNAME. |
| `password` | string | no | Password for the username-password flow. Defaults to SF_PASSWORD. |
| `security_token` | string | no | Security token appended to the password. Defaults to SF_SECURITY_TOKEN. |
| `consumer_key` | string | no | Connected app consumer key (client_id). Defaults to SF_CONSUMER_KEY. |
| `consumer_secret` | string | no | Connected app consumer secret. Defaults to SF_CONSUMER_SECRET. |
| `private_key_file` | string | no | PEM private key path for the JWT bearer flow. Defaults to SF_PRIVATE_KEY_FILE. |
| `refresh_token` | string | no | OAuth refresh token from a prior authorization code grant. Defaults to SF_REFRESH_TOKEN. |
| `access_token` | string | no | Pre-issued access token (requires instance_url). Defaults to SF_ACCESS_TOKEN. |
| `credentials_file` | string | no | JSON credentials file with grant_type jwt-bearer, password, or authorization_code. Defaults to SF_CREDENTIALS_FILE. |
| `api_version` | string | no | Salesforce API version. Defaults to 64.0. |
| `sandbox` | boolean | no | Force the sandbox login host https://test.salesforce.com. Defaults to SF_SANDBOX or detection from the instance URL. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `record_limit` | number | no | Maximum records to read per SOQL query before recording truncation. Defaults to 2000. |
| `certificate_expiry_warning_days` | number | no | Warn when a certificate expires within this many days. Defaults to 30. |

#### `salesforce_assess_monitoring_integrations`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance_url` | string | no | Salesforce instance or My Domain URL, for example https://acme.my.salesforce.com. Defaults to SF_INSTANCE_URL. |
| `login_url` | string | no | OAuth login host. Defaults to SF_LOGIN_URL, else https://test.salesforce.com for sandboxes or https://login.salesforce.com. |
| `username` | string | no | Salesforce username for JWT bearer or username-password flows. Defaults to SF_USERNAME. |
| `password` | string | no | Password for the username-password flow. Defaults to SF_PASSWORD. |
| `security_token` | string | no | Security token appended to the password. Defaults to SF_SECURITY_TOKEN. |
| `consumer_key` | string | no | Connected app consumer key (client_id). Defaults to SF_CONSUMER_KEY. |
| `consumer_secret` | string | no | Connected app consumer secret. Defaults to SF_CONSUMER_SECRET. |
| `private_key_file` | string | no | PEM private key path for the JWT bearer flow. Defaults to SF_PRIVATE_KEY_FILE. |
| `refresh_token` | string | no | OAuth refresh token from a prior authorization code grant. Defaults to SF_REFRESH_TOKEN. |
| `access_token` | string | no | Pre-issued access token (requires instance_url). Defaults to SF_ACCESS_TOKEN. |
| `credentials_file` | string | no | JSON credentials file with grant_type jwt-bearer, password, or authorization_code. Defaults to SF_CREDENTIALS_FILE. |
| `api_version` | string | no | Salesforce API version. Defaults to 64.0. |
| `sandbox` | boolean | no | Force the sandbox login host https://test.salesforce.com. Defaults to SF_SANDBOX or detection from the instance URL. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `record_limit` | number | no | Maximum records to read per SOQL query before recording truncation. Defaults to 2000. |
| `login_history_days` | number | no | Login history lookback window in days. Defaults to 30. |
| `audit_trail_days` | number | no | Setup audit trail lookback window in days (max 180). Defaults to 90. |

#### `salesforce_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance_url` | string | no | Salesforce instance or My Domain URL, for example https://acme.my.salesforce.com. Defaults to SF_INSTANCE_URL. |
| `login_url` | string | no | OAuth login host. Defaults to SF_LOGIN_URL, else https://test.salesforce.com for sandboxes or https://login.salesforce.com. |
| `username` | string | no | Salesforce username for JWT bearer or username-password flows. Defaults to SF_USERNAME. |
| `password` | string | no | Password for the username-password flow. Defaults to SF_PASSWORD. |
| `security_token` | string | no | Security token appended to the password. Defaults to SF_SECURITY_TOKEN. |
| `consumer_key` | string | no | Connected app consumer key (client_id). Defaults to SF_CONSUMER_KEY. |
| `consumer_secret` | string | no | Connected app consumer secret. Defaults to SF_CONSUMER_SECRET. |
| `private_key_file` | string | no | PEM private key path for the JWT bearer flow. Defaults to SF_PRIVATE_KEY_FILE. |
| `refresh_token` | string | no | OAuth refresh token from a prior authorization code grant. Defaults to SF_REFRESH_TOKEN. |
| `access_token` | string | no | Pre-issued access token (requires instance_url). Defaults to SF_ACCESS_TOKEN. |
| `credentials_file` | string | no | JSON credentials file with grant_type jwt-bearer, password, or authorization_code. Defaults to SF_CREDENTIALS_FILE. |
| `api_version` | string | no | Salesforce API version. Defaults to 64.0. |
| `sandbox` | boolean | no | Force the sandbox login host https://test.salesforce.com. Defaults to SF_SANDBOX or detection from the instance URL. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `record_limit` | number | no | Maximum records to read per SOQL query before recording truncation. Defaults to 2000. |
| `output_dir` | string | no | Output root. Defaults to ./export/salesforce. |
| `max_admins` | number | no | Maximum acceptable administrator-class users before failing. Defaults to 5. |
| `login_history_days` | number | no | Login history lookback window in days. Defaults to 30. |
| `audit_trail_days` | number | no | Setup audit trail lookback window in days. Defaults to 90. |
| `certificate_expiry_warning_days` | number | no | Warn when a certificate expires within this many days. Defaults to 30. |
| `stale_login_days` | number | no | Days without login after which an administrator is stale. Defaults to 90. |


## Authentication

Supported modes:

- JWT bearer
- username/password plus security token
- OAuth refresh token
- explicit access token

Credential precedence, highest first:

1. Explicit access token and instance URL
2. Explicit refresh token
3. Explicit JWT credentials
4. Password grant
5. Credentials file and SF_* environment variables

Environment variables: `SF_INSTANCE_URL`, `SF_LOGIN_URL`, `SF_USERNAME`, `SF_PASSWORD`, `SF_SECURITY_TOKEN`, `SF_CONSUMER_KEY`, `SF_CONSUMER_SECRET`, `SF_PRIVATE_KEY`, `SF_REFRESH_TOKEN`, `SF_ACCESS_TOKEN`

Configuration locations: Explicit credentials JSON file

Credential and deployment variants: Production login, Sandbox login, Custom My Domain login

Configuration fields: `instanceUrl`, `loginUrl`, `username`, `password`, `securityToken`, `consumerKey`, `consumerSecret`, `privateKey`, `refreshToken`, `accessToken`, `apiVersion`

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

Credential refresh: POST /services/oauth2/token with the selected JWT bearer, refresh_token, or password grant.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| role | `API Enabled` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `View Setup and Configuration` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `View Health Check` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `View All Users` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `Manage MFA in API` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `Metadata API read privileges` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `View Event Log Files where licensed` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `standard-query` | HTTP | `GET /services/data/v64.0/query` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `records`, `totalSize`, `done`, `nextRecordsUrl` | [Official documentation](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_query.htm) |
| `tooling-query` | HTTP | `GET /services/data/v64.0/tooling/query` | Salesforce Tooling API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `records`, `totalSize`, `done`, `nextRecordsUrl` | [Official documentation](https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/intro_rest_resources.htm) |
| `metadata-read` | HTTP | `POST /services/Soap/m/64.0` | Salesforce Metadata API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `SecuritySettings`, `MyDomainSettings`, `Profile`, `ConnectedApp` | [Official documentation](https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_readMetadata.htm) |
| `limits` | HTTP | `GET /services/data/v64.0/limits` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `DailyApiRequests`, `HourlyODataCallout`, `DailyAsyncApexExecutions` | [Official documentation](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_limits.htm) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `standard-query` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `standard-query` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `standard-query` | response | A JSON object or list containing only the documented records, totalSize, done, nextRecordsUrl members consumed by verdicts. | yes |
| `tooling-query` | client | Use the configured Salesforce Tooling API origin; never follow a server link to a different origin. | yes |
| `tooling-query` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `tooling-query` | response | A JSON object or list containing only the documented records, totalSize, done, nextRecordsUrl members consumed by verdicts. | yes |
| `metadata-read` | client | Use the configured Salesforce Metadata API origin; never follow a server link to a different origin. | yes |
| `metadata-read` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `metadata-read` | response | A JSON object or list containing only the documented SecuritySettings, MyDomainSettings, Profile, ConnectedApp members consumed by verdicts. | yes |
| `limits` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `limits` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `limits` | response | A JSON object or list containing only the documented DailyApiRequests, HourlyODataCallout, DailyAsyncApexExecutions members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `standard-query`, `tooling-query`, `metadata-read`, `limits` | `nextRecordsUrl`, `done`, `totalSize` | 2000 | 2000 | none | totalSize is authoritative when present; done=true and seen equal total prove completion. | done true with matching total; Configured row cap; Repeated nextRecordsUrl; Empty page with continuation; Missing or larger total; Rejected cross-origin or user-information cursor |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Salesforce Security Inspector | Organization edition and license determine daily and concurrent API limits | `Sforce-Limit-Info`, `Retry-After` | 429, 500, 502, 503, 504 | Use bounded Retry-After and exponential retry; preserve REQUEST_LIMIT_EXCEEDED as unreadable evidence. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | Health Check score | SF-01 | Evaluate the ordered first-match rules for SF-01 below. |
| 2 | Session timeout | SF-02 | Evaluate the ordered first-match rules for SF-02 below. |
| 3 | Password policy | SF-03 | Evaluate the ordered first-match rules for SF-03 below. |
| 4 | MFA enforcement | SF-04 | Evaluate the ordered first-match rules for SF-04 below. |
| 5 | IP range restrictions | SF-05 | Evaluate the ordered first-match rules for SF-05 below. |
| 6 | Login hour restrictions | SF-06 | Evaluate the ordered first-match rules for SF-06 below. |
| 7 | API access controls | SF-07 | Evaluate the ordered first-match rules for SF-07 below. |
| 8 | Field-level security | SF-08 | Evaluate the ordered first-match rules for SF-08 below. |
| 9 | Permission set review | SF-09 | Evaluate the ordered first-match rules for SF-09 below. |
| 10 | Profile permissions | SF-10 | Evaluate the ordered first-match rules for SF-10 below. |
| 11 | Connected app OAuth policies | SF-11 | Evaluate the ordered first-match rules for SF-11 below. |
| 12 | Sharing settings | SF-12 | Evaluate the ordered first-match rules for SF-12 below. |
| 13 | Guest user access | SF-13 | Evaluate the ordered first-match rules for SF-13 below. |
| 14 | Login forensics | SF-14 | Evaluate the ordered first-match rules for SF-14 below. |
| 15 | Setup change tracking | SF-15 | Evaluate the ordered first-match rules for SF-15 below. |
| 16 | Data encryption status | SF-16 | Evaluate the ordered first-match rules for SF-16 below. |
| 17 | Certificate management | SF-17 | Evaluate the ordered first-match rules for SF-17 below. |
| 18 | My Domain enforcement | SF-18 | Evaluate the ordered first-match rules for SF-18 below. |
| 19 | Clickjack protection | SF-19 | Evaluate the ordered first-match rules for SF-19 below. |
| 20 | CSRF protection | SF-20 | Evaluate the ordered first-match rules for SF-20 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `SF-01` | medium | `salesforce_assess_platform_security` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Health Check score returns pass from complete, readable evidence. | The portable derivation for Health Check score returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Health Check score returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Health Check score is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-02` | medium | `salesforce_assess_platform_security` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Session timeout returns pass from complete, readable evidence. | The portable derivation for Session timeout returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Session timeout returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Session timeout is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-03` | high | `salesforce_assess_platform_security` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Password policy returns pass from complete, readable evidence. | The portable derivation for Password policy returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Password policy returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Password policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-04` | critical | `salesforce_assess_identity_access` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for MFA enforcement returns pass from complete, readable evidence. | The portable derivation for MFA enforcement returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for MFA enforcement returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for MFA enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-05` | high | `salesforce_assess_platform_security` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for IP range restrictions returns pass from complete, readable evidence. | The portable derivation for IP range restrictions returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for IP range restrictions returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for IP range restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-06` | high | `salesforce_assess_identity_access` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Login hour restrictions returns pass from complete, readable evidence. | The portable derivation for Login hour restrictions returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Login hour restrictions returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Login hour restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-07` | medium | `salesforce_assess_identity_access` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for API access controls returns pass from complete, readable evidence. | The portable derivation for API access controls returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for API access controls returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for API access controls is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-08` | medium | `salesforce_assess_data_protection` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Field-level security returns pass from complete, readable evidence. | The portable derivation for Field-level security returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Field-level security returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Field-level security is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-09` | high | `salesforce_assess_identity_access` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Permission set review returns pass from complete, readable evidence. | The portable derivation for Permission set review returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Permission set review returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Permission set review is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-10` | high | `salesforce_assess_identity_access` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Profile permissions returns pass from complete, readable evidence. | The portable derivation for Profile permissions returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Profile permissions returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Profile permissions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-11` | high | `salesforce_assess_monitoring_integrations` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Connected app OAuth policies returns pass from complete, readable evidence. | The portable derivation for Connected app OAuth policies returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Connected app OAuth policies returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Connected app OAuth policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-12` | high | `salesforce_assess_data_protection` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Sharing settings returns pass from complete, readable evidence. | The portable derivation for Sharing settings returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Sharing settings returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Sharing settings is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-13` | medium | `salesforce_assess_identity_access` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Guest user access returns pass from complete, readable evidence. | The portable derivation for Guest user access returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Guest user access returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Guest user access is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-14` | medium | `salesforce_assess_monitoring_integrations` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Login forensics returns pass from complete, readable evidence. | The portable derivation for Login forensics returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Login forensics returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Login forensics is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-15` | medium | `salesforce_assess_monitoring_integrations` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Setup change tracking returns pass from complete, readable evidence. | The portable derivation for Setup change tracking returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Setup change tracking returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Setup change tracking is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-16` | high | `salesforce_assess_data_protection` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Data encryption status returns pass from complete, readable evidence. | The portable derivation for Data encryption status returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Data encryption status returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Data encryption status is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-17` | high | `salesforce_assess_data_protection` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Certificate management returns pass from complete, readable evidence. | The portable derivation for Certificate management returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Certificate management returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Certificate management is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-18` | medium | `salesforce_assess_platform_security` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for My Domain enforcement returns pass from complete, readable evidence. | The portable derivation for My Domain enforcement returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for My Domain enforcement returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for My Domain enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-19` | medium | `salesforce_assess_platform_security` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for Clickjack protection returns pass from complete, readable evidence. | The portable derivation for Clickjack protection returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Clickjack protection returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Clickjack protection is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-20` | medium | `salesforce_assess_platform_security` | `standard-query`, `tooling-query`, `metadata-read`, `limits` | `decision_status` | The portable derivation for CSRF protection returns pass from complete, readable evidence. | The portable derivation for CSRF protection returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for CSRF protection returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for CSRF protection is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `SF-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-06` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-06` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-06` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-06` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-07` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-07` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-07` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-07` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-08` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-08` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-08` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-08` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-09` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-09` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-09` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-09` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-10` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-10` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-10` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-10` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-11` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-11` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-11` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-11` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-12` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-12` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-12` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-12` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-13` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-13` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-13` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-13` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-14` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-14` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-14` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-14` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-15` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-15` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-15` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-15` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-16` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-16` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-16` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-16` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-17` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-17` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-17` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-17` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-18` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-18` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-18` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-18` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-19` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-19` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-19` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-19` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SF-20` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SF-20` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SF-20` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SF-20` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `SF-01` | `decision_status` | Using complete source cardinalities, return pass for a Health Check score of at least 90, warn from 70 through 89, fail below 70, and manual when SecurityHealthCheck exposes no score. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-02` | `decision_status` | Using complete source cardinalities, return pass when session timeout is at most 120 minutes, forced logout is enabled, and sessions are locked to the originating IP; warn when only the IP lock is missing, fail for an excessive timeout or disabled forced logout, and manual for absent values. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-03` | `decision_status` | Using complete source cardinalities, evaluate minimum length 12, strongest complexity, expiration at most 90 days, and history at least five; return pass with no gap, warn with one gap, fail with two or more gaps, and manual when a required field is absent. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-04` | `decision_status` | Using complete source cardinalities, return fail when direct-UI MFA is not required or more than 25 percent of visible active standard users lack a registered method, warn for a smaller unenrolled population or partial reads, and pass when complete evidence shows MFA required and every user enrolled. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-05` | `decision_status` | Using complete source cardinalities, return pass when every sensitive profile has login IP ranges, per-request enforcement is enabled, and an org-wide trusted range exists; fail when none exists at either level, and warn or manual for mixed, unresolved, or unreadable coverage. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-06` | `decision_status` | Using complete source cardinalities, return pass when every sensitive profile restricts login hours every day, fail when none does, and warn when only some do or profile resolution is incomplete. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-07` | `decision_status` | Using complete source cardinalities, return pass when no visible active user is assigned a profile with API Enabled, warn when such users are below the configured ratio or evidence is partial, and fail when the configured excessive-access threshold is crossed. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-08` | `decision_status` | Using complete source cardinalities, return fail when any sensitive-name field is broadly readable by more than five profile or permission-set grants, warn for narrower grants or partial rows, and manual when no field matches the classification patterns. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-09` | `decision_status` | Using complete source cardinalities, return pass when no permission set grants elevated permissions, warn when elevated sets are assigned within the configured administrator threshold or evidence is partial, fail above the threshold, and manual when the standard inventory is implausibly empty. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-10` | `decision_status` | Using complete source cardinalities, return fail when active administrator-profile users exceed the configured maximum, warn for stale, undated, or partial administrator evidence, and pass when the complete recent population is within the maximum. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-11` | `decision_status` | Using complete source cardinalities, return fail when more than half of connected apps allow user self-authorization, warn for a smaller open set or when visible policies require pre-approval because scopes remain unreadable, and manual when no app or no policy flag is visible. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-12` | `decision_status` | Using complete source cardinalities, return fail when at least three standard objects have public organization-wide defaults, warn for one or two public defaults or for private defaults whose custom objects and sharing rules remain manual, and manual when no default-access field is exposed. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-13` | `decision_status` | Using complete source cardinalities, return fail when any active guest user has API Enabled or elevated data permissions, warn when other active guests exist or coverage is partial, and pass when a complete user inventory has no active guest. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-14` | `decision_status` | Using complete source cardinalities, return fail for severe login forensics such as a failure ratio above the configured threshold, repeated-source failures, or legacy TLS, warn for lesser anomalies, undated rows, or partial reads, and pass when the complete non-empty window has none. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-15` | `decision_status` | Using complete source cardinalities, return pass when complete setup-audit and Event Monitoring evidence is readable and no collection gap exists, warn for high-risk changes or partial or absent EventLogFile evidence, and manual when the active-org audit window is unreadable or implausibly empty. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-16` | `decision_status` | Using complete source cardinalities, return fail when a readable complete TenantSecret inventory has no active key, warn when active keys are undated, older than 365 days, or partial, pass for complete recent active keys, and manual when Shield encryption is unavailable or scoped out. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-17` | `decision_status` | Using complete source cardinalities, return fail when any certificate is expired or has a key under 2048 bits, warn for near expiry, missing dates, exportable private keys, pending chains, or partial evidence, pass when all certificates are valid and managed, and manual when none is returned. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-18` | `decision_status` | Using complete source cardinalities, return fail when My Domain is absent or still permits login.salesforce.com, pass when it is enforced for UI and API login, warn when API login is not restricted, and manual when the enforcement flag is absent. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-19` | `decision_status` | Using complete source cardinalities, return pass when all four setup, non-setup, Visualforce-with-header, and Visualforce-without-header clickjack flags are enabled, fail when at least two are disabled, warn when one is disabled, and manual when flags are absent. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `SF-20` | `decision_status` | Using complete source cardinalities, return pass when CSRF protection is enabled for both GET and POST, fail when either is disabled, and manual when either flag is absent. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `SF-01` | `passStatus` | pass |
| `SF-01` | `warnStatus` | warn |
| `SF-01` | `failStatus` | fail |
| `SF-01` | `manualStatus` | manual |
| `SF-02` | `passStatus` | pass |
| `SF-02` | `warnStatus` | warn |
| `SF-02` | `failStatus` | fail |
| `SF-02` | `manualStatus` | manual |
| `SF-03` | `passStatus` | pass |
| `SF-03` | `warnStatus` | warn |
| `SF-03` | `failStatus` | fail |
| `SF-03` | `manualStatus` | manual |
| `SF-04` | `passStatus` | pass |
| `SF-04` | `warnStatus` | warn |
| `SF-04` | `failStatus` | fail |
| `SF-04` | `manualStatus` | manual |
| `SF-05` | `passStatus` | pass |
| `SF-05` | `warnStatus` | warn |
| `SF-05` | `failStatus` | fail |
| `SF-05` | `manualStatus` | manual |
| `SF-06` | `passStatus` | pass |
| `SF-06` | `warnStatus` | warn |
| `SF-06` | `failStatus` | fail |
| `SF-06` | `manualStatus` | manual |
| `SF-07` | `passStatus` | pass |
| `SF-07` | `warnStatus` | warn |
| `SF-07` | `failStatus` | fail |
| `SF-07` | `manualStatus` | manual |
| `SF-08` | `passStatus` | pass |
| `SF-08` | `warnStatus` | warn |
| `SF-08` | `failStatus` | fail |
| `SF-08` | `manualStatus` | manual |
| `SF-09` | `passStatus` | pass |
| `SF-09` | `warnStatus` | warn |
| `SF-09` | `failStatus` | fail |
| `SF-09` | `manualStatus` | manual |
| `SF-10` | `passStatus` | pass |
| `SF-10` | `warnStatus` | warn |
| `SF-10` | `failStatus` | fail |
| `SF-10` | `manualStatus` | manual |
| `SF-11` | `passStatus` | pass |
| `SF-11` | `warnStatus` | warn |
| `SF-11` | `failStatus` | fail |
| `SF-11` | `manualStatus` | manual |
| `SF-12` | `passStatus` | pass |
| `SF-12` | `warnStatus` | warn |
| `SF-12` | `failStatus` | fail |
| `SF-12` | `manualStatus` | manual |
| `SF-13` | `passStatus` | pass |
| `SF-13` | `warnStatus` | warn |
| `SF-13` | `failStatus` | fail |
| `SF-13` | `manualStatus` | manual |
| `SF-14` | `passStatus` | pass |
| `SF-14` | `warnStatus` | warn |
| `SF-14` | `failStatus` | fail |
| `SF-14` | `manualStatus` | manual |
| `SF-15` | `passStatus` | pass |
| `SF-15` | `warnStatus` | warn |
| `SF-15` | `failStatus` | fail |
| `SF-15` | `manualStatus` | manual |
| `SF-16` | `passStatus` | pass |
| `SF-16` | `warnStatus` | warn |
| `SF-16` | `failStatus` | fail |
| `SF-16` | `manualStatus` | manual |
| `SF-17` | `passStatus` | pass |
| `SF-17` | `warnStatus` | warn |
| `SF-17` | `failStatus` | fail |
| `SF-17` | `manualStatus` | manual |
| `SF-18` | `passStatus` | pass |
| `SF-18` | `warnStatus` | warn |
| `SF-18` | `failStatus` | fail |
| `SF-18` | `manualStatus` | manual |
| `SF-19` | `passStatus` | pass |
| `SF-19` | `warnStatus` | warn |
| `SF-19` | `failStatus` | fail |
| `SF-19` | `manualStatus` | manual |
| `SF-20` | `passStatus` | pass |
| `SF-20` | `warnStatus` | warn |
| `SF-20` | `failStatus` | fail |
| `SF-20` | `manualStatus` | manual |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `SF-01` | compliant | All required source reads are complete and this derivation returns pass: return pass for a Health Check score of at least 90, warn from 70 through 89, fail below 70, and manual when SecurityHealthCheck exposes no score. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass for a Health Check score of at least 90, warn from 70 through 89, fail below 70, and manual when SecurityHealthCheck exposes no score. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-02` | compliant | All required source reads are complete and this derivation returns pass: return pass when session timeout is at most 120 minutes, forced logout is enabled, and sessions are locked to the originating IP; warn when only the IP lock is missing, fail for an excessive timeout or disabled forced logout, and manual for absent values. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when session timeout is at most 120 minutes, forced logout is enabled, and sessions are locked to the originating IP; warn when only the IP lock is missing, fail for an excessive timeout or disabled forced logout, and manual for absent values. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-03` | compliant | All required source reads are complete and this derivation returns pass: evaluate minimum length 12, strongest complexity, expiration at most 90 days, and history at least five; return pass with no gap, warn with one gap, fail with two or more gaps, and manual when a required field is absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: evaluate minimum length 12, strongest complexity, expiration at most 90 days, and history at least five; return pass with no gap, warn with one gap, fail with two or more gaps, and manual when a required field is absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-04` | compliant | All required source reads are complete and this derivation returns pass: return fail when direct-UI MFA is not required or more than 25 percent of visible active standard users lack a registered method, warn for a smaller unenrolled population or partial reads, and pass when complete evidence shows MFA required and every user enrolled. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when direct-UI MFA is not required or more than 25 percent of visible active standard users lack a registered method, warn for a smaller unenrolled population or partial reads, and pass when complete evidence shows MFA required and every user enrolled. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-05` | compliant | All required source reads are complete and this derivation returns pass: return pass when every sensitive profile has login IP ranges, per-request enforcement is enabled, and an org-wide trusted range exists; fail when none exists at either level, and warn or manual for mixed, unresolved, or unreadable coverage. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every sensitive profile has login IP ranges, per-request enforcement is enabled, and an org-wide trusted range exists; fail when none exists at either level, and warn or manual for mixed, unresolved, or unreadable coverage. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-06` | compliant | All required source reads are complete and this derivation returns pass: return pass when every sensitive profile restricts login hours every day, fail when none does, and warn when only some do or profile resolution is incomplete. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every sensitive profile restricts login hours every day, fail when none does, and warn when only some do or profile resolution is incomplete. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-07` | compliant | All required source reads are complete and this derivation returns pass: return pass when no visible active user is assigned a profile with API Enabled, warn when such users are below the configured ratio or evidence is partial, and fail when the configured excessive-access threshold is crossed. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when no visible active user is assigned a profile with API Enabled, warn when such users are below the configured ratio or evidence is partial, and fail when the configured excessive-access threshold is crossed. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-08` | compliant | All required source reads are complete and this derivation returns pass: return fail when any sensitive-name field is broadly readable by more than five profile or permission-set grants, warn for narrower grants or partial rows, and manual when no field matches the classification patterns. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-08` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any sensitive-name field is broadly readable by more than five profile or permission-set grants, warn for narrower grants or partial rows, and manual when no field matches the classification patterns. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-09` | compliant | All required source reads are complete and this derivation returns pass: return pass when no permission set grants elevated permissions, warn when elevated sets are assigned within the configured administrator threshold or evidence is partial, fail above the threshold, and manual when the standard inventory is implausibly empty. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-09` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when no permission set grants elevated permissions, warn when elevated sets are assigned within the configured administrator threshold or evidence is partial, fail above the threshold, and manual when the standard inventory is implausibly empty. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-09` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-09` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-10` | compliant | All required source reads are complete and this derivation returns pass: return fail when active administrator-profile users exceed the configured maximum, warn for stale, undated, or partial administrator evidence, and pass when the complete recent population is within the maximum. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-10` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when active administrator-profile users exceed the configured maximum, warn for stale, undated, or partial administrator evidence, and pass when the complete recent population is within the maximum. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-10` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-10` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-11` | compliant | All required source reads are complete and this derivation returns pass: return fail when more than half of connected apps allow user self-authorization, warn for a smaller open set or when visible policies require pre-approval because scopes remain unreadable, and manual when no app or no policy flag is visible. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-11` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when more than half of connected apps allow user self-authorization, warn for a smaller open set or when visible policies require pre-approval because scopes remain unreadable, and manual when no app or no policy flag is visible. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-11` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-11` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-12` | compliant | All required source reads are complete and this derivation returns pass: return fail when at least three standard objects have public organization-wide defaults, warn for one or two public defaults or for private defaults whose custom objects and sharing rules remain manual, and manual when no default-access field is exposed. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-12` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when at least three standard objects have public organization-wide defaults, warn for one or two public defaults or for private defaults whose custom objects and sharing rules remain manual, and manual when no default-access field is exposed. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-12` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-12` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-13` | compliant | All required source reads are complete and this derivation returns pass: return fail when any active guest user has API Enabled or elevated data permissions, warn when other active guests exist or coverage is partial, and pass when a complete user inventory has no active guest. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-13` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any active guest user has API Enabled or elevated data permissions, warn when other active guests exist or coverage is partial, and pass when a complete user inventory has no active guest. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-13` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-13` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-14` | compliant | All required source reads are complete and this derivation returns pass: return fail for severe login forensics such as a failure ratio above the configured threshold, repeated-source failures, or legacy TLS, warn for lesser anomalies, undated rows, or partial reads, and pass when the complete non-empty window has none. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-14` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail for severe login forensics such as a failure ratio above the configured threshold, repeated-source failures, or legacy TLS, warn for lesser anomalies, undated rows, or partial reads, and pass when the complete non-empty window has none. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-14` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-14` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-15` | compliant | All required source reads are complete and this derivation returns pass: return pass when complete setup-audit and Event Monitoring evidence is readable and no collection gap exists, warn for high-risk changes or partial or absent EventLogFile evidence, and manual when the active-org audit window is unreadable or implausibly empty. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-15` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when complete setup-audit and Event Monitoring evidence is readable and no collection gap exists, warn for high-risk changes or partial or absent EventLogFile evidence, and manual when the active-org audit window is unreadable or implausibly empty. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-15` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-15` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-16` | compliant | All required source reads are complete and this derivation returns pass: return fail when a readable complete TenantSecret inventory has no active key, warn when active keys are undated, older than 365 days, or partial, pass for complete recent active keys, and manual when Shield encryption is unavailable or scoped out. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-16` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when a readable complete TenantSecret inventory has no active key, warn when active keys are undated, older than 365 days, or partial, pass for complete recent active keys, and manual when Shield encryption is unavailable or scoped out. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-16` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-16` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-17` | compliant | All required source reads are complete and this derivation returns pass: return fail when any certificate is expired or has a key under 2048 bits, warn for near expiry, missing dates, exportable private keys, pending chains, or partial evidence, pass when all certificates are valid and managed, and manual when none is returned. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-17` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any certificate is expired or has a key under 2048 bits, warn for near expiry, missing dates, exportable private keys, pending chains, or partial evidence, pass when all certificates are valid and managed, and manual when none is returned. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-17` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-17` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-18` | compliant | All required source reads are complete and this derivation returns pass: return fail when My Domain is absent or still permits login.salesforce.com, pass when it is enforced for UI and API login, warn when API login is not restricted, and manual when the enforcement flag is absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-18` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when My Domain is absent or still permits login.salesforce.com, pass when it is enforced for UI and API login, warn when API login is not restricted, and manual when the enforcement flag is absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-18` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-18` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-19` | compliant | All required source reads are complete and this derivation returns pass: return pass when all four setup, non-setup, Visualforce-with-header, and Visualforce-without-header clickjack flags are enabled, fail when at least two are disabled, warn when one is disabled, and manual when flags are absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-19` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when all four setup, non-setup, Visualforce-with-header, and Visualforce-without-header clickjack flags are enabled, fail when at least two are disabled, warn when one is disabled, and manual when flags are absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-19` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-19` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SF-20` | compliant | All required source reads are complete and this derivation returns pass: return pass when CSRF protection is enabled for both GET and POST, fail when either is disabled, and manual when either flag is absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-20` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when CSRF protection is enabled for both GET and POST, fail when either is disabled, and manual when either flag is absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SF-20` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SF-20` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Health Check score | - | - | - | - | - | - | - | - |
| 2 | Session timeout | - | - | - | - | - | - | - | - |
| 3 | Password policy | - | - | - | - | - | - | - | - |
| 4 | MFA enforcement | - | - | - | - | - | - | - | - |
| 5 | IP range restrictions | - | - | - | - | - | - | - | - |
| 6 | Login hour restrictions | - | - | - | - | - | - | - | - |
| 7 | API access controls | - | - | - | - | - | - | - | - |
| 8 | Field-level security | - | - | - | - | - | - | - | - |
| 9 | Permission set review | - | - | - | - | - | - | - | - |
| 10 | Profile permissions | - | - | - | - | - | - | - | - |
| 11 | Connected app OAuth policies | - | - | - | - | - | - | - | - |
| 12 | Sharing settings | - | - | - | - | - | - | - | - |
| 13 | Guest user access | - | - | - | - | - | - | - | - |
| 14 | Login forensics | - | - | - | - | - | - | - | - |
| 15 | Setup change tracking | - | - | - | - | - | - | - | - |
| 16 | Data encryption status | - | - | - | - | - | - | - | - |
| 17 | Certificate management | - | - | - | - | - | - | - | - |
| 18 | My Domain enforcement | - | - | - | - | - | - | - | - |
| 19 | Clickjack protection | - | - | - | - | - | - | - | - |
| 20 | CSRF protection | - | - | - | - | - | - | - | - |

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

Sensitive fields and values: password, securityToken, consumerSecret, privateKey, refreshToken, accessToken, authorization, sessionId

Credential formats: Salesforce OAuth access and refresh tokens, security tokens, private keys, signed JWT assertions, SOAP session IDs

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `standard-query` | `records`, `totalSize`, `done`, `nextRecordsUrl` |
| `tooling-query` | `records`, `totalSize`, `done`, `nextRecordsUrl` |
| `metadata-read` | `SecuritySettings`, `MyDomainSettings`, `Profile`, `ConnectedApp` |
| `limits` | `DailyApiRequests`, `HourlyODataCallout`, `DailyAsyncApexExecutions` |

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

Archive pairing: Create salesforce-audit.zip beside the allocated salesforce-audit directory, applying the same suffix to both.
