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
- Username/password plus security token
- OAuth refresh token
- Explicit access token

Credential precedence, highest first:

1. Explicit tool arguments
2. SF_* environment variables
3. Explicit credentials JSON file

Environment variables: `SF_CREDENTIALS_FILE`, `SF_INSTANCE_URL`, `SF_LOGIN_URL`, `SF_USERNAME`, `SF_PASSWORD`, `SF_SECURITY_TOKEN`, `SF_CONSUMER_KEY`, `SF_CLIENT_ID`, `SF_CONSUMER_SECRET`, `SF_CLIENT_SECRET`, `SF_PRIVATE_KEY_FILE`, `SF_PRIVATE_KEY`, `SF_REFRESH_TOKEN`, `SF_ACCESS_TOKEN`, `SF_API_VERSION`, `SF_GRANT_TYPE`, `SF_SANDBOX`, `SF_TIMEOUT`, `SF_MAX_RETRIES`

Configuration locations: Explicit credentials JSON file from credentials_file or SF_CREDENTIALS_FILE

Credential and deployment variants: Production login, Sandbox login, Custom My Domain login

Configuration fields: `instance_url`, `instanceUrl`, `login_url`, `loginUrl`, `username`, `password`, `security_token`, `securityToken`, `consumer_key`, `client_id`, `consumerKey`, `clientId`, `consumer_secret`, `client_secret`, `consumerSecret`, `clientSecret`, `private_key_file`, `privateKeyFile`, `private_key`, `privateKey`, `refresh_token`, `refreshToken`, `access_token`, `accessToken`, `api_version`, `apiVersion`, `grant_type`, `grantType`, `sandbox`

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

Credential refresh: POST /services/oauth2/token with the selected JWT bearer, refresh_token, or password grant.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| role | `API Enabled` | `limits`, `organization`, `health-check`, `health-check-risks`, `users`, `profiles`, `permission-sets`, `permission-set-assignments`, `two-factor-methods`, `field-permissions`, `tenant-secrets`, `certificates`, `connected-applications`, `oauth-tokens`, `caller-permissions`, `login-history`, `setup-audit-trail`, `event-log-files` |  |
| role | `View Setup and Configuration` | `organization`, `users`, `profiles`, `permission-sets`, `permission-set-assignments`, `field-permissions`, `tenant-secrets`, `certificates`, `connected-applications`, `oauth-tokens`, `caller-permissions`, `setup-audit-trail` |  |
| role | `View Health Check` | `health-check`, `health-check-risks` |  |
| role | `Manage Multi-Factor Authentication in API` | `two-factor-methods` |  |
| role | `Modify Metadata Through Metadata API Functions` | `security-settings`, `my-domain-settings`, `profile-metadata` | The runtime performs only readMetadata and listMetadata calls. |
| license | `Event Monitoring plus View Event Log Files` | `event-log-files` |  |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `limits` | HTTP | `GET /services/data/v{version}/limits` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `organization` | HTTP | `GET /services/data/v{version}/query?q=Organization` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `health-check` | HTTP | `GET /services/data/v{version}/tooling/query?q=SecurityHealthCheck` | Salesforce Tooling API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `health-check-risks` | HTTP | `GET /services/data/v{version}/tooling/query?q=SecurityHealthCheckRisks` | Salesforce Tooling API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `security-settings` | HTTP | `POST /services/Soap/m/{version} readMetadata(SecuritySettings)` | Salesforce Metadata API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `my-domain-settings` | HTTP | `POST /services/Soap/m/{version} readMetadata(MyDomainSettings)` | Salesforce Metadata API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `users` | HTTP | `GET /services/data/v{version}/query?q=User` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `profiles` | HTTP | `GET /services/data/v{version}/query?q=Profile` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `profile-metadata` | HTTP | `POST /services/Soap/m/{version} listMetadata(Profile)+readMetadata(Profile)` | Salesforce Metadata API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `permission-sets` | HTTP | `GET /services/data/v{version}/query?q=PermissionSet` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `permission-set-assignments` | HTTP | `GET /services/data/v{version}/query?q=PermissionSetAssignment` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `two-factor-methods` | HTTP | `GET /services/data/v{version}/query?q=TwoFactorMethodsInfo` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `field-permissions` | HTTP | `GET /services/data/v{version}/query?q=FieldPermissions` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `tenant-secrets` | HTTP | `GET /services/data/v{version}/query?q=TenantSecret` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `certificates` | HTTP | `GET /services/data/v{version}/tooling/query?q=Certificate` | Salesforce Tooling API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `connected-applications` | HTTP | `GET /services/data/v{version}/query?q=ConnectedApplication` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `oauth-tokens` | HTTP | `GET /services/data/v{version}/query?q=OauthToken` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `caller-permissions` | HTTP | `GET /services/data/v{version}/query?q=UserPermissionAccess` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `login-history` | HTTP | `GET /services/data/v{version}/query?q=LoginHistory` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `setup-audit-trail` | HTTP | `GET /services/data/v{version}/query?q=SetupAuditTrail` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |
| `event-log-files` | HTTP | `GET /services/data/v{version}/query?q=EventLogFile` | Salesforce REST API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `selected fields named in the runtime SOQL or Metadata API request` | [Official documentation](https://developer.salesforce.com/docs/platform/) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `limits` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `limits` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `limits` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `organization` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `organization` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `organization` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `health-check` | client | Use the configured Salesforce Tooling API origin; never follow a server link to a different origin. | yes |
| `health-check` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `health-check` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `health-check-risks` | client | Use the configured Salesforce Tooling API origin; never follow a server link to a different origin. | yes |
| `health-check-risks` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `health-check-risks` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `security-settings` | client | Use the configured Salesforce Metadata API origin; never follow a server link to a different origin. | yes |
| `security-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `security-settings` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `my-domain-settings` | client | Use the configured Salesforce Metadata API origin; never follow a server link to a different origin. | yes |
| `my-domain-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `my-domain-settings` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `users` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `users` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `profiles` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `profiles` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `profiles` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `profile-metadata` | client | Use the configured Salesforce Metadata API origin; never follow a server link to a different origin. | yes |
| `profile-metadata` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `profile-metadata` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `permission-sets` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `permission-sets` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `permission-sets` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `permission-set-assignments` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `permission-set-assignments` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `permission-set-assignments` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `two-factor-methods` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `two-factor-methods` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `two-factor-methods` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `field-permissions` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `field-permissions` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `field-permissions` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `tenant-secrets` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `tenant-secrets` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `tenant-secrets` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `certificates` | client | Use the configured Salesforce Tooling API origin; never follow a server link to a different origin. | yes |
| `certificates` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `certificates` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `connected-applications` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `connected-applications` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `connected-applications` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `oauth-tokens` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `oauth-tokens` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `oauth-tokens` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `caller-permissions` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `caller-permissions` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `caller-permissions` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `login-history` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `login-history` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `login-history` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `setup-audit-trail` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `setup-audit-trail` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `setup-audit-trail` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |
| `event-log-files` | client | Use the configured Salesforce REST API origin; never follow a server link to a different origin. | yes |
| `event-log-files` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `event-log-files` | response | A JSON object or list containing only the documented selected fields named in the runtime SOQL or Metadata API request members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `organization`, `health-check`, `health-check-risks`, `users`, `profiles`, `permission-sets`, `permission-set-assignments`, `two-factor-methods`, `field-permissions`, `tenant-secrets`, `certificates`, `connected-applications`, `oauth-tokens`, `caller-permissions`, `login-history`, `setup-audit-trail`, `event-log-files` | `nextRecordsUrl`, `done`, `totalSize` | service default | 2000 | none | totalSize is authoritative when present; done=true and seen equal total prove completion. | done true with matching total; Configured row cap; Repeated nextRecordsUrl; Empty page with continuation; Missing or larger total; Rejected cross-origin or user-information cursor |

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
| `SF-01` | medium | `salesforce_assess_platform_security` | `health-check` | `health_readable`, `score_present`, `risks_readable`, `risks_complete`, `score`, `high_risk_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass for a Health Check score of at least 90, warn from 70 through 89, fail below 70, and manual when SecurityHealthCheck exposes no score. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass for a Health Check score of at least 90, warn from 70 through 89, fail below 70, and manual when SecurityHealthCheck exposes no score. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass for a Health Check score of at least 90, warn from 70 through 89, fail below 70, and manual when SecurityHealthCheck exposes no score. | The required evidence for Health Check score is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-02` | medium | `salesforce_assess_platform_security` | `security-settings` | `settings_readable`, `required_fields_present`, `timeout_minutes`, `force_logout`, `lock_to_ip` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when session timeout is at most 120 minutes, forced logout is enabled, and sessions are locked to the originating IP; warn when only the IP lock is missing, fail for an excessive timeout or disabled forced logout, and manual for absent values. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when session timeout is at most 120 minutes, forced logout is enabled, and sessions are locked to the originating IP; warn when only the IP lock is missing, fail for an excessive timeout or disabled forced logout, and manual for absent values. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when session timeout is at most 120 minutes, forced logout is enabled, and sessions are locked to the originating IP; warn when only the IP lock is missing, fail for an excessive timeout or disabled forced logout, and manual for absent values. | The required evidence for Session timeout is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-03` | high | `salesforce_assess_platform_security` | `security-settings` | `settings_readable`, `required_fields_present`, `gap_count` | Complete readable evidence satisfies the compliant branch of this derivation: evaluate minimum length 12, strongest complexity, expiration at most 90 days, and history at least five; return pass with no gap, warn with one gap, fail with two or more gaps, and manual when a required field is absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: evaluate minimum length 12, strongest complexity, expiration at most 90 days, and history at least five; return pass with no gap, warn with one gap, fail with two or more gaps, and manual when a required field is absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: evaluate minimum length 12, strongest complexity, expiration at most 90 days, and history at least five; return pass with no gap, warn with one gap, fail with two or more gaps, and manual when a required field is absent. | The required evidence for Password policy is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-04` | critical | `salesforce_assess_identity_access` | `security-settings`, `users`, `profiles`, `two-factor-methods` | `requirement_available`, `requirement_failed`, `requirement_met`, `enrollment_readable`, `population_sane`, `active_standard_user_count`, `unenrolled_count`, `quarter_user_count`, `enrollment_complete`, `secondary_sources_complete` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when direct-UI MFA is not required or more than 25 percent of visible active standard users lack a registered method, warn for a smaller unenrolled population or partial reads, and pass when complete evidence shows MFA required and every user enrolled. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when direct-UI MFA is not required or more than 25 percent of visible active standard users lack a registered method, warn for a smaller unenrolled population or partial reads, and pass when complete evidence shows MFA required and every user enrolled. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when direct-UI MFA is not required or more than 25 percent of visible active standard users lack a registered method, warn for a smaller unenrolled population or partial reads, and pass when complete evidence shows MFA required and every user enrolled. | The required evidence for MFA enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-05` | high | `salesforce_assess_platform_security` | `security-settings`, `profiles`, `profile-metadata` | `settings_readable`, `profile_evidence_available`, `resolved_profile_count`, `profiles_with_ranges_count`, `org_range_count`, `profile_complete`, `enforce_every_request` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every sensitive profile has login IP ranges, per-request enforcement is enabled, and an org-wide trusted range exists; fail when none exists at either level, and warn or manual for mixed, unresolved, or unreadable coverage. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every sensitive profile has login IP ranges, per-request enforcement is enabled, and an org-wide trusted range exists; fail when none exists at either level, and warn or manual for mixed, unresolved, or unreadable coverage. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every sensitive profile has login IP ranges, per-request enforcement is enabled, and an org-wide trusted range exists; fail when none exists at either level, and warn or manual for mixed, unresolved, or unreadable coverage. | The required evidence for IP range restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-06` | high | `salesforce_assess_identity_access` | `profiles`, `profile-metadata` | `profile_evidence_available`, `resolved_profile_count`, `fully_restricted_count`, `partially_restricted_count`, `complete` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every sensitive profile restricts login hours every day, fail when none does, and warn when only some do or profile resolution is incomplete. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every sensitive profile restricts login hours every day, fail when none does, and warn when only some do or profile resolution is incomplete. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every sensitive profile restricts login hours every day, fail when none does, and warn when only some do or profile resolution is incomplete. | The required evidence for Login hour restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-07` | medium | `salesforce_assess_identity_access` | `users`, `profiles` | `population_sane`, `complete`, `api_profile_ratio` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when no visible active user is assigned a profile with API Enabled, warn when such users are below the configured ratio or evidence is partial, and fail when the configured excessive-access threshold is crossed. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when no visible active user is assigned a profile with API Enabled, warn when such users are below the configured ratio or evidence is partial, and fail when the configured excessive-access threshold is crossed. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when no visible active user is assigned a profile with API Enabled, warn when such users are below the configured ratio or evidence is partial, and fail when the configured excessive-access threshold is crossed. | The required evidence for API access controls is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-08` | medium | `salesforce_assess_data_protection` | `field-permissions` | `readable`, `complete`, `sensitive_field_count`, `broad_field_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any sensitive-name field is broadly readable by more than five profile or permission-set grants, warn for narrower grants or partial rows, pass when complete evidence finds classified fields with no readable grants, and manual when no field matches the classification patterns. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any sensitive-name field is broadly readable by more than five profile or permission-set grants, warn for narrower grants or partial rows, pass when complete evidence finds classified fields with no readable grants, and manual when no field matches the classification patterns. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any sensitive-name field is broadly readable by more than five profile or permission-set grants, warn for narrower grants or partial rows, pass when complete evidence finds classified fields with no readable grants, and manual when no field matches the classification patterns. | The required evidence for Field-level security is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-09` | high | `salesforce_assess_identity_access` | `permission-sets`, `permission-set-assignments` | `sets_readable`, `population_sane`, `set_count`, `elevated_set_count`, `assignments_readable`, `complete`, `assignee_count`, `max_admins` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when no permission set grants elevated permissions, warn when elevated sets are assigned within the configured administrator threshold or evidence is partial, fail above the threshold, and manual when the standard inventory is implausibly empty. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when no permission set grants elevated permissions, warn when elevated sets are assigned within the configured administrator threshold or evidence is partial, fail above the threshold, and manual when the standard inventory is implausibly empty. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when no permission set grants elevated permissions, warn when elevated sets are assigned within the configured administrator threshold or evidence is partial, fail above the threshold, and manual when the standard inventory is implausibly empty. | The required evidence for Permission set review is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-10` | high | `salesforce_assess_identity_access` | `users`, `profiles` | `population_sane`, `complete`, `admin_count`, `max_admins`, `stale_admin_count`, `undated_admin_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when active administrator-profile users exceed the configured maximum, warn for stale, undated, or partial administrator evidence, and pass when the complete recent population is within the maximum. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when active administrator-profile users exceed the configured maximum, warn for stale, undated, or partial administrator evidence, and pass when the complete recent population is within the maximum. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when active administrator-profile users exceed the configured maximum, warn for stale, undated, or partial administrator evidence, and pass when the complete recent population is within the maximum. | The required evidence for Profile permissions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-11` | high | `salesforce_assess_monitoring_integrations` | `connected-applications`, `oauth-tokens` | `readable`, `app_count`, `policy_visible`, `open_app_count`, `half_app_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when more than half of connected apps allow user self-authorization, warn for a smaller open set or when visible policies require pre-approval because scopes remain unreadable, and manual when no app or no policy flag is visible. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when more than half of connected apps allow user self-authorization, warn for a smaller open set or when visible policies require pre-approval because scopes remain unreadable, and manual when no app or no policy flag is visible. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when more than half of connected apps allow user self-authorization, warn for a smaller open set or when visible policies require pre-approval because scopes remain unreadable, and manual when no app or no policy flag is visible. | The required evidence for Connected app OAuth policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-12` | high | `salesforce_assess_data_protection` | `organization` | `readable`, `defaults_visible`, `open_default_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when at least three standard objects have public organization-wide defaults, warn for one or two public defaults or for private defaults whose custom objects and sharing rules remain manual, and manual when no default-access field is exposed. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when at least three standard objects have public organization-wide defaults, warn for one or two public defaults or for private defaults whose custom objects and sharing rules remain manual, and manual when no default-access field is exposed. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when at least three standard objects have public organization-wide defaults, warn for one or two public defaults or for private defaults whose custom objects and sharing rules remain manual, and manual when no default-access field is exposed. | The required evidence for Sharing settings is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-13` | medium | `salesforce_assess_identity_access` | `users`, `profiles` | `population_sane`, `users_complete`, `active_guest_count`, `risky_guest_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any active guest user has API Enabled or elevated data permissions, warn when other active guests exist or coverage is partial, and pass when a complete user inventory has no active guest. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any active guest user has API Enabled or elevated data permissions, warn when other active guests exist or coverage is partial, and pass when a complete user inventory has no active guest. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any active guest user has API Enabled or elevated data permissions, warn when other active guests exist or coverage is partial, and pass when a complete user inventory has no active guest. | The required evidence for Guest user access is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-14` | medium | `salesforce_assess_monitoring_integrations` | `login-history` | `readable`, `login_count`, `complete`, `severe_anomaly`, `warning_anomaly` | Complete readable evidence satisfies the compliant branch of this derivation: return fail for severe login forensics such as a failure ratio above the configured threshold, repeated-source failures, or legacy TLS, warn for lesser anomalies, undated rows, or partial reads, and pass when the complete non-empty window has none. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail for severe login forensics such as a failure ratio above the configured threshold, repeated-source failures, or legacy TLS, warn for lesser anomalies, undated rows, or partial reads, and pass when the complete non-empty window has none. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail for severe login forensics such as a failure ratio above the configured threshold, repeated-source failures, or legacy TLS, warn for lesser anomalies, undated rows, or partial reads, and pass when the complete non-empty window has none. | The required evidence for Login forensics is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-15` | medium | `salesforce_assess_monitoring_integrations` | `setup-audit-trail`, `event-log-files` | `audit_readable`, `audit_count`, `audit_complete`, `high_risk_count`, `undated_count`, `event_log_readable` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when complete setup-audit and Event Monitoring evidence is readable and no collection gap exists, warn for high-risk changes or partial or absent EventLogFile evidence, and manual when the active-org audit window is unreadable or implausibly empty. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when complete setup-audit and Event Monitoring evidence is readable and no collection gap exists, warn for high-risk changes or partial or absent EventLogFile evidence, and manual when the active-org audit window is unreadable or implausibly empty. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when complete setup-audit and Event Monitoring evidence is readable and no collection gap exists, warn for high-risk changes or partial or absent EventLogFile evidence, and manual when the active-org audit window is unreadable or implausibly empty. | The required evidence for Setup change tracking is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-16` | high | `salesforce_assess_data_protection` | `tenant-secrets` | `readable`, `complete`, `secret_count`, `active_count`, `undated_active_count`, `oldest_active_age_days` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when a readable complete TenantSecret inventory has no active key, warn when active keys are undated, older than 365 days, or partial, pass for complete recent active keys, and manual when Shield encryption is unavailable or scoped out. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when a readable complete TenantSecret inventory has no active key, warn when active keys are undated, older than 365 days, or partial, pass for complete recent active keys, and manual when Shield encryption is unavailable or scoped out. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when a readable complete TenantSecret inventory has no active key, warn when active keys are undated, older than 365 days, or partial, pass for complete recent active keys, and manual when Shield encryption is unavailable or scoped out. | The required evidence for Data encryption status is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-17` | high | `salesforce_assess_data_protection` | `certificates` | `readable`, `complete`, `certificate_count`, `failure_count`, `warning_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any certificate is expired or has a key under 2048 bits, warn for near expiry, missing dates, exportable private keys, pending chains, or partial evidence, pass when all certificates are valid and managed, and manual when none is returned. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any certificate is expired or has a key under 2048 bits, warn for near expiry, missing dates, exportable private keys, pending chains, or partial evidence, pass when all certificates are valid and managed, and manual when none is returned. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any certificate is expired or has a key under 2048 bits, warn for near expiry, missing dates, exportable private keys, pending chains, or partial evidence, pass when all certificates are valid and managed, and manual when none is returned. | The required evidence for Certificate management is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-18` | medium | `salesforce_assess_platform_security` | `my-domain-settings` | `readable`, `has_my_domain`, `enforcement_present`, `prevent_legacy_login`, `require_domain_for_api` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when My Domain is absent or still permits login.salesforce.com, pass when it is enforced for UI and API login, warn when API login is not restricted, and manual when the enforcement flag is absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when My Domain is absent or still permits login.salesforce.com, pass when it is enforced for UI and API login, warn when API login is not restricted, and manual when the enforcement flag is absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when My Domain is absent or still permits login.salesforce.com, pass when it is enforced for UI and API login, warn when API login is not restricted, and manual when the enforcement flag is absent. | The required evidence for My Domain enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-19` | medium | `salesforce_assess_platform_security` | `security-settings` | `settings_readable`, `all_enabled`, `disabled_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when all four setup, non-setup, Visualforce-with-header, and Visualforce-without-header clickjack flags are enabled, fail when at least two are disabled, warn when one is disabled, and manual when flags are absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when all four setup, non-setup, Visualforce-with-header, and Visualforce-without-header clickjack flags are enabled, fail when at least two are disabled, warn when one is disabled, and manual when flags are absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when all four setup, non-setup, Visualforce-with-header, and Visualforce-without-header clickjack flags are enabled, fail when at least two are disabled, warn when one is disabled, and manual when flags are absent. | The required evidence for Clickjack protection is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SF-20` | medium | `salesforce_assess_platform_security` | `security-settings` | `settings_readable`, `both_present`, `get_enabled`, `post_enabled` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when CSRF protection is enabled for both GET and POST, fail when either is disabled, and manual when either flag is absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when CSRF protection is enabled for both GET and POST, fail when either is disabled, and manual when either flag is absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when CSRF protection is enabled for both GET and POST, fail when either is disabled, and manual when either flag is absent. | The required evidence for CSRF protection is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `SF-01` | 1 | manual | any of (`health_readable` does not equal true; `score_present` does not equal true; `risks_readable` does not equal true) |  |
| `SF-01` | 2 | pass | all of (`score` is at least 90; `high_risk_count` equals 0; `risks_complete` equals true) |  |
| `SF-01` | 3 | warn | `score` is at least 70 |  |
| `SF-01` | 4 | fail | always |  |
| `SF-02` | 1 | manual | any of (`settings_readable` does not equal true; `required_fields_present` does not equal true) |  |
| `SF-02` | 2 | pass | all of (`timeout_minutes` is at most 120; `force_logout` equals true; `lock_to_ip` equals true) |  |
| `SF-02` | 3 | warn | all of (`timeout_minutes` is at most 120; `force_logout` equals true) |  |
| `SF-02` | 4 | fail | always |  |
| `SF-03` | 1 | manual | any of (`settings_readable` does not equal true; `required_fields_present` does not equal true) |  |
| `SF-03` | 2 | pass | `gap_count` equals 0 |  |
| `SF-03` | 3 | warn | `gap_count` equals 1 |  |
| `SF-03` | 4 | fail | always |  |
| `SF-04` | 1 | manual | `requirement_available` does not equal true |  |
| `SF-04` | 2 | fail | `requirement_failed` equals true |  |
| `SF-04` | 3 | manual | `requirement_met` does not equal true |  |
| `SF-04` | 4 | manual | any of (`enrollment_readable` does not equal true; `population_sane` does not equal true; `active_standard_user_count` equals 0) |  |
| `SF-04` | 5 | fail | all of (`enrollment_complete` equals true; `unenrolled_count` is greater than `quarter_user_count`) |  |
| `SF-04` | 6 | warn | any of (`unenrolled_count` is greater than 0; `enrollment_complete` does not equal true; `secondary_sources_complete` does not equal true) |  |
| `SF-04` | 7 | pass | always |  |
| `SF-05` | 1 | manual | any of (`settings_readable` does not equal true; `profile_evidence_available` does not equal true) |  |
| `SF-05` | 2 | fail | all of (`profiles_with_ranges_count` equals 0; `org_range_count` equals 0) |  |
| `SF-05` | 3 | pass | all of (`profiles_with_ranges_count` equals `resolved_profile_count`; `profile_complete` equals true; `enforce_every_request` equals true; `org_range_count` is greater than 0) |  |
| `SF-05` | 4 | warn | always |  |
| `SF-06` | 1 | manual | `profile_evidence_available` does not equal true |  |
| `SF-06` | 2 | pass | all of (`fully_restricted_count` equals `resolved_profile_count`; `complete` equals true) |  |
| `SF-06` | 3 | fail | all of (`fully_restricted_count` equals 0; `partially_restricted_count` equals 0) |  |
| `SF-06` | 4 | warn | always |  |
| `SF-07` | 1 | manual | `population_sane` does not equal true |  |
| `SF-07` | 2 | warn | `complete` does not equal true |  |
| `SF-07` | 3 | fail | `api_profile_ratio` is greater than 0.5 |  |
| `SF-07` | 4 | warn | `api_profile_ratio` is greater than 0.25 |  |
| `SF-07` | 5 | pass | always |  |
| `SF-08` | 1 | manual | any of (`readable` does not equal true; `sensitive_field_count` equals 0) |  |
| `SF-08` | 2 | warn | `broad_field_count` is greater than 0 |  |
| `SF-08` | 3 | warn | `complete` does not equal true |  |
| `SF-08` | 4 | pass | always |  |
| `SF-09` | 1 | manual | any of (`sets_readable` does not equal true; `population_sane` does not equal true; `set_count` equals 0) |  |
| `SF-09` | 2 | warn | all of (`elevated_set_count` equals 0; `complete` does not equal true) |  |
| `SF-09` | 3 | pass | `elevated_set_count` equals 0 |  |
| `SF-09` | 4 | manual | `assignments_readable` does not equal true |  |
| `SF-09` | 5 | fail | `assignee_count` is greater than `max_admins` |  |
| `SF-09` | 6 | warn | `assignee_count` is greater than 0 |  |
| `SF-09` | 7 | warn | `complete` does not equal true |  |
| `SF-09` | 8 | pass | always |  |
| `SF-10` | 1 | manual | `population_sane` does not equal true |  |
| `SF-10` | 2 | fail | any of (`admin_count` is greater than `max_admins`; `stale_admin_count` is greater than 0) |  |
| `SF-10` | 3 | warn | any of (`undated_admin_count` is greater than 0; `complete` does not equal true) |  |
| `SF-10` | 4 | pass | always |  |
| `SF-11` | 1 | manual | any of (`readable` does not equal true; `app_count` equals 0; `policy_visible` does not equal true) |  |
| `SF-11` | 2 | fail | `open_app_count` is greater than `half_app_count` |  |
| `SF-11` | 3 | warn | always |  |
| `SF-12` | 1 | manual | any of (`readable` does not equal true; `defaults_visible` does not equal true) |  |
| `SF-12` | 2 | fail | `open_default_count` is at least 3 |  |
| `SF-12` | 3 | warn | always |  |
| `SF-13` | 1 | manual | `population_sane` does not equal true |  |
| `SF-13` | 2 | warn | `users_complete` does not equal true |  |
| `SF-13` | 3 | pass | `active_guest_count` equals 0 |  |
| `SF-13` | 4 | fail | `risky_guest_count` is greater than 0 |  |
| `SF-13` | 5 | warn | always |  |
| `SF-14` | 1 | manual | any of (`readable` does not equal true; `login_count` equals 0) |  |
| `SF-14` | 2 | warn | `complete` does not equal true |  |
| `SF-14` | 3 | fail | `severe_anomaly` equals true |  |
| `SF-14` | 4 | warn | `warning_anomaly` equals true |  |
| `SF-14` | 5 | pass | always |  |
| `SF-15` | 1 | manual | any of (`audit_readable` does not equal true; `audit_count` equals 0) |  |
| `SF-15` | 2 | warn | any of (`audit_complete` does not equal true; `high_risk_count` is greater than 0; `undated_count` is greater than 0; `event_log_readable` does not equal true) |  |
| `SF-15` | 3 | pass | always |  |
| `SF-16` | 1 | manual | `readable` does not equal true |  |
| `SF-16` | 2 | manual | all of (`secret_count` equals 0; `complete` does not equal true) |  |
| `SF-16` | 3 | fail | any of (`secret_count` equals 0; `active_count` equals 0) |  |
| `SF-16` | 4 | warn | any of (`undated_active_count` is greater than 0; `oldest_active_age_days` is greater than 365; `complete` does not equal true) |  |
| `SF-16` | 5 | pass | always |  |
| `SF-17` | 1 | manual | any of (`readable` does not equal true; `certificate_count` equals 0) |  |
| `SF-17` | 2 | fail | `failure_count` is greater than 0 |  |
| `SF-17` | 3 | warn | any of (`warning_count` is greater than 0; `complete` does not equal true) |  |
| `SF-17` | 4 | pass | always |  |
| `SF-18` | 1 | manual | `readable` does not equal true |  |
| `SF-18` | 2 | fail | `has_my_domain` does not equal true |  |
| `SF-18` | 3 | manual | `enforcement_present` does not equal true |  |
| `SF-18` | 4 | pass | all of (`prevent_legacy_login` equals true; `require_domain_for_api` equals true) |  |
| `SF-18` | 5 | warn | `prevent_legacy_login` equals true |  |
| `SF-18` | 6 | fail | always |  |
| `SF-19` | 1 | manual | `settings_readable` does not equal true |  |
| `SF-19` | 2 | pass | `all_enabled` equals true |  |
| `SF-19` | 3 | fail | `disabled_count` is at least 2 |  |
| `SF-19` | 4 | warn | `disabled_count` equals 1 |  |
| `SF-19` | 5 | manual | always |  |
| `SF-20` | 1 | manual | any of (`settings_readable` does not equal true; `both_present` does not equal true) |  |
| `SF-20` | 2 | pass | all of (`get_enabled` equals true; `post_enabled` equals true) |  |
| `SF-20` | 3 | fail | always |  |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| None |  |  |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `SF-01` | `requiredEvidenceReadable` | true |
| `SF-01` | `requiredEvidenceComplete` | true |
| `SF-02` | `requiredEvidenceReadable` | true |
| `SF-02` | `requiredEvidenceComplete` | true |
| `SF-03` | `requiredEvidenceReadable` | true |
| `SF-03` | `requiredEvidenceComplete` | true |
| `SF-04` | `requiredEvidenceReadable` | true |
| `SF-04` | `requiredEvidenceComplete` | true |
| `SF-05` | `requiredEvidenceReadable` | true |
| `SF-05` | `requiredEvidenceComplete` | true |
| `SF-06` | `requiredEvidenceReadable` | true |
| `SF-06` | `requiredEvidenceComplete` | true |
| `SF-07` | `requiredEvidenceReadable` | true |
| `SF-07` | `requiredEvidenceComplete` | true |
| `SF-08` | `requiredEvidenceReadable` | true |
| `SF-08` | `requiredEvidenceComplete` | true |
| `SF-09` | `requiredEvidenceReadable` | true |
| `SF-09` | `requiredEvidenceComplete` | true |
| `SF-10` | `requiredEvidenceReadable` | true |
| `SF-10` | `requiredEvidenceComplete` | true |
| `SF-11` | `requiredEvidenceReadable` | true |
| `SF-11` | `requiredEvidenceComplete` | true |
| `SF-12` | `requiredEvidenceReadable` | true |
| `SF-12` | `requiredEvidenceComplete` | true |
| `SF-13` | `requiredEvidenceReadable` | true |
| `SF-13` | `requiredEvidenceComplete` | true |
| `SF-14` | `requiredEvidenceReadable` | true |
| `SF-14` | `requiredEvidenceComplete` | true |
| `SF-15` | `requiredEvidenceReadable` | true |
| `SF-15` | `requiredEvidenceComplete` | true |
| `SF-16` | `requiredEvidenceReadable` | true |
| `SF-16` | `requiredEvidenceComplete` | true |
| `SF-17` | `requiredEvidenceReadable` | true |
| `SF-17` | `requiredEvidenceComplete` | true |
| `SF-18` | `requiredEvidenceReadable` | true |
| `SF-18` | `requiredEvidenceComplete` | true |
| `SF-19` | `requiredEvidenceReadable` | true |
| `SF-19` | `requiredEvidenceComplete` | true |
| `SF-20` | `requiredEvidenceReadable` | true |
| `SF-20` | `requiredEvidenceComplete` | true |

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
| `SF-08` | compliant | All required source reads are complete and this derivation returns pass: return fail when any sensitive-name field is broadly readable by more than five profile or permission-set grants, warn for narrower grants or partial rows, pass when complete evidence finds classified fields with no readable grants, and manual when no field matches the classification patterns. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SF-08` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any sensitive-name field is broadly readable by more than five profile or permission-set grants, warn for narrower grants or partial rows, pass when complete evidence finds classified fields with no readable grants, and manual when no field matches the classification patterns. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
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
| 1 | Health Check score | CA-2 | L2 CA.L2-3.12.1 | CC4.1 | 1.1 | 11.3.1 | SRG-APP-000516 | ISM-1526 | 11.3.1 |
| 2 | Session timeout | AC-12 | L2 AC.L2-3.1.10 | CC6.1 | 2.1 | 8.2.8 | SRG-APP-000295 | ISM-1164 | 8.2.8 |
| 3 | Password policy | IA-5(1) | L2 IA.L2-3.5.7 | CC6.1 | 2.2 | 8.3.6 | SRG-APP-000164 | ISM-0421 | 8.3.6 |
| 4 | MFA enforcement | IA-2(1) | L2 IA.L2-3.5.3 | CC6.1 | 2.3 | 8.4.1 | SRG-APP-000149 | ISM-1401 | 8.4.1 |
| 5 | IP range restrictions | AC-3, SC-7 | L2 SC.L2-3.13.1 | CC6.6 | 2.4 | 1.3.1 | SRG-APP-000142 | ISM-1416 | 1.3.1 |
| 6 | Login hour restrictions | AC-2(5) | L2 AC.L2-3.1.8 | CC6.1 | 2.5 | 7.2.1 | SRG-APP-000025 | ISM-0988 | 7.2.1 |
| 7 | API access controls | AC-3 | L2 AC.L2-3.1.2 | CC6.3 | 3.1 | 7.2.2 | SRG-APP-000033 | ISM-1508 | 7.2.2 |
| 8 | Field-level security | AC-3 | L2 AC.L2-3.1.3 | CC6.1 | 3.2 | 7.2.1 | SRG-APP-000033 | ISM-0405 | 7.2.1 |
| 9 | Permission set review | AC-6(1) | L2 AC.L2-3.1.5 | CC6.3 | 3.3 | 7.2.2 | SRG-APP-000340 | ISM-1508 | 7.2.2 |
| 10 | Profile permissions | AC-6(5) | L2 AC.L2-3.1.6 | CC6.3 | 3.4 | 7.2.1 | SRG-APP-000340 | ISM-1508 | 7.2.1 |
| 11 | Connected app OAuth policies | AC-3 | L2 AC.L2-3.1.2 | CC6.1 | 4.1 | 6.4.1 | SRG-APP-000033 | ISM-1508 | 6.4.1 |
| 12 | Sharing settings | AC-4 | L2 AC.L2-3.1.3 | CC6.1 | 3.5 | 7.2.1 | SRG-APP-000038 | ISM-0405 | 7.2.1 |
| 13 | Guest user access | AC-14 | L2 AC.L2-3.1.1 | CC6.1 | 3.6 | 7.2.5 | SRG-APP-000033 | ISM-1508 | 7.2.5 |
| 14 | Login forensics | AU-6 | L2 AU.L2-3.3.5 | CC7.2 | 5.1 | 10.6.1 | SRG-APP-000343 | ISM-0580 | 10.6.1 |
| 15 | Setup change tracking | AU-2, AU-3 | L2 AU.L2-3.3.1 | CC7.2 | 5.2 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 10.2.1 |
| 16 | Data encryption status | SC-28(1) | L2 SC.L2-3.13.16 | CC6.1 | 6.1 | 3.4.1 | SRG-APP-000231 | ISM-0457 | 3.4.1 |
| 17 | Certificate management | SC-17 | L2 SC.L2-3.13.10 | CC6.1 | 6.2 | 4.1.1 | SRG-APP-000514 | ISM-1139 | 4.1.1 |
| 18 | My Domain enforcement | IA-8 | L2 IA.L2-3.5.2 | CC6.1 | 2.6 | 2.2.1 | SRG-APP-000516 | ISM-1590 | 2.2.1 |
| 19 | Clickjack protection | SC-18 | L2 SC.L2-3.13.1 | CC6.1 | 7.1 | 6.2.4 | SRG-APP-000516 | ISM-1486 | 6.2.4 |
| 20 | CSRF protection | SC-18 | L2 SC.L2-3.13.1 | CC6.1 | 7.2 | 6.2.4 | SRG-APP-000516 | ISM-1486 | 6.2.4 |

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
| `limits` | `selected fields named in the runtime SOQL or Metadata API request` |
| `organization` | `selected fields named in the runtime SOQL or Metadata API request` |
| `health-check` | `selected fields named in the runtime SOQL or Metadata API request` |
| `health-check-risks` | `selected fields named in the runtime SOQL or Metadata API request` |
| `security-settings` | `selected fields named in the runtime SOQL or Metadata API request` |
| `my-domain-settings` | `selected fields named in the runtime SOQL or Metadata API request` |
| `users` | `selected fields named in the runtime SOQL or Metadata API request` |
| `profiles` | `selected fields named in the runtime SOQL or Metadata API request` |
| `profile-metadata` | `selected fields named in the runtime SOQL or Metadata API request` |
| `permission-sets` | `selected fields named in the runtime SOQL or Metadata API request` |
| `permission-set-assignments` | `selected fields named in the runtime SOQL or Metadata API request` |
| `two-factor-methods` | `selected fields named in the runtime SOQL or Metadata API request` |
| `field-permissions` | `selected fields named in the runtime SOQL or Metadata API request` |
| `tenant-secrets` | `selected fields named in the runtime SOQL or Metadata API request` |
| `certificates` | `selected fields named in the runtime SOQL or Metadata API request` |
| `connected-applications` | `selected fields named in the runtime SOQL or Metadata API request` |
| `oauth-tokens` | `selected fields named in the runtime SOQL or Metadata API request` |
| `caller-permissions` | `selected fields named in the runtime SOQL or Metadata API request` |
| `login-history` | `selected fields named in the runtime SOQL or Metadata API request` |
| `setup-audit-trail` | `selected fields named in the runtime SOQL or Metadata API request` |
| `event-log-files` | `selected fields named in the runtime SOQL or Metadata API request` |

## Export layout

Required paths:

- `metadata.json`
- `QUICK_REFERENCE.md`
- `core_data/access_check.json`
- `core_data/organization.json`
- `core_data/security_health_check.json`
- `core_data/security_health_check_risks.json`
- `core_data/security_settings.json`
- `core_data/my_domain_settings.json`
- `core_data/users.json`
- `core_data/profiles.json`
- `core_data/profile_metadata.json`
- `core_data/permission_sets.json`
- `core_data/permission_set_assignments.json`
- `core_data/two_factor_methods_info.json`
- `core_data/field_permissions_sensitive.json`
- `core_data/tenant_secrets.json`
- `core_data/certificates.json`
- `core_data/connected_applications.json`
- `core_data/oauth_tokens.json`
- `core_data/caller_permissions.json`
- `core_data/login_history.json`
- `core_data/setup_audit_trail.json`
- `core_data/event_log_files.json`
- `analysis/platform_security.json`
- `analysis/identity_access.json`
- `analysis/data_protection.json`
- `analysis/monitoring_integrations.json`
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

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `metadata.json` | json | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `QUICK_REFERENCE.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `core_data/access_check.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/organization.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/security_health_check.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/security_health_check_risks.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/security_settings.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/my_domain_settings.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/users.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/profiles.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/profile_metadata.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/permission_sets.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/permission_set_assignments.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/two_factor_methods_info.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/field_permissions_sensitive.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/tenant_secrets.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/certificates.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/connected_applications.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/oauth_tokens.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/caller_permissions.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/login_history.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/setup_audit_trail.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/event_log_files.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/platform_security.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/identity_access.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/data_protection.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/monitoring_integrations.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
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

Overwrite policy: Allocate a new {organization}-audit-bundle directory with a numeric suffix when needed; never overwrite a prior directory.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Write a sibling zip named from the exact allocated bundle-directory basename plus .zip.
