---
slug: "servicenow-sec-inspector"
name: "ServiceNow Security Inspector"
vendor: "ServiceNow"
category: "it-service-management"
language: "language-neutral"
status: "generated"
version: "1.0.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# ServiceNow Security Inspector

Portable contract for the shipped ServiceNow identity, hardening, access-control, and operations-governance assessments.

## Purpose

Assess ServiceNow instance identity, access controls, hardening, auditability, integrations, plugins, and operations governance through read-only Table and Aggregate APIs.

## Design guidance

Cross-check row visibility with authoritative counts because ACL filtering can silently hide records. Preserve unreadable properties, tables, and licensed features as unknown evidence, and never convert a skipped dependent request into an empty list.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- Table API rows and Aggregate API counts are cross-checked; missing totals, ACL-filtered visibility, truncation, denied reads, and skipped child requests prevent pass.
- Encoded-query pagination uses sysparm_offset plus X-Total-Count, rejects foreign next links, and preserves exact seen, total, page, and stop-reason evidence.
- MFA, encryption, script, IP, email, and outbound TLS controls use documented properties and tables available to the runtime; unavailable Instance Security Center and product-specific proofs remain manual.
- The configuration parser recognizes the legacy mtls selector only to reject it with an explicit unsupported-mode error; no mTLS transport is implemented.
- Several Instance Security Center, Scan, DKIM, adaptive MFA, MID mutual-authentication, and retention proofs remain manual.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `servicenow_check_access` | Validate read-only ServiceNow Table API and Aggregate API access across the users, roles, ACL, property, SSO, audit, update set, session, OAuth, dictionary, encryption, MID Server, and plugin tables, reporting forbidden and ACL-filtered tables. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `servicenow_assess_identity_access` | Assess ServiceNow role hierarchy (control 3), user access review (4), password policy (6), MFA enforcement (7), LDAP and SSO integration (8), and integration user permissions (14) with evidence-gated verdicts. | `SNOW-03`, `SNOW-04`, `SNOW-06`, `SNOW-07`, `SNOW-08`, `SNOW-14` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `servicenow_assess_platform_hardening` | Assess ServiceNow instance security properties (control 1), session timeout (5), script execution restrictions (12), instance hardening (13), debug mode (16), IP access restrictions (17), and email security (18) from sys_properties and related tables. | `SNOW-01`, `SNOW-05`, `SNOW-12`, `SNOW-13`, `SNOW-16`, `SNOW-17`, `SNOW-18` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `servicenow_assess_access_control` | Assess ServiceNow ACL rule completeness including wildcard, unrestricted, and public page exposure (control 2) and table-level ACL coverage for sensitive tables (11). | `SNOW-02`, `SNOW-11` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `servicenow_assess_operations_governance` | Assess ServiceNow encryption at rest (control 9), audit logging configuration (10), update set management (15), MID Server security (19), and plugin inventory (20); controls whose evidence is not exposed through the API render as manual with the evidence a human must collect. | `SNOW-09`, `SNOW-10`, `SNOW-15`, `SNOW-19`, `SNOW-20` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `servicenow_export_audit_bundle` | Export a ServiceNow evidence bundle with raw table snapshots (core_data/), normalized findings (analysis/), executive summary, unified compliance matrix, per-framework reports (compliance/), QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a paired zip archive. | `SNOW-01`, `SNOW-02`, `SNOW-03`, `SNOW-04`, `SNOW-05`, `SNOW-06`, `SNOW-07`, `SNOW-08`, `SNOW-09`, `SNOW-10`, `SNOW-11`, `SNOW-12`, `SNOW-13`, `SNOW-14`, `SNOW-15`, `SNOW-16`, `SNOW-17`, `SNOW-18`, `SNOW-19`, `SNOW-20` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `servicenow_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance` | string | no | ServiceNow instance name (for https://<instance>.service-now.com). Defaults to SERVICENOW_INSTANCE. |
| `instance_url` | string | no | Full instance URL. Defaults to SERVICENOW_URL, or is derived from the instance name. |
| `auth_method` | string | no | basic or oauth. The legacy mtls selector is recognized only to return an unsupported-mode error. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
| `username` | string | no | Audit account user name for basic auth or the OAuth password grant. Defaults to SERVICENOW_USERNAME. |
| `password` | string | no | Audit account password. Defaults to SERVICENOW_PASSWORD. |
| `client_id` | string | no | OAuth application registry client ID. Defaults to SERVICENOW_CLIENT_ID. |
| `client_secret` | string | no | OAuth application registry client secret. Defaults to SERVICENOW_CLIENT_SECRET. |
| `access_token` | string | no | Pre-issued OAuth bearer token. Defaults to SERVICENOW_ACCESS_TOKEN. |
| `refresh_token` | string | no | OAuth refresh token issued earlier to the client; with client_id and client_secret the first token exchange uses the refresh_token grant. Defaults to SERVICENOW_REFRESH_TOKEN. |
| `config_file` | string | no | YAML config file. Defaults to SERVICENOW_CONFIG_FILE, ./.servicenow.yaml, or ~/.servicenow-sec-inspector/config.yaml. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses. Defaults to 3. |
| `page_size` | number | no | Table API page size (sysparm_limit). Defaults to 500. |

#### `servicenow_assess_identity_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance` | string | no | ServiceNow instance name (for https://<instance>.service-now.com). Defaults to SERVICENOW_INSTANCE. |
| `instance_url` | string | no | Full instance URL. Defaults to SERVICENOW_URL, or is derived from the instance name. |
| `auth_method` | string | no | basic or oauth. The legacy mtls selector is recognized only to return an unsupported-mode error. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
| `username` | string | no | Audit account user name for basic auth or the OAuth password grant. Defaults to SERVICENOW_USERNAME. |
| `password` | string | no | Audit account password. Defaults to SERVICENOW_PASSWORD. |
| `client_id` | string | no | OAuth application registry client ID. Defaults to SERVICENOW_CLIENT_ID. |
| `client_secret` | string | no | OAuth application registry client secret. Defaults to SERVICENOW_CLIENT_SECRET. |
| `access_token` | string | no | Pre-issued OAuth bearer token. Defaults to SERVICENOW_ACCESS_TOKEN. |
| `refresh_token` | string | no | OAuth refresh token issued earlier to the client; with client_id and client_secret the first token exchange uses the refresh_token grant. Defaults to SERVICENOW_REFRESH_TOKEN. |
| `config_file` | string | no | YAML config file. Defaults to SERVICENOW_CONFIG_FILE, ./.servicenow.yaml, or ~/.servicenow-sec-inspector/config.yaml. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses. Defaults to 3. |
| `page_size` | number | no | Table API page size (sysparm_limit). Defaults to 500. |
| `record_limit` | number | no | Maximum rows to page through per table before recording truncation. Defaults to 10000. |
| `inactive_days` | number | no | Days without login before a user counts as inactive. Defaults to 90. |
| `min_password_length` | number | no | Minimum acceptable password length. Defaults to 12. |
| `cert_expiry_warn_days` | number | no | Warn when a certificate expires within this many days. Defaults to 30. |
| `max_admins` | number | no | Maximum acceptable admin or security_admin users before failing. Defaults to 10. |

#### `servicenow_assess_platform_hardening`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance` | string | no | ServiceNow instance name (for https://<instance>.service-now.com). Defaults to SERVICENOW_INSTANCE. |
| `instance_url` | string | no | Full instance URL. Defaults to SERVICENOW_URL, or is derived from the instance name. |
| `auth_method` | string | no | basic or oauth. The legacy mtls selector is recognized only to return an unsupported-mode error. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
| `username` | string | no | Audit account user name for basic auth or the OAuth password grant. Defaults to SERVICENOW_USERNAME. |
| `password` | string | no | Audit account password. Defaults to SERVICENOW_PASSWORD. |
| `client_id` | string | no | OAuth application registry client ID. Defaults to SERVICENOW_CLIENT_ID. |
| `client_secret` | string | no | OAuth application registry client secret. Defaults to SERVICENOW_CLIENT_SECRET. |
| `access_token` | string | no | Pre-issued OAuth bearer token. Defaults to SERVICENOW_ACCESS_TOKEN. |
| `refresh_token` | string | no | OAuth refresh token issued earlier to the client; with client_id and client_secret the first token exchange uses the refresh_token grant. Defaults to SERVICENOW_REFRESH_TOKEN. |
| `config_file` | string | no | YAML config file. Defaults to SERVICENOW_CONFIG_FILE, ./.servicenow.yaml, or ~/.servicenow-sec-inspector/config.yaml. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses. Defaults to 3. |
| `page_size` | number | no | Table API page size (sysparm_limit). Defaults to 500. |
| `record_limit` | number | no | Maximum rows to page through per table before recording truncation. Defaults to 10000. |
| `max_session_timeout_minutes` | number | no | Maximum acceptable glide.ui.session_timeout in minutes. Defaults to 60 (ServiceNow hardening guidance); the spec suggests 30. |

#### `servicenow_assess_access_control`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance` | string | no | ServiceNow instance name (for https://<instance>.service-now.com). Defaults to SERVICENOW_INSTANCE. |
| `instance_url` | string | no | Full instance URL. Defaults to SERVICENOW_URL, or is derived from the instance name. |
| `auth_method` | string | no | basic or oauth. The legacy mtls selector is recognized only to return an unsupported-mode error. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
| `username` | string | no | Audit account user name for basic auth or the OAuth password grant. Defaults to SERVICENOW_USERNAME. |
| `password` | string | no | Audit account password. Defaults to SERVICENOW_PASSWORD. |
| `client_id` | string | no | OAuth application registry client ID. Defaults to SERVICENOW_CLIENT_ID. |
| `client_secret` | string | no | OAuth application registry client secret. Defaults to SERVICENOW_CLIENT_SECRET. |
| `access_token` | string | no | Pre-issued OAuth bearer token. Defaults to SERVICENOW_ACCESS_TOKEN. |
| `refresh_token` | string | no | OAuth refresh token issued earlier to the client; with client_id and client_secret the first token exchange uses the refresh_token grant. Defaults to SERVICENOW_REFRESH_TOKEN. |
| `config_file` | string | no | YAML config file. Defaults to SERVICENOW_CONFIG_FILE, ./.servicenow.yaml, or ~/.servicenow-sec-inspector/config.yaml. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses. Defaults to 3. |
| `page_size` | number | no | Table API page size (sysparm_limit). Defaults to 500. |
| `record_limit` | number | no | Maximum rows to page through per table before recording truncation. Defaults to 10000. |

#### `servicenow_assess_operations_governance`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance` | string | no | ServiceNow instance name (for https://<instance>.service-now.com). Defaults to SERVICENOW_INSTANCE. |
| `instance_url` | string | no | Full instance URL. Defaults to SERVICENOW_URL, or is derived from the instance name. |
| `auth_method` | string | no | basic or oauth. The legacy mtls selector is recognized only to return an unsupported-mode error. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
| `username` | string | no | Audit account user name for basic auth or the OAuth password grant. Defaults to SERVICENOW_USERNAME. |
| `password` | string | no | Audit account password. Defaults to SERVICENOW_PASSWORD. |
| `client_id` | string | no | OAuth application registry client ID. Defaults to SERVICENOW_CLIENT_ID. |
| `client_secret` | string | no | OAuth application registry client secret. Defaults to SERVICENOW_CLIENT_SECRET. |
| `access_token` | string | no | Pre-issued OAuth bearer token. Defaults to SERVICENOW_ACCESS_TOKEN. |
| `refresh_token` | string | no | OAuth refresh token issued earlier to the client; with client_id and client_secret the first token exchange uses the refresh_token grant. Defaults to SERVICENOW_REFRESH_TOKEN. |
| `config_file` | string | no | YAML config file. Defaults to SERVICENOW_CONFIG_FILE, ./.servicenow.yaml, or ~/.servicenow-sec-inspector/config.yaml. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses. Defaults to 3. |
| `page_size` | number | no | Table API page size (sysparm_limit). Defaults to 500. |
| `record_limit` | number | no | Maximum rows to page through per table before recording truncation. Defaults to 10000. |

#### `servicenow_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `instance` | string | no | ServiceNow instance name (for https://<instance>.service-now.com). Defaults to SERVICENOW_INSTANCE. |
| `instance_url` | string | no | Full instance URL. Defaults to SERVICENOW_URL, or is derived from the instance name. |
| `auth_method` | string | no | basic or oauth. The legacy mtls selector is recognized only to return an unsupported-mode error. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
| `username` | string | no | Audit account user name for basic auth or the OAuth password grant. Defaults to SERVICENOW_USERNAME. |
| `password` | string | no | Audit account password. Defaults to SERVICENOW_PASSWORD. |
| `client_id` | string | no | OAuth application registry client ID. Defaults to SERVICENOW_CLIENT_ID. |
| `client_secret` | string | no | OAuth application registry client secret. Defaults to SERVICENOW_CLIENT_SECRET. |
| `access_token` | string | no | Pre-issued OAuth bearer token. Defaults to SERVICENOW_ACCESS_TOKEN. |
| `refresh_token` | string | no | OAuth refresh token issued earlier to the client; with client_id and client_secret the first token exchange uses the refresh_token grant. Defaults to SERVICENOW_REFRESH_TOKEN. |
| `config_file` | string | no | YAML config file. Defaults to SERVICENOW_CONFIG_FILE, ./.servicenow.yaml, or ~/.servicenow-sec-inspector/config.yaml. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429 and 5xx responses. Defaults to 3. |
| `page_size` | number | no | Table API page size (sysparm_limit). Defaults to 500. |
| `record_limit` | number | no | Maximum rows to page through per table before recording truncation. Defaults to 10000. |
| `inactive_days` | number | no | Days without login before a user counts as inactive. Defaults to 90. |
| `min_password_length` | number | no | Minimum acceptable password length. Defaults to 12. |
| `cert_expiry_warn_days` | number | no | Warn when a certificate expires within this many days. Defaults to 30. |
| `max_admins` | number | no | Maximum acceptable admin or security_admin users before failing. Defaults to 10. |
| `max_session_timeout_minutes` | number | no | Maximum acceptable glide.ui.session_timeout in minutes. Defaults to 60 (ServiceNow hardening guidance); the spec suggests 30. |
| `output_dir` | string | no | Output root. Defaults to ./export/servicenow. |


## Authentication

Supported modes:

- Basic username and password
- OAuth client credentials or refresh token
- Explicit OAuth access token

Credential precedence, highest first:

1. Explicit access token
2. Explicit OAuth client credentials or refresh token
3. Explicit Basic credentials
4. Config file
5. SERVICENOW_* environment variables

Environment variables: `SERVICENOW_INSTANCE`, `SERVICENOW_USERNAME`, `SERVICENOW_PASSWORD`, `SERVICENOW_CLIENT_ID`, `SERVICENOW_CLIENT_SECRET`, `SERVICENOW_ACCESS_TOKEN`, `SERVICENOW_REFRESH_TOKEN`

Configuration locations: ~/.servicenow-sec-inspector/config.yaml

Credential and deployment variants: Instance name or explicit HTTPS instance URL

Configuration fields: `instanceUrl`, `instanceName`, `authMode`, `username`, `password`, `clientId`, `clientSecret`, `accessToken`, `refreshToken`, `pageSize`

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

Credential refresh: POST /oauth_token.do with client_credentials or refresh_token form fields.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| role | `Table API read ACLs for every listed table` | `users`, `privileged-assignments`, `role-inheritance`, `identity-properties`, `password-policies`, `sso-providers`, `ldap-servers`, `certificates`, `oauth-entities`, `mfa-criteria`, `hardening-properties`, `debug-properties`, `eval-scripts`, `ip-access`, `ip-authenticator-plugin`, `email-accounts`, `acls`, `acl-roles`, `public-pages`, `encryption-contexts`, `crypto-modules`, `encrypted-fields`, `audit-dictionary`, `update-sets`, `sensitive-update-xml`, `mid-servers`, `mid-properties`, `plugins` | The exact ServiceNow roles are instance-specific because table and field ACLs can be customized. |
| role | `Aggregate API count ACLs matching the Table API population` | `role-inheritance-count`, `acl-count`, `recent-audit-count`, `recent-transaction-count`, `update-set-count` |  |
| role | `security_admin where protected security tables require elevation` | `acls`, `acl-roles`, `acl-count` | Elevation does not replace each table's read ACL. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `users` | HTTP | `GET /api/now/table/sys_user` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `user_name`, `active`, `last_login_time`, `web_service_access_only`, `internal_integration_user`, `enable_multifactor_authn`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `privileged-assignments` | HTTP | `GET /api/now/table/sys_user_has_role` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `user`, `user.user_name`, `user.active`, `user.web_service_access_only`, `user.internal_integration_user`, `role`, `role.name` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `role-inheritance` | HTTP | `GET /api/now/table/sys_user_role_contains` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `role`, `role.name`, `contains`, `contains.name` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `role-inheritance-count` | HTTP | `GET /api/now/stats/sys_user_role_contains` | ServiceNow Aggregate API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `result.stats.count` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AggregateAPI.html) |
| `identity-properties` | HTTP | `GET /api/now/table/sys_properties` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `value`, `description`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `password-policies` | HTTP | `GET /api/now/table/password_policy` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `active`, `minimum_password_length`, `maximum_password_length`, `strength`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `sso-providers` | HTTP | `GET /api/now/table/sso_properties` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `active`, `default`, `auto_redirect_idp`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `ldap-servers` | HTTP | `GET /api/now/table/ldap_server_config` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `active`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `certificates` | HTTP | `GET /api/now/table/sys_certificate` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `active`, `valid_from`, `expires`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `oauth-entities` | HTTP | `GET /api/now/table/oauth_entity` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `type`, `active`, `client_id`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `mfa-criteria` | HTTP | `GET /api/now/table/multi_factor_criteria` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `active`, `order`, `roles`, `multi_factor_roles`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `hardening-properties` | HTTP | `GET /api/now/table/sys_properties` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `value`, `description`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `debug-properties` | HTTP | `GET /api/now/table/sys_properties` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `value`, `description`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `eval-scripts` | HTTP | `GET /api/now/table/sys_script` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `collection`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `ip-access` | HTTP | `GET /api/now/table/ip_access` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `type`, `direction`, `active`, `range_start`, `range_end`, `description`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `ip-authenticator-plugin` | HTTP | `GET /api/now/table/sys_plugins` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `source`, `active`, `state`, `version`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `email-accounts` | HTTP | `GET /api/now/table/sys_email_account` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `type`, `active`, `connection_security`, `enable_ssl`, `enable_tls`, `authentication`, `server`, `port`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `acls` | HTTP | `GET /api/now/table/sys_security_acl` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `operation`, `type`, `active`, `admin_overrides`, `condition-present`, `script-present`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `acl-roles` | HTTP | `GET /api/now/table/sys_security_acl_role` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `sys_security_acl`, `sys_user_role`, `sys_user_role.name` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `acl-count` | HTTP | `GET /api/now/stats/sys_security_acl` | ServiceNow Aggregate API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `result.stats.count` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AggregateAPI.html) |
| `public-pages` | HTTP | `GET /api/now/table/sys_public` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `page`, `active`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `encryption-contexts` | HTTP | `GET /api/now/table/sys_encryption_context` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `type`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `crypto-modules` | HTTP | `GET /api/now/table/sys_kmf_crypto_module` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `module_name`, `state`, `sys_scope`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `encrypted-fields` | HTTP | `GET /api/now/table/sys_dictionary` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `element`, `internal_type` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `audit-dictionary` | HTTP | `GET /api/now/table/sys_dictionary` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `audit`, `attributes` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `recent-audit-count` | HTTP | `GET /api/now/stats/sys_audit` | ServiceNow Aggregate API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `result.stats.count` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AggregateAPI.html) |
| `recent-transaction-count` | HTTP | `GET /api/now/stats/syslog_transaction` | ServiceNow Aggregate API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `result.stats.count` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AggregateAPI.html) |
| `update-sets` | HTTP | `GET /api/now/table/sys_update_set` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `state`, `application`, `sys_created_by`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `update-set-count` | HTTP | `GET /api/now/stats/sys_update_set` | ServiceNow Aggregate API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `result.stats.count` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AggregateAPI.html) |
| `sensitive-update-xml` | HTTP | `GET /api/now/table/sys_update_xml` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `type`, `target_name`, `action`, `update_set`, `update_set.name`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `mid-servers` | HTTP | `GET /api/now/table/ecc_agent` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `status`, `validated`, `version`, `host_name`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `mid-properties` | HTTP | `GET /api/now/table/sys_properties` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `value`, `description`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `plugins` | HTTP | `GET /api/now/table/sys_plugins` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `source`, `active`, `state`, `version`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `users` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `users` | response | A JSON object or list containing only the documented sys_id, user_name, active, last_login_time, web_service_access_only, internal_integration_user, enable_multifactor_authn, sys_updated_on members consumed by verdicts. | yes |
| `privileged-assignments` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `privileged-assignments` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `privileged-assignments` | response | A JSON object or list containing only the documented sys_id, user, user.user_name, user.active, user.web_service_access_only, user.internal_integration_user, role, role.name members consumed by verdicts. | yes |
| `role-inheritance` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `role-inheritance` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `role-inheritance` | response | A JSON object or list containing only the documented sys_id, role, role.name, contains, contains.name members consumed by verdicts. | yes |
| `role-inheritance-count` | client | Use the configured ServiceNow Aggregate API origin; never follow a server link to a different origin. | yes |
| `role-inheritance-count` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `role-inheritance-count` | response | A JSON object or list containing only the documented result.stats.count members consumed by verdicts. | yes |
| `identity-properties` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `identity-properties` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `identity-properties` | response | A JSON object or list containing only the documented sys_id, name, value, description, sys_updated_on members consumed by verdicts. | yes |
| `password-policies` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `password-policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `password-policies` | response | A JSON object or list containing only the documented sys_id, name, active, minimum_password_length, maximum_password_length, strength, sys_updated_on members consumed by verdicts. | yes |
| `sso-providers` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `sso-providers` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `sso-providers` | response | A JSON object or list containing only the documented sys_id, name, active, default, auto_redirect_idp, sys_updated_on members consumed by verdicts. | yes |
| `ldap-servers` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `ldap-servers` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `ldap-servers` | response | A JSON object or list containing only the documented sys_id, name, active, sys_updated_on members consumed by verdicts. | yes |
| `certificates` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `certificates` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `certificates` | response | A JSON object or list containing only the documented sys_id, name, active, valid_from, expires, sys_updated_on members consumed by verdicts. | yes |
| `oauth-entities` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `oauth-entities` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `oauth-entities` | response | A JSON object or list containing only the documented sys_id, name, type, active, client_id, sys_updated_on members consumed by verdicts. | yes |
| `mfa-criteria` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `mfa-criteria` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `mfa-criteria` | response | A JSON object or list containing only the documented sys_id, name, active, order, roles, multi_factor_roles, sys_updated_on members consumed by verdicts. | yes |
| `hardening-properties` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `hardening-properties` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `hardening-properties` | response | A JSON object or list containing only the documented sys_id, name, value, description, sys_updated_on members consumed by verdicts. | yes |
| `debug-properties` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `debug-properties` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `debug-properties` | response | A JSON object or list containing only the documented sys_id, name, value, description, sys_updated_on members consumed by verdicts. | yes |
| `eval-scripts` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `eval-scripts` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `eval-scripts` | response | A JSON object or list containing only the documented sys_id, name, collection, sys_updated_on members consumed by verdicts. | yes |
| `ip-access` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `ip-access` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `ip-access` | response | A JSON object or list containing only the documented sys_id, type, direction, active, range_start, range_end, description, sys_updated_on members consumed by verdicts. | yes |
| `ip-authenticator-plugin` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `ip-authenticator-plugin` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `ip-authenticator-plugin` | response | A JSON object or list containing only the documented sys_id, name, source, active, state, version, sys_updated_on members consumed by verdicts. | yes |
| `email-accounts` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `email-accounts` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `email-accounts` | response | A JSON object or list containing only the documented sys_id, name, type, active, connection_security, enable_ssl, enable_tls, authentication, server, port, sys_updated_on members consumed by verdicts. | yes |
| `acls` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `acls` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `acls` | response | A JSON object or list containing only the documented sys_id, name, operation, type, active, admin_overrides, condition-present, script-present, sys_updated_on members consumed by verdicts. | yes |
| `acl-roles` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `acl-roles` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `acl-roles` | response | A JSON object or list containing only the documented sys_id, sys_security_acl, sys_user_role, sys_user_role.name members consumed by verdicts. | yes |
| `acl-count` | client | Use the configured ServiceNow Aggregate API origin; never follow a server link to a different origin. | yes |
| `acl-count` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `acl-count` | response | A JSON object or list containing only the documented result.stats.count members consumed by verdicts. | yes |
| `public-pages` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `public-pages` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `public-pages` | response | A JSON object or list containing only the documented sys_id, page, active, sys_updated_on members consumed by verdicts. | yes |
| `encryption-contexts` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `encryption-contexts` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `encryption-contexts` | response | A JSON object or list containing only the documented sys_id, name, type, sys_updated_on members consumed by verdicts. | yes |
| `crypto-modules` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `crypto-modules` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `crypto-modules` | response | A JSON object or list containing only the documented sys_id, name, module_name, state, sys_scope, sys_updated_on members consumed by verdicts. | yes |
| `encrypted-fields` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `encrypted-fields` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `encrypted-fields` | response | A JSON object or list containing only the documented sys_id, name, element, internal_type members consumed by verdicts. | yes |
| `audit-dictionary` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `audit-dictionary` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `audit-dictionary` | response | A JSON object or list containing only the documented sys_id, name, audit, attributes members consumed by verdicts. | yes |
| `recent-audit-count` | client | Use the configured ServiceNow Aggregate API origin; never follow a server link to a different origin. | yes |
| `recent-audit-count` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `recent-audit-count` | response | A JSON object or list containing only the documented result.stats.count members consumed by verdicts. | yes |
| `recent-transaction-count` | client | Use the configured ServiceNow Aggregate API origin; never follow a server link to a different origin. | yes |
| `recent-transaction-count` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `recent-transaction-count` | response | A JSON object or list containing only the documented result.stats.count members consumed by verdicts. | yes |
| `update-sets` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `update-sets` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `update-sets` | response | A JSON object or list containing only the documented sys_id, name, state, application, sys_created_by, sys_updated_on members consumed by verdicts. | yes |
| `update-set-count` | client | Use the configured ServiceNow Aggregate API origin; never follow a server link to a different origin. | yes |
| `update-set-count` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `update-set-count` | response | A JSON object or list containing only the documented result.stats.count members consumed by verdicts. | yes |
| `sensitive-update-xml` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `sensitive-update-xml` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `sensitive-update-xml` | response | A JSON object or list containing only the documented sys_id, name, type, target_name, action, update_set, update_set.name, sys_updated_on members consumed by verdicts. | yes |
| `mid-servers` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `mid-servers` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `mid-servers` | response | A JSON object or list containing only the documented sys_id, name, status, validated, version, host_name, sys_updated_on members consumed by verdicts. | yes |
| `mid-properties` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `mid-properties` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `mid-properties` | response | A JSON object or list containing only the documented sys_id, name, value, description, sys_updated_on members consumed by verdicts. | yes |
| `plugins` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `plugins` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `plugins` | response | A JSON object or list containing only the documented sys_id, name, source, active, state, version, sys_updated_on members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `users`, `privileged-assignments`, `role-inheritance`, `identity-properties`, `password-policies`, `sso-providers`, `ldap-servers`, `certificates`, `oauth-entities`, `mfa-criteria`, `hardening-properties`, `debug-properties`, `eval-scripts`, `ip-access`, `ip-authenticator-plugin`, `email-accounts`, `acls`, `acl-roles`, `public-pages`, `encryption-contexts`, `crypto-modules`, `encrypted-fields`, `audit-dictionary`, `update-sets`, `sensitive-update-xml`, `mid-servers`, `mid-properties`, `plugins` | `sysparm_offset`, `sysparm_limit`, `X-Total-Count`, `Link rel=next` | 500 | 10000 | none | X-Total-Count or Aggregate count is authoritative; absent or mismatched totals prevent proven exhaustion. | Seen count reaches authoritative total; Short page with authoritative completion; Configured item cap; Empty page before total; Repeated offset; Missing total; Rejected next link |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| ServiceNow Security Inspector | Instance and node configuration determine ServiceNow inbound REST limits | `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining` | 429, 500, 502, 503, 504 | Honor bounded Retry-After and retry transient reads three times; exhausted reads remain unavailable. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | Instance security properties | SNOW-01 | Evaluate the ordered first-match rules for SNOW-01 below. |
| 2 | ACL rule completeness | SNOW-02 | Evaluate the ordered first-match rules for SNOW-02 below. |
| 3 | Role hierarchy audit | SNOW-03 | Evaluate the ordered first-match rules for SNOW-03 below. |
| 4 | User access review | SNOW-04 | Evaluate the ordered first-match rules for SNOW-04 below. |
| 5 | Session timeout configuration | SNOW-05 | Evaluate the ordered first-match rules for SNOW-05 below. |
| 6 | Password policy enforcement | SNOW-06 | Evaluate the ordered first-match rules for SNOW-06 below. |
| 7 | MFA enforcement | SNOW-07 | Evaluate the ordered first-match rules for SNOW-07 below. |
| 8 | LDAP and SSO integration | SNOW-08 | Evaluate the ordered first-match rules for SNOW-08 below. |
| 9 | Encryption at rest | SNOW-09 | Evaluate the ordered first-match rules for SNOW-09 below. |
| 10 | Audit logging configuration | SNOW-10 | Evaluate the ordered first-match rules for SNOW-10 below. |
| 11 | Table-level access controls | SNOW-11 | Evaluate the ordered first-match rules for SNOW-11 below. |
| 12 | Script execution restrictions | SNOW-12 | Evaluate the ordered first-match rules for SNOW-12 below. |
| 13 | Instance hardening | SNOW-13 | Evaluate the ordered first-match rules for SNOW-13 below. |
| 14 | Integration user permissions | SNOW-14 | Evaluate the ordered first-match rules for SNOW-14 below. |
| 15 | Update set management | SNOW-15 | Evaluate the ordered first-match rules for SNOW-15 below. |
| 16 | Debug mode verification | SNOW-16 | Evaluate the ordered first-match rules for SNOW-16 below. |
| 17 | IP access restrictions | SNOW-17 | Evaluate the ordered first-match rules for SNOW-17 below. |
| 18 | Email security | SNOW-18 | Evaluate the ordered first-match rules for SNOW-18 below. |
| 19 | MID Server security | SNOW-19 | Evaluate the ordered first-match rules for SNOW-19 below. |
| 20 | Plugin inventory and licensing | SNOW-20 | Evaluate the ordered first-match rules for SNOW-20 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `SNOW-01` | high | `servicenow_assess_platform_hardening` | `hardening-properties` | `readable`, `complete`, `noncompliant_count`, `absent_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete security-property set enables the documented secure defaults, fail when any required property is explicitly insecure, and warn when optional hardening is absent or evidence is partial. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete security-property set enables the documented secure defaults, fail when any required property is explicitly insecure, and warn when optional hardening is absent or evidence is partial. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete security-property set enables the documented secure defaults, fail when any required property is explicitly insecure, and warn when optional hardening is absent or evidence is partial. | The required evidence for Instance security properties is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-02` | high | `servicenow_assess_access_control` | `acls`, `acl-roles`, `acl-count`, `public-pages` | `readable`, `complete`, `inventory_proven`, `visible_acl_count`, `unrestricted_count`, `wildcard_count`, `public_page_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any active ACL lacks both a role and a condition or script, warn when questionable ACLs remain or ACL and role joins are partial, and pass when every active ACL has an explicit restriction. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any active ACL lacks both a role and a condition or script, warn when questionable ACLs remain or ACL and role joins are partial, and pass when every active ACL has an explicit restriction. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any active ACL lacks both a role and a condition or script, warn when questionable ACLs remain or ACL and role joins are partial, and pass when every active ACL has an explicit restriction. | The required evidence for ACL rule completeness is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-03` | high | `servicenow_assess_identity_access` | `role-inheritance`, `role-inheritance-count` | `readable`, `complete`, `inventory_proven`, `inheriting_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when administrator-equivalent roles exceed the configured population threshold, warn for broad inheritance, stale assignments, or partial role data, and pass when complete role and assignment evidence stays within the threshold. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when administrator-equivalent roles exceed the configured population threshold, warn for broad inheritance, stale assignments, or partial role data, and pass when complete role and assignment evidence stays within the threshold. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when administrator-equivalent roles exceed the configured population threshold, warn for broad inheritance, stale assignments, or partial role data, and pass when complete role and assignment evidence stays within the threshold. | The required evidence for Role hierarchy audit is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-04` | high | `servicenow_assess_identity_access` | `users`, `privileged-assignments` | `readable`, `complete`, `user_count`, `admin_assignment_count`, `admin_count`, `max_admins`, `stale_admin_count`, `warning_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when active privileged users exceed the configured maximum or include stale accounts beyond the configured age, warn for undated users or partial evidence, and pass when the complete population is bounded and recent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when active privileged users exceed the configured maximum or include stale accounts beyond the configured age, warn for undated users or partial evidence, and pass when the complete population is bounded and recent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when active privileged users exceed the configured maximum or include stale accounts beyond the configured age, warn for undated users or partial evidence, and pass when the complete population is bounded and recent. | The required evidence for User access review is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-05` | medium | `servicenow_assess_platform_hardening` | `hardening-properties` | `readable`, `complete`, `timeout_present`, `timeout_valid`, `rotate_disabled` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the inactivity timeout is positive and at or below the configured threshold, warn when it exceeds the threshold, fail when disabled, and manual when the property is absent or unreadable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the inactivity timeout is positive and at or below the configured threshold, warn when it exceeds the threshold, fail when disabled, and manual when the property is absent or unreadable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the inactivity timeout is positive and at or below the configured threshold, warn when it exceeds the threshold, fail when disabled, and manual when the property is absent or unreadable. | The required evidence for Session timeout configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-06` | high | `servicenow_assess_identity_access` | `identity-properties`, `password-policies` | `readable`, `complete`, `policy_enabled`, `policy_count`, `minimum_fields_readable`, `weak_policy_count`, `enablement_present` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the password policy meets minimum and maximum length, character-class, and strength requirements, warn when only some fields miss the baseline, fail for a weak preset or multiple gaps, and manual when decisive fields are absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the password policy meets minimum and maximum length, character-class, and strength requirements, warn when only some fields miss the baseline, fail for a weak preset or multiple gaps, and manual when decisive fields are absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the password policy meets minimum and maximum length, character-class, and strength requirements, warn when only some fields miss the baseline, fail for a weak preset or multiple gaps, and manual when decisive fields are absent. | The required evidence for Password policy enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-07` | critical | `servicenow_assess_identity_access` | `identity-properties`, `users`, `privileged-assignments`, `mfa-criteria` | `readable`, `complete`, `properties_complete`, `platform_property_present`, `platform_enabled`, `criteria_count`, `admin_count`, `active_role_criteria_count`, `role_enforced`, `user_enforced`, `email_otp_enabled` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when an active multi-factor criterion covers every required privileged role, fail when no active criterion exists, warn for incomplete role coverage, and manual when criteria or role evidence is unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when an active multi-factor criterion covers every required privileged role, fail when no active criterion exists, warn for incomplete role coverage, and manual when criteria or role evidence is unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when an active multi-factor criterion covers every required privileged role, fail when no active criterion exists, warn for incomplete role coverage, and manual when criteria or role evidence is unavailable. | The required evidence for MFA enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-08` | high | `servicenow_assess_identity_access` | `sso-providers`, `ldap-servers`, `identity-properties`, `certificates` | `readable`, `complete`, `providers_complete`, `provider_count`, `expired_certificate_count`, `concern_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when an active SSO or LDAP integration is visible with enabled redirect policy and valid dated certificates, fail when complete evidence has no active external identity provider or an active certificate is expired, warn for weak redirect policy or near-expiry and undated certificates, and manual when integration evidence is unreadable or partial. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when an active SSO or LDAP integration is visible with enabled redirect policy and valid dated certificates, fail when complete evidence has no active external identity provider or an active certificate is expired, warn for weak redirect policy or near-expiry and undated certificates, and manual when integration evidence is unreadable or partial. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when an active SSO or LDAP integration is visible with enabled redirect policy and valid dated certificates, fail when complete evidence has no active external identity provider or an active certificate is expired, warn for weak redirect policy or near-expiry and undated certificates, and manual when integration evidence is unreadable or partial. | The required evidence for LDAP and SSO integration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-09` | medium | `servicenow_assess_operations_governance` | `encryption-contexts`, `crypto-modules`, `encrypted-fields` | None | Complete readable evidence satisfies the compliant branch of this derivation: return pass when an active customer encryption module or encrypted field evidence is visible, warn when only platform-default encryption is evident, fail when readable evidence explicitly disables encryption, and manual when the licensed encryption surface is unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when an active customer encryption module or encrypted field evidence is visible, warn when only platform-default encryption is evident, fail when readable evidence explicitly disables encryption, and manual when the licensed encryption surface is unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when an active customer encryption module or encrypted field evidence is visible, warn when only platform-default encryption is evident, fail when readable evidence explicitly disables encryption, and manual when the licensed encryption surface is unavailable. | The required evidence for Encryption at rest is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-10` | high | `servicenow_assess_operations_governance` | `audit-dictionary`, `recent-audit-count`, `recent-transaction-count` | `readable`, `unaudited_count`, `missing_dictionary_count`, `recent_audit_count_known`, `recent_audit_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when system auditing is enabled and the complete lookback contains records, warn when the readable window is empty or partial, fail when auditing is explicitly disabled, and manual when properties or audit rows are unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when system auditing is enabled and the complete lookback contains records, warn when the readable window is empty or partial, fail when auditing is explicitly disabled, and manual when properties or audit rows are unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when system auditing is enabled and the complete lookback contains records, warn when the readable window is empty or partial, fail when auditing is explicitly disabled, and manual when properties or audit rows are unavailable. | The required evidence for Audit logging configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-11` | high | `servicenow_assess_access_control` | `acls`, `acl-roles`, `acl-count` | `readable`, `complete`, `inventory_proven`, `uncovered_table_count`, `operation_gap_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any sensitive table has an active permissive ACL without role, condition, or script restrictions, warn for incomplete table or ACL evidence, and pass when every inspected sensitive table is explicitly protected. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any sensitive table has an active permissive ACL without role, condition, or script restrictions, warn for incomplete table or ACL evidence, and pass when every inspected sensitive table is explicitly protected. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any sensitive table has an active permissive ACL without role, condition, or script restrictions, warn for incomplete table or ACL evidence, and pass when every inspected sensitive table is explicitly protected. | The required evidence for Table-level access controls is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-12` | high | `servicenow_assess_platform_hardening` | `hardening-properties`, `eval-scripts` | `readable`, `complete`, `noncompliant_count`, `absent_count`, `eval_rule_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when unrestricted server-side script execution is enabled, pass when the documented script restrictions are enabled, warn for mixed settings, and manual when the required properties are absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when unrestricted server-side script execution is enabled, pass when the documented script restrictions are enabled, warn for mixed settings, and manual when the required properties are absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when unrestricted server-side script execution is enabled, pass when the documented script restrictions are enabled, warn for mixed settings, and manual when the required properties are absent. | The required evidence for Script execution restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-13` | high | `servicenow_assess_platform_hardening` | `hardening-properties` | `readable`, `complete`, `noncompliant_count`, `absent_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when all documented baseline hardening properties are secure, fail when any critical property is explicitly insecure, and warn when noncritical settings are weak or evidence is partial. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when all documented baseline hardening properties are secure, fail when any critical property is explicitly insecure, and warn when noncritical settings are weak or evidence is partial. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when all documented baseline hardening properties are secure, fail when any critical property is explicitly insecure, and warn when noncritical settings are weak or evidence is partial. | The required evidence for Instance hardening is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-14` | high | `servicenow_assess_identity_access` | `users`, `privileged-assignments`, `oauth-entities` | `readable`, `complete`, `integration_user_count`, `admin_integration_count`, `privileged_assignment_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when an active integration user has administrator-equivalent roles, warn for broad non-admin roles, stale users, or partial assignments, and pass when complete evidence shows least-privileged integration identities. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when an active integration user has administrator-equivalent roles, warn for broad non-admin roles, stale users, or partial assignments, and pass when complete evidence shows least-privileged integration identities. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when an active integration user has administrator-equivalent roles, warn for broad non-admin roles, stale users, or partial assignments, and pass when complete evidence shows least-privileged integration identities. | The required evidence for Integration user permissions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-15` | medium | `servicenow_assess_operations_governance` | `update-sets`, `update-set-count`, `sensitive-update-xml` | `readable`, `complete`, `inventory_proven`, `visibility_proven`, `in_progress_count`, `sensitive_change_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when complete update-set evidence shows recent completed sets with no unresolved preview or commit errors, warn for in-progress, stale, failed, or partial sets, and manual when update-set tables are unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when complete update-set evidence shows recent completed sets with no unresolved preview or commit errors, warn for in-progress, stale, failed, or partial sets, and manual when update-set tables are unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when complete update-set evidence shows recent completed sets with no unresolved preview or commit errors, warn for in-progress, stale, failed, or partial sets, and manual when update-set tables are unavailable. | The required evidence for Update set management is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-16` | medium | `servicenow_assess_platform_hardening` | `hardening-properties`, `debug-properties` | `readable`, `complete`, `enabled_debug_count`, `hardening_property_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when debug and diagnostic properties are disabled, fail when any is enabled, warn when the property inventory is partial, and manual when no decisive debug property is readable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when debug and diagnostic properties are disabled, fail when any is enabled, warn when the property inventory is partial, and manual when no decisive debug property is readable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when debug and diagnostic properties are disabled, fail when any is enabled, warn when the property inventory is partial, and manual when no decisive debug property is readable. | The required evidence for Debug mode verification is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-17` | medium | `servicenow_assess_platform_hardening` | `hardening-properties`, `ip-access`, `ip-authenticator-plugin` | `readable`, `complete`, `plugin_present`, `plugin_inventory_complete`, `plugin_active`, `active_rule_count`, `rule_inventory_complete`, `table_available`, `strict_enabled` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete IP access-control inventory contains active restrictive ranges, fail when an explicit allow-all rule exists, warn when no rule exists or coverage is partial, and manual when the table is unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete IP access-control inventory contains active restrictive ranges, fail when an explicit allow-all rule exists, warn when no rule exists or coverage is partial, and manual when the table is unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete IP access-control inventory contains active restrictive ranges, fail when an explicit allow-all rule exists, warn when no rule exists or coverage is partial, and manual when the table is unavailable. | The required evidence for IP access restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-18` | medium | `servicenow_assess_platform_hardening` | `hardening-properties`, `email-accounts` | `readable`, `smtp_account_count`, `insecure_count`, `smtp_auth_disabled`, `unverified_count`, `starttls_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when documented outbound email TLS and security properties are enabled, fail when TLS is explicitly disabled, warn for weaker optional settings, and manual when decisive properties are absent. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when documented outbound email TLS and security properties are enabled, fail when TLS is explicitly disabled, warn for weaker optional settings, and manual when decisive properties are absent. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when documented outbound email TLS and security properties are enabled, fail when TLS is explicitly disabled, warn for weaker optional settings, and manual when decisive properties are absent. | The required evidence for Email security is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-19` | medium | `servicenow_assess_operations_governance` | `mid-servers`, `mid-properties` | `readable`, `server_count`, `not_validated_count`, `version_override_present` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every active MID Server is validated, recent, and uses a non-administrator service identity, fail for administrator identities or failed validation, warn for stale, down, or partial records, and manual when the MID inventory is unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every active MID Server is validated, recent, and uses a non-administrator service identity, fail for administrator identities or failed validation, warn for stale, down, or partial records, and manual when the MID inventory is unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every active MID Server is validated, recent, and uses a non-administrator service identity, fail for administrator identities or failed validation, warn for stale, down, or partial records, and manual when the MID inventory is unavailable. | The required evidence for MID Server security is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-20` | medium | `servicenow_assess_operations_governance` | `plugins` | `readable`, `complete`, `plugin_count`, `observed_inactive_required_count`, `missing_required_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when a complete plugin inventory is missing a required baseline security plugin or a visible required plugin is inactive, and manual when the inventory is empty, partial around a missing baseline plugin, or all required plugins are active because licensing and intended use cannot be inferred from the API. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when a complete plugin inventory is missing a required baseline security plugin or a visible required plugin is inactive, and manual when the inventory is empty, partial around a missing baseline plugin, or all required plugins are active because licensing and intended use cannot be inferred from the API. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when a complete plugin inventory is missing a required baseline security plugin or a visible required plugin is inactive, and manual when the inventory is empty, partial around a missing baseline plugin, or all required plugins are active because licensing and intended use cannot be inferred from the API. | The required evidence for Plugin inventory and licensing is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `SNOW-01` | 1 | manual | `readable` does not equal true |  |
| `SNOW-01` | 2 | fail | `noncompliant_count` is greater than 0 |  |
| `SNOW-01` | 3 | warn | any of (`absent_count` is greater than 0; `complete` does not equal true) |  |
| `SNOW-01` | 4 | pass | always |  |
| `SNOW-02` | 1 | manual | any of (`readable` does not equal true; `inventory_proven` does not equal true; `visible_acl_count` equals 0) |  |
| `SNOW-02` | 2 | fail | `unrestricted_count` is greater than 0 |  |
| `SNOW-02` | 3 | warn | any of (`wildcard_count` is greater than 0; `public_page_count` is greater than 0; `complete` does not equal true) |  |
| `SNOW-02` | 4 | pass | always |  |
| `SNOW-03` | 1 | manual | any of (`readable` does not equal true; `inventory_proven` does not equal true) |  |
| `SNOW-03` | 2 | warn | `inheriting_count` is greater than 0 |  |
| `SNOW-03` | 3 | warn | `complete` does not equal true |  |
| `SNOW-03` | 4 | pass | always |  |
| `SNOW-04` | 1 | manual | any of (`readable` does not equal true; `user_count` equals 0; `admin_assignment_count` equals 0) |  |
| `SNOW-04` | 2 | fail | any of (`admin_count` is greater than `max_admins`; `stale_admin_count` is greater than 0) |  |
| `SNOW-04` | 3 | warn | any of (`warning_count` is greater than 0; `complete` does not equal true) |  |
| `SNOW-04` | 4 | pass | always |  |
| `SNOW-05` | 1 | manual | `readable` does not equal true |  |
| `SNOW-05` | 2 | fail | all of (`timeout_present` equals true; `timeout_valid` does not equal true) |  |
| `SNOW-05` | 3 | warn | any of (`timeout_present` does not equal true; `rotate_disabled` equals true; `complete` does not equal true) |  |
| `SNOW-05` | 4 | pass | always |  |
| `SNOW-06` | 1 | manual | `readable` does not equal true |  |
| `SNOW-06` | 2 | fail | `policy_enabled` equals false |  |
| `SNOW-06` | 3 | manual | all of (`policy_count` equals 0; `complete` does not equal true) |  |
| `SNOW-06` | 4 | fail | `policy_count` equals 0 |  |
| `SNOW-06` | 5 | manual | `minimum_fields_readable` does not equal true |  |
| `SNOW-06` | 6 | fail | `weak_policy_count` is greater than 0 |  |
| `SNOW-06` | 7 | warn | any of (`enablement_present` does not equal true; `complete` does not equal true) |  |
| `SNOW-06` | 8 | pass | always |  |
| `SNOW-07` | 1 | manual | `readable` does not equal true |  |
| `SNOW-07` | 2 | manual | all of (`platform_property_present` does not equal true; `properties_complete` does not equal true) |  |
| `SNOW-07` | 3 | fail | `platform_enabled` does not equal true |  |
| `SNOW-07` | 4 | manual | any of (`criteria_count` equals 0; `admin_count` equals 0) |  |
| `SNOW-07` | 5 | fail | all of (`active_role_criteria_count` equals 0; `user_enforced` does not equal true) |  |
| `SNOW-07` | 6 | warn | any of (`active_role_criteria_count` equals 0; all of (`role_enforced` does not equal true; `user_enforced` does not equal true); `email_otp_enabled` equals true; `complete` does not equal true) |  |
| `SNOW-07` | 7 | pass | always |  |
| `SNOW-08` | 1 | manual | `readable` does not equal true |  |
| `SNOW-08` | 2 | manual | all of (`provider_count` equals 0; `providers_complete` does not equal true) |  |
| `SNOW-08` | 3 | fail | `provider_count` equals 0 |  |
| `SNOW-08` | 4 | fail | `expired_certificate_count` is greater than 0 |  |
| `SNOW-08` | 5 | warn | any of (`concern_count` is greater than 0; `complete` does not equal true) |  |
| `SNOW-08` | 6 | pass | always |  |
| `SNOW-09` | 1 | manual | always |  |
| `SNOW-10` | 1 | manual | `readable` does not equal true |  |
| `SNOW-10` | 2 | fail | `unaudited_count` is greater than 0 |  |
| `SNOW-10` | 3 | manual | `missing_dictionary_count` is greater than 0 |  |
| `SNOW-10` | 4 | fail | all of (`recent_audit_count_known` equals true; `recent_audit_count` equals 0) |  |
| `SNOW-10` | 5 | manual | always |  |
| `SNOW-11` | 1 | manual | any of (`readable` does not equal true; `inventory_proven` does not equal true) |  |
| `SNOW-11` | 2 | manual | all of (`complete` does not equal true; any of (`uncovered_table_count` is greater than 0; `operation_gap_count` is greater than 0)) |  |
| `SNOW-11` | 3 | fail | `uncovered_table_count` is greater than 0 |  |
| `SNOW-11` | 4 | warn | `operation_gap_count` is greater than 0 |  |
| `SNOW-11` | 5 | warn | `complete` does not equal true |  |
| `SNOW-11` | 6 | pass | always |  |
| `SNOW-12` | 1 | manual | `readable` does not equal true |  |
| `SNOW-12` | 2 | fail | any of (`eval_rule_count` is greater than 0; `noncompliant_count` is greater than 0) |  |
| `SNOW-12` | 3 | warn | any of (`absent_count` is greater than 0; `complete` does not equal true) |  |
| `SNOW-12` | 4 | pass | always |  |
| `SNOW-13` | 1 | manual | `readable` does not equal true |  |
| `SNOW-13` | 2 | fail | `noncompliant_count` is greater than 0 |  |
| `SNOW-13` | 3 | warn | any of (`absent_count` is greater than 0; `complete` does not equal true) |  |
| `SNOW-13` | 4 | pass | always |  |
| `SNOW-14` | 1 | manual | `readable` does not equal true |  |
| `SNOW-14` | 2 | fail | `admin_integration_count` is greater than 0 |  |
| `SNOW-14` | 3 | manual | `integration_user_count` equals 0 |  |
| `SNOW-14` | 4 | warn | any of (`privileged_assignment_count` is greater than 0; `complete` does not equal true) |  |
| `SNOW-14` | 5 | pass | always |  |
| `SNOW-15` | 1 | manual | any of (`readable` does not equal true; `inventory_proven` does not equal true; `visibility_proven` does not equal true) |  |
| `SNOW-15` | 2 | warn | any of (`in_progress_count` is greater than 0; `sensitive_change_count` is greater than 0; `complete` does not equal true) |  |
| `SNOW-15` | 3 | pass | always |  |
| `SNOW-16` | 1 | manual | `readable` does not equal true |  |
| `SNOW-16` | 2 | fail | `enabled_debug_count` is greater than 0 |  |
| `SNOW-16` | 3 | manual | `hardening_property_count` equals 0 |  |
| `SNOW-16` | 4 | warn | `complete` does not equal true |  |
| `SNOW-16` | 5 | pass | always |  |
| `SNOW-17` | 1 | manual | `readable` does not equal true |  |
| `SNOW-17` | 2 | warn | all of (`plugin_present` does not equal true; `active_rule_count` is greater than 0) |  |
| `SNOW-17` | 3 | manual | all of (`plugin_present` does not equal true; `plugin_inventory_complete` does not equal true) |  |
| `SNOW-17` | 4 | fail | `plugin_active` does not equal true |  |
| `SNOW-17` | 5 | manual | `table_available` does not equal true |  |
| `SNOW-17` | 6 | manual | all of (`active_rule_count` equals 0; `rule_inventory_complete` does not equal true) |  |
| `SNOW-17` | 7 | fail | `active_rule_count` equals 0 |  |
| `SNOW-17` | 8 | warn | any of (`strict_enabled` does not equal true; `complete` does not equal true) |  |
| `SNOW-17` | 9 | pass | always |  |
| `SNOW-18` | 1 | manual | `readable` does not equal true |  |
| `SNOW-18` | 2 | fail | any of (`insecure_count` is greater than 0; `smtp_auth_disabled` equals true) |  |
| `SNOW-18` | 3 | manual | `smtp_account_count` equals 0 |  |
| `SNOW-18` | 4 | manual | `unverified_count` is greater than 0 |  |
| `SNOW-18` | 5 | warn | `starttls_count` is greater than 0 |  |
| `SNOW-18` | 6 | manual | always |  |
| `SNOW-19` | 1 | manual | any of (`readable` does not equal true; `server_count` equals 0) |  |
| `SNOW-19` | 2 | fail | `not_validated_count` is greater than 0 |  |
| `SNOW-19` | 3 | warn | `version_override_present` equals true |  |
| `SNOW-19` | 4 | manual | always |  |
| `SNOW-20` | 1 | manual | any of (`readable` does not equal true; `plugin_count` equals 0) |  |
| `SNOW-20` | 2 | fail | `observed_inactive_required_count` is greater than 0 |  |
| `SNOW-20` | 3 | manual | all of (`missing_required_count` is greater than 0; `complete` does not equal true) |  |
| `SNOW-20` | 4 | fail | `missing_required_count` is greater than 0 |  |
| `SNOW-20` | 5 | manual | always |  |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| None |  |  |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `SNOW-01` | `requiredEvidenceReadable` | true |
| `SNOW-01` | `requiredEvidenceComplete` | true |
| `SNOW-02` | `requiredEvidenceReadable` | true |
| `SNOW-02` | `requiredEvidenceComplete` | true |
| `SNOW-03` | `requiredEvidenceReadable` | true |
| `SNOW-03` | `requiredEvidenceComplete` | true |
| `SNOW-04` | `requiredEvidenceReadable` | true |
| `SNOW-04` | `requiredEvidenceComplete` | true |
| `SNOW-05` | `requiredEvidenceReadable` | true |
| `SNOW-05` | `requiredEvidenceComplete` | true |
| `SNOW-06` | `requiredEvidenceReadable` | true |
| `SNOW-06` | `requiredEvidenceComplete` | true |
| `SNOW-07` | `requiredEvidenceReadable` | true |
| `SNOW-07` | `requiredEvidenceComplete` | true |
| `SNOW-08` | `requiredEvidenceReadable` | true |
| `SNOW-08` | `requiredEvidenceComplete` | true |
| `SNOW-09` | `requiredEvidenceReadable` | true |
| `SNOW-09` | `requiredEvidenceComplete` | true |
| `SNOW-10` | `requiredEvidenceReadable` | true |
| `SNOW-10` | `requiredEvidenceComplete` | true |
| `SNOW-11` | `requiredEvidenceReadable` | true |
| `SNOW-11` | `requiredEvidenceComplete` | true |
| `SNOW-12` | `requiredEvidenceReadable` | true |
| `SNOW-12` | `requiredEvidenceComplete` | true |
| `SNOW-13` | `requiredEvidenceReadable` | true |
| `SNOW-13` | `requiredEvidenceComplete` | true |
| `SNOW-14` | `requiredEvidenceReadable` | true |
| `SNOW-14` | `requiredEvidenceComplete` | true |
| `SNOW-15` | `requiredEvidenceReadable` | true |
| `SNOW-15` | `requiredEvidenceComplete` | true |
| `SNOW-16` | `requiredEvidenceReadable` | true |
| `SNOW-16` | `requiredEvidenceComplete` | true |
| `SNOW-17` | `requiredEvidenceReadable` | true |
| `SNOW-17` | `requiredEvidenceComplete` | true |
| `SNOW-18` | `requiredEvidenceReadable` | true |
| `SNOW-18` | `requiredEvidenceComplete` | true |
| `SNOW-19` | `requiredEvidenceReadable` | true |
| `SNOW-19` | `requiredEvidenceComplete` | true |
| `SNOW-20` | `requiredEvidenceReadable` | true |
| `SNOW-20` | `requiredEvidenceComplete` | true |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `SNOW-01` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete security-property set enables the documented secure defaults, fail when any required property is explicitly insecure, and warn when optional hardening is absent or evidence is partial. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete security-property set enables the documented secure defaults, fail when any required property is explicitly insecure, and warn when optional hardening is absent or evidence is partial. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-02` | compliant | All required source reads are complete and this derivation returns pass: return fail when any active ACL lacks both a role and a condition or script, warn when questionable ACLs remain or ACL and role joins are partial, and pass when every active ACL has an explicit restriction. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any active ACL lacks both a role and a condition or script, warn when questionable ACLs remain or ACL and role joins are partial, and pass when every active ACL has an explicit restriction. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-03` | compliant | All required source reads are complete and this derivation returns pass: return fail when administrator-equivalent roles exceed the configured population threshold, warn for broad inheritance, stale assignments, or partial role data, and pass when complete role and assignment evidence stays within the threshold. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when administrator-equivalent roles exceed the configured population threshold, warn for broad inheritance, stale assignments, or partial role data, and pass when complete role and assignment evidence stays within the threshold. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-04` | compliant | All required source reads are complete and this derivation returns pass: return fail when active privileged users exceed the configured maximum or include stale accounts beyond the configured age, warn for undated users or partial evidence, and pass when the complete population is bounded and recent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when active privileged users exceed the configured maximum or include stale accounts beyond the configured age, warn for undated users or partial evidence, and pass when the complete population is bounded and recent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-05` | compliant | All required source reads are complete and this derivation returns pass: return pass when the inactivity timeout is positive and at or below the configured threshold, warn when it exceeds the threshold, fail when disabled, and manual when the property is absent or unreadable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the inactivity timeout is positive and at or below the configured threshold, warn when it exceeds the threshold, fail when disabled, and manual when the property is absent or unreadable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-06` | compliant | All required source reads are complete and this derivation returns pass: return pass when the password policy meets minimum and maximum length, character-class, and strength requirements, warn when only some fields miss the baseline, fail for a weak preset or multiple gaps, and manual when decisive fields are absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the password policy meets minimum and maximum length, character-class, and strength requirements, warn when only some fields miss the baseline, fail for a weak preset or multiple gaps, and manual when decisive fields are absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-07` | compliant | All required source reads are complete and this derivation returns pass: return pass when an active multi-factor criterion covers every required privileged role, fail when no active criterion exists, warn for incomplete role coverage, and manual when criteria or role evidence is unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when an active multi-factor criterion covers every required privileged role, fail when no active criterion exists, warn for incomplete role coverage, and manual when criteria or role evidence is unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-08` | compliant | All required source reads are complete and this derivation returns pass: return pass when an active SSO or LDAP integration is visible with enabled redirect policy and valid dated certificates, fail when complete evidence has no active external identity provider or an active certificate is expired, warn for weak redirect policy or near-expiry and undated certificates, and manual when integration evidence is unreadable or partial. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-08` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when an active SSO or LDAP integration is visible with enabled redirect policy and valid dated certificates, fail when complete evidence has no active external identity provider or an active certificate is expired, warn for weak redirect policy or near-expiry and undated certificates, and manual when integration evidence is unreadable or partial. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-09` | compliant | All required source reads are complete and this derivation returns pass: return pass when an active customer encryption module or encrypted field evidence is visible, warn when only platform-default encryption is evident, fail when readable evidence explicitly disables encryption, and manual when the licensed encryption surface is unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-09` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when an active customer encryption module or encrypted field evidence is visible, warn when only platform-default encryption is evident, fail when readable evidence explicitly disables encryption, and manual when the licensed encryption surface is unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-09` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-09` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-10` | compliant | All required source reads are complete and this derivation returns pass: return pass when system auditing is enabled and the complete lookback contains records, warn when the readable window is empty or partial, fail when auditing is explicitly disabled, and manual when properties or audit rows are unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-10` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when system auditing is enabled and the complete lookback contains records, warn when the readable window is empty or partial, fail when auditing is explicitly disabled, and manual when properties or audit rows are unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-10` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-10` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-11` | compliant | All required source reads are complete and this derivation returns pass: return fail when any sensitive table has an active permissive ACL without role, condition, or script restrictions, warn for incomplete table or ACL evidence, and pass when every inspected sensitive table is explicitly protected. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-11` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any sensitive table has an active permissive ACL without role, condition, or script restrictions, warn for incomplete table or ACL evidence, and pass when every inspected sensitive table is explicitly protected. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-11` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-11` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-12` | compliant | All required source reads are complete and this derivation returns pass: return fail when unrestricted server-side script execution is enabled, pass when the documented script restrictions are enabled, warn for mixed settings, and manual when the required properties are absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-12` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when unrestricted server-side script execution is enabled, pass when the documented script restrictions are enabled, warn for mixed settings, and manual when the required properties are absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-12` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-12` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-13` | compliant | All required source reads are complete and this derivation returns pass: return pass when all documented baseline hardening properties are secure, fail when any critical property is explicitly insecure, and warn when noncritical settings are weak or evidence is partial. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-13` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when all documented baseline hardening properties are secure, fail when any critical property is explicitly insecure, and warn when noncritical settings are weak or evidence is partial. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-13` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-13` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-14` | compliant | All required source reads are complete and this derivation returns pass: return fail when an active integration user has administrator-equivalent roles, warn for broad non-admin roles, stale users, or partial assignments, and pass when complete evidence shows least-privileged integration identities. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-14` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when an active integration user has administrator-equivalent roles, warn for broad non-admin roles, stale users, or partial assignments, and pass when complete evidence shows least-privileged integration identities. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-14` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-14` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-15` | compliant | All required source reads are complete and this derivation returns pass: return pass when complete update-set evidence shows recent completed sets with no unresolved preview or commit errors, warn for in-progress, stale, failed, or partial sets, and manual when update-set tables are unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-15` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when complete update-set evidence shows recent completed sets with no unresolved preview or commit errors, warn for in-progress, stale, failed, or partial sets, and manual when update-set tables are unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-15` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-15` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-16` | compliant | All required source reads are complete and this derivation returns pass: return pass when debug and diagnostic properties are disabled, fail when any is enabled, warn when the property inventory is partial, and manual when no decisive debug property is readable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-16` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when debug and diagnostic properties are disabled, fail when any is enabled, warn when the property inventory is partial, and manual when no decisive debug property is readable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-16` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-16` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-17` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete IP access-control inventory contains active restrictive ranges, fail when an explicit allow-all rule exists, warn when no rule exists or coverage is partial, and manual when the table is unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-17` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete IP access-control inventory contains active restrictive ranges, fail when an explicit allow-all rule exists, warn when no rule exists or coverage is partial, and manual when the table is unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-17` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-17` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-18` | compliant | All required source reads are complete and this derivation returns pass: return pass when documented outbound email TLS and security properties are enabled, fail when TLS is explicitly disabled, warn for weaker optional settings, and manual when decisive properties are absent. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-18` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when documented outbound email TLS and security properties are enabled, fail when TLS is explicitly disabled, warn for weaker optional settings, and manual when decisive properties are absent. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-18` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-18` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-19` | compliant | All required source reads are complete and this derivation returns pass: return pass when every active MID Server is validated, recent, and uses a non-administrator service identity, fail for administrator identities or failed validation, warn for stale, down, or partial records, and manual when the MID inventory is unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-19` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every active MID Server is validated, recent, and uses a non-administrator service identity, fail for administrator identities or failed validation, warn for stale, down, or partial records, and manual when the MID inventory is unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-19` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-19` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-20` | compliant | All required source reads are complete and this derivation returns pass: return fail when a complete plugin inventory is missing a required baseline security plugin or a visible required plugin is inactive, and manual when the inventory is empty, partial around a missing baseline plugin, or all required plugins are active because licensing and intended use cannot be inferred from the API. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-20` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when a complete plugin inventory is missing a required baseline security plugin or a visible required plugin is inactive, and manual when the inventory is empty, partial around a missing baseline plugin, or all required plugins are active because licensing and intended use cannot be inferred from the API. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-20` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-20` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Instance security properties | CM-6 | 3.4.2 | CC6.1 | 5.1 | 2.2.1 | SRG-APP-000384 | ISM-1624 | CPS.CM-6 |
| 2 | ACL rule completeness | AC-3 | 3.1.2 | CC6.1 | n/a | 7.1.1 | SRG-APP-000033 | ISM-0405 | CPS.AC-3 |
| 3 | Role hierarchy audit | AC-6(1) | 3.1.5 | CC6.3 | n/a | 7.1.1 | SRG-APP-000340 | ISM-1507 | CPS.AC-6 |
| 4 | User access review | AC-2(3) | 3.1.12 | CC6.2 | 5.3 | 8.1.4 | SRG-APP-000025 | ISM-1591 | CPS.AC-2 |
| 5 | Session timeout configuration | AC-12 | 3.1.10 | CC6.1 | 16.4 | 8.2.8 | SRG-APP-000295 | ISM-1164 | CPS.AC-7 |
| 6 | Password policy enforcement | IA-5(1) | 3.5.7 | CC6.1 | 5.2 | 8.3.6 | SRG-APP-000164 | ISM-0421 | CPS.IA-5 |
| 7 | MFA enforcement | IA-2(1) | 3.5.3 | CC6.1 | 6.3 | 8.4.2 | SRG-APP-000149 | ISM-1504 | CPS.AT-2 |
| 8 | LDAP and SSO integration | IA-2(12) | 3.5.3 | CC6.1 | 16.2 | 8.4.1 | SRG-APP-000395 | ISM-1546 | CPS.IA-2 |
| 9 | Encryption at rest | SC-28 | 3.13.16 | CC6.1 | n/a | 3.4.1 | SRG-APP-000429 | ISM-0457 | CPS.SC-28 |
| 10 | Audit logging configuration | AU-3 | 3.3.1 | CC7.2 | 8.5 | 10.2.1 | SRG-APP-000095 | ISM-0580 | CPS.AU-3 |
| 11 | Table-level access controls | AC-3(7) | 3.1.2 | CC6.1 | n/a | 7.1.2 | SRG-APP-000033 | ISM-0405 | CPS.AC-3 |
| 12 | Script execution restrictions | CM-7(2) | 3.4.8 | CC6.8 | n/a | 6.2.4 | SRG-APP-000141 | ISM-1624 | CPS.CM-7 |
| 13 | Instance hardening | CM-6(1) | 3.4.2 | CC6.1 | n/a | 2.2.1 | SRG-APP-000384 | ISM-1624 | CPS.CM-6 |
| 14 | Integration user permissions | AC-6(10) | 3.1.7 | CC6.3 | n/a | 7.1.2 | SRG-APP-000343 | ISM-0988 | CPS.AC-6 |
| 15 | Update set management | CM-3 | 3.4.3 | CC8.1 | n/a | 6.5.1 | SRG-APP-000380 | ISM-1624 | CPS.CM-3 |
| 16 | Debug mode verification | CM-7 | 3.4.7 | CC6.1 | n/a | 2.2.1 | SRG-APP-000141 | ISM-1624 | CPS.CM-7 |
| 17 | IP access restrictions | AC-17(1) | 3.1.12 | CC6.6 | n/a | 1.3.1 | SRG-APP-000142 | ISM-1528 | CPS.AC-17 |
| 18 | Email security | SC-8 | 3.13.8 | CC6.7 | n/a | 4.1.1 | SRG-APP-000411 | ISM-0572 | CPS.SC-8 |
| 19 | MID Server security | SC-7(7) | 3.13.6 | CC6.6 | n/a | 1.3.2 | SRG-APP-000001 | ISM-1528 | CPS.SC-7 |
| 20 | Plugin inventory and licensing | CM-7(4) | 3.4.8 | CC6.8 | n/a | 2.2.1 | SRG-APP-000386 | ISM-1624 | CPS.CM-7 |

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

Sensitive fields and values: password, client_secret, access_token, refresh_token, authorization, cookie, sysparm_query

Credential formats: ServiceNow passwords, OAuth bearer and refresh tokens, client secrets, JSESSIONID cookies

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `users` | `sys_id`, `user_name`, `active`, `last_login_time`, `web_service_access_only`, `internal_integration_user`, `enable_multifactor_authn`, `sys_updated_on` |
| `privileged-assignments` | `sys_id`, `user`, `user.user_name`, `user.active`, `user.web_service_access_only`, `user.internal_integration_user`, `role`, `role.name` |
| `role-inheritance` | `sys_id`, `role`, `role.name`, `contains`, `contains.name` |
| `role-inheritance-count` | `result.stats.count` |
| `identity-properties` | `sys_id`, `name`, `value`, `description`, `sys_updated_on` |
| `password-policies` | `sys_id`, `name`, `active`, `minimum_password_length`, `maximum_password_length`, `strength`, `sys_updated_on` |
| `sso-providers` | `sys_id`, `name`, `active`, `default`, `auto_redirect_idp`, `sys_updated_on` |
| `ldap-servers` | `sys_id`, `name`, `active`, `sys_updated_on` |
| `certificates` | `sys_id`, `name`, `active`, `valid_from`, `expires`, `sys_updated_on` |
| `oauth-entities` | `sys_id`, `name`, `type`, `active`, `client_id`, `sys_updated_on` |
| `mfa-criteria` | `sys_id`, `name`, `active`, `order`, `roles`, `multi_factor_roles`, `sys_updated_on` |
| `hardening-properties` | `sys_id`, `name`, `value`, `description`, `sys_updated_on` |
| `debug-properties` | `sys_id`, `name`, `value`, `description`, `sys_updated_on` |
| `eval-scripts` | `sys_id`, `name`, `collection`, `sys_updated_on` |
| `ip-access` | `sys_id`, `type`, `direction`, `active`, `range_start`, `range_end`, `description`, `sys_updated_on` |
| `ip-authenticator-plugin` | `sys_id`, `name`, `source`, `active`, `state`, `version`, `sys_updated_on` |
| `email-accounts` | `sys_id`, `name`, `type`, `active`, `connection_security`, `enable_ssl`, `enable_tls`, `authentication`, `server`, `port`, `sys_updated_on` |
| `acls` | `sys_id`, `name`, `operation`, `type`, `active`, `admin_overrides`, `condition-present`, `script-present`, `sys_updated_on` |
| `acl-roles` | `sys_id`, `sys_security_acl`, `sys_user_role`, `sys_user_role.name` |
| `acl-count` | `result.stats.count` |
| `public-pages` | `sys_id`, `page`, `active`, `sys_updated_on` |
| `encryption-contexts` | `sys_id`, `name`, `type`, `sys_updated_on` |
| `crypto-modules` | `sys_id`, `name`, `module_name`, `state`, `sys_scope`, `sys_updated_on` |
| `encrypted-fields` | `sys_id`, `name`, `element`, `internal_type` |
| `audit-dictionary` | `sys_id`, `name`, `audit`, `attributes` |
| `recent-audit-count` | `result.stats.count` |
| `recent-transaction-count` | `result.stats.count` |
| `update-sets` | `sys_id`, `name`, `state`, `application`, `sys_created_by`, `sys_updated_on` |
| `update-set-count` | `result.stats.count` |
| `sensitive-update-xml` | `sys_id`, `name`, `type`, `target_name`, `action`, `update_set`, `update_set.name`, `sys_updated_on` |
| `mid-servers` | `sys_id`, `name`, `status`, `validated`, `version`, `host_name`, `sys_updated_on` |
| `mid-properties` | `sys_id`, `name`, `value`, `description`, `sys_updated_on` |
| `plugins` | `sys_id`, `name`, `source`, `active`, `state`, `version`, `sys_updated_on` |

## Export layout

Required paths:

- `metadata.json`
- `QUICK_REFERENCE.md`
- `core_data/access_check.json`
- `core_data/sys_user.json`
- `core_data/sys_user_has_role_privileged.json`
- `core_data/sys_user_role_contains.json`
- `core_data/sys_user_role_contains_count.json`
- `core_data/sys_properties_identity.json`
- `core_data/password_policy.json`
- `core_data/sso_properties.json`
- `core_data/ldap_server_config.json`
- `core_data/sys_certificate.json`
- `core_data/oauth_entity.json`
- `core_data/multi_factor_criteria.json`
- `core_data/sys_properties_hardening.json`
- `core_data/sys_properties_debug.json`
- `core_data/sys_script_eval.json`
- `core_data/ip_access.json`
- `core_data/sys_plugins_ip_authenticator.json`
- `core_data/sys_email_account.json`
- `core_data/sys_security_acl.json`
- `core_data/sys_security_acl_role.json`
- `core_data/sys_security_acl_count.json`
- `core_data/sys_public.json`
- `core_data/sys_encryption_context.json`
- `core_data/sys_kmf_crypto_module.json`
- `core_data/sys_dictionary_encrypted.json`
- `core_data/sys_dictionary_audit.json`
- `core_data/sys_audit_count.json`
- `core_data/syslog_transaction_count.json`
- `core_data/sys_update_set_in_progress.json`
- `core_data/sys_update_set_count.json`
- `core_data/sys_update_xml_sensitive.json`
- `core_data/ecc_agent.json`
- `core_data/sys_properties_mid.json`
- `core_data/sys_plugins.json`
- `analysis/identity_access.json`
- `analysis/platform_hardening.json`
- `analysis/access_control.json`
- `analysis/operations_governance.json`
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
| `core_data/sys_user.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_user_has_role_privileged.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_user_role_contains.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_user_role_contains_count.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_properties_identity.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/password_policy.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sso_properties.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/ldap_server_config.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_certificate.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/oauth_entity.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/multi_factor_criteria.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_properties_hardening.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_properties_debug.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_script_eval.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/ip_access.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_plugins_ip_authenticator.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_email_account.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_security_acl.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_security_acl_role.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_security_acl_count.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_public.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_encryption_context.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_kmf_crypto_module.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_dictionary_encrypted.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_dictionary_audit.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_audit_count.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/syslog_transaction_count.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_update_set_in_progress.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_update_set_count.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_update_xml_sensitive.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/ecc_agent.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_properties_mid.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sys_plugins.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/identity_access.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/platform_hardening.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/access_control.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/operations_governance.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
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

Overwrite policy: Allocate a new {instance}-audit-bundle directory with a numeric suffix when needed; never overwrite a prior directory.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Write a sibling zip named from the exact allocated bundle-directory basename plus .zip.
