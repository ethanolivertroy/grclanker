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
- mTLS transport and several Instance Security Center, Scan, DKIM, adaptive MFA, MID, and retention proofs remain manual.

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
| `auth_method` | string | no | basic, oauth, or mtls. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
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
| `auth_method` | string | no | basic, oauth, or mtls. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
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
| `auth_method` | string | no | basic, oauth, or mtls. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
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
| `auth_method` | string | no | basic, oauth, or mtls. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
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
| `auth_method` | string | no | basic, oauth, or mtls. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
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
| `auth_method` | string | no | basic, oauth, or mtls. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided. |
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
- mTLS configuration metadata

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
| role | `Read access to sys_user, role, ACL, property, audit, update-set, dictionary, plugin, and MID Server tables` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `Aggregate API count visibility matching Table API row visibility` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `table-api` | HTTP | `GET /api/now/table/{table}` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `result`, `sys_id`, `sys_updated_on`, `active`, `name`, `value` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) |
| `aggregate-api` | HTTP | `GET /api/now/stats/{table}` | ServiceNow Aggregate API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `result.stats.count` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AggregateAPI.html) |
| `system-properties` | HTTP | `GET /api/now/table/sys_properties` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `name`, `value`, `description`, `sys_updated_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-platform-security/page/administer/security/reference/security-properties.html) |
| `access-controls` | HTTP | `GET /api/now/table/sys_security_acl` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `sys_id`, `name`, `operation`, `active`, `admin_overrides`, `requires_role`, `script` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-platform-security/page/administer/contextual-security/concept/access-control-rules.html) |
| `audit` | HTTP | `GET /api/now/table/sys_audit` | ServiceNow Table API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `documentkey`, `tablename`, `fieldname`, `oldvalue`, `newvalue`, `sys_created_on` | [Official documentation](https://www.servicenow.com/docs/bundle/zurich-platform-administration/page/administer/security/concept/c_SystemAuditLog.html) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `table-api` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `table-api` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `table-api` | response | A JSON object or list containing only the documented result, sys_id, sys_updated_on, active, name, value members consumed by verdicts. | yes |
| `aggregate-api` | client | Use the configured ServiceNow Aggregate API origin; never follow a server link to a different origin. | yes |
| `aggregate-api` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `aggregate-api` | response | A JSON object or list containing only the documented result.stats.count members consumed by verdicts. | yes |
| `system-properties` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `system-properties` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `system-properties` | response | A JSON object or list containing only the documented name, value, description, sys_updated_on members consumed by verdicts. | yes |
| `access-controls` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `access-controls` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `access-controls` | response | A JSON object or list containing only the documented sys_id, name, operation, active, admin_overrides, requires_role, script members consumed by verdicts. | yes |
| `audit` | client | Use the configured ServiceNow Table API origin; never follow a server link to a different origin. | yes |
| `audit` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `audit` | response | A JSON object or list containing only the documented documentkey, tablename, fieldname, oldvalue, newvalue, sys_created_on members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `sysparm_offset`, `sysparm_limit`, `X-Total-Count`, `Link rel=next` | 500 | 10000 | none | X-Total-Count or Aggregate count is authoritative; absent or mismatched totals prevent proven exhaustion. | Seen count reaches authoritative total; Short page with authoritative completion; Configured item cap; Empty page before total; Repeated offset; Missing total; Rejected next link |

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
| `SNOW-01` | high | `servicenow_assess_platform_hardening` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Instance security properties; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Instance security properties, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Instance security properties; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Instance security properties is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-02` | high | `servicenow_assess_access_control` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for ACL rule completeness; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for ACL rule completeness, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of ACL rule completeness; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for ACL rule completeness is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-03` | high | `servicenow_assess_identity_access` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Role hierarchy audit; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Role hierarchy audit, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Role hierarchy audit; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Role hierarchy audit is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-04` | high | `servicenow_assess_identity_access` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for User access review; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for User access review, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of User access review; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for User access review is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-05` | medium | `servicenow_assess_platform_hardening` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Session timeout configuration; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Session timeout configuration, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Session timeout configuration; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Session timeout configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-06` | high | `servicenow_assess_identity_access` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Password policy enforcement; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Password policy enforcement, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Password policy enforcement; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Password policy enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-07` | critical | `servicenow_assess_identity_access` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for MFA enforcement; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for MFA enforcement, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of MFA enforcement; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for MFA enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-08` | high | `servicenow_assess_identity_access` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for LDAP and SSO integration; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for LDAP and SSO integration, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of LDAP and SSO integration; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for LDAP and SSO integration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-09` | medium | `servicenow_assess_operations_governance` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Encryption at rest; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Encryption at rest, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Encryption at rest; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Encryption at rest is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-10` | high | `servicenow_assess_operations_governance` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Audit logging configuration; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Audit logging configuration, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Audit logging configuration; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Audit logging configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-11` | high | `servicenow_assess_access_control` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Table-level access controls; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Table-level access controls, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Table-level access controls; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Table-level access controls is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-12` | high | `servicenow_assess_platform_hardening` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Script execution restrictions; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Script execution restrictions, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Script execution restrictions; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Script execution restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-13` | high | `servicenow_assess_platform_hardening` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Instance hardening; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Instance hardening, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Instance hardening; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Instance hardening is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-14` | high | `servicenow_assess_identity_access` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Integration user permissions; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Integration user permissions, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Integration user permissions; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Integration user permissions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-15` | medium | `servicenow_assess_operations_governance` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Update set management; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Update set management, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Update set management; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Update set management is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-16` | medium | `servicenow_assess_platform_hardening` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Debug mode verification; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Debug mode verification, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Debug mode verification; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Debug mode verification is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-17` | medium | `servicenow_assess_platform_hardening` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for IP access restrictions; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for IP access restrictions, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of IP access restrictions; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for IP access restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-18` | medium | `servicenow_assess_platform_hardening` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Email security; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Email security, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Email security; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Email security is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-19` | medium | `servicenow_assess_operations_governance` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for MID Server security; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for MID Server security, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of MID Server security; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for MID Server security is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `SNOW-20` | medium | `servicenow_assess_operations_governance` | `table-api`, `aggregate-api`, `system-properties`, `access-controls`, `audit` | `decision_status` | Complete, readable evidence satisfies the runtime predicates for Plugin inventory and licensing; partial, denied, missing, or null evidence cannot select this outcome. | Readable evidence establishes an incomplete or review-required posture for Plugin inventory and licensing, including any runtime sampling or truncation limitation. | Readable evidence establishes a configured violation of Plugin inventory and licensing; this outcome has first-match precedence over partial-evidence warnings. | The required evidence for Plugin inventory and licensing is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `SNOW-01` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-01` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-01` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-01` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-02` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-02` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-02` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-02` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-03` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-03` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-03` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-03` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-04` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-04` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-04` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-04` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-05` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-05` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-05` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-05` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-06` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-06` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-06` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-06` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-07` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-07` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-07` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-07` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-08` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-08` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-08` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-08` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-09` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-09` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-09` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-09` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-10` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-10` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-10` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-10` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-11` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-11` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-11` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-11` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-12` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-12` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-12` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-12` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-13` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-13` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-13` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-13` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-14` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-14` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-14` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-14` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-15` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-15` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-15` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-15` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-16` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-16` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-16` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-16` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-17` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-17` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-17` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-17` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-18` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-18` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-18` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-18` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-19` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-19` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-19` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-19` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `SNOW-20` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `SNOW-20` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `SNOW-20` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `SNOW-20` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `SNOW-01` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-02` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-03` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-04` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-05` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-06` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-07` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-08` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-09` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-10` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-11` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-12` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-13` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-14` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-15` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-16` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-17` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-18` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-19` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |
| `SNOW-20` | `decision_status` | Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `SNOW-01` | `passStatus` | pass |
| `SNOW-01` | `warnStatus` | warn |
| `SNOW-01` | `failStatus` | fail |
| `SNOW-01` | `manualStatus` | manual |
| `SNOW-02` | `passStatus` | pass |
| `SNOW-02` | `warnStatus` | warn |
| `SNOW-02` | `failStatus` | fail |
| `SNOW-02` | `manualStatus` | manual |
| `SNOW-03` | `passStatus` | pass |
| `SNOW-03` | `warnStatus` | warn |
| `SNOW-03` | `failStatus` | fail |
| `SNOW-03` | `manualStatus` | manual |
| `SNOW-04` | `passStatus` | pass |
| `SNOW-04` | `warnStatus` | warn |
| `SNOW-04` | `failStatus` | fail |
| `SNOW-04` | `manualStatus` | manual |
| `SNOW-05` | `passStatus` | pass |
| `SNOW-05` | `warnStatus` | warn |
| `SNOW-05` | `failStatus` | fail |
| `SNOW-05` | `manualStatus` | manual |
| `SNOW-06` | `passStatus` | pass |
| `SNOW-06` | `warnStatus` | warn |
| `SNOW-06` | `failStatus` | fail |
| `SNOW-06` | `manualStatus` | manual |
| `SNOW-07` | `passStatus` | pass |
| `SNOW-07` | `warnStatus` | warn |
| `SNOW-07` | `failStatus` | fail |
| `SNOW-07` | `manualStatus` | manual |
| `SNOW-08` | `passStatus` | pass |
| `SNOW-08` | `warnStatus` | warn |
| `SNOW-08` | `failStatus` | fail |
| `SNOW-08` | `manualStatus` | manual |
| `SNOW-09` | `passStatus` | pass |
| `SNOW-09` | `warnStatus` | warn |
| `SNOW-09` | `failStatus` | fail |
| `SNOW-09` | `manualStatus` | manual |
| `SNOW-10` | `passStatus` | pass |
| `SNOW-10` | `warnStatus` | warn |
| `SNOW-10` | `failStatus` | fail |
| `SNOW-10` | `manualStatus` | manual |
| `SNOW-11` | `passStatus` | pass |
| `SNOW-11` | `warnStatus` | warn |
| `SNOW-11` | `failStatus` | fail |
| `SNOW-11` | `manualStatus` | manual |
| `SNOW-12` | `passStatus` | pass |
| `SNOW-12` | `warnStatus` | warn |
| `SNOW-12` | `failStatus` | fail |
| `SNOW-12` | `manualStatus` | manual |
| `SNOW-13` | `passStatus` | pass |
| `SNOW-13` | `warnStatus` | warn |
| `SNOW-13` | `failStatus` | fail |
| `SNOW-13` | `manualStatus` | manual |
| `SNOW-14` | `passStatus` | pass |
| `SNOW-14` | `warnStatus` | warn |
| `SNOW-14` | `failStatus` | fail |
| `SNOW-14` | `manualStatus` | manual |
| `SNOW-15` | `passStatus` | pass |
| `SNOW-15` | `warnStatus` | warn |
| `SNOW-15` | `failStatus` | fail |
| `SNOW-15` | `manualStatus` | manual |
| `SNOW-16` | `passStatus` | pass |
| `SNOW-16` | `warnStatus` | warn |
| `SNOW-16` | `failStatus` | fail |
| `SNOW-16` | `manualStatus` | manual |
| `SNOW-17` | `passStatus` | pass |
| `SNOW-17` | `warnStatus` | warn |
| `SNOW-17` | `failStatus` | fail |
| `SNOW-17` | `manualStatus` | manual |
| `SNOW-18` | `passStatus` | pass |
| `SNOW-18` | `warnStatus` | warn |
| `SNOW-18` | `failStatus` | fail |
| `SNOW-18` | `manualStatus` | manual |
| `SNOW-19` | `passStatus` | pass |
| `SNOW-19` | `warnStatus` | warn |
| `SNOW-19` | `failStatus` | fail |
| `SNOW-19` | `manualStatus` | manual |
| `SNOW-20` | `passStatus` | pass |
| `SNOW-20` | `warnStatus` | warn |
| `SNOW-20` | `failStatus` | fail |
| `SNOW-20` | `manualStatus` | manual |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `SNOW-01` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-01` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-02` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-02` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-03` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-03` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-04` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-04` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-05` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-05` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-06` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-06` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-07` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-07` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-08` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-08` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-09` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-09` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-09` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-09` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-10` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-10` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-10` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-10` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-11` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-11` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-11` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-11` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-12` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-12` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-12` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-12` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-13` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-13` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-13` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-13` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-14` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-14` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-14` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-14` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-15` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-15` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-15` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-15` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-16` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-16` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-16` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-16` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-17` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-17` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-17` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-17` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-18` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-18` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-18` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-18` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-19` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-19` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-19` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-19` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `SNOW-20` | compliant | All required source reads are complete and the evidence-specific runtime evaluation returns pass. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `SNOW-20` | noncompliant | A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `SNOW-20` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `SNOW-20` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Instance security properties | - | - | - | - | - | - | - | - |
| 2 | ACL rule completeness | - | - | - | - | - | - | - | - |
| 3 | Role hierarchy audit | - | - | - | - | - | - | - | - |
| 4 | User access review | - | - | - | - | - | - | - | - |
| 5 | Session timeout configuration | - | - | - | - | - | - | - | - |
| 6 | Password policy enforcement | - | - | - | - | - | - | - | - |
| 7 | MFA enforcement | - | - | - | - | - | - | - | - |
| 8 | LDAP and SSO integration | - | - | - | - | - | - | - | - |
| 9 | Encryption at rest | - | - | - | - | - | - | - | - |
| 10 | Audit logging configuration | - | - | - | - | - | - | - | - |
| 11 | Table-level access controls | - | - | - | - | - | - | - | - |
| 12 | Script execution restrictions | - | - | - | - | - | - | - | - |
| 13 | Instance hardening | - | - | - | - | - | - | - | - |
| 14 | Integration user permissions | - | - | - | - | - | - | - | - |
| 15 | Update set management | - | - | - | - | - | - | - | - |
| 16 | Debug mode verification | - | - | - | - | - | - | - | - |
| 17 | IP access restrictions | - | - | - | - | - | - | - | - |
| 18 | Email security | - | - | - | - | - | - | - | - |
| 19 | MID Server security | - | - | - | - | - | - | - | - |
| 20 | Plugin inventory and licensing | - | - | - | - | - | - | - | - |

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
| `table-api` | `result`, `sys_id`, `sys_updated_on`, `active`, `name`, `value` |
| `aggregate-api` | `result.stats.count` |
| `system-properties` | `name`, `value`, `description`, `sys_updated_on` |
| `access-controls` | `sys_id`, `name`, `operation`, `active`, `admin_overrides`, `requires_role`, `script` |
| `audit` | `documentkey`, `tablename`, `fieldname`, `oldvalue`, `newvalue`, `sys_created_on` |

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

Archive pairing: Create servicenow-audit.zip beside the allocated servicenow-audit directory, applying the same suffix to both.
