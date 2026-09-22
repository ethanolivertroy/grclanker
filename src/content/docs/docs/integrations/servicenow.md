---
title: ServiceNow
description: Read-only ServiceNow instance security inspection covering identity, ACLs, platform hardening, and operations governance with evidence-gated verdicts and an exportable audit bundle.
---

grclanker ships six native ServiceNow tools that inspect an instance through the Table API and the Aggregate API. They never write to the instance. Every verdict is evidence-gated: a forbidden, ACL-filtered, truncated, or empty read never produces a pass on its own.

## What it inspects

The tools cover the twenty security controls in `specs/servicenow-sec-inspector.spec.md`:

- Identity and access: role hierarchy, user access review, password policy, MFA, LDAP and SSO integration, integration user permissions
- Platform hardening: instance security properties, session timeout, script execution restrictions, instance hardening, debug mode, IP access restrictions, email security
- Access control: ACL rule completeness (wildcard, unrestricted, and public page exposure) and table-level ACL coverage for sensitive tables
- Operations governance: encryption at rest, audit logging, update set management, MID Server security, plugin inventory

Tables read: `sys_user`, `sys_user_has_role`, `sys_user_role`, `sys_user_role_contains`, `sys_properties`, `password_policy`, `sso_properties`, `ldap_server_config`, `sys_certificate`, `oauth_entity`, `multi_factor_criteria`, `sys_security_acl`, `sys_security_acl_role`, `sys_public`, `sys_script`, `ip_access` (IP Address Access Controls, present once `com.snc.ipauthenticator` is active), `sys_email_account`, `sys_kmf_crypto_module`, `sys_encryption_context` (legacy Column Level Encryption contexts; treated as absent when the instance reports the table as invalid), `sys_dictionary`, `sys_audit` (count only), `syslog_transaction` (count only), `sys_update_set`, `sys_update_xml`, `sys_user_session` (access probe), `ecc_agent`, and `sys_plugins`.

## Setup and authentication

Create a dedicated audit account. The `admin` role reads every table above; a scoped read role must at minimum grant read on the listed tables (note that `sys_audit` requires `admin` and `sys_dictionary` normally requires `personalize_dictionary`). Forbidden or ACL-filtered tables render as `manual` findings instead of silently passing.

Configuration precedence is explicit tool arguments, then environment variables, then a YAML config file (`SERVICENOW_CONFIG_FILE`, `./.servicenow.yaml`, or `~/.servicenow-sec-inspector/config.yaml`; a top-level `servicenow:` section is accepted).

| Variable | Purpose |
| --- | --- |
| `SERVICENOW_INSTANCE` | Instance name, expanded to `https://<instance>.service-now.com` |
| `SERVICENOW_URL` | Full instance URL (overrides the instance name) |
| `SERVICENOW_AUTH_METHOD` | `basic`, `oauth`, or `mtls` (inferred from the credentials when omitted) |
| `SERVICENOW_USERNAME` / `SERVICENOW_PASSWORD` | Basic auth, or the OAuth password grant when client credentials are also set |
| `SERVICENOW_CLIENT_ID` / `SERVICENOW_CLIENT_SECRET` | OAuth application registry client (client credentials grant, or password grant with a user) |
| `SERVICENOW_ACCESS_TOKEN` | Pre-issued bearer token |
| `SERVICENOW_CONFIG_FILE` | YAML config file path |
| `SERVICENOW_TIMEOUT`, `SERVICENOW_MAX_RETRIES`, `SERVICENOW_PAGE_SIZE` | HTTP timeout in seconds (default 30), retries for 429 and 5xx (default 3), Table API page size (default 500) |

### Basic authentication

Set `SERVICENOW_INSTANCE`, `SERVICENOW_USERNAME`, and `SERVICENOW_PASSWORD`. Requests carry `Authorization: Basic base64(username:password)`.

### OAuth 2.0

Tokens are exchanged at `POST https://<instance>.service-now.com/oauth_token.do` with an `application/x-www-form-urlencoded` body and cached until they expire.

- Client credentials grant: create an application registry entry ("Create an OAuth API endpoint for external clients"), set the OAuth Application User to the audit account, and set the system property `glide.oauth.inbound.client.credential.grant_type.enabled` to `true`. Provide `SERVICENOW_CLIENT_ID` and `SERVICENOW_CLIENT_SECRET`.
- Password grant: provide the client ID and secret plus `SERVICENOW_USERNAME` and `SERVICENOW_PASSWORD`; the client sends `grant_type=password` and refreshes with `refresh_token` when one is issued.
- Pre-issued token: provide `SERVICENOW_ACCESS_TOKEN`.

### Mutual TLS

`SERVICENOW_AUTH_METHOD=mtls` is recognized but rejected with a clear error: the runtime's `fetch` client cannot present a client certificate. Use basic or OAuth for now.

## Tools

| Tool | Purpose |
| --- | --- |
| `servicenow_check_access` | Probes 27 audit tables with a one-row Table API read plus an Aggregate API count and reports each as `readable`, `forbidden`, `acl_filtered`, or `not_readable`. An aggregate count above zero with no rows returned is reported as ACL-filtered. |
| `servicenow_assess_identity_access` | Controls 3, 4, 6, 7, 8, 14. Options: `inactive_days` (90), `min_password_length` (12), `cert_expiry_warn_days` (30), `max_admins` (10), `record_limit` (10000). |
| `servicenow_assess_platform_hardening` | Controls 1, 5, 12, 13, 16, 17, 18. Options: `max_session_timeout_minutes` (60), `record_limit`. |
| `servicenow_assess_access_control` | Controls 2 and 11. Option: `record_limit`. |
| `servicenow_assess_operations_governance` | Controls 9, 10, 15, 19, 20. Option: `record_limit`. |
| `servicenow_export_audit_bundle` | Runs the access check and all four assessments, then writes `core_data/` (Table API and Aggregate API snapshots projected to the requested `sysparm_fields`, with `truncated`, `total_unknown`, and `partial` flags per table; a table or aggregate that was forbidden, errored, or never requested is written as a `{ collected: false, table, query, status, endpoint, error }` marker instead of an empty list), `analysis/` (`findings.json`, per-area results with an `inventories` map that reports each table as read, `unread (...)`, or `not requested (...)`, `summary.json`), `compliance/` (`executive_summary.md`, `unified_compliance_matrix.md`, one report per framework), `QUICK_REFERENCE.md`, `metadata.json`, `_errors.log` when collection partially failed, and a zip archive named after the allocated output directory. Reruns allocate `-2`, `-3`, ... instead of overwriting. Default output root: `./export/servicenow`. |

All tools accept the authentication arguments (`instance`, `instance_url`, `auth_method`, `username`, `password`, `client_id`, `client_secret`, `access_token`, `config_file`, `timeout_seconds`, `max_retries`, `page_size`).

## Verdict semantics

- `pass`: complete, readable evidence shows the compliant configuration. Pagination ran to completion and X-Total-Count (or an Aggregate count) matched the rows returned.
- `warn`: the visible evidence is compliant but the view is partial or truncated (seen and total counts are reported), a documented property has no `sys_properties` row (its default is never assumed), or a hygiene gap remains.
- `fail`: a verified non-compliant setting or record.
- `manual`: the read was forbidden (401/403), ACL-filtered, or errored; the inventory was empty where emptiness cannot be trusted; the control is out of scope or not exposed through the API. The summary names the cause and `manualEvidence` states exactly what a human must collect.

Rows without a date (`last_login_time`, `expires`) are bucketed separately and never counted as active or valid.

### Partial and unread inputs

Every finding is gated on the tables it reads (the `Inputs` column below), in this order:

- Unread input: when any input was forbidden (401/403), ACL-filtered, or errored, the finding is `manual`, its summary names the table and the observed status ("Verdict unknown: sys_user read was forbidden (403)"), and `manualEvidence` states what to collect. Nothing is evaluated on the remaining inputs.
- Truncated input: when an input stopped at `record_limit`, returned fewer rows than `X-Total-Count`, or has no total, the finding's summary carries "Partial view: ..." and a `pass` becomes `warn`. An absence-driven `fail` (a property, ACL, identity provider, access rule, or plugin not found among the visible rows: SNOW-07, SNOW-08, SNOW-11, SNOW-17, SNOW-20) is capped at `manual` and the names of the things not seen are dropped, because an unseen row may sit in the unread remainder; a `fail` observed on a visible row (a non-compliant value, an inactive plugin row, an unvalidated MID Server) stands.
- Named principals: user, admin, and integration account names and the counts derived from them are rendered `null` with a `principals_withheld` note whenever `sys_user` or `sys_user_has_role` is partial (SNOW-04, SNOW-07, SNOW-14).
- Evidence: every finding carries `inputs[]` with one entry per table read (`table`, `state`, `visible_rows`, `total_rows`, `pages`, `truncated`, `total_unknown`, `partial`), each `null` when the read was not answered. Area summaries render every count derived from an unread table as `null` and carry an `inventories` map naming each table as read, `unread (<status>)`, or `not requested (<reason>)`.

## Control coverage

| # | Control | Tool | Finding | Inputs | Status semantics |
| --- | --- | --- | --- | --- | --- |
| 1 | Instance security properties | platform_hardening | SNOW-01 | `sys_properties` | pass when the five `glide.security.*` properties exist with compliant values; warn when any row is absent; fail on a non-compliant value. Manual when `sys_properties` is unread; a truncated read turns pass into warn and caps an absent-property fail at manual |
| 2 | ACL rule completeness | access_control | SNOW-02 | `sys_security_acl`, `sys_security_acl_role`, `sys_public` | manual unless the Aggregate ACL count proves visibility; fail on role-less, condition-less, script-less record ACLs; warn on wildcard ACLs or active public pages. Manual when any input is unread; a truncated ACL read turns pass into warn (a fail on a visible ACL stands) |
| 3 | Role hierarchy audit | identity_access | SNOW-03 | `sys_user_role_contains` | manual unless `sys_user_role_contains` is proven visible; warn when roles inherit `admin` or `security_admin`; pass when none do. A truncated read turns pass into warn |
| 4 | User access review | identity_access | SNOW-04 | `sys_user`, `sys_user_has_role` | manual on zero users or zero admin assignments; fail on stale admins or admin count above `max_admins`; warn on inactive users, users without a login date, locked-out active accounts (`sys_user.locked_out`, admins listed separately), or stacked privileged roles. Manual when either input is unread; on a partial read the summary switches to "Among the visible rows ...", admin, inactive, and locked-out names and counts are `null` with `principals_withheld`, and pass becomes warn |
| 5 | Session timeout configuration | platform_hardening | SNOW-05 | `sys_properties` | fail above `max_session_timeout_minutes`; warn when the property is absent (fallback of 30 minutes is not assumed) or rotation is off. Manual when `sys_properties` is unread; a truncated read turns pass into warn |
| 6 | Password policy enforcement | identity_access | SNOW-06 | `sys_properties`, `password_policy` | fail when `glide.enable.password_policy=false`, no policy row is visible (a complete read with zero rows), or a visible policy is weaker than the threshold; warn when the property row is absent. Manual when either input is unread; a truncated read turns pass into warn |
| 7 | MFA enforcement | identity_access | SNOW-07 | `sys_properties`, `sys_user`, `sys_user_has_role`, `multi_factor_criteria` | fail when `glide.authenticate.multifactor` is false, or absent from a complete `sys_properties` read (documented default is false), or when the Role-based multi-factor authentication record in `multi_factor_criteria` is inactive and admins lack `enable_multifactor_authn`; manual when `multi_factor_criteria` is forbidden or returns no rows (the baseline record always exists), or when the property was not among the visible rows of a truncated `sys_properties` read; warn when the active role-based record does not list `admin` and `security_admin` while admins lack the per-user flag, when only per-user flags enforce MFA, or when email OTP is enabled; pass when the role-based record is active and covers both roles (or every admin carries the per-user flag). Manual when any input is unread; admins without the per-user flag are withheld when `sys_user` or `sys_user_has_role` is partial |
| 8 | LDAP/SSO integration | identity_access | SNOW-08 | `sso_properties`, `ldap_server_config`, `sys_properties`, `sys_certificate` | fail with no active SSO provider or LDAP server (asserted only when both `sso_properties` and `ldap_server_config` were read to completion), or an expired certificate; warn when Multi-Provider SSO or the default redirect IdP is not set or certificates expire soon. Manual when any input is unread, or when no active provider was among the visible rows of a partial read; a truncated read turns pass into warn |
| 9 | Encryption at rest | operations_governance | SNOW-09 | `sys_encryption_context`, `sys_kmf_crypto_module`, `sys_dictionary` | always manual: KMF cryptographic modules (`sys_kmf_crypto_module`, used by Column Level Encryption Enterprise), legacy encryption contexts, and encrypted dictionary fields are inventoried, but coverage and licensing (CLE Enterprise, Cloud Encryption, Edge Encryption) are not exposed through the API. An unread or truncated input is named in the summary |
| 10 | Audit logging configuration | operations_governance | SNOW-10 | `sys_dictionary` (plus the `sys_audit` count) | fail when a critical table is not audited or `sys_audit` received zero rows in 7 days; otherwise manual because retention is not exposed through the API. Manual when `sys_dictionary` is unread or the `sys_audit` count failed; on a truncated dictionary read the unseen tables "were not visible, so their audit flags cannot be verified" (manual) |
| 11 | Table-level access controls | access_control | SNOW-11 | `sys_security_acl`, `sys_security_acl_role` | fail when a sensitive table has no active record ACL; warn when read, write, or delete is missing; pass when all three exist. Manual when either input is unread; on a truncated ACL read the absence of an ACL is not asserted: the finding is manual, the tables and operations not seen are not named, and only ACL gaps observed on visible rows are reported |
| 12 | Script execution restrictions | platform_hardening | SNOW-12 | `sys_properties`, `sys_script` | fail on non-compliant `glide.script.*` values or active business rules calling `eval(`; warn on absent properties. Manual when either input is unread; a truncated read turns pass into warn (an `eval(` observed in a visible script still fails) |
| 13 | Instance hardening | platform_hardening | SNOW-13 | `sys_properties` | pass when the eleven hardening properties exist with compliant values; warn on absent rows; fail on non-compliant values. Manual when `sys_properties` is unread; a truncated read turns pass into warn |
| 14 | Integration user permissions | identity_access | SNOW-14 | `sys_user`, `sys_user_has_role`, `oauth_entity` | fail when an integration account holds `admin` or `security_admin`; manual when no integration-flagged user exists; warn on other privileged roles. Manual when any input is unread; on a partial user or role read the integration account names and counts are `null` with `principals_withheld` and pass becomes warn |
| 15 | Update set management | operations_governance | SNOW-15 | `sys_update_set`, `sys_update_xml` | manual unless the update set inventory is proven visible; warn on in-progress sets or pending ACL, role, script, or property changes. A truncated read turns pass into warn |
| 16 | Debug mode verification | platform_hardening | SNOW-16 | `sys_properties` (all rows and the `*debug*` query) | fail when any `*debug*` property is true; manual when `sys_properties` visibility is unproven or either read is unread; a truncated read turns pass into warn |
| 17 | IP access restrictions | platform_hardening | SNOW-17 | `sys_properties`, `ip_access`, `sys_plugins` | fail when the IP Range Based Authentication plugin (`com.snc.ipauthenticator`) is inactive or absent from a complete `sys_plugins` read, or when no active `ip_access` rule exists (a missing `ip_access` table is treated as the plugin not being activated); warn when the plugin row is not visible while active rules exist, or `glide.ip.authenticate.strict` is not true. Manual when any input is unread, when no active rule was among the visible rows of a partial `ip_access` read, or when the plugin row was not among the visible rows of a partial `sys_plugins` read; a truncated read turns pass into warn |
| 18 | Email security | platform_hardening | SNOW-18 | `sys_properties`, `sys_email_account` | reads the Connection Security choice (`connection_security`, falling back to the legacy `enable_ssl` and `enable_tls` flags): fail when an active SMTP account uses None or `glide.smtp.auth=false`; warn on STARTTLS (the documentation warns it may expose data); manual when the value is not returned (never assumed) or when every account uses SSL/TLS, because DKIM and notification headers are not exposed through the API. Manual when either input is unread |
| 19 | MID Server security | operations_governance | SNOW-19 | `ecc_agent`, `sys_properties` | fail on unvalidated MID Servers; warn when `mid.version.override` pins upgrades; manual for mutual authentication and allow lists, or "not applicable as observed" when no MID Server exists. Manual when either input is unread; a truncated `ecc_agent` read caps "not applicable" at manual (an unvalidated visible server still fails) |
| 20 | Plugin inventory and licensing | operations_governance | SNOW-20 | `sys_plugins` | fail when High Security Settings, Contextual Security: Role Management V2, or Security Jump Start is observed inactive; otherwise manual for necessity review. Manual when `sys_plugins` is unread; on a truncated read a baseline plugin not among the visible rows is reported as unknown (`present: null`) rather than missing, and its name is not asserted as absent |

Controls 9, 10, 18, 19, and 20 never pass because part of their evidence is not exposed through the Table API.

## Framework mappings

Every finding carries eight mappings from the spec's compliance table: FedRAMP / NIST 800-53, CMMC 2.0, SOC 2, CIS Controls, PCI-DSS, DISA STIG, IRAP / ISM, and ISMAP. The audit bundle writes one report per framework under `compliance/` plus a unified matrix.

## Live smoke test

```bash
npm --prefix cli run test:servicenow:live
```

The script prints a skip message and exits 0 when no ServiceNow configuration is present. Otherwise it runs `servicenow_check_access`, stops if any core table is unreadable, and runs the platform hardening assessment.

## Limitations and manual controls

- ServiceNow ACLs can hide rows without returning 403, and `X-Total-Count` is computed before ACL evaluation. The client compares the total against the rows returned and treats a mismatch as a partial view; `sysparm_no_count` is never sent so the header stays available. A response with zero rows and no `X-Total-Count` header is reported as "visibility unproven" and never supports a pass, even when an Aggregate API count for the table is above zero.
- `sysparm_limit` is applied before ACL evaluation, so a page can legitimately return fewer rows than requested. Pagination follows `Link rel="next"` to completion or records truncation at `record_limit` and downgrades the verdict.
- Every table read sends an explicit `sysparm_fields` list and the client projects the returned rows to those columns before they are stored, so password hashes, client secrets, bind and mailbox passwords, keystore material, and `sys_update_xml` payloads never land in `core_data/`; ACL `condition` and `script` bodies are reduced to `has_condition` and `has_script`. A `Link rel="next"` that arrives with an empty page or a non-advancing offset, or a non-empty read without `X-Total-Count`, is reported as truncated or "total unknown" and keeps dependent findings at `warn`; a finding that reads several inventories stays `manual` while any one of them is forbidden.
- Rate limiting (429 with `Retry-After`) and 5xx responses are retried with backoff up to `max_retries`.
- Every string a snapshot, an evidence list, or a summary keeps from a ServiceNow response passes the data-side pass at the collector (`readTable`, the one path every table read takes): the client's remembered credentials in every form and every carrier (`Authorization`, `Cookie`, `Set-Cookie`, and API key headers, quoted or bare; URL userinfo and query strings, which go whole; credential-named assignments and fields; auth schemes; JWTs; PEM blocks) are removed from a description, a note, a name, or a comment; no bare-token rule runs on data, so identifiers such as `prod-us-east-2026`, a UUID, or a quoted `Content-Type` header stay.
- Error strings never quote a response body. An error body that is not JSON (a proxy or gateway page, whatever its content type claims) or JSON without ServiceNow's documented `error.message`, `error.detail`, `status`, or `error_description` fields is described as "non-JSON body (text/html, 5120 bytes)" or "JSON body without documented error fields (...)". Every error string is passed through one redaction pass when it is built and again when it is recorded, so `access_check.json`, `analysis/*.json` `errors` arrays, `_errors.log`, and tool results carry status, path, and shape only. The pass removes the configured and obtained credentials whatever their shape and in their base64, base64url, URL-encoded, and JSON-escaped forms; any value inside a carrier whatever its shape (`Authorization`, `Cookie`, `Set-Cookie`, and API key headers, cookie and session assignments, URL userinfo and query pairs, the `Bearer`, `Basic`, `Digest`, `Token`, and `ApiKey` schemes, credential-named fields and assignments, SOAP credential elements, command-line flags); and bare values only when they have a real token shape (JWTs, PEM blocks, hex digests, vendor-prefixed keys, and runs of 16 or more characters with base64 symbols, scattered digits, or token casing). A bare name-shaped value standing alone in prose, such as a table name or `prod-us-east-2026`, is indistinguishable from a resource name and stays.
- Config file errors are fixed text. A file that cannot be read fails with "Unable to read ServiceNow config file <path> (<CODE>)" (the Node error code only, `ENOENT` included when the path was given explicitly); a file that cannot be parsed fails with "Unable to parse ServiceNow config file: invalid YAML in <path> at line N" (the line only when the parser reports one). Neither the parser's message, which quotes the offending line or an unresolved alias value, nor the filesystem's wording is ever included.
- Instance Security Center hardening scores, Instance Scan results, Edge Encryption, DKIM configuration, MID Server mutual authentication, and audit retention are not read; the corresponding findings state the evidence to collect.
- MFA enforcement is read from the Role-based multi-factor authentication record in `multi_factor_criteria` (Active flag and its Multi-factor Roles list, when the Table API returns it) plus `sys_user.enable_multifactor_authn`. Adaptive authentication MFA policies are not read; when the roles list is not returned, enforcement falls back to the per-user flags and the finding says so.
- Mutual TLS is not supported by the runtime's HTTP client.

## Official documentation

- Table API: https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html
- Aggregate API: https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_AggregateAPI
- OAuth client credentials grant workflow: https://www.servicenow.com/docs/r/platform-security/authentication/client-credentials-grant-workflow.html
- OAuth Application User for client credentials: https://www.servicenow.com/docs/r/platform-security/authentication/add-oauth-application-user.html
- MFA system properties: https://www.servicenow.com/docs/r/platform-security/authentication/mfa-properties.html
- Role-based multi-factor authentication (`multi_factor_criteria`): https://www.servicenow.com/docs/r/platform-security/instance-security-hardening-settings/sc-role-based-multi-factor-authentication.html
- Email OTP for multi-factor authentication (`glide.authenticate.multifactor.email.otp.enabled`): https://www.servicenow.com/docs/r/platform-security/instance-security-hardening-settings/sc-enable-email-otp-for-multi-factor-authentication.html
- Password policy properties: https://www.servicenow.com/docs/r/platform-security/authentication/password-policy-properties.html
- High Security Settings: https://www.servicenow.com/docs/r/platform-security/exploring-high-security-settings.html
- Session activity timeout hardening: https://www.servicenow.com/docs/r/platform-security/instance-security-hardening-settings/sc-session-activity-timeout.html
- Anti-CSRF token hardening: https://www.servicenow.com/docs/r/platform-security/instance-security-hardening-settings/anti-csrf-token.html
- Restrict access to specific IP ranges plugin: https://www.servicenow.com/docs/r/platform-security/instance-security-hardening-settings/sc-restrict-access-to-specific-ip-ranges-plugin.html
- IP address access control (`ip_access` fields): https://www.servicenow.com/docs/r/platform-security/authentication/t_AccessControl.html
- Email account Connection Security choices: https://www.servicenow.com/docs/r/platform-administration/t_ConfAltEmailConfServers.html
- Configuring auditing for a table: https://www.servicenow.com/docs/r/platform-security/t_EnableAuditingForATable.html
- Sys Audit table: https://www.servicenow.com/docs/r/platform-security/servicenow-ai-platform-security/c_UnderstandingTheSysAuditTable.html
- Cryptographic modules (`sys_kmf_crypto_module`): https://www.servicenow.com/docs/r/platform-security/platform-encryption/create-cryptographic-module.html
- Activate Column Level Encryption Enterprise: https://www.servicenow.com/docs/r/platform-security/activate-platform-encryption-2.html
- Instance security best practices guide: https://www.servicenow.com/content/dam/servicenow-assets/public/en-us/doc-type/resource-center/white-paper/instance-security-best-practice.pdf
