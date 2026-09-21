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
| `servicenow_export_audit_bundle` | Runs the access check and all four assessments, then writes `core_data/` (raw Table API and Aggregate API snapshots), `analysis/` (`findings.json`, per-area results, `summary.json`), `compliance/` (`executive_summary.md`, `unified_compliance_matrix.md`, one report per framework), `QUICK_REFERENCE.md`, `metadata.json`, `_errors.log` when collection partially failed, and a zip archive named after the allocated output directory. Reruns allocate `-2`, `-3`, ... instead of overwriting. Default output root: `./export/servicenow`. |

All tools accept the authentication arguments (`instance`, `instance_url`, `auth_method`, `username`, `password`, `client_id`, `client_secret`, `access_token`, `config_file`, `timeout_seconds`, `max_retries`, `page_size`).

## Verdict semantics

- `pass`: complete, readable evidence shows the compliant configuration. Pagination ran to completion and X-Total-Count (or an Aggregate count) matched the rows returned.
- `warn`: the visible evidence is compliant but the view is partial or truncated (seen and total counts are reported), a documented property has no `sys_properties` row (its default is never assumed), or a hygiene gap remains.
- `fail`: a verified non-compliant setting or record.
- `manual`: the read was forbidden (401/403), ACL-filtered, or errored; the inventory was empty where emptiness cannot be trusted; the control is out of scope or not exposed through the API. The summary names the cause and `manualEvidence` states exactly what a human must collect.

Rows without a date (`last_login_time`, `expires`) are bucketed separately and never counted as active or valid.

## Control coverage

| # | Control | Tool | Finding | Status semantics |
| --- | --- | --- | --- | --- |
| 1 | Instance security properties | platform_hardening | SNOW-01 | pass when the five `glide.security.*` properties exist with compliant values; warn when any row is absent; fail on a non-compliant value |
| 2 | ACL rule completeness | access_control | SNOW-02 | manual unless the Aggregate ACL count proves visibility; fail on role-less, condition-less, script-less record ACLs; warn on wildcard ACLs or active public pages |
| 3 | Role hierarchy audit | identity_access | SNOW-03 | manual unless `sys_user_role_contains` is proven visible; warn when roles inherit `admin` or `security_admin`; pass when none do |
| 4 | User access review | identity_access | SNOW-04 | manual on zero users or zero admin assignments; fail on stale admins or admin count above `max_admins`; warn on inactive users, users without a login date, locked-out active accounts (`sys_user.locked_out`, admins listed separately), or stacked privileged roles |
| 5 | Session timeout configuration | platform_hardening | SNOW-05 | fail above `max_session_timeout_minutes`; warn when the property is absent (fallback of 30 minutes is not assumed) or rotation is off |
| 6 | Password policy enforcement | identity_access | SNOW-06 | fail when `glide.enable.password_policy=false`, no policy row is visible, or a policy is weaker than the threshold; warn when the property row is absent |
| 7 | MFA enforcement | identity_access | SNOW-07 | fail when `glide.authenticate.multifactor` is false or absent (documented default is false), or when the Role-based multi-factor authentication record in `multi_factor_criteria` is inactive and admins lack `enable_multifactor_authn`; manual when `multi_factor_criteria` is forbidden or returns no rows (the baseline record always exists); warn when the active role-based record does not list `admin` and `security_admin` while admins lack the per-user flag, when only per-user flags enforce MFA, or when email OTP is enabled; pass when the role-based record is active and covers both roles (or every admin carries the per-user flag) |
| 8 | LDAP/SSO integration | identity_access | SNOW-08 | fail with no active SSO provider or LDAP server, or an expired certificate; warn when Multi-Provider SSO or the default redirect IdP is not set or certificates expire soon |
| 9 | Encryption at rest | operations_governance | SNOW-09 | always manual: KMF cryptographic modules (`sys_kmf_crypto_module`, used by Column Level Encryption Enterprise), legacy encryption contexts, and encrypted dictionary fields are inventoried, but coverage and licensing (CLE Enterprise, Cloud Encryption, Edge Encryption) are not exposed through the API |
| 10 | Audit logging configuration | operations_governance | SNOW-10 | fail when a critical table is not audited or `sys_audit` received zero rows in 7 days; otherwise manual because retention is not exposed through the API |
| 11 | Table-level access controls | access_control | SNOW-11 | fail when a sensitive table has no active record ACL; warn when read, write, or delete is missing; pass when all three exist |
| 12 | Script execution restrictions | platform_hardening | SNOW-12 | fail on non-compliant `glide.script.*` values or active business rules calling `eval(`; warn on absent properties |
| 13 | Instance hardening | platform_hardening | SNOW-13 | pass when the eleven hardening properties exist with compliant values; warn on absent rows; fail on non-compliant values |
| 14 | Integration user permissions | identity_access | SNOW-14 | fail when an integration account holds `admin` or `security_admin`; manual when no integration-flagged user exists; warn on other privileged roles |
| 15 | Update set management | operations_governance | SNOW-15 | manual unless the update set inventory is proven visible; warn on in-progress sets or pending ACL, role, script, or property changes |
| 16 | Debug mode verification | platform_hardening | SNOW-16 | fail when any `*debug*` property is true; manual when `sys_properties` visibility is unproven |
| 17 | IP access restrictions | platform_hardening | SNOW-17 | fail when the IP Range Based Authentication plugin (`com.snc.ipauthenticator`) is inactive or absent from `sys_plugins`, or when no active `ip_access` rule exists (a missing `ip_access` table is treated as the plugin not being activated); warn when the plugin row is not visible or `glide.ip.authenticate.strict` is not true |
| 18 | Email security | platform_hardening | SNOW-18 | reads the Connection Security choice (`connection_security`, falling back to the legacy `enable_ssl` and `enable_tls` flags): fail when an active SMTP account uses None or `glide.smtp.auth=false`; warn on STARTTLS (the documentation warns it may expose data); manual when the value is not returned (never assumed) or when every account uses SSL/TLS, because DKIM and notification headers are not exposed through the API |
| 19 | MID Server security | operations_governance | SNOW-19 | fail on unvalidated MID Servers; warn when `mid.version.override` pins upgrades; manual for mutual authentication and allow lists, or "not applicable as observed" when no MID Server exists |
| 20 | Plugin inventory and licensing | operations_governance | SNOW-20 | fail when High Security Settings, Contextual Security: Role Management V2, or Security Jump Start is inactive; otherwise manual for necessity review |

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
