---
title: Snowflake
description: Read-only Snowflake security posture checks over the SQL REST API with key-pair JWT or OAuth, covering all 25 controls in the Snowflake security inspector spec.
---

The Snowflake integration runs read-only `SHOW` commands and `SNOWFLAKE.ACCOUNT_USAGE` queries through the Snowflake SQL REST API and turns the results into normalized findings with FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP mappings. It never issues `CREATE`, `ALTER`, `DROP`, `GRANT`, or `USE ROLE`; the client rejects any statement that does not start with `SHOW`, `DESCRIBE`, `SELECT`, `WITH`, or `EXPLAIN`.

## What it inspects

- Network policies, account-level activation, and IP allowlist breadth
- MFA coverage for person users, password policies, session policies, SAML2 and SCIM integrations
- Key-pair authentication for `SERVICE` and `LEGACY_SERVICE` users
- Role hierarchy, `ACCOUNTADMIN` and `SECURITYADMIN` membership, routine `ACCOUNTADMIN` usage, direct user grants, and `PUBLIC` grants
- Failed login patterns, stale users, retention parameters, `ACCESS_HISTORY` readability, warehouse auto-suspend
- Masking and row access policy assignment, tag-based classification, stage and unload restrictions, Time Travel retention, outbound shares and listings, API and external access integrations
- Tri-Secret Secure and customer-managed keys as manual evidence findings (not queryable through SQL)

## Setup and authentication

The Snowflake SQL REST API accepts key-pair JWTs, OAuth access tokens, and programmatic access tokens. Username and password authentication is not available on the SQL API, so the tools reject password-only configuration with an explicit error.

### Key-pair authentication (recommended)

Generate an RSA key pair and register the public key on the audit user, following the [key-pair authentication guide](https://docs.snowflake.com/en/user-guide/key-pair-auth):

```bash
openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -nocrypt
openssl rsa -in rsa_key.p8 -pubout -out rsa_key.pub
```

```sql
ALTER USER GRCLANKER_SVC SET RSA_PUBLIC_KEY = 'MIIBIjANBgkqh...';
```

The client builds the JWT with `node:crypto`: `iss` is `<ACCOUNT>.<USER>.SHA256:<public key fingerprint>`, `sub` is `<ACCOUNT>.<USER>` (account and user upper-cased, region and cloud segments stripped from legacy locators), the token is signed with RS256, and it expires within one hour and is refreshed automatically. Encrypted private keys are supported through a passphrase.

### Environment variables

| Variable | Purpose |
|----------|---------|
| `SNOWFLAKE_ACCOUNT` | Account identifier (`orgname-accountname` or legacy locator such as `xy12345.us-east-1`) |
| `SNOWFLAKE_USER` | Audit user |
| `SNOWFLAKE_PRIVATE_KEY_PATH` (or `SNOWFLAKE_PRIVATE_KEY_FILE`) | Path to the PKCS#8 private key |
| `SNOWFLAKE_PRIVATE_KEY` (or `SNOWFLAKE_PRIVATE_KEY_RAW`) | Inline private key PEM (`\n` escapes accepted) |
| `SNOWFLAKE_PRIVATE_KEY_PASSPHRASE` (or `PRIVATE_KEY_PASSPHRASE`) | Passphrase for an encrypted key |
| `SNOWFLAKE_TOKEN` (or `SNOWFLAKE_OAUTH_TOKEN`, `SNOWFLAKE_ACCESS_TOKEN`) | OAuth or programmatic access token |
| `SNOWFLAKE_TOKEN_TYPE` (or `SNOWFLAKE_AUTHENTICATOR`) | `KEYPAIR_JWT`, `OAUTH`, or `PROGRAMMATIC_ACCESS_TOKEN` |
| `SNOWFLAKE_ROLE` | Role for every statement (defaults to the user's default role) |
| `SNOWFLAKE_WAREHOUSE` | Warehouse for `ACCOUNT_USAGE` queries (X-Small is enough) |
| `SNOWFLAKE_DATABASE`, `SNOWFLAKE_SCHEMA` | Optional session context |
| `SNOWFLAKE_BASE_URL` (or `SNOWFLAKE_HOST`) | Override for PrivateLink or non-standard hosts |
| `SNOWFLAKE_CONNECTION_NAME` (or `SNOWFLAKE_DEFAULT_CONNECTION_NAME`) | Connection entry to read from the TOML config files |
| `SNOWFLAKE_HOME` | Alternate directory for `connections.toml` and `config.toml` |
| `SNOWFLAKE_TIMEOUT`, `SNOWFLAKE_STATEMENT_TIMEOUT`, `SNOWFLAKE_POLL_INTERVAL_MS` | HTTP timeout (seconds), server-side statement timeout (seconds), and async poll interval |

Precedence is explicit tool arguments, then environment variables, then `~/.snowflake/connections.toml` (a `[<name>]` table) or `~/.snowflake/config.toml` (`default_connection_name` plus `[connections.<name>]` tables), matching the [connections.toml format](https://docs.snowflake.com/en/developer-guide/snowflake-cli/connecting/configure-connections) used by Snowflake CLI and the Python connector. The reader accepts the documented keys `account`, `user`, `role`, `warehouse`, `database`, `schema`, `host`, `private_key_file`, `private_key_raw`, `private_key_file_pwd`, `token`, and `authenticator`.

### Recommended read-only role

```sql
CREATE ROLE SNOWFLAKE_AUDITOR;
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE SNOWFLAKE_AUDITOR;
GRANT USAGE ON WAREHOUSE AUDIT_WH TO ROLE SNOWFLAKE_AUDITOR;
GRANT ROLE SNOWFLAKE_AUDITOR TO USER GRCLANKER_SVC;
```

`IMPORTED PRIVILEGES` on the `SNOWFLAKE` database unlocks the `ACCOUNT_USAGE` views ([enabling ACCOUNT_USAGE for other roles](https://docs.snowflake.com/en/sql-reference/account-usage#enabling-the-snowflake-database-usage-for-other-roles)). `SHOW` commands only list objects the active role can access, and `SHOW SHARES` returns an empty result without the `IMPORT SHARE` privilege, so the tools treat `ACCOUNTADMIN` and `SECURITYADMIN` as full-visibility roles and flag every other role as partial visibility: an empty `SHOW` inventory under a custom role yields `manual` or `warn`, never `pass`. `ACCESS_HISTORY` requires Enterprise Edition or higher.

## Tools

| Tool | Purpose |
|------|---------|
| `snowflake_check_access` | Probes the session context, every `SHOW` command, and every `ACCOUNT_USAGE` view the assessments use; reports readable, denied, errored, and timed-out surfaces, whether the role has full visibility, and the credential source chain |
| `snowflake_assess_network_and_authentication` | Controls 1-6 and 25 |
| `snowflake_assess_access_control` | Controls 7-10 and 16 |
| `snowflake_assess_monitoring_and_lifecycle` | Controls 11-13 and 24 |
| `snowflake_assess_data_protection` | Controls 14-15 and 17-23 |
| `snowflake_export_audit_bundle` | Runs the access check and all four assessments, then writes `core_data/` (raw result sets per statement), `analysis/` (`findings.json` plus per-area JSON and markdown), `compliance/` (`executive_summary.md`, `unified_compliance_matrix.md`, one report per framework), `QUICK_REFERENCE.md`, `metadata.json`, `_errors.log` when any statement failed, and a paired `.zip`; a rerun allocates a new `-2`, `-3` directory and archive instead of overwriting |

All tools accept the same authentication arguments (`account`, `user`, `private_key_path`, `private_key`, `private_key_passphrase`, `token`, `token_type`, `role`, `warehouse`, `database`, `schema`, `base_url`, `connection`, `timeout_seconds`, `statement_timeout_seconds`, `row_limit`). The assessment and export tools add thresholds: `lookback_days` (30), `stale_user_days` (90), `failed_login_threshold` (10), `max_accountadmins` (3), `max_auto_suspend_seconds` (600), `max_session_idle_minutes` (60), `min_password_length` (14), and `min_retention_days` (1).

### Statement execution

Statements are submitted with `POST /api/v2/statements?async=true` and polled with `GET /api/v2/statements/{handle}` while the API returns `202`, honoring `Retry-After`. When `resultSetMetaData.partitionInfo` lists more than one partition, every partition is fetched with `?partition=N`; if the partition cap or the `row_limit` is hit, the result is marked truncated and the affected findings are downgraded. `429` and `5xx` responses are retried with exponential backoff, HTTP timeouts abort the request, and error messages are redacted of bearer tokens, JWTs, private keys, and passphrases.

## Verdict semantics

Every finding carries `id`, `control`, `title`, `severity`, `status`, `summary`, `evidence`, and `mappings`. Statuses follow these rules:

- `pass`: the enabling flag was read and satisfied on a complete inventory from a role with sufficient visibility.
- `warn`: the control is partly met, or the evidence is partial (truncated partitions, row limit hit, custom role without full `SHOW` visibility, items with missing dates).
- `fail`: the control is not met, including empty inventories where emptiness contradicts the control's intent (zero network policies, zero password policies, zero masking policies).
- `manual`: a required statement was denied, failed, or timed out; the control is not verifiable through SQL; the account edition does not expose it; or the empty result cannot be distinguished from view latency or restricted privileges. The summary names the cause and the evidence to collect.

Items with a NULL `LAST_SUCCESS_LOGIN` are reported in their own bucket and never counted as active. An empty result only passes when the control's intent makes emptiness compliant and the statement was readable: no direct user grants (10), no `PUBLIC` grants (16), no outbound shares (22), and no enabled API or external access integrations (23), the last two only under `ACCOUNTADMIN` or `SECURITYADMIN`.

## Control coverage

| # | Spec control | Tool | Finding | Status semantics |
|---|--------------|------|---------|------------------|
| 1 | Network policy configured and applied to account | network_and_authentication | SNOWFLAKE-01 | pass when `SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT` reports a policy at `ACCOUNT` level; warn when only user-level `POLICY_REFERENCES` exist; fail on zero policies or no activation |
| 2 | Network policy IP allowlist is restrictive | network_and_authentication | SNOWFLAKE-02 | fail on `0.0.0.0/0`, `::/0`, or CIDRs broader than `/8`, or zero policies in `NETWORK_POLICIES`; warn when every `ALLOWED_IP_LIST` is empty |
| 3 | MFA enforced for all human users | network_and_authentication | SNOWFLAKE-03 | reads `TYPE`, `DISABLED`, `HAS_PASSWORD`, `HAS_MFA`, `EXT_AUTHN_DUO`; fail if any enabled person user with a password lacks both flags; manual on zero users |
| 4 | Password policy meets complexity requirements | network_and_authentication | SNOWFLAKE-04 | requires an `ACCOUNT`-level assignment in `POLICY_REFERENCES` and a policy meeting `min_password_length`, one of each character class, and retries <= 10 |
| 5 | Key pair authentication used for service accounts | network_and_authentication | SNOWFLAKE-05 | fail if any `SERVICE` or `LEGACY_SERVICE` user lacks `HAS_RSA_PUBLIC_KEY` or `HAS_WORKLOAD_IDENTITY`, or still has a password; manual when no user is typed as a service user |
| 6 | SSO/SAML integration configured | network_and_authentication | SNOWFLAKE-06 | pass on an enabled `SAML2` security integration (SCIM reported); fail when none is enabled; manual when a custom role sees none |
| 7 | Role hierarchy follows least privilege | access_control | SNOWFLAKE-07 | fail if a custom role inherits `ACCOUNTADMIN` or `SECURITYADMIN`; warn on sensitive global privileges on custom roles or roles that do not roll up to `SYSADMIN`; manual on an empty graph |
| 8 | ACCOUNTADMIN role has minimal members | access_control | SNOWFLAKE-08 | fail above `max_accountadmins`; warn on a single member; manual on zero rows (Snowflake always has at least one) |
| 9 | ACCOUNTADMIN not used for routine queries | access_control | SNOWFLAKE-09 | fail at 10 percent or 100 routine queries in the lookback window; warn on any usage; manual on an empty window |
| 10 | No direct object grants to users | access_control | SNOWFLAKE-10 | pass only when `GRANTS_TO_ROLES WHERE GRANTED_TO = 'USER'` was readable and empty |
| 11 | Failed login monitoring | monitoring_and_lifecycle | SNOWFLAKE-11 | fail when a user/IP source exceeds `failed_login_threshold`; manual when `LOGIN_HISTORY` has zero events in the window |
| 12 | Stale users disabled | monitoring_and_lifecycle | SNOWFLAKE-12 | fail on enabled person users beyond `stale_user_days`; warn when any enabled user has a NULL `LAST_SUCCESS_LOGIN`; manual on zero users |
| 13 | History and data retention configured | monitoring_and_lifecycle | SNOWFLAKE-13 | fail below `min_retention_days`; warn when `ACCESS_HISTORY` is not readable; manual when the parameter is absent |
| 14 | Dynamic data masking policies applied | data_protection | SNOWFLAKE-14 | fail on zero masking policies or zero `POLICY_REFERENCES` assignments; warn on non-`ACTIVE` references |
| 15 | Row access policies applied | data_protection | SNOWFLAKE-15 | fail on zero policies or zero assignments |
| 16 | No PUBLIC grants on sensitive objects | access_control | SNOWFLAKE-16 | pass only when readable and empty; fail on data-object grants; warn on other `PUBLIC` grants |
| 17 | Storage integration required for stages | data_protection | SNOWFLAKE-17 | pass when both `REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION` and `_OPERATION` are true; warn when one is; manual when absent |
| 18 | Stage unload restrictions | data_protection | SNOWFLAKE-18 | pass when both `PREVENT_UNLOAD_TO_INLINE_URL` and `PREVENT_UNLOAD_TO_INTERNAL_STAGES` are true |
| 19 | Time Travel retention for databases | data_protection | SNOWFLAKE-19 | fail when a customer database has `retention_time` below `min_retention_days`; warn under a custom role; manual on zero databases |
| 20 | Tri-Secret Secure | data_protection | SNOWFLAKE-20 | always manual: Business Critical feature enabled through Snowflake Support, not exposed in SQL |
| 21 | Customer-managed keys configured | data_protection | SNOWFLAKE-21 | always manual: `SYSTEM$GET_SNOWFLAKE_PLATFORM_INFO()` returns VPC/VNet IDs only; collect KMS evidence |
| 22 | Outbound shares reviewed | data_protection | SNOWFLAKE-22 | warn on any `OUTBOUND` share (listing exposure counted); pass on zero outbound shares only under `ACCOUNTADMIN` or `SECURITYADMIN`; manual on zero rows under other roles |
| 23 | External functions and API integrations reviewed | data_protection | SNOWFLAKE-23 | warn on enabled `API` or `EXTERNAL_ACCESS` integrations; pass on none only with full visibility |
| 24 | Warehouse auto-suspend configured | monitoring_and_lifecycle | SNOWFLAKE-24 | fail on `auto_suspend` NULL or 0; warn above `max_auto_suspend_seconds` or under a custom role; manual on zero warehouses |
| 25 | Session policies configured | network_and_authentication | SNOWFLAKE-25 | requires an `ACCOUNT`-level `POLICY_REFERENCES` assignment with idle timeouts within `max_session_idle_minutes` |

Any control whose required statement is denied, fails, or times out renders as `manual` with the cause and the Snowsight evidence to collect.

## Framework mappings

Each finding carries the eight mappings from the spec's compliance table, for example SNOWFLAKE-03 maps to FedRAMP IA-2(1), CMMC IA.L2-3.5.3, SOC 2 CC6.1, CIS 4.5, PCI-DSS 8.3.2, STIG SRG-APP-000149, IRAP ISM-1401, and ISMAP 8.2.2. The audit bundle renders `compliance/fedramp.md`, `cmmc.md`, `soc-2.md`, `cis.md`, `pci-dss.md`, `stig.md`, `irap.md`, `ismap.md`, and a `unified_compliance_matrix.md` with one row per finding.

## Live smoke test

```bash
npm --prefix cli run test:snowflake:live
```

The script exits 0 with a skip message when no credentials resolve. With credentials it runs `snowflake_check_access` and the network and authentication assessment and prints the finding statuses.

## Limitations and manual controls

- Tri-Secret Secure (20) and customer-managed keys (21) are never SQL-verifiable and always require Snowflake Support and cloud KMS evidence.
- `ACCOUNT_USAGE` views lag: `USERS` and grants up to 2 hours, `LOGIN_HISTORY` up to 2 hours, `QUERY_HISTORY` up to 45 minutes, `ACCESS_HISTORY` up to 3 hours. Recent changes may not be visible, which is why empty inventories become `manual` rather than `pass`.
- `SHOW` commands are role-scoped. Use `ACCOUNTADMIN` or `SECURITYADMIN` for complete inventories; otherwise controls 1, 6, 19, 22, 23, and 24 cap at `warn` or `manual`.
- Password authentication and browser-based SSO are not supported by the SQL REST API.
- Replication and failover groups are collected as evidence for control 22 but Standard Edition accounts return an empty inventory; Trust Center findings are not queried in this release.
- Inventory queries carry a `row_limit` (default 20,000) and a partition cap (50); hitting either marks the statement truncated and downgrades any `pass`.

## Official documentation

- [Snowflake SQL REST API](https://docs.snowflake.com/en/developer-guide/sql-api/index)
- [Authenticating to the SQL API](https://docs.snowflake.com/en/developer-guide/sql-api/authenticating)
- [Submitting a request to execute SQL statements](https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests)
- [Handling responses](https://docs.snowflake.com/en/developer-guide/sql-api/handling-responses)
- [SQL API reference](https://docs.snowflake.com/en/developer-guide/sql-api/reference)
- [Key-pair authentication and key-pair rotation](https://docs.snowflake.com/en/user-guide/key-pair-auth)
- [Connecting with connections.toml](https://docs.snowflake.com/en/developer-guide/snowflake-cli/connecting/configure-connections)
- [Account Usage overview and latency](https://docs.snowflake.com/en/sql-reference/account-usage)
- [USERS view](https://docs.snowflake.com/en/sql-reference/account-usage/users)
- [LOGIN_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/login_history)
- [ACCESS_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/access_history)
- [QUERY_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/query_history)
- [GRANTS_TO_ROLES view](https://docs.snowflake.com/en/sql-reference/account-usage/grants_to_roles)
- [GRANTS_TO_USERS view](https://docs.snowflake.com/en/sql-reference/account-usage/grants_to_users)
- [NETWORK_POLICIES view](https://docs.snowflake.com/en/sql-reference/account-usage/network_policies)
- [PASSWORD_POLICIES view](https://docs.snowflake.com/en/sql-reference/account-usage/password_policies)
- [SESSION_POLICIES view](https://docs.snowflake.com/en/sql-reference/account-usage/session_policies)
- [MASKING_POLICIES view](https://docs.snowflake.com/en/sql-reference/account-usage/masking_policies)
- [ROW_ACCESS_POLICIES view](https://docs.snowflake.com/en/sql-reference/account-usage/row_access_policies)
- [POLICY_REFERENCES view](https://docs.snowflake.com/en/sql-reference/account-usage/policy_references)
- [TAG_REFERENCES view](https://docs.snowflake.com/en/sql-reference/account-usage/tag_references)
- [SHOW NETWORK POLICIES](https://docs.snowflake.com/en/sql-reference/sql/show-network-policies)
- [SHOW PARAMETERS](https://docs.snowflake.com/en/sql-reference/sql/show-parameters)
- [SHOW INTEGRATIONS](https://docs.snowflake.com/en/sql-reference/sql/show-integrations)
- [SHOW WAREHOUSES](https://docs.snowflake.com/en/sql-reference/sql/show-warehouses)
- [SHOW DATABASES](https://docs.snowflake.com/en/sql-reference/sql/show-databases)
- [SHOW SHARES](https://docs.snowflake.com/en/sql-reference/sql/show-shares)
- [SHOW REPLICATION GROUPS](https://docs.snowflake.com/en/sql-reference/sql/show-replication-groups)
- [Parameters reference (REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_*, PREVENT_UNLOAD_TO_*, DATA_RETENTION_TIME_IN_DAYS, NETWORK_POLICY)](https://docs.snowflake.com/en/sql-reference/parameters)
- [SYSTEM$GET_SNOWFLAKE_PLATFORM_INFO](https://docs.snowflake.com/en/sql-reference/functions/system_get_snowflake_platform_info)
- [Understanding encryption key management and Tri-Secret Secure](https://docs.snowflake.com/en/user-guide/security-encryption-manage)
- [Trust Center overview](https://docs.snowflake.com/en/user-guide/trust-center/overview)
