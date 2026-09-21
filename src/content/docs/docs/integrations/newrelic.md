---
title: New Relic
description: Read-only New Relic organization security inspection covering identity, API keys, access grants, alerting, and data governance, mapped to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP.
---

The New Relic integration implements the [New Relic Security Inspector spec](https://github.com/hackIDLE/grclanker/blob/main/specs/newrelic-sec-inspector.spec.md) as native grclanker tools. It reads organization, user, role, API key, alerting, and data governance configuration through NerdGraph (GraphQL) and the REST API v2, evaluates the 20 numbered controls from the spec, and emits normalized findings that carry the spec's compliance mappings. Every tool is read-only: no mutation is ever sent to New Relic.

## What it inspects

- Identity: authentication domain SSO method and provisioning type, user types, admin group membership, inactive users.
- Access control: user, license, and browser key inventory, key age, orphaned or unconfirmed keys, group role grants, production and non-production account overlap, custom roles.
- Alerting: alert policies and NRQL conditions, alertable entity coverage, notification destinations and channels, workflows and enrichments, workload status.
- Data governance: event retention rules, log obfuscation rules and expressions, Pipeline Control cloud rules, legacy NRQL drop rules, dashboards and public live URLs, synthetic monitor scripts and secure credentials, plaintext secret patterns in `Log` data, infrastructure agent version evidence from `SystemSample`.

## Setup and authentication

New Relic authenticates API calls with a **User API key** (`NRAK-...`) sent in the `API-Key` header. The key inherits the permissions of the user who created it, so the inspector only sees what that user can see. For complete coverage use a key from a user who:

- holds the **Organization manager** and **Authentication domain manager** roles (organization and user management reads),
- is a member of a group with access to every account in scope (alerts, dashboards, data management, and NRQL reads are account scoped),
- is a **core** or **full platform** user, because New Relic applies user type restrictions to administration features the same way through NerdGraph as through the UI.

A user key is required for NerdGraph; license, browser, and ingest keys cannot authenticate, and `newrelic_check_access` reports every required surface as not readable when one is supplied.

### Environment variables

| Variable | Purpose |
|----------|---------|
| `NEW_RELIC_API_KEY` | User API key. Required unless supplied as an argument or in the config file. |
| `NEW_RELIC_ACCOUNT_ID` | Account ID or comma-separated account IDs to inspect. When omitted the tools inspect every account visible to the key (`actor.accounts`). |
| `NEW_RELIC_REGION` | `US` (default) or `EU`. Maps to `https://api.newrelic.com` or `https://api.eu.newrelic.com`. |
| `NEW_RELIC_SEC_INSPECTOR_CONFIG` | Optional path to a YAML config file. Defaults to `~/.newrelic-sec-inspector/config.yaml`. |
| `NEW_RELIC_TIMEOUT` | Optional HTTP timeout in seconds (default 30). |
| `NEW_RELIC_AUDIT_WINDOW_DAYS` | Optional `NrAuditEvent` lookback window in days (default 30, maximum 395). |

### Config file

`~/.newrelic-sec-inspector/config.yaml` (or the path in `NEW_RELIC_SEC_INSPECTOR_CONFIG` / the `config_file` argument):

```yaml
api_key: NRAK-XXXXXXXXXXXXXXXXXXXXXXXXXXXX
account_ids:
  - 1234567
  - 2345678
region: US
timeout_seconds: 30
audit_window_days: 30
```

Resolution precedence is explicit tool arguments, then environment variables, then the config file, then defaults (US region, account discovery through `actor.accounts`). The audit bundle's `metadata.json` records the `source_chain` that was used. API key values are redacted from every error message and never requested from the API, so they never appear in audit bundles.

### API behavior

- NerdGraph queries are POSTed to `/graphql` and paginated with `nextCursor` where the schema exposes a cursor. `apiAccess.keySearch` is tried with a cursor first and falls back to a single page if the schema rejects the argument.
- REST API v2 calls send `Api-Key` and follow RFC 5988 `Link` headers (`rel="next"`) or the `page=` parameter.
- HTTP 429, 500, 502, 503, and 504 responses are retried up to three times. The delay honors `Retry-After` or `X-RateLimit-Reset` when present and otherwise backs off exponentially, capped at 15 seconds per wait. New Relic documents a REST API v2 limit of 1000 calls per minute per key.
- Every request has a timeout (30 seconds by default).

## Tools

All tools accept the shared authentication arguments `api_key`, `account_id`, `region`, `config_file`, `timeout_seconds`, and `audit_window_days`.

### `newrelic_check_access`

Probes each read surface the assessments depend on and reports `healthy` or `limited`. Required surfaces: `actor.user`, `actor.accounts`, `actor.organization`, `organization.userManagement.authenticationDomains`, `organization.authorizationManagement.roles`, `actor.apiAccess.keySearch`, and `actor.account.nrql` (`NrAuditEvent`). Optional surfaces: `entitySearch`, `alerts.policiesSearch`, `dataManagement.eventRetentionRules`, `logConfigurations.obfuscationRules`, and REST v2 `GET /v2/users.json` (original user model only, informational).

### `newrelic_assess_identity`

Spec controls 1, 2, 3, 18, 19. Extra arguments: `user_limit` (2000), `inactive_days` (90), `max_admins` (10), `max_full_platform_percent` (60), `admin_role_pattern` (`organization manager|authentication domain manager|all product admin`).

### `newrelic_assess_access_control`

Spec controls 4, 5, 6, 7, 8, 20. Extra arguments: `user_limit`, `inactive_days`, `max_key_age_days` (90), `max_accounts_per_user` (5), `admin_role_pattern`, `production_account_pattern` (`prod`), `nonproduction_account_pattern` (`dev|test|stag|sandbox|qa|nonprod|non-prod|uat|demo`).

### `newrelic_assess_alerting`

Spec controls 9, 10, 17. Extra arguments: `entity_limit` (1000), `approved_email_domains` (comma-separated; defaults to the authenticated user's email domain).

### `newrelic_assess_data_governance`

Spec controls 11, 12, 13, 14, 15, 16. Extra arguments: `entity_limit`, `min_retention_days` (30), `script_sample_limit` (25).

### `newrelic_export_audit_bundle`

Runs all four assessments and writes an evidence bundle under `output_dir` (default `./export/newrelic`). The bundle directory is named `newrelic-<account ids>-audit-bundle` (suffixed `-2` through `-6` on repeat runs) and contains:

- `metadata.json`: region, endpoint, accounts, audit window, and configuration source chain.
- `core_data/*.json`: raw NerdGraph and REST snapshots (accounts, organization, authentication domains, users, group role grants, roles, API keys, audit events, alert policies and conditions, destinations, channels, workflows, alertable entities, workloads, retention rules and namespaces, obfuscation rules and expressions, pipeline cloud rules, drop rules, dashboards, live URL metadata, synthetic monitors, secure credentials, script scan results, log scan counts, infrastructure host and agent version rows).
- `analysis/findings.json` plus `analysis/identity.json`, `analysis/access_control.json`, `analysis/alerting.json`, and `analysis/data_governance.json`.
- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, and one report per framework: `compliance/fedramp/fedramp_compliance_report.md`, `compliance/cmmc/cmmc_compliance_report.md`, `compliance/soc2/soc2_compliance_report.md`, `compliance/cis/cis_compliance_report.md`, `compliance/pci_dss/pci_dss_compliance_report.md`, `compliance/disa_stig/stig_compliance_checklist.md`, `compliance/irap/irap_compliance_report.md`, `compliance/ismap/ismap_compliance_report.md`.
- `QUICK_REFERENCE.md`, `_errors.log` (only when some reads failed), and a sibling `.zip` of the whole directory.

Output paths are resolved with traversal and symlink protection: every file is resolved against the real path of `output_dir`, anything that would escape it is rejected, and symlinked path components (including a pre-existing symlink at the bundle path itself) abort the export. Directories are created with mode `0700` and files with `0600`.

## Control coverage

Findings use four statuses: `pass` (the control is met from API evidence), `warn` (met with caveats or needs review), `fail` (API evidence shows a violation), and `manual` (the API cannot establish the control, and the finding summary names the exact UI evidence a reviewer must collect). When a required read fails, the affected finding degrades to `manual` instead of silently passing.

| # | Spec control | Tool | Finding id | Status semantics |
|---|--------------|------|------------|------------------|
| 1 | SSO/SAML Enforcement | `newrelic_assess_identity` | `NR-01-SSO-ENFORCEMENT` | `fail` if any authentication domain uses password login, `pass` if all use SAML or OIDC SSO, `warn` if no auth type is exposed, `manual` when `customerAdministration` does not expose `authenticationType` (single-tenant organizations). |
| 2 | User Type Least Privilege | `newrelic_assess_identity` | `NR-02-USER-TYPE-LEAST-PRIVILEGE` | `fail` if full platform users are inactive past `inactive_days`, `warn` if the full platform share exceeds `max_full_platform_percent`, otherwise `pass`. |
| 3 | Admin User Minimization | `newrelic_assess_identity` | `NR-03-ADMIN-MINIMIZATION` | `fail` if admin group members exceed `max_admins`, `warn` if no group matches `admin_role_pattern`, otherwise `pass`. |
| 4 | API Key Inventory | `newrelic_assess_access_control` | `NR-04-API-KEY-INVENTORY` | `warn` if keys are unnamed or user keys belong to admin group members, otherwise `pass`. |
| 5 | API Key Age | `newrelic_assess_access_control` | `NR-05-API-KEY-AGE` | `fail` if user keys exceed `max_key_age_days`, `warn` if only license keys exceed it, `manual` if `createdAt` is not exposed, otherwise `pass`. |
| 6 | Unused API Keys | `newrelic_assess_access_control` | `NR-06-UNUSED-API-KEYS` | `pass` when no keys exist, `warn` for keys owned by missing or inactive users, otherwise `manual` because `NrAuditEvent` records configuration changes only, not read traffic. |
| 7 | Account Access Controls | `newrelic_assess_access_control` | `NR-07-ACCOUNT-ACCESS-CONTROLS` | `warn` if non-admin users hold organization-scoped grants or exceed `max_accounts_per_user`, otherwise `pass`. |
| 8 | Cross-Account Access Restrictions | `newrelic_assess_access_control` | `NR-08-CROSS-ACCOUNT-RESTRICTIONS` | `warn` if non-admin users reach both production and non-production accounts, `pass` with one account or no overlap, `manual` if account names match neither pattern. |
| 9 | Alert Policy Coverage | `newrelic_assess_alerting` | `NR-09-ALERT-POLICY-COVERAGE` | `fail` with no policies or with reporting APM, host, or synthetic entities that have `alertSeverity = NOT_CONFIGURED`, `warn` for other uncovered entities or policies without enabled conditions, otherwise `pass`. |
| 10 | Alert Notification Channels | `newrelic_assess_alerting` | `NR-10-ALERT-NOTIFICATION-CHANNELS` | `fail` for personal email destinations, `warn` for unapproved domains, inactive destinations, or policies with no enabled workflow, otherwise `pass`. |
| 11 | Data Retention Settings | `newrelic_assess_data_governance` | `NR-11-DATA-RETENTION` | `fail` if active rules retain less than `min_retention_days`, `warn` when no custom rules exist (defaults apply), otherwise `pass`. |
| 12 | Log Obfuscation Rules | `newrelic_assess_data_governance` | `NR-12-LOG-OBFUSCATION` | `fail` with no enabled obfuscation rules, `warn` if expressions do not cover both credential and PII patterns, otherwise `pass`. |
| 13 | Synthetic Monitor Security | `newrelic_assess_data_governance` | `NR-13-SYNTHETIC-MONITOR-SECURITY` | `fail` if sampled scripts contain credential patterns, `warn` if no script references `$secure.*` and no secure credentials exist, `manual` if scripts are unreadable, otherwise `pass`. |
| 14 | Dashboard Permissions | `newrelic_assess_data_governance` | `NR-14-DASHBOARD-PERMISSIONS` | `fail` if public live URLs exist, `warn` for `PUBLIC_READ_WRITE` dashboards, otherwise `pass`. |
| 15 | Logs in Context Security | `newrelic_assess_data_governance` | `NR-15-LOGS-IN-CONTEXT-SECURITY` | `fail` if `Log` messages match credential patterns in the last day, `warn` when no logs were ingested, otherwise `pass`. Only counts are collected, never matching messages. |
| 16 | Infrastructure Agent Configuration | `newrelic_assess_data_governance` | `NR-16-INFRA-AGENT-CONFIGURATION` | Always `manual`: agent transport settings are not API visible. Evidence lists reporting hosts and agent versions. |
| 17 | Applied Intelligence Sensitivity | `newrelic_assess_alerting` | `NR-17-APPLIED-INTELLIGENCE-SENSITIVITY` | `warn` if enabled workflows attach NRQL enrichments to external destinations, otherwise `manual` because correlation decision settings are not API visible. |
| 18 | Authentication Domain Configuration | `newrelic_assess_identity` | `NR-18-AUTH-DOMAIN-CONFIGURATION` | `warn` if any domain provisions users manually instead of SCIM or no domains are visible, otherwise `pass`. Session and upgrade settings remain UI evidence. |
| 19 | Inactive User Accounts | `newrelic_assess_identity` | `NR-19-INACTIVE-USER-ACCOUNTS` | `fail` if users exceed `inactive_days` since `lastActive`, `warn` if users have never been active, otherwise `pass`. |
| 20 | Custom Role Permissions | `newrelic_assess_access_control` | `NR-20-CUSTOM-ROLE-PERMISSIONS` | `pass` when no custom roles exist, otherwise `manual` because NerdGraph does not expose role capabilities. |

Coverage: 20 of 20 controls. Controls 16 and 20 (when custom roles exist), 17 (when no enrichment routes externally), and 6 (when keys exist without owner signals) resolve to `manual` by design, and each `manual` summary states the UI evidence to collect.

## Framework mappings

Every finding carries eight mappings taken from the spec's compliance table, formatted as `<Framework> <control>` (for example `FedRAMP IA-2`, `CMMC AC.L2-3.1.1`, `SOC 2 CC6.1`, `CIS 1.1`, `PCI-DSS 8.3.1`, `STIG SRG-APP-000148`, `IRAP ISM-1557`, `ISMAP CPS-04`). The unified matrix and the per-framework reports in the audit bundle are generated from these mappings, so a finding appears under each framework it maps to.

## Live smoke test

```bash
npm --prefix cli run test:newrelic:live
```

The script skips with exit code 0 when neither `NEW_RELIC_API_KEY`, `NEW_RELIC_SEC_INSPECTOR_CONFIG`, nor `~/.newrelic-sec-inspector/config.yaml` is present. With credentials it runs `newrelic_check_access` and `newrelic_assess_identity` against the real organization and fails if any required surface is unreadable.

## Limitations and manual controls

- `authenticationType` is only exposed by `customerAdministration.authenticationDomains`, which serves multi-tenant organizations. Single-tenant organizations receive a `manual` SSO finding with the exact UI path to capture.
- `NrAuditEvent` records configuration changes, so it cannot prove that a key is unused for read traffic (control 6) or that a user logged in (control 19 uses `lastActive` from user management instead).
- NerdGraph does not expose role capabilities (control 20), correlation decision settings (control 17), session or user upgrade settings (control 18), or infrastructure agent transport configuration (control 16).
- REST API v2 `GET /v2/users.json` only lists original user model users and is collected for reference only. The spec's `notification_channels.json` endpoint does not exist in REST v2; notification data comes from NerdGraph destinations, channels, and workflows.
- NRQL drop rules reached end of life in favor of Pipeline Control cloud rules. Cloud rules are collected first and legacy drop rules are collected best effort.
- Dashboard live URL values and `uuid`s are deliberately not collected; only title, type, and creation time are recorded.
- Synthetic script scanning samples up to `script_sample_limit` scripted monitors and reports indicator labels, never script contents.

## Official documentation consulted

- [Introduction to NerdGraph](https://docs.newrelic.com/docs/apis/nerdgraph/get-started/introduction-new-relic-nerdgraph/) (endpoints, `API-Key` header)
- [New Relic API keys](https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/)
- [NerdGraph tutorial: manage users](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-manage-users/)
- [NerdGraph tutorial: manage groups and access grants](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-manage-groups/)
- [NerdGraph tutorial: manage API keys](https://docs.newrelic.com/docs/apis/nerdgraph/examples/use-nerdgraph-manage-license-keys-user-keys/)
- [NerdGraph tutorial: NRQL](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-nrql-tutorial/)
- [NerdGraph tutorial: entities](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-entities-api-tutorial/)
- [NerdGraph tutorial: alert policies](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-api-alerts-policies/)
- [NerdGraph tutorial: NRQL conditions](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-api-nrql-condition-alerts/)
- [NerdGraph tutorial: destinations](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-api-notifications-destinations/)
- [NerdGraph tutorial: channels](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-api-notifications-channels/)
- [NerdGraph tutorial: workflows](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-api-workflows/)
- [NerdGraph tutorial: dashboards](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-dashboards/)
- [NerdGraph tutorial: workloads](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-workloads-api-tutorials/)
- [NerdGraph synthetics API overview](https://docs.newrelic.com/docs/apis/nerdgraph/examples/synthetics-api/overview/)
- [Secure credentials for synthetic monitors](https://docs.newrelic.com/docs/synthetics/synthetic-monitoring/using-monitors/store-secure-credentials-scripted-browsers-api-tests/)
- [Log obfuscation](https://docs.newrelic.com/docs/logs/ui-data/obfuscation-ui/)
- [Manage data retention](https://docs.newrelic.com/docs/data-apis/manage-data/manage-data-retention/)
- [Pipeline Control cloud rules API](https://docs.newrelic.com/docs/new-relic-control/pipeline-control/cloud-rules-api/)
- [Drop data using NerdGraph (NRQL drop rules)](https://docs.newrelic.com/docs/data-apis/manage-data/drop-data-using-nerdgraph/)
- [Query account audit logs (NrAuditEvent)](https://docs.newrelic.com/docs/accounts/accounts/account-maintenance/query-account-audit-logs-nrauditevent/)
- [NrAuditEvent attribute dictionary](https://docs.newrelic.com/attribute-dictionary/?event=NrAuditEvent)
- [Delegated administration (customerAdministration)](https://docs.newrelic.com/docs/accounts/accounts-billing/account-structure/multi-tenancy/delegated-administration/)
- [Authentication domains: SAML SSO, SCIM, and more](https://docs.newrelic.com/docs/accounts/accounts-billing/new-relic-one-user-management/authentication-domains-saml-sso-scim-more/)
- [User type](https://docs.newrelic.com/docs/accounts/accounts-billing/new-relic-one-user-management/user-type/)
- [User management concepts](https://docs.newrelic.com/docs/accounts/accounts-billing/new-relic-one-user-management/user-management-concepts/)
- [Share charts and dashboards externally](https://docs.newrelic.com/docs/query-your-data/explore-query-data/dashboards/share-charts-dashboards-externally/)
- [Incident workflows](https://docs.newrelic.com/docs/alerts/get-notified/incident-workflows/)
- [Infrastructure agent configuration settings](https://docs.newrelic.com/docs/infrastructure/install-infrastructure-agent/configuration/infrastructure-agent-configuration-settings/)
- [Choose your data center (US and EU)](https://docs.newrelic.com/docs/accounts/accounts-billing/account-setup/choose-your-data-center/)
- [Introduction to REST API v2](https://docs.newrelic.com/docs/apis/rest-api-v2/get-started/introduction-new-relic-rest-api-v2/)
- [REST API v2 pagination](https://docs.newrelic.com/docs/apis/rest-api-v2/requirements/pagination-api-output/)
- [REST API v2 overload protection and 429 errors](https://docs.newrelic.com/docs/apis/rest-api-v2/requirements/api-overload-protection-handling-429-errors/)
- [Query limits](https://docs.newrelic.com/docs/data-apis/manage-data/query-limits/)
