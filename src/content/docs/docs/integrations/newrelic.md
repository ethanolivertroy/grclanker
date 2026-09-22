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

Resolution precedence is explicit tool arguments, then environment variables, then the config file, then defaults (US region, account discovery through `actor.accounts`). The audit bundle's `metadata.json` records the `source_chain` that was used. The API key is never requested from the API, and every error message is scrubbed of credential material before it is stored (see rule 13 under "Verdict safety"), so neither the configured key nor a credential an upstream error page happens to carry appears in an audit bundle.

### API behavior

- NerdGraph queries are POSTed to `/graphql` and paginated with `nextCursor` where the schema exposes a cursor. A listing is complete only when the API returned no next cursor and the items seen reach the reported total; a cursor that stops advancing, an empty page beside a next cursor, the item limit, the page maximum, or a total larger than the items returned all mark the list incomplete with the number of items seen and the reported total, and the affected findings record the truncation. `apiAccess.keySearch` is tried in three layers (schema-cited fields with a cursor, the same fields on a single page, then only the fields shown on the docs page); `aiWorkflows.workflows` and `authorizationManagement` group grants fall back to the documented unpaginated shape when the schema rejects the cursor or filter argument. Every fallback is recorded as an incomplete listing.
- Every field in every NerdGraph selection is traceable to a public docs.newrelic.com page or to the public NerdGraph schema; see "NerdGraph field provenance" below.
- A NerdGraph response that carries `errors` entries is treated as a failed read even when it also carries partial `data`.
- REST API v2 calls send `Api-Key` and follow RFC 5988 `Link` headers (`rel="next"`) or the `page=` parameter.
- HTTP 429, 500, 502, 503, and 504 responses are retried up to three times. The delay honors `Retry-After` or `X-RateLimit-Reset` when present and otherwise backs off exponentially, capped at 15 seconds per wait. New Relic documents a REST API v2 limit of 1000 calls per minute per key.
- Every request has a timeout (30 seconds by default).

## Tools

All tools accept the shared authentication arguments `api_key`, `account_id`, `region`, `config_file`, `timeout_seconds`, and `audit_window_days`.

### `newrelic_check_access`

Probes each read surface the assessments depend on and reports `healthy` or `limited`. Required surfaces: `actor.user`, `actor.accounts`, `actor.organization`, `organization.userManagement.authenticationDomains`, `actor.apiAccess.keySearch`, and `actor.account.nrql` (`NrAuditEvent`). Optional surfaces: `customerAdministration.roles` (the documented role catalog, only served to organizations with the multi-tenancy entitlement; control 20 renders manual without it), `entitySearch`, `alerts.policiesSearch`, `dataManagement.eventRetentionRules`, `logConfigurations.obfuscationRules`, and REST v2 `GET /v2/users.json` (original user model only, informational).

### `newrelic_assess_identity`

Spec controls 1, 2, 3, 18, 19. Extra arguments: `user_limit` (2000), `inactive_days` (90), `max_admins` (10), `max_full_platform_percent` (60), `admin_role_pattern` (`organization manager|authentication domain manager|all product admin`).

### `newrelic_assess_access_control`

Spec controls 4, 5, 6, 7, 8, 20. Extra arguments: `user_limit`, `inactive_days`, `max_key_age_days` (90), `max_accounts_per_user` (5), `admin_role_pattern`, `production_account_pattern` (`prod`), `nonproduction_account_pattern` (`dev|test|stag|sandbox|qa|nonprod|non-prod|uat|demo`).

### `newrelic_assess_alerting`

Spec controls 9, 10, 17. Extra arguments: `entity_limit` (1000), `approved_email_domains` (comma-separated; defaults to the authenticated user's email domain).

### `newrelic_assess_data_governance`

Spec controls 11, 12, 13, 14, 15, 16. Extra arguments: `entity_limit`, `min_retention_days` (30), `script_sample_limit` (25).

### `newrelic_export_audit_bundle`

Runs all four assessments and writes an evidence bundle under `output_dir` (default `./export/newrelic`). The bundle directory is named `newrelic-<account ids>-audit-bundle` (suffixed `-2` through `-6` on repeat runs, skipping any name whose directory or zip already exists), the zip takes the same name as the directory, and the directory contains:

- `metadata.json`: region, endpoint, accounts, audit window, and configuration source chain.
- `core_data/*.json`: NerdGraph and REST records projected to the fields each query selects (accounts, organization, authentication domains, users, group role grants, roles, API keys, audit events, alert policies and conditions, destinations, channels, workflows, alertable entities, workloads, retention rules and namespaces, obfuscation rules and expressions, pipeline cloud rules, drop rules, dashboards, live URL metadata, synthetic monitors, secure credentials, script scan results, log scan counts, infrastructure host and agent version rows). A file whose query failed, was never issued, or lost a scope is written as `{ status, records }` (the readable rows for a partial listing, `null` when nothing was read) rather than as an empty list. See "Bundle secret hygiene" below for what is deliberately not stored.
- `analysis/findings.json` plus `analysis/identity.json`, `analysis/access_control.json`, `analysis/alerting.json`, and `analysis/data_governance.json`; every count in a category `summary` carries a paired `*_status` naming the queries it rests on (`complete`, `truncated`, `partial`, `unreadable`, or `not collected`, with `null` beside the last three), and each category file lists its `coverage` limitations (truncated lists, unreadable datasets and scopes with their query paths, fallback pagination).
- `compliance/executive_summary.md` (including a Coverage Limitations section when any inventory was partial), `compliance/unified_compliance_matrix.md`, and one report per framework: `compliance/fedramp/fedramp_compliance_report.md`, `compliance/cmmc/cmmc_compliance_report.md`, `compliance/soc2/soc2_compliance_report.md`, `compliance/cis/cis_compliance_report.md`, `compliance/pci_dss/pci_dss_compliance_report.md`, `compliance/disa_stig/stig_compliance_checklist.md`, `compliance/irap/irap_compliance_report.md`, `compliance/ismap/ismap_compliance_report.md`.
- `QUICK_REFERENCE.md`, `_errors.log` (only when some reads failed or were skipped because the account or domain list they iterate was unavailable), and a sibling `.zip` of the whole directory.

Output paths are resolved with traversal and symlink protection: every file is resolved against the real path of `output_dir`, anything that would escape it is rejected, and symlinked path components (including a pre-existing symlink at the bundle path itself) abort the export. Directories are created with mode `0700` and files with `0600`.

## Control coverage

Findings use four statuses: `pass` (the control is met from complete API evidence), `warn` (met with caveats, or the evidence was incomplete), `fail` (API evidence shows a violation), and `manual` (the API cannot establish the control, and the finding summary names the cause and the exact UI evidence a reviewer must collect).

### Verdict safety

Every finding follows the same evidence rules, and `cli/tests/newrelic.test.mjs` carries a regression test for each:

1. An unreadable, forbidden, or errored NerdGraph field or REST endpoint (including GraphQL `errors` alongside partial `data`) never yields `pass`. The finding is `manual`, and its summary names the failing surface, the error, and the evidence to collect.
2. An empty inventory never yields `pass` by default. Each summary states whether emptiness is unknown (`manual`) or a violation (`fail`, for example zero destinations while alert policies exist). The one accepted empty pass states its conditions in the summary: control 20 passes on zero custom roles only when the role listing was readable, complete, and returned standard roles. Zero keys from `keySearch` is always `manual` (controls 4, 5, and 6 agree): every account has its original license key, so a complete listing cannot be empty and an empty one means the key cannot see them.
3. Controls that are scoped out or unavailable on the tenant (single-tenant organizations without `customerAdministration`, a single visible account for control 8, no scripted monitors for control 13) render as `manual` with a "not applicable" or "scoped out" summary.
4. Items without a date (`lastActive`, `createdAt`) are never counted as active, fresh, or rotated. They are reported in their own evidence bucket and cap the verdict at `warn`.
5. A partial view (a key scoped to some accounts, the `keySearch` single-page fallback, sampled synthetic scripts at `script_sample_limit`, an `entitySearch` or user list that stopped before `nextCursor` was exhausted, or an unreadable account or authentication domain among several) limits an otherwise passing finding to `warn`. The summary opens with a `Partial view:` clause naming the gap (seen and total counts, or the denied scope and query path) before any count from the readable data, and the assessment result lists every limitation under `coverage`.
6. Every flag a verdict depends on is read explicitly: `authenticationType`, user `type`, group membership and role grants, condition `enabled`, `workflowEnabled` with the channel `destinationId` route to an inventoried destination, destination `type`, obfuscation rule `enabled`, `retentionInDays` per namespace, dashboard `permissions`, and `monitorType`. A value whose enabling flag is `false` or absent never supports `pass`, and a flag the public schema does not document (such as a destination `active` state) is not read at all.
7. Pagination runs to completion or records truncation. A first page is never treated as the whole population.
8. Repeated exports never overwrite a prior bundle: the zip name is derived from the allocated bundle directory, and the allocator skips any name whose directory or zip already exists.
9. Bundle secret hygiene: every stored record is projected to the fields its query selects plus the scope fields the inspector attaches, so a value the API volunteers beyond the selection (a key string, a password hash, a live URL token) never reaches `core_data/` or a finding. Notification destination `properties` keep their keys, and a value only for the `email` key that control 10 reads; webhook URLs, security codes, Slack access tokens, and header values are dropped before storage. The regression test plants fake credentials in every collected object that can carry one and asserts that none appears in any bundle file or zip entry.
10. Truncation on every cap exit: a cursor walk is reported complete only when the API returned no next cursor and the number of items seen reaches the reported total. A cursor that stops advancing, an empty page beside a next cursor, a page larger than the item limit, the page maximum, and a listing that ends short of its `totalCount` or `count` are all reported as truncated with the seen and total counts in the note, so the dependent findings are limited to `warn`.
11. Secondary inventories (the rule 1 corollary): a finding that reads more than one inventory is limited below `pass` when any of them is unreadable, even when its verdict was computed from a complete primary inventory and the failure is already disclosed in the errors array or `_errors.log`. A denied query, a NerdGraph field returned as null beside an `errors` entry, and a denial for one account or authentication domain among several all count. The finding is `warn` (or `manual` when the unreadable dataset is its primary inventory), the summary names the dataset and its query path (for example "alerts.policiesSearch: unreadable (account 111: NerdGraph returned errors: Not authorized (at actor.account.alerts.policiesSearch); ...)"), and every count or list derived from the unreadable or partly readable inventory is rendered as `null` beside a `*_status` evidence field, never as `0` or `[]`; a count from the readable scopes only appears in the summary text after the `Partial view:` clause, never as the evidence value. A cause longer than the 200 character summary budget is compacted per scope, so the status text and query path of every denied scope stay in the summary while the full text remains in the errors array.
12. Never-collected inventories: a scoped query that had no scope to run over is `not collected`, not an empty result. When `actor.accounts` is unreadable or answers with zero accounts and no `account_ids` are configured, no account-scoped query is issued; every account-scoped inventory is recorded as `not collected` naming `actor.accounts` and the skipped query, every finding that reads one renders `manual` (never `fail` or `pass`) naming `actor.accounts`, and its counts render `null` beside that status. The same holds for domain-scoped queries when the authentication domain listing is unavailable and for the synthetic script scan when the monitor listing is unavailable: a derived inventory takes its status from the inventory it was computed from, and when its own query was not needed (a monitor listing with no scripted monitor) the status names the listing it rests on. A `complete`, `truncated`, or `partial` status only ever names queries that were issued; the test suite records every request the fixture client receives (one record per assessor, so a status may only name a query the assessor that rendered it issued itself) and checks every evidence, summary, and `core_data` status against that record, and checks that no `0`, `[]`, `{}`, or `false` stands beside an `unreadable`, `not collected`, `unknown`, or `partial` status. The same standard applies to a comparison whose basis turned out empty: control 10's `unapproved_email_destinations` carries the approved-domain inventory (`actor.user`, unless `approved_email_domains` was passed) in its status and renders `null` beside an `unknown` status when there is no approved domain to compare against, and control 8's `cross_environment_users` renders `null` beside an `unknown` status naming the classification gap (how many accounts matched the production and non-production patterns) when the accounts cannot be placed on both sides of the production boundary, rather than an empty list beside `complete`.
13. Error text hygiene: an upstream error body is never copied into an error message. A failed NerdGraph or REST exchange becomes an error at one point per protocol (the client's failure constructors), which records the status and the endpoint or query path and then either the documented error fields (NerdGraph `errors[].message`, `errors[].extensions.errorClass`, and `path`; REST v2 `error.title`) or, for a non-JSON or undocumented body, only its content type and byte length, for example `NerdGraph request failed (502 Bad Gateway) at POST /graphql: non-JSON error body (text/html; 412 bytes)`. Every message passes through `scrubErrorText`, which removes the configured credential by exact match, `NRAK-`, `NRII-`, `NRJS-`, and `NRBR-` key shapes, 40 character hex keys, `Authorization`, `Bearer`, and `Basic` values, `Cookie` and `Set-Cookie` values, credential name-value pairs quoted or not (api key, license key, session, access, refresh, and id tokens, client secret, password), the userinfo, query, and fragment of any embedded URL, and long token-like runs (16 or more characters with a digit or mixed case; schema identifiers, enum codes, finding ids, digit runs, and entity guids are kept). The same scrub runs in the error-to-string helper every collector and tool handler uses, so causes in statuses, summaries, coverage notes, errors arrays, and `_errors.log` are scrubbed before the 200 character summary compaction, and it runs once more, without the long-token rule (account ids, entity guids, and policy ids are evidence), over every bundle file as a second layer. The regression tests cover each shape on the function itself, and a table-driven walk derived from `NEWRELIC_CLIENT_SURFACE_METHODS` routes every client method through a real client that answers with a 502 `text/html` page carrying bearer, session, and license key canaries, a GraphQL `errors[]` message embedding a tokenised URL, and a free-text message with a long token, asserting that no canary reaches any thrown error, finding, summary, coverage note, errors array, bundle file, or zip entry and that every failure is disclosed with its status, path, and content type plus length or documented fields.

#### Bundle secret hygiene

`core_data/` never holds an API key string (the `key` field is not selected and would be dropped if returned), a user credential, a live URL or its token (`url` and `uuid` are not selected), or a notification destination property value other than the email address list. Records this inspector builds itself (script scan results, log scan counts, host counts) contain only derived counts and flags; scripted monitor source text is scanned in memory and never written. Two kinds of evidence are stored verbatim because their text is the evidence: drop-rule and pipeline-rule NRQL (`nrql`), and obfuscation rule filters and obfuscation expression regexes (`filter`, `regex`). Both may quote literals from your own configuration, such as attribute names or the patterns you obfuscate, so review them before sharing a bundle outside the audit team. The module exports the projection shapes as `NEWRELIC_STORED_RECORD_SHAPES`, and the test suite holds every NerdGraph-backed shape to the identifiers its selection requests.

| # | Spec control | Tool | Finding id | Status semantics |
|---|--------------|------|------------|------------------|
| 1 | SSO/SAML Enforcement | `newrelic_assess_identity` | `NR-01-SSO-ENFORCEMENT` | `fail` if any authentication domain uses password login. `manual` when domains are unreadable, zero domains are returned, `customerAdministration` does not expose `authenticationType` (single-tenant organizations, scoped out), or a domain exposes no recognizable type. `pass` only when every listed domain exposes a SAML or OIDC `authenticationType`. |
| 2 | User Type Least Privilege | `newrelic_assess_identity` | `NR-02-USER-TYPE-LEAST-PRIVILEGE` | `manual` when users are unreadable or zero users are returned. `fail` if full platform users are inactive past `inactive_days`. `warn` if the full platform share exceeds `max_full_platform_percent`, or if any full platform user has no `lastActive` or any user exposes no type. `pass` otherwise. |
| 3 | Admin User Minimization | `newrelic_assess_identity` | `NR-03-ADMIN-MINIMIZATION` | `manual` when groups or users are unreadable or empty, or when no group exposes role grants or no user exposes group membership. `fail` if admin group members exceed `max_admins`. `warn` if no group matches `admin_role_pattern` or some role or membership data is missing. `pass` otherwise. |
| 4 | API Key Inventory | `newrelic_assess_access_control` | `NR-04-API-KEY-INVENTORY` | `manual` when keys, users, or group grants are unreadable, zero keys are returned (every account has its original license key), or no user key exposes `userId` (the documented-only `keySearch` layer). `warn` if keys are unnamed, expose no type, belong to admin group members, or admin detection is incomplete, including a group grant listing (`authorizationManagement.groups`) that is readable for some authentication domains only: an admin roster built from part of the domains never concludes that no admin-owned keys exist, and `admin_owned_user_keys` renders as `null`. `pass` otherwise. The `NrAuditEvent` key-actor rows are not part of this finding; control 6 renders them with their own status. |
| 5 | API Key Age | `newrelic_assess_access_control` | `NR-05-API-KEY-AGE` | `manual` when keys are unreadable, zero keys are returned, no key exposes `createdAt`, or no user or license keys exist to age-check. `fail` if user keys exceed `max_key_age_days`. `warn` if license keys exceed it or any key has no `createdAt`. `pass` otherwise. |
| 6 | Unused API Keys | `newrelic_assess_access_control` | `NR-06-UNUSED-API-KEYS` | `warn` for user keys owned by missing, inactive, or undated users. `manual` when keys are unreadable, zero keys are returned (a complete listing cannot be empty, so the key cannot see them), no user key exposes `userId`, or keys exist without owner signals, because `NrAuditEvent` records configuration changes only. Never `pass`. |
| 7 | Account Access Controls | `newrelic_assess_access_control` | `NR-07-ACCOUNT-ACCESS-CONTROLS` | `manual` when groups, users, or accounts are unreadable, empty, or expose no role or membership data. `warn` if non-admin users hold organization-scoped grants, exceed `max_accounts_per_user`, or some role or membership data is missing. `pass` otherwise. |
| 8 | Cross-Account Access Restrictions | `newrelic_assess_access_control` | `NR-08-CROSS-ACCOUNT-RESTRICTIONS` | `manual` when groups, users, or accounts are unreadable or empty, when only one account is visible (not applicable), or when account names match neither pattern; `cross_environment_users` then renders as `null` beside an `unknown` status naming the classification gap, never as an empty list beside `complete`. `warn` if non-admin users reach both production and non-production accounts or some accounts are unclassified. `pass` only when every account is classified and no overlap exists. |
| 9 | Alert Policy Coverage | `newrelic_assess_alerting` | `NR-09-ALERT-POLICY-COVERAGE` | `manual` when policies, conditions, or entities are unreadable, or when zero reporting entities are visible. `fail` with no policies while entities report, no condition with `enabled = true`, or reporting APM, host, or synthetic entities with `alertSeverity = NOT_CONFIGURED`. `warn` for other uncovered entities, policies without enabled conditions, or conditions missing the `enabled` flag. `pass` otherwise, limited to `warn` when the workload listing (`entitySearch` workloads) is unreadable for any account; `workloads` and `disrupted_workloads` then render as `null` beside `workloads_status`. |
| 10 | Alert Notification Channels | `newrelic_assess_alerting` | `NR-10-ALERT-NOTIFICATION-CHANNELS` | `manual` when destinations, channels, or workflows are unreadable (including a documented per-account `error { details }`), when nothing exists and policies are absent or unreadable, when no workflow exposes `workflowEnabled`, or when no enabled workflow routes through a channel `destinationId` to an inventoried destination. `fail` for personal email destinations or zero destinations while policies exist. `warn` for unapproved domains, no workflow with `workflowEnabled = true`, destinations missing `type`, or no approved domain list. `pass` otherwise, limited to `warn` when alert policies (`alerts.policiesSearch`) are unreadable for any account, since the pass path compares routing against the policy inventory; the summary notes that destination active state is not read because the public schema does not document it. `unapproved_email_destinations` rests on the destination listing and on the approved-domain inventory (`actor.user`, unless `approved_email_domains` was passed), so its status names both, and it renders as `null` when `actor.user` is unreadable or yields no email domain rather than as an empty list. |
| 11 | Data Retention Settings | `newrelic_assess_data_governance` | `NR-11-DATA-RETENTION` | `manual` when rules are unreadable or no custom rules exist (defaults are not exposed by the API). `fail` if active rules retain less than `min_retention_days`. `warn` if a rule exposes no `retentionInDays`, namespaces are unreadable, or a customizable namespace has no rule. `pass` only when every customizable namespace has an explicit rule at or above the threshold. |
| 12 | Log Obfuscation Rules | `newrelic_assess_data_governance` | `NR-12-LOG-OBFUSCATION` | `manual` when rules are unreadable or were never collected because no account resolved (`actor.accounts` unreadable or empty with no `account_ids` configured), or when no rules exist and no logs were ingested (not applicable). `fail` with no rule that has `enabled = true`. `warn` if expressions are unreadable, do not cover both credential and PII patterns, or rules lack the `enabled` flag. `pass` otherwise, limited to `warn` naming the query path when Pipeline Control cloud rules (`entityManagement.pipelineCloudRules`), NRQL drop rules (`nrqlDropRules.list`), or the `Log` volume NRQL are unreadable for any account, because attribute drop coverage or log volume is then unverified; `pipeline_cloud_rules`, `legacy_drop_rules`, `attribute_drop_rules`, and `log_events_last_day` render as `null` beside their status fields instead of a count from the readable subset. A 403 on Pipeline Control cannot be told apart from a missing entitlement, so it is reported as unverified rather than as zero rules. |
| 13 | Synthetic Monitor Security | `newrelic_assess_data_governance` | `NR-13-SYNTHETIC-MONITOR-SECURITY` | `manual` when monitors are unreadable, zero monitors or zero scripted monitors exist (not applicable), `monitorType` is missing, or scripts are unreadable or unsampled. `fail` if sampled scripts contain credential patterns. `warn` if the sample hit `script_sample_limit`, secure credentials are unreadable, or no script references `$secure.*` while no secure credentials exist. `pass` only when every scripted monitor's script was scanned. |
| 14 | Dashboard Permissions | `newrelic_assess_data_governance` | `NR-14-DASHBOARD-PERMISSIONS` | `manual` when dashboards or the live URL listing are unreadable, or zero dashboards are returned. `fail` if public live URLs exist. `warn` for `PUBLIC_READ_WRITE` dashboards or dashboards without a `permissions` value. `pass` otherwise. |
| 15 | Logs in Context Security | `newrelic_assess_data_governance` | `NR-15-LOGS-IN-CONTEXT-SECURITY` | `manual` when the pattern query or log volume query is unreadable, or when no logs were ingested in the last day. `fail` if `Log` messages match credential patterns. `pass` otherwise. Only counts are collected, never matching messages. |
| 16 | Infrastructure Agent Configuration | `newrelic_assess_data_governance` | `NR-16-INFRA-AGENT-CONFIGURATION` | Always `manual`: agent transport settings are not API visible. Evidence lists reporting hosts and agent versions. |
| 17 | Applied Intelligence Sensitivity | `newrelic_assess_alerting` | `NR-17-APPLIED-INTELLIGENCE-SENSITIVITY` | `warn` if enabled workflows attach NRQL enrichments to external or unidentified destination types, otherwise `manual` because correlation decision settings are not API visible. Never `pass`. |
| 18 | Authentication Domain Configuration | `newrelic_assess_identity` | `NR-18-AUTH-DOMAIN-CONFIGURATION` | `warn` if any domain provisions users manually instead of SCIM, otherwise `manual`: session duration and user upgrade settings are not exposed by NerdGraph, so the finding stays manual even when every domain uses SCIM. Never `pass`. |
| 19 | Inactive User Accounts | `newrelic_assess_identity` | `NR-19-INACTIVE-USER-ACCOUNTS` | `manual` when users are unreadable or zero users are returned. `fail` if users exceed `inactive_days` since `lastActive`. `warn` if any user has no `lastActive` value. `pass` otherwise. |
| 20 | Custom Role Permissions | `newrelic_assess_access_control` | `NR-20-CUSTOM-ROLE-PERMISSIONS` | `manual` when the `customerAdministration.roles` catalog is unreadable (organizations without the multi-tenancy entitlement; custom roles seen in group grants are listed), zero roles are returned, custom roles exist (NerdGraph does not expose role capabilities), or roles expose no `type` (`CUSTOM` or `STANDARD`). `warn` if the role listing was incomplete, or if group grants (`authorizationManagement.groups`, or the domain listing they depend on) are unreadable or readable for some domains only, because the roles in use were not fully cross-checked against the catalog; `custom_roles_in_group_grants` and `groups_granted_custom_roles` then render as `null`. `pass` only when the catalog listing was readable and complete and returned standard roles and the complete group grant listing confirms no custom role is in use; the summary states the conditions. |

Every `pass` above additionally requires a complete inventory: when a list was truncated, a scope was unreadable, `keySearch` fell back to a single page, or any secondary inventory the finding reads was unreadable (fully or for one account or domain), the finding is limited to `warn` and the summary carries a `Partial view:` clause naming the dataset and query path.

Coverage: 20 of 20 controls. Controls 6, 16, 17, and 18 never pass by design (control 6 because `NrAuditEvent` cannot prove read-only key usage and an empty key listing means the key cannot see the keys), and control 20 is manual whenever custom roles exist. Each `manual` summary states the UI evidence to collect.

### NerdGraph field provenance

Every field the inspector requests is traceable to one of two public sources, and the code cites the source in a comment block above each `QUERY_*` constant in `cli/extensions/grc-tools/newrelic.ts`:

- Documented: the field appears in a query or response on a docs.newrelic.com page (for example `keySearch { keys { name type ... on ApiAccessIngestKey { ingestType } } }` on the API keys tutorial, or `customerAdministration.roles { items { id name scope type } }` on the delegated administration page).
- Schema reference: the field is in the public NerdGraph schema shown by the GraphiQL explorer and mirrored by the generated types in `newrelic-client-go` (for example `ApiAccessUserKey.userId`, `ApiAccessKeySearchResult.nextCursor`, `DashboardEntityOutline.permissions`, `MultiTenantAuthorizationRoleTypeEnum` with `CUSTOM` and `STANDARD`). Schema-cited fields are only requested when a verdict needs them, and when NerdGraph rejects them the client falls back to the documented shape and the dependent controls render `manual` with the reason (controls 4, 5, and 6 when `createdAt` or `userId` is unavailable).

Fields that are neither documented nor read by any verdict are not requested, because one unknown field fails the whole document and every control that reads it. The following were removed for that reason: user `emailVerificationState` and `timeZone`; dashboard `dashboardParentGuid`, `createdAt`, `updatedAt`, and `owner { email userId }`; synthetic monitor `monitoredUrl`, `period`, and `monitorId`; the `SecureCredentialEntityOutline` fragment (`secureCredentialId`, `updatedAt`, `description`); alert policy `accountId`; the obfuscation action `expression { id }`; API key `notes`; destination `active`, `status`, `isUserAuthenticated`, `lastSent`, and `properties { displayValue }`; channel `product`, `active`, and `status`; workflow `enrichments { type }`; the `authorizationManagement.roles` catalog (replaced by `customerAdministration.roles`); and live URL `url` and `uuid`. The module exports every selection as `NEWRELIC_NERDGRAPH_SELECTIONS`, and `cli/tests/newrelic.test.mjs` holds each one to an identifier allowlist, so a new undocumented field fails the suite.

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
- Synthetic script scanning samples up to `script_sample_limit` scripted monitors and reports indicator labels, never script contents. When the sample hits the limit, control 13 is capped at `warn`.
- Default retention values for namespaces without a custom rule are not exposed by the API, so control 11 only passes when every customizable namespace has an explicit rule.
- `keySearch` obfuscates the key values of other users' user keys but still lists the keys, so key inventory findings cover every visible key; key values are never requested.

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
- [NerdGraph synthetics API: query synthetics data](https://docs.newrelic.com/docs/apis/nerdgraph/examples/synthetics-api/query-synthetics-data/) (`monitorType`, secure credential entities, `script { text }`)
- [Secure credentials for synthetic monitors](https://docs.newrelic.com/docs/synthetics/synthetic-monitoring/using-monitors/store-secure-credentials-scripted-browsers-api-tests/)
- [Manage live chart URLs via API](https://docs.newrelic.com/docs/apis/nerdgraph/examples/manage-live-chart-urls-via-api/)
- [Manage live dashboard URLs via API](https://docs.newrelic.com/docs/apis/nerdgraph/examples/manage-live-dashboard-urls-via-api/)
- [Log obfuscation](https://docs.newrelic.com/docs/logs/ui-data/obfuscation-ui/)
- [Manage data retention](https://docs.newrelic.com/docs/data-apis/manage-data/manage-data-retention/)
- [Pipeline Control cloud rules API reference](https://docs.newrelic.com/docs/new-relic-control/pipeline-control/cloud-rules/api-reference/)
- [newrelic-client-go generated NerdGraph types](https://github.com/newrelic/newrelic-client-go/tree/main/pkg) (public schema mirror used for schema-cited fields)
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
