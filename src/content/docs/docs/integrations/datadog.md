---
title: Datadog
description: Read-only Datadog security inspector covering SAML, MFA, RBAC, keys, Audit Trail, Cloud SIEM, CSM, logs, and org settings across 20 controls.
---

The Datadog integration audits a Datadog organization's own tenant configuration: who can sign in and how, which roles and keys exist, whether the Audit Trail and Cloud SIEM are active, how logs are retained and redacted, and which organization-level sharing and network settings are in place. It never mutates the org: every request is a `GET` against the documented v1 and v2 read endpoints.

It implements the 20 controls in `specs/datadog-sec-inspector.spec.md` and maps every finding to FedRAMP, CMMC 2.0, SOC 2, CIS, PCI-DSS 4.0, DISA STIG, IRAP, and ISMAP references from the spec's compliance table.

## What it inspects

| Area | Datadog surfaces read |
|---|---|
| Identity | Organization settings (`/api/v1/org`), users (`/api/v2/users`), roles and role permissions (`/api/v2/roles`, `/api/v2/roles/{id}/permissions`), org configs (`/api/v2/org_configs`) |
| Keys and sharing | API keys (`/api/v2/api_keys`), application keys with owners (`/api/v2/application_keys?include=owned_by`), shared dashboards (`/api/v1/dashboard?filter[shared]=true`), IP allowlist (`/api/v2/ip_allowlist`), AWS, GCP, and Azure integrations (`/api/v1/integration/{aws,gcp,azure}`) |
| Security monitoring | Detection and compliance rules (`/api/v2/security_monitoring/rules`), open signals (`/api/v2/security_monitoring/signals`), posture findings (`/api/v2/posture_management/findings`), monitors (`/api/v1/monitor`) |
| Data protection | Audit Trail events (`/api/v2/audit/events`), log pipelines and indexes (`/api/v1/logs/config/pipelines`, `/api/v1/logs/config/indexes`), log archives (`/api/v2/logs/config/archives`), Sensitive Data Scanner (`/api/v2/sensitive-data-scanner/config`), org connections (`/api/v2/org_connections`) |

## Setup and authentication

Every request carries two headers, `DD-API-KEY` and `DD-APPLICATION-KEY`, as described in the [Datadog authentication reference](https://docs.datadoghq.com/api/latest/authentication/). The API key identifies the organization; the application key inherits the permissions of the user or service account that created it, so create it from a principal that holds the read permissions listed below (or scope the key to exactly those permissions).

### Credential sources and precedence

Explicit tool arguments win, then environment variables, then a dogshell-style config file.

| Setting | Argument | Environment variables | Config file |
|---|---|---|---|
| API key | `api_key` | `DD_API_KEY`, `DATADOG_API_KEY` | `apikey` under `[Connection]` |
| Application key | `app_key` | `DD_APP_KEY`, `DD_APPLICATION_KEY`, `DATADOG_APP_KEY` | `appkey` under `[Connection]` |
| Site | `site` | `DD_SITE`, `DATADOG_SITE` | none (defaults to `datadoghq.com`) |
| Base URL override | `base_url` | `DD_HOST`, `DATADOG_HOST` | `api_host` under `[Connection]` |
| Config file path | `config_file` | `DD_CONFIG_FILE`, `DATADOG_CONFIG_FILE` | defaults to `~/.dogrc` |
| Timeout (seconds) | `timeout_seconds` | `DD_TIMEOUT` | none (defaults to 30) |
| Retries | `max_retries` | `DD_MAX_RETRIES` | none (defaults to 3) |

The config file uses the same INI layout as `dogshell` from `datadogpy`:

```ini
[Connection]
apikey = ...
appkey = ...
api_host = https://api.datadoghq.eu
```

### Sites

`DD_SITE` maps to the API base URL `https://api.<site>` per the [Datadog sites guide](https://docs.datadoghq.com/getting_started/site/). Full hostnames, `https://api.<site>` URLs, and short aliases are accepted.

| Site value | Aliases | API base URL |
|---|---|---|
| `datadoghq.com` | `us`, `us1` | `https://api.datadoghq.com` |
| `datadoghq.eu` | `eu`, `eu1` | `https://api.datadoghq.eu` |
| `us3.datadoghq.com` | `us3` | `https://api.us3.datadoghq.com` |
| `us5.datadoghq.com` | `us5` | `https://api.us5.datadoghq.com` |
| `ap1.datadoghq.com` | `ap1` | `https://api.ap1.datadoghq.com` |
| `ap2.datadoghq.com` | `ap2` | `https://api.ap2.datadoghq.com` |
| `uk1.datadoghq.com` | `uk1` | `https://api.uk1.datadoghq.com` |
| `ddog-gov.com` | `gov`, `us1-fed` | `https://api.ddog-gov.com` |
| `us2.ddog-gov.com` | `us2-fed`, `us2gov` | `https://api.us2.ddog-gov.com` |

### Required application key permissions

Permission names come from the [Datadog RBAC permissions list](https://docs.datadoghq.com/account_management/rbac/permissions/) and the `x-permission` metadata in the official OpenAPI definitions. `datadog_check_access` reports which of these are missing when a surface returns 403.

| Permission | Surfaces |
|---|---|
| `org_management` | Organization settings, IP allowlist |
| `user_access_read` | Users, roles, role permissions, permissions catalog |
| `api_keys_read` | API keys |
| `org_app_keys_read` | Application keys for the whole org |
| `audit_logs_read` | Audit Trail events |
| `security_monitoring_rules_read` | Detection and compliance rules |
| `security_monitoring_signals_read` | Security signals |
| `security_monitoring_findings_read` | Posture findings |
| `data_scanner_read` | Sensitive Data Scanner configuration |
| `logs_read_config` | Log pipelines and indexes |
| `logs_read_archives` | Log archives |
| `dashboards_read` | Shared dashboards |
| `monitors_read` | Monitors |
| `aws_configuration_read`, `gcp_configuration_read`, `azure_configuration_read` | Cloud integrations |
| `org_connections_read` | Cross-org connections |

`GET /api/v1/validate`, `GET /api/v2/validate_keys`, and `GET /api/v2/org_configs` require no extra permission.

### Client behavior

- Pagination follows each endpoint's documented style: `page[size]` and `page[number]` for users, roles, API keys, application keys, and rules; `page[limit]` plus `page[cursor]` with `meta.page.after` for audit events and signals; `page[limit]` plus `page[cursor]` from `meta.page.cursor` for posture findings; `page` and `page_size` for monitors; `count` and `start` for dashboards; `limit` and `offset` (documented default 1000) for org connections. Every paginated list runs to completion up to its limit, and the collector requests one item beyond the limit so it can tell a truncated inventory from a complete one.
- `429` responses are retried after the number of seconds in `X-RateLimit-Reset` (capped at 60 seconds), and `5xx` responses are retried with exponential backoff, up to `max_retries` times, following the [rate limits reference](https://docs.datadoghq.com/api/latest/rate-limits/).
- Requests time out after `timeout_seconds`.
- API and application key values are redacted from every error message and from the exported bundle.

## Tools

All tools accept the credential arguments above (`api_key`, `app_key`, `site`, `base_url`, `config_file`, `timeout_seconds`, `max_retries`).

### `datadog_check_access`

Validates the API key with `GET /api/v1/validate`, validates the API key and application key pair with `GET /api/v2/validate_keys`, then probes all 20 read surfaces (including `org_connections`) with a minimal request each. Returns `healthy` only when the key pair validates and every data surface is readable, `limited` when the pair does not validate or any surface returns 401, 403, or an error, and `failed` when the API key is invalid or nothing beyond validation is readable. Lists the missing permissions by name; 401 responses are treated like 403.

### `datadog_assess_identity`

Controls 1, 2, 3, 4, 16, and 19. Extra arguments: `user_limit`, `role_limit`, `max_admins`, `inactive_days`, `pending_invite_days`, `key_rotation_days`, `service_account_pattern`.

### `datadog_assess_access_controls`

Controls 5, 6, 14, 15, and 18. Extra arguments: `key_limit`, `key_rotation_days`, `key_unused_days`.

### `datadog_assess_security_monitoring`

Controls 8, 9, 12, 13, and 17. Extra arguments: `rule_limit`, `signal_limit`, `signal_sla_hours`, `signal_lookback_days`, `monitor_limit`, `finding_limit`, `min_posture_pass_rate`, `required_frameworks`.

### `datadog_assess_data_protection`

Controls 7, 10, 11, and 20. Extra arguments: `min_audit_retention_days`, `min_log_retention_days`.

### `datadog_export_audit_bundle`

Runs the access check plus all four assessments and writes an evidence bundle under `output_dir` (default `./export/datadog`). Accepts every assessment argument listed above. The bundle directory is named `<site>-audit-bundle` (suffixed with `-2`, `-3`, and so on if it already exists) and contains:

```text
README.md
QUICK_REFERENCE.md
metadata.json
_errors.log                      (only when a collection surface failed)
core_data/                       (raw API snapshots: access, organization, users, roles, org_configs,
                                  api_keys, application_keys, shared_dashboards, ip_allowlist,
                                  cloud_integrations, security_rules, security_signals, posture_findings,
                                  monitors, audit_events, log_pipelines, log_indexes, log_archives,
                                  sensitive_data_scanner, org_connections)
analysis/findings.json           (all 20 normalized findings)
analysis/<category>.json         (identity, access-controls, security-monitoring, data-protection)
analysis/summary.json
compliance/executive_summary.md
compliance/unified_compliance_matrix.md
compliance/frameworks/{fedramp,cmmc,soc2,cis,pci-dss,disa-stig,irap,ismap}.md
```

A zip archive named after the allocated directory (`<site>-audit-bundle.zip`, `<site>-audit-bundle-2.zip`, and so on) is written next to it, so a rerun never overwrites a prior bundle or its zip. Output paths are resolved with traversal and symlink-parent protection, so `output_dir` values that escape the output root are rejected.

## Findings

Every finding has the shape `{ id, title, severity, status, summary, evidence, mappings[] }`.

- `id` is `DD-NN` where `NN` is the spec control number.
- `severity` is `critical`, `high`, `medium`, `low`, or `info` and is fixed per control.
- `status` is `pass`, `warn`, `fail`, or `manual`. A finding is `manual` when the control cannot be verified through the API, either because Datadog does not expose the setting or because the surface returned 401, 403, or an error; its summary states exactly what evidence a human must collect.
- `mappings` lists the framework references from the spec's compliance table for that control, for example `FedRAMP IA-2(1)` or `PCI-DSS 8.4.1`.

### Verdict safety rules

Every finding follows the same rules so that a `pass` always rests on data that was actually read:

1. An unreadable, forbidden (401 or 403), or errored endpoint never yields `pass`; it yields `manual` with the cause and the evidence to collect. Controls that read several surfaces (7, 10, 12, 14, 20) go `manual` when any one of them is unreadable.
2. An empty inventory never yields `pass` by default. Each control decides whether emptiness is `fail` or `manual` and says so in the summary: empty audit events (7), rules (8), scanning groups (11), and compliance rules (13) are `fail` with a note on recording the control as not applicable when the product is not licensed; empty users, roles, API keys, application keys, indexes, monitors, and cloud footprints (2, 3, 4, 5, 6, 10, 12, 17, 19) are `manual` because the list cannot be complete (the key in use must exist) or there is nothing to evaluate.
3. Controls the API cannot observe (16, 18) render as `manual`, never `pass`.
4. Items missing a date (users without `last_login_time` or `created_at`, keys without `created_at` or `last_used_at`, signals or audit events without `timestamp`) are never counted as fresh, recent, or active; they are reported in their own evidence bucket and cap the verdict at `warn`.
5. A partial inventory (permission-limited role permissions, application keys without an owner record, scanning groups referenced but not returned) flags the partial view and never passes.
6. Every flag the verdict depends on is read explicitly; a missing `saml`, `saml_strict_mode`, `private_widget_share`, `enabled`, or `is_enabled` value yields `manual`, not `pass`.
7. Pagination runs to completion or records truncation: when an inventory hits its `*_limit`, the finding carries `<surface>_inventory_truncated: true`, the assessment records the truncation in `errors`, and a would-be `pass` is downgraded to `warn`.
8. Export reruns never overwrite a prior bundle or zip.

When a `pass` is downgraded under these rules, the summary ends with `Downgraded to warn: ...` and the evidence carries `verdict_caveats`.

## Control coverage

| # | Control | Tool | Finding | Status semantics |
|---|---|---|---|---|
| 1 | SAML SSO Enforcement | `datadog_assess_identity` | `DD-01` | `fail` when SAML is disabled; `warn` when SAML is on but strict mode is off; `pass` when strict mode is enforced. `manual` if `/api/v1/org` is unreadable or the response omits `saml` or `saml_strict_mode`. |
| 2 | MFA Status | `datadog_assess_identity` | `DD-02` | `pass` only when `mfa_enabled` was read as `true` for every active human user; `fail` when password-capable users lack MFA; `manual` when SAML strict mode is on but users lack native MFA (the API cannot observe IdP MFA, so the IdP authentication policy must be captured), when `mfa_enabled` is absent, or when the user list is empty; `warn` when no active human users remain or the list is truncated. |
| 3 | RBAC Configuration (Custom Roles) | `datadog_assess_identity` | `DD-03` | `fail` when a custom role grants `org_management`, `user_access_manage`, `api_keys_write`, `org_app_keys_write`, or `service_account_write`; `manual` when any custom role's permissions could not be read (count in the summary) or the role list is empty; `warn` when Datadog Admin Role membership exceeds `max_admins`, its `user_count` is missing, or the role list is truncated; otherwise `pass`. |
| 4 | User Access Review | `datadog_assess_identity` | `DD-04` | `fail` when active users have not signed in within `inactive_days`; `warn` when invitations are pending longer than `pending_invite_days`, users have neither `last_login_time` nor `created_at`, or the list is truncated; `manual` when the user list is empty; otherwise `pass`. |
| 5 | API Key Rotation | `datadog_assess_access_controls` | `DD-05` | `fail` when keys are older than `key_rotation_days`; `warn` when keys are unused beyond `key_unused_days`, carry placeholder names, lack `created_at`, or the list is truncated; `manual` when the key list is empty; otherwise `pass`. |
| 6 | Application Key Audit | `datadog_assess_access_controls` | `DD-06` | `fail` when keys belong to disabled users; `warn` when keys are unscoped, idle beyond `key_unused_days`, have no owner record in the response, have no date, or the list is truncated; `manual` when the key list is empty; otherwise `pass`. |
| 7 | Audit Log Enabled and Retained | `datadog_assess_data_protection` | `DD-07` | `manual` when either audit query is unreadable; `fail` when no audit events exist; `pass` when the oldest event within the window is at least `min_audit_retention_days - 7` days old and events exist in the last 7 days; `warn` when the oldest event has no timestamp, no recent events exist, or retention could not be confirmed. |
| 8 | Security Detection Rules Enabled | `datadog_assess_security_monitoring` | `DD-08` | `fail` when the rule list is empty, no detection rules are enabled, or a critical category (authentication, privilege escalation, data exfiltration) has none; `warn` when default rules are disabled or the list is truncated; otherwise `pass`. |
| 9 | Security Signals Review | `datadog_assess_security_monitoring` | `DD-09` | `fail` when unresolved high or critical signals exceed `signal_sla_hours`; `warn` when such signals are open within SLA, lack timestamps, or the list is truncated; `manual` when the signal list is empty but the rule inventory is unreadable or has no enabled detection rules; `pass` only when none are open in `signal_lookback_days` and enabled detection rules exist. |
| 10 | Log Pipeline Security | `datadog_assess_data_protection` | `DD-10` | `fail` when an enabled index exclusion filter drops security sources; `manual` when pipelines, indexes, or archives are unreadable or the index list is empty; `warn` when no archive exists or an archive is failing; otherwise `pass`. Field redaction is assessed under control 11. |
| 11 | Sensitive Data Scanner | `datadog_assess_data_protection` | `DD-11` | `fail` when no scanning group or no PII/PCI rule is enabled; `manual` when no group can be confirmed enabled because groups are referenced but not returned or lack `is_enabled`; `warn` when enabled groups do not cover logs, APM, RUM, and events or the group inventory is partial; otherwise `pass`. |
| 12 | Cloud Security Posture Management | `datadog_assess_security_monitoring` | `DD-12` | `manual` when rules, cloud integrations, or either posture findings query is unreadable, or when no cloud integration and no `cloud_configuration` rule exists; `fail` when integrations exist but none has CSPM resource collection and no compliance rule is enabled; `warn` when the posture counts are truncated (no `total_filtered_count` and the paged data hit `finding_limit`), no findings were returned, or the passing rate is below `min_posture_pass_rate`; otherwise `pass`. |
| 13 | Compliance Rule Coverage | `datadog_assess_security_monitoring` | `DD-13` | `fail` when no enabled compliance rules exist or a framework in `required_frameworks` has no rule tagged for it; `warn` when the rule list is truncated; otherwise `pass`. |
| 14 | Public Dashboard Restrictions | `datadog_assess_access_controls` | `DD-14` | `fail` when `private_widget_share` is enabled; `manual` when org settings or the dashboard list are unreadable or the response omits `private_widget_share`; `warn` when dashboards are shared by public link (the list endpoint does not expose the share type) or the list is truncated; `pass` only when the shared list was read and is empty and `private_widget_share` was read as `false`. |
| 15 | IP Allowlisting | `datadog_assess_access_controls` | `DD-15` | `fail` when the allowlist is disabled or contains /8 or wider entries; `manual` when the response omits `enabled`; `warn` for entries wider than /16 or when the allowlist is enabled but no entries were returned; otherwise `pass`. |
| 16 | Session Timeout | `datadog_assess_identity` | `DD-16` | Always `manual`: the public API does not expose the session duration. Evidence lists the readable `org_configs` names. |
| 17 | Monitor Notification Channels | `datadog_assess_security_monitoring` | `DD-17` | `fail` when security monitors have no notification handles; `manual` when the monitor list is empty; `warn` when they notify individual email addresses only, when no monitor is identifiable as a security monitor, or the list is truncated; otherwise `pass`. |
| 18 | Integration Permissions | `datadog_assess_access_controls` | `DD-18` | Always `manual` with API-visible evidence: AWS, GCP, and Azure integrations are inventoried and AWS accounts using static access keys instead of role delegation are listed, but cloud-side IAM policies and webhook URLs are not exposed. |
| 19 | Service Account Audit | `datadog_assess_identity` | `DD-19` | `fail` when service accounts show login history or their application keys exceed `key_rotation_days`; `manual` when the user list is empty or no service accounts exist (not applicable rather than compliant); `warn` when names do not match `service_account_pattern`, keys are unreadable or lack `created_at`, or the user or key list is truncated; otherwise `pass`. |
| 20 | Organization Settings (Retention and Sharing) | `datadog_assess_data_protection` | `DD-20` | `fail` when widget sharing outside the org is enabled; `manual` when org settings, log indexes, or org connections are unreadable, `private_widget_share` is absent, or the index list is empty; `warn` when indexes retain less than `min_log_retention_days` or lack `num_retention_days`, cross-org connections exist, or SAML auto-creation has no domain restriction; `pass` only when every input was read and the org connections list is empty. |

Every control becomes `manual` when any surface it depends on is unreadable, and the finding summary names the console page and setting to capture.

## Framework mappings

Each finding carries the references below (from the spec's compliance mapping table), and the bundle writes one report per framework under `compliance/frameworks/`.

| Framework | Report file | Example references |
|---|---|---|
| FedRAMP (NIST 800-53) | `fedramp.md` | AC-2, IA-2(1), AU-11, SI-4, SC-7 |
| CMMC 2.0 | `cmmc.md` | AC.L2-3.1.1, IA.L2-3.5.3, AU.L2-3.3.1 |
| SOC 2 | `soc2.md` | CC6.1, CC6.6, CC7.2, CC7.3 |
| CIS | `cis.md` | 5.1, 5.2, 6.1, 4.2 |
| PCI-DSS 4.0 | `pci-dss.md` | 8.3.1, 8.4.1, 10.1, 1.3.1 |
| DISA STIG | `disa-stig.md` | SRG-APP-000023, SRG-APP-000149, SRG-APP-000092 |
| IRAP (ISM) | `irap.md` | ISM-1546, ISM-1401, ISM-0580 |
| ISMAP | `ismap.md` | CPS-9.1, CPS-9.2, CPS-11.1 |

## Live smoke test

```bash
export DD_API_KEY="..."
export DD_APP_KEY="..."
export DD_SITE="datadoghq.com"   # or datadoghq.eu, us3, us5, ap1, ddog-gov.com
npm --prefix cli run test:datadog:live
```

The script prints a skip message and exits 0 when `DD_API_KEY` or `DD_APP_KEY` is missing. Otherwise it runs `datadog_check_access` and the identity assessment against the real organization and prints each surface and finding.

## Limitations and manual controls

- Session timeout (control 16) and integration permissions (control 18) always produce `manual` findings because Datadog does not expose the session duration, cloud-side IAM policies, or webhook URLs through the public API.
- Audit Trail retention (control 7) is inferred from the oldest event returned within the `min_audit_retention_days` window; the retention setting itself is not exposed by the API.
- The dashboards list endpoint reports whether a dashboard is shared but not whether the share is public or invite-only, so shared dashboards produce `warn` rather than `fail`.
- Security signal review (control 9) queries `status:(critical OR high) -@workflow.triage.state:archived` over the lookback window; signals resolved in the UI but not archived still count as open.
- Compliance framework coverage (control 13) relies on `framework:`, `compliance_framework:`, or `requirement_framework:` tags on enabled `cloud_configuration` and `infrastructure_configuration` rules.
- MFA status (control 2) can only observe Datadog-native MFA (`mfa_enabled`). SAML strict mode disables password login but does not tell the API whether the identity provider enforces a second factor, so a strict-mode org whose users lack native MFA is `manual` and the IdP authentication policy (for example an Okta authentication policy or Entra ID conditional access policy requiring MFA for the Datadog app) must be captured.
- `GET /api/v2/posture_management/findings` is marked as a legacy endpoint in the OpenAPI definition. It remains the documented list endpoint with `filter[evaluation]`, so the inspector uses it for the CSPM passing rate. It reads `meta.page.total_filtered_count` when present and otherwise pages by `page[cursor]` up to `finding_limit`; if that limit is hit the count is marked truncated and the verdict is `warn`.
- `GET /api/v1/integration/aws` and `GET /api/v1/integration/gcp` are marked deprecated in the OpenAPI definitions (the v2 replacements are `/api/v2/integration/aws/accounts` and `/api/v2/integration/gcp/accounts`). The inspector still reads the v1 endpoints because they remain documented and return the CSPM resource collection flags; switching to v2 is tracked in the spec.
- User, role, key, rule, signal, monitor, dashboard, org connection, and posture finding collection stop at their `*_limit` arguments. When a limit is hit the finding says so, the assessment records it in `errors`, and a would-be `pass` becomes `warn`; raise the limit for very large organizations.

## Official documentation

- [Datadog API reference](https://docs.datadoghq.com/api/latest/)
- [Authentication](https://docs.datadoghq.com/api/latest/authentication/) and [API and application keys](https://docs.datadoghq.com/account_management/api-app-keys/)
- [Rate limits](https://docs.datadoghq.com/api/latest/rate-limits/)
- [Datadog sites](https://docs.datadoghq.com/getting_started/site/)
- [RBAC permissions](https://docs.datadoghq.com/account_management/rbac/permissions/)
- [Organizations](https://docs.datadoghq.com/api/latest/organizations/) and [SAML strict mode](https://docs.datadoghq.com/account_management/saml/)
- [Users](https://docs.datadoghq.com/api/latest/users/) and [Roles](https://docs.datadoghq.com/api/latest/roles/)
- [Key Management](https://docs.datadoghq.com/api/latest/key-management/)
- [Audit](https://docs.datadoghq.com/api/latest/audit/) and [Audit Trail](https://docs.datadoghq.com/account_management/audit_trail/)
- [Security Monitoring](https://docs.datadoghq.com/api/latest/security-monitoring/)
- [IP Allowlist](https://docs.datadoghq.com/api/latest/ip-allowlist/) and [IP allowlist settings](https://docs.datadoghq.com/account_management/org_settings/ip_allowlist/)
- [Sensitive Data Scanner](https://docs.datadoghq.com/api/latest/sensitive-data-scanner/)
- [Logs Pipelines](https://docs.datadoghq.com/api/latest/logs-pipelines/), [Logs Indexes](https://docs.datadoghq.com/api/latest/logs-indexes/), and [Logs Archives](https://docs.datadoghq.com/api/latest/logs-archives/)
- [Dashboards](https://docs.datadoghq.com/api/latest/dashboards/) and [Monitors](https://docs.datadoghq.com/api/latest/monitors/)
- [AWS](https://docs.datadoghq.com/api/latest/aws-integration/), [GCP](https://docs.datadoghq.com/api/latest/gcp-integration/), and [Azure](https://docs.datadoghq.com/api/latest/azure-integration/) integrations
- [Org Connections](https://docs.datadoghq.com/api/latest/org-connections/)
- [Official OpenAPI definitions](https://github.com/DataDog/datadog-api-client-typescript/tree/master/.generator/schemas) (v1 and v2) and the [dogshell `.dogrc` loader](https://github.com/DataDog/datadogpy/blob/master/datadog/dogshell/common.py)
