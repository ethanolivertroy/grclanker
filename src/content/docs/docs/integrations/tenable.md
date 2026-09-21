---
title: "Tenable"
description: "Read-only Tenable Vulnerability Management and Tenable Security Center inspector covering scan programs, sensors, access control, and vulnerability management."
---

The Tenable inspector audits a Tenable Vulnerability Management tenant (cloud.tenable.com or the FedRAMP cloud fedcloud.tenable.com) and, optionally, a Tenable Security Center deployment. It is read-only: the only POST calls are the documented asset and vulnerability export requests, and no scan, user, policy, or exclusion is ever modified.

## What it inspects

- Scan program: scan templates in use, recurring schedule discipline, credentialed scan ratio, scan exclusions, compliance audit templates, and legacy target groups.
- Sensors and assets: asset discovery coverage, Nessus Agent deployment and grouping, linked scanner health, plugin currency, network objects, and asset tagging.
- Access control: user roles and role counts, MFA and SAML enforcement, API key usage, permissions and legacy access groups, managed credential hygiene, and the activity log.
- Vulnerability management: VPR prioritization coverage, severity SLA backlog and mean time to remediate, and export automation evidence, all driven by the bulk vulnerability and asset exports.
- Tenable Security Center equivalents for scan schedules, scanner health and plugin feeds, and user hygiene, when a Security Center URL is configured.

## Setup and authentication

### Tenable Vulnerability Management

1. Sign in to Tenable Vulnerability Management as a user with the Administrator [64] role. Lower roles work but produce partial views: Scan Manager keys only see their own or shared scans, and any key below Administrator receives a reduced `GET /users` payload, so the inspector caps verdicts at warn and says so in the summary.
2. Generate an API key pair from Settings > My Account > API Keys.
3. Export the keys:

```bash
export TENABLE_ACCESS_KEY="..."
export TENABLE_SECRET_KEY="..."
export TENABLE_URL="https://cloud.tenable.com"      # default; use https://fedcloud.tenable.com for FedRAMP
```

Requests carry the documented header `X-ApiKeys: accessKey={access_key};secretKey={secret_key}`. Keys are never written to disk and are redacted from error messages.

### Tenable Security Center (optional)

Security Center controls run when a Security Center URL is configured. Set `TENABLE_URL` to the Security Center host to inspect only Security Center, or set `TENABLE_SC_URL` alongside the cloud variables to inspect both.

```bash
export TENABLE_SC_URL="https://securitycenter.example.internal"
export TENABLE_SC_ACCESS_KEY="..."
export TENABLE_SC_SECRET_KEY="..."
```

Requests use the documented `x-apikey: accesskey={access_key}; secretkey={secret_key};` header against `/rest/` resources. API keys must be enabled in Security Center (System > Configuration > Security) and generated per user. Session token authentication (`POST /rest/token`) requires a write call to log in and is not implemented; use API keys.

### Configuration file

Values not supplied as tool arguments or environment variables are read from a YAML or JSON file at `TENABLE_CONFIG_FILE` or `~/.tenable/config.yaml`:

```yaml
access_key: "..."
secret_key: "..."
url: "https://cloud.tenable.com"
sc_url: "https://securitycenter.example.internal"
sc_access_key: "..."
sc_secret_key: "..."
```

Precedence is explicit tool arguments, then environment variables, then the config file.

## Tools

| Tool | Purpose |
|------|---------|
| `tenable_check_access` | Probes every read surface the assessments depend on (scans, templates, export job lists, scanners, agents, networks, exclusions, credentials, users, groups, roles, permissions, audit log, tags, target groups, and Security Center current user, scans, scanners, users), reports whether the key holds the Administrator role, and names the role each refused surface needs. |
| `tenable_assess_scan_program` | Spec controls 1, 2, 4, 13, 17, 20 plus the Security Center schedule equivalent. |
| `tenable_assess_sensor_coverage` | Spec controls 3, 5, 6, 7, 8, 9, 16 plus the Security Center scanner equivalent. |
| `tenable_assess_access_control` | Spec controls 10, 11, 12, 18 plus the Security Center user equivalent. |
| `tenable_assess_vulnerability_management` | Spec controls 14, 15, 19 using the bulk vulnerability and asset exports. |
| `tenable_export_audit_bundle` | Runs everything above and writes `core_data/` (raw API snapshots), `analysis/` (findings.json and per-category summaries), `compliance/` (executive summary, unified matrix, one report per framework), `QUICK_REFERENCE.md`, `_errors.log` when collection partially failed, and a `.zip` paired with the allocated output directory (a rerun never overwrites a prior bundle). |

Every assessment accepts the shared authentication arguments plus thresholds such as `stale_scan_days` (30), `stale_asset_days` (30), `agent_offline_days` (7), `plugin_stale_hours` (24), `inactive_user_days` (90), `max_admins` (5), `credential_threshold` (0.8), `tagged_threshold` (0.9), `audit_lookback_days` (30), `vuln_lookback_days` (90), `sla_critical_days` (15), `sla_high_days` (30), `sla_medium_days` (90), `sla_low_days` (180), `expected_asset_count`, and `max_chunks` (50).

## Control coverage

Status semantics: `pass` requires complete, readable evidence with every enabling flag confirmed; `warn` marks partial views, undated items, or minor drift; `fail` marks a verified deficiency; `manual` marks unknown, forbidden, unlicensed, or not applicable evidence and states what a human must collect.

| # | Control | Tool | Finding | Semantics |
|---|---------|------|---------|-----------|
| 1 | Scan policy configuration | scan_program | TENABLE-01 | Reads `GET /policies/{policy_id}` for every policy a scan references and judges `settings.safe_checks`, `settings.portscan_range`, and the `plugins` family map: `safe_checks=no` or every family disabled `fail`; a custom port range or more than half of the families disabled `warn`; `pass` when every referenced policy enables safe checks on the default or full port range. Zero scans or discovery-only scans `fail`; a refused details read (needs Standard [32] plus Can View), a policy exposing no settings, or scans without `policy_id` `manual`. |
| 2 | Scan schedule discipline | scan_program | TENABLE-02, TENABLE-02-SC | `pass` when every scan with `enabled=true` and non-ONETIME `rrules` launched within `stale_scan_days`; undated or never-run scans cap at `warn`; zero scans or zero enabled recurring scans `fail`. |
| 3 | Asset discovery coverage | sensor_coverage | TENABLE-03 | `manual` unless `expected_asset_count` is supplied; compares the completed asset export against it and flags stale or undated `last_seen`; zero assets `fail`. |
| 4 | Credentialed scan ratio | scan_program | TENABLE-04 | Ratio of exported assets with `last_authentication_scan_status=Success` or `has_agent=true`; below `credential_threshold` `fail`; zero assets `manual`; truncated export caps at `warn`. |
| 5 | Agent deployment status | sensor_coverage | TENABLE-05 | Reads `status`, `last_connect`, and `core_version`; offline or stale agents `fail`, undated agents cap at `warn`; zero agents `manual` (agents may be unlicensed). |
| 6 | Agent group organization | sensor_coverage | TENABLE-06 | Ungrouped agents `warn` or `fail`; zero agents `manual`. |
| 7 | Scanner health and version | sensor_coverage | TENABLE-07, TENABLE-07-SC | Linked scanners must report `status=on`, `linked=1`, and a recent `last_connect`; cloud-only tenants are `manual` (not applicable); zero scanners `manual`. |
| 8 | Plugin update currency | sensor_coverage | TENABLE-08 | Container `plugin_set` and the `loaded_plugin_set` of every scanner entry that exposes one (cloud scanners included) newer than `plugin_stale_hours`; scanner instances without a plugin set cap at `warn`; an unreadable scanner list, zero scanners, or zero entries exposing a plugin set `manual`, never `pass`. |
| 9 | Network zone configuration | sensor_coverage | TENABLE-09 | Networks with `scanner_count=0` `warn` or `fail`; zero networks `manual` (the default network always exists). |
| 10 | User role and permission audit | access_control | TENABLE-10, TENABLE-10-SC | Reads `enabled`, `permissions`, `lastlogin`, `two_factor`, `ui_saml_only`, `login_fail_count`, `locked`, and `last_apikey_access`; excessive admins, admins without MFA or SAML, or inactive enabled users `fail`; users without an `enabled` flag are not counted as enabled and cap at `warn`; zero users or zero users with `enabled=true` `manual`. |
| 11 | Access group review | access_control | TENABLE-11 | Permissions granting every user (subject type `AllUsers` or the tenant-wide `UserGroup` `00000000-0000-0000-0000-000000000000`, named All Users) write-style actions (`CanEdit`, `CanScan`, `CanUse`) on `AllAssets`, `AllObjects`, or `AllTags` `fail`, including Tenable's default All Assets permission when it still grants CanScan; remaining legacy access groups `warn`; zero permissions `manual`. |
| 12 | Managed credential hygiene | access_control | TENABLE-12 | Credential type coverage, `created_date`, and `last_used_by`; zero managed credentials `manual`. |
| 13 | Scan exclusion audit | scan_program | TENABLE-13 | Exclusions with `schedule.enabled=false`, no description, or /16 or wider members `fail` or `warn`; `pagination.total=0` passes because nothing is excluded. |
| 14 | Vulnerability prioritization (VPR) | vulnerability_management | TENABLE-14 | Share of rated open findings carrying `plugin.vpr.score`; partial exports `warn`; zero assets or zero open findings `manual`. |
| 15 | Vulnerability SLA tracking | vulnerability_management | TENABLE-15 | Open findings older than the per-severity SLA from `first_found`; MTTR from `time_taken_to_fix`; zero findings pass only when the export FINISHED completely and assets are non-zero. |
| 16 | Asset tagging strategy | sensor_coverage | TENABLE-16 | Ratio of exported assets with tags versus `tagged_threshold`; zero assets `manual`. |
| 17 | Compliance audit templates | scan_program | TENABLE-17 | Enabled recurring scans whose template title looks like a compliance audit (CIS, STIG, PCI, SCAP, Audit); none `fail`. |
| 18 | Audit log review | access_control | TENABLE-18 | Sensitive `action` values (deletes, user or permission changes, exclusion and policy edits) and `is_failure` events in the lookback window; zero events `warn`. |
| 19 | Export and reporting automation | vulnerability_management | TENABLE-19 | Export jobs from `GET /vulns/export/status` and `GET /assets/export/status` within the previous three days (the documented window for completed jobs), excluding this tool's own runs by UUID and by export shape (`num_assets_per_chunk` 5000 with the open, reopened, fixed state filter; 10000 with no filters): jobs on two distinct days `pass`, jobs on one day `warn`, none `manual`. Report schedules are not exposed by the API and remain a manual check. |
| 20 | Target group management | scan_program | TENABLE-20 | Deprecated target groups: stale or overlapping members `warn`; an empty list passes because tags replaced target groups. |

Every finding carries the FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, DISA STIG, IRAP, and ISMAP mappings from the spec table for that control. Verdicts are additionally capped at `warn` whenever the API key is not confirmed as Administrator, a paginated list returned fewer records than `pagination.total`, or an export downloaded fewer chunks than were available.

## Live smoke

```bash
npm --prefix cli run test:tenable:live
```

The script prints a skip message and exits 0 without credentials. With credentials it runs `tenable_check_access` and the scan program assessment against the configured tenant.

## Limitations and manual controls

- Control 1 reads `GET /policies/{policy_id}` (documented `settings` and `plugins` objects) for every policy referenced by a scan, capped at 100 policies per run; the details read needs the Standard [32] role plus Can View on each scan template, and a refused read renders the control `manual`. Performance settings (`max_hosts_per_scan`, `max_checks_per_host`, `thorough_tests`, `report_paranoia`) are recorded as evidence, not judged.
- Report schedules and Lumin exposure metrics have no documented read endpoint; control 19 relies on export job history, which the API returns for completed jobs only within the previous three days, so it is a point-in-time signal rather than proof of a recurring schedule.
- Tenable Security Center controls are `manual` (not applicable) until `TENABLE_SC_URL` is configured; Security Center session token authentication is not implemented.
- Agents that are not licensed render controls 5 and 6 as `manual`.
- Export chunk downloads stop at `max_chunks` (default 50) and the vulnerability export uses `num_assets=5000`; the resulting truncation downgrades verdicts to `warn` and is recorded in `_errors.log`.

## Official documentation

- [Tenable Vulnerability Management API reference](https://developer.tenable.com/reference/navigate) (scans, policies, editor templates, exclusions, scanners, agents, agent groups, networks, credentials, users, groups, access control roles and permissions, activity log, tags, target groups, export status lists)
- [Rate limiting](https://developer.tenable.com/docs/rate-limiting) and [concurrency limiting](https://developer.tenable.com/docs/concurrency-limiting)
- [Retrieve vulnerability data (export workflow)](https://developer.tenable.com/docs/retrieve-vulnerability-data-from-tenableio), [Export vulnerabilities](https://developer.tenable.com/reference/exports-vulns-request-export), [List vuln export jobs](https://developer.tenable.com/reference/exports-vulns-export-status-recent), [Export assets v1](https://developer.tenable.com/reference/export-assets-v1), and [List asset export jobs](https://developer.tenable.com/reference/exports-assets-export-status-recent)
- [List scans](https://developer.tenable.com/reference/scans-list), [List policy details](https://developer.tenable.com/reference/policies-details), [List scanners](https://developer.tenable.com/reference/scanners-list), [List permissions](https://developer.tenable.com/reference/permissions-list), and [List users](https://developer.tenable.com/reference/users-list)
- [User roles](https://developer.tenable.com/docs/roles) and [permissions](https://developer.tenable.com/docs/permissions)
- [Tenable Security Center API](https://docs.tenable.com/security-center/api/index.htm) (Scan, Scan Result, Scanner, User, Current User, and Feed resources) and [Tenable Security Center API key generation](https://docs.tenable.com/security-center/Content/GenerateAPIKey.htm)
