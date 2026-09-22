---
title: Qualys
description: Read-only Qualys scanning program inspector covering scan coverage, asset inventory, vulnerability management, and administration hygiene with framework-mapped findings and an exportable audit bundle.
---

The Qualys integration audits the health of a Qualys subscription itself: whether scans are scheduled and authenticated, whether the asset inventory is complete and tagged, whether vulnerabilities are remediated inside SLA, and whether users, reports, and activity logs are managed. It never launches scans, edits configuration, or modifies the subscription.

Spec: `specs/qualys-sec-inspector.spec.md` (20 numbered security controls).

## What it inspects

| Area | Qualys surfaces | Protocol |
|------|-----------------|----------|
| Scan coverage | Scan schedules, scan history, option profiles, excluded hosts, asset groups | VM/PC API v2 (XML) |
| Asset inventory | Asset groups, host assets, scanner appliances, Asset Management connectors, Cloud Agent host assets, tags | VM/PC API v2 (XML) and QPS 2.0 (JSON) |
| Vulnerability management | Authentication records, Policy Compliance policies, VMDR host detections, KnowledgeBase patch data | VM/PC API v2 (XML) |
| Administration | Scheduled reports, report history, users, activity log, WAS web apps, WAS scans, WAS auth records, WAS schedules | VM/PC API v2 (XML and CSV), Administration API (QPS 2.0), WAS API (QPS 3.0) |

## Setup and authentication

### Required Qualys account

- A dedicated API user with the **Manager** or **Unit Manager** role and the **API access** permission enabled.
- Subscriptions for the modules you want assessed: VM/VMDR is required; PC, WAS, Cloud Agent, and Asset Management (CSAM or GAV) are optional. Controls that depend on an unsubscribed module are reported with status `manual`.
- Every request carries the mandatory `X-Requested-With` header that the Qualys API requires from non-browser clients.

### Credentials and platform

Configuration precedence is explicit tool arguments, then environment variables, then the config file.

| Setting | Environment variable | Config file key | Notes |
|---------|---------------------|-----------------|-------|
| Username | `QUALYS_USERNAME` (or `QUALYS_USER`) | `username` | Required for basic and OAuth modes |
| Password | `QUALYS_PASSWORD` | `password` | Required for basic and OAuth modes |
| Pre-issued bearer token | `QUALYS_TOKEN` (or `QUALYS_ACCESS_TOKEN`) | `token` | Bearer mode, skips username and password |
| OAuth mode | `QUALYS_USE_OAUTH=true` | `use_oauth` | Requests a JWT from the platform gateway `/auth` endpoint with `username`, `password`, and `token=true`, then sends `Authorization: Bearer` |
| Platform | `QUALYS_PLATFORM` (or `QUALYS_API_SERVER`) | `platform` or `hostname` | Platform ID, API server hostname, or https URL. Defaults to `US1` |
| Base URL override | `QUALYS_BASE_URL` (or `QUALYS_API_URL`) | `base_url` | Bypasses the platform mapping |
| Gateway URL override | `QUALYS_GATEWAY_URL` | `gateway_url` | Only used for OAuth token requests |
| Config file path | `QUALYS_CONFIG_FILE` | n/a | Defaults to `~/.qcrc`, key=value or INI style |
| Timeout | `QUALYS_TIMEOUT` (seconds) | `timeout` | Defaults to 60 |
| Retries | `QUALYS_MAX_RETRIES` | n/a | Defaults to 3 |
| Lookback window | `QUALYS_LOOKBACK_DAYS` | n/a | Defaults to 30 |

Example:

```bash
export QUALYS_USERNAME=api_user
export QUALYS_PASSWORD=...
export QUALYS_PLATFORM=US2
```

### Platform URLs

The platform ID maps to the API server and API gateway published on the Qualys platform identification page.

| Platform ID | API server | API gateway (OAuth) |
|-------------|------------|---------------------|
| `US1` | `https://qualysapi.qualys.com` | `https://gateway.qg1.apps.qualys.com` |
| `US2` | `https://qualysapi.qg2.apps.qualys.com` | `https://gateway.qg2.apps.qualys.com` |
| `US3` | `https://qualysapi.qg3.apps.qualys.com` | `https://gateway.qg3.apps.qualys.com` |
| `US4` | `https://qualysapi.qg4.apps.qualys.com` | `https://gateway.qg4.apps.qualys.com` |
| `GOV1` | `https://qualysapi.gov1.qualys.us` | `https://gateway.gov1.qualys.us` |
| `EU1` | `https://qualysapi.qualys.eu` | `https://gateway.qg1.apps.qualys.eu` |
| `EU2` | `https://qualysapi.qg2.apps.qualys.eu` | `https://gateway.qg2.apps.qualys.eu` |
| `EU3` | `https://qualysapi.qg3.apps.qualys.it` | `https://gateway.qg3.apps.qualys.it` |
| `IN1` | `https://qualysapi.qg1.apps.qualys.in` | `https://gateway.qg1.apps.qualys.in` |
| `CA1` | `https://qualysapi.qg1.apps.qualys.ca` | `https://gateway.qg1.apps.qualys.ca` |
| `AE1` | `https://qualysapi.qg1.apps.qualys.ae` | `https://gateway.qg1.apps.qualys.ae` |
| `UK1` | `https://qualysapi.qg1.apps.qualys.co.uk` | `https://gateway.qg1.apps.qualys.co.uk` |
| `AU1` | `https://qualysapi.qg1.apps.qualys.com.au` | `https://gateway.qg1.apps.qualys.com.au` |
| `KSA1` | `https://qualysapi.qg1.apps.qualysksa.com` | `https://gateway.qg1.apps.qualysksa.com` |

A hostname such as `qualysapi.qg2.apps.qualys.com` is accepted in place of the ID. Unknown hostnames are used as-is with platform `custom`.

### Rate limits and retries

The client records `X-RateLimit-Limit`, `X-RateLimit-Window-Sec`, `X-RateLimit-Remaining`, `X-RateLimit-ToWait-Sec`, `X-Concurrency-Limit-Limit`, and `X-Concurrency-Limit-Running` from every response. On HTTP 409 or 429 it waits for `X-RateLimit-ToWait-Sec` (capped at 30 seconds, exponential backoff when the header is absent) and retries up to `QUALYS_MAX_RETRIES` times.

### Error messages and secrets

A failed request is reported with its HTTP status and endpoint path, never with the response body. A documented error envelope contributes only its documented fields: `SIMPLE_RETURN` `CODE` and `TEXT`, the `/msp/` `ERROR` number and text, or a QPS `responseCode` and `responseErrorDetails.errorMessage`. The code itself is a pattern-validated field: a `CODE`, `ERROR` number, or `RETURN` number renders only when it is a documented small integer (`^\d{1,6}$`, for example `1905` or `999`), a `responseCode` only when it is a documented uppercase constant (for example `INVALID_REQUEST` or `UNAUTHORIZED`), and anything else renders as the fixed `UnknownError`. Any other body (an HTML gateway page, CSV, unexpected JSON) is described by content type and byte length only, for example `non-XML error body (text/html; 236 bytes)`. Every error string passes through one scrub before it exists: the configured password, token, and basic auth string are removed, and so are embedded URL queries and fragments, `Bearer` and `Basic` values, `Cookie` and `Set-Cookie` values, credential name-value pairs (api key, session, access, refresh, and id tokens, client secret, password), and any 16-character or longer run with a digit or mixed case that a Qualys server echoes in free text. Every bundle file is scrubbed again on write with the same rules minus the long-token rule, so QIDs, asset ids, and tag ids survive as evidence.

## Tools

All tools accept the same connection arguments (`username`, `password`, `token`, `platform`, `base_url`, `gateway_url`, `use_oauth`, `config_file`, `timeout_seconds`, `lookback_days`). Assessment tools add `host_limit`, `detection_limit`, `min_auth_scan_percent`, `min_agent_coverage_percent`, `max_managers`, `sla_critical_days`, `sla_high_days`, and `sla_medium_days`.

### `qualys_check_access`

Probes 15 read surfaces across VM, VMDR, PC, Administration, Asset Management, Cloud Agent, and WAS and reports each as `readable`, `not_readable`, or `module_unavailable`. Overall status is `healthy` (everything readable), `degraded` (core VM/VMDR readable, some optional modules missing), or `limited` (core VM/VMDR surfaces not readable). The response lists unavailable modules, the API user's view scope, and the last observed rate limit headers.

| Surface | Module | Endpoint |
|---------|--------|----------|
| `scheduled_scans` | VM | `GET /api/2.0/fo/schedule/scan/?action=list` |
| `hosts` | VM | `GET /api/2.0/fo/asset/host/?action=list&details=All&show_tags=1` |
| `asset_groups` | VM | `GET /api/2.0/fo/asset/group/?action=list` |
| `option_profiles` | VM | `GET /api/2.0/fo/subscription/option_profile/vm/?action=list` |
| `appliances` | VM | `GET /api/2.0/fo/appliance/?action=list&output_mode=full` |
| `auth_records` | VM | `GET /api/2.0/fo/auth/?action=list` |
| `detections` | VMDR | `GET /api/2.0/fo/asset/host/vm/detection/?action=list` |
| `compliance_policies` | PC | `GET /api/2.0/fo/compliance/policy/?action=list` |
| `activity_log` | Administration | `GET /api/2.0/fo/activity_log/?action=list` (CSV) |
| `users` | Administration | `POST /qps/rest/2.0/search/am/user/` |
| `user_list` | Administration | `GET /msp/user_list.php` (`user_list_output.dtd`) |
| `tags` | Asset Management | `POST /qps/rest/2.0/search/am/tag` |
| `cloud_agents` | Cloud Agent | `POST /qps/rest/2.0/search/am/hostasset` |
| `connectors` | Asset Management | `POST /qps/rest/2.0/search/am/assetdataconnector` |
| `was_webapps` | WAS | `POST /qps/rest/3.0/search/was/webapp` |

The assessments additionally read `GET /api/2.0/fo/scan/?action=list` (finished scans), `GET /api/2.0/fo/asset/excluded_ip/?action=list`, `GET /api/2.0/fo/knowledge_base/vuln/?action=list&details=Basic`, `GET /api/2.0/fo/schedule/report/?action=list&is_active=1`, `GET /api/2.0/fo/report/?action=list`, `POST /qps/rest/3.0/search/was/wasscan` (scan dates, bounded to the lookback window and then unbounded by `webApp.id` for web apps still unresolved), `POST /qps/rest/3.0/search/was/webappauthrecord`, and `POST /qps/rest/3.0/search/was/wasscanschedule`. Every XML list follows its `WARNING/URL` continuation and every QPS search pages with `hasMoreRecords` and `lastId`; a page that fills `limitResults` without `hasMoreRecords` is treated as a possible continuation and recorded as truncated when it cannot be followed.

### `qualys_assess_scan_coverage`

Controls 1, 2, 3, 14, 16, 20: schedule coverage against asset groups, authenticated scan ratio from host `LAST_VM_AUTH_SCANNED_DATE`, option profile authentication settings, external scanner perimeter schedules, excluded host ranges and QID exclusions, and segment-specific scanning.

### `qualys_assess_asset_inventory`

Controls 4, 5, 6, 7, 18: asset group and never-scanned host evidence for CMDB reconciliation, Asset Management connector state and last sync, scanner appliance status, heartbeat, and version currency, Cloud Agent coverage and staleness, and tag coverage across hosts.

### `qualys_assess_vulnerability_management`

Controls 8, 9, 10, 11, 17: authentication record types compared against the OS mix of scanned hosts, Policy Compliance policy assignment and status, open severity 3 to 5 detection age against 15/30/90 day SLAs, patch availability and patch age from the KnowledgeBase, and Qualys Detection Score coverage.

### `qualys_assess_administration`

Controls 12, 13, 15, 19: active scheduled reports and recent report output, user role concentration, shared and generic accounts, and inactive users, WAS web application scan freshness and authentication record age, and activity log volume with sensitive actions flagged for reviewer sign-off.

### `qualys_export_audit_bundle`

Runs the access check and all four assessments, then writes `export/qualys/qualys-<platform>-audit-bundle/` (a numeric suffix is appended when the directory exists) containing:

- `QUICK_REFERENCE.md` and `metadata.json`
- `core_data/access.json` and `core_data/<category>/<dataset>.json`, one status wrapper per collected surface carrying `name`, `endpoint`, `status` (`readable`, `truncated`, `unreadable`, or `not_collected`), `count` with a `count_status` of `complete` or `partial`, and `records`, a per-record projection (identifiers, names, statuses, dates, counts, and the documented fields the verdicts read). A denied or never-issued read carries `count: null` and `records: null` with a `reason`, never `[]`. Option profile configuration, authentication record values, connector ARNs and external IDs, agent activation IDs, report distribution settings, and notification recipients are never written
- `analysis/findings.json` plus one `analysis/<category>.json` summary per assessment
- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, and one report per framework under `compliance/fedramp/`, `compliance/cmmc/`, `compliance/soc2/`, `compliance/cis/`, `compliance/pci_dss/`, `compliance/disa_stig/`, `compliance/irap/`, and `compliance/ismap/`
- `_errors.log` when any collection step failed
- a sibling `.zip` archive of the whole directory

Output paths are resolved with traversal and symlink-parent protection; `output_dir` values that escape the working directory or pass through a symlinked parent are rejected.

## Control coverage

Finding IDs are `QUALYS-C01` through `QUALYS-C20`. Every finding carries the framework mappings from the spec table for that control. Any control whose API surface is unreadable (missing module, missing role, or API error) is downgraded to `manual` with a summary that states exactly what evidence to collect.

| # | Control | Tool | Finding | Status semantics |
|---|---------|------|---------|------------------|
| 1 | Scan schedule coverage | `qualys_assess_scan_coverage` | `QUALYS-C01` | `fail` with no active schedules; `warn` when asset groups lack a schedule or hosts were last scanned more than 30 days ago; otherwise `pass` |
| 2 | Authenticated scan ratio | `qualys_assess_scan_coverage` | `QUALYS-C02` | `pass` at or above `min_auth_scan_percent` (default 80); `fail` below; `warn` when no scanned hosts were returned |
| 3 | Scan option profile review | `qualys_assess_scan_coverage` | `QUALYS-C03` | `fail` with no option profiles; `warn` when profiles have no authentication enabled; otherwise `pass` |
| 4 | Asset group completeness | `qualys_assess_asset_inventory` | `QUALYS-C04` | Always `manual`: the API cannot see the CMDB or IPAM. Evidence lists empty asset groups and never-scanned hosts to reconcile |
| 5 | Cloud connector status | `qualys_assess_asset_inventory` | `QUALYS-C05` | `fail` when a connector reports an error state; `warn` when none exist or the last sync is stale; otherwise `pass` |
| 6 | Scanner appliance health | `qualys_assess_asset_inventory` | `QUALYS-C06` | `fail` when appliances are offline; `warn` when heartbeats were missed, software or vulnerability signatures are behind the latest version, or no appliances exist; otherwise `pass` |
| 7 | Agent deployment coverage | `qualys_assess_asset_inventory` | `QUALYS-C07` | `pass` at or above `min_agent_coverage_percent` (default 50) with no inactive or stale agents; `warn` when coverage is met but agents are stale; `fail` below the threshold |
| 8 | Authentication record completeness | `qualys_assess_vulnerability_management` | `QUALYS-C08` | `fail` when no records exist or scanned Windows or Unix-family hosts have no matching record type; otherwise `pass`. The evidence lists every record type present so network device coverage and failing credentials can be confirmed against the Authentication Report |
| 9 | Policy compliance profile assignment | `qualys_assess_vulnerability_management` | `QUALYS-C09` | `fail` when active policies have no asset group or tag assignment; `warn` when policies are inactive or none exist; `manual` when PC is not subscribed |
| 10 | Vulnerability SLA adherence | `qualys_assess_vulnerability_management` | `QUALYS-C10` | `pass` at 95 percent or more of open severity 3 to 5 detections inside SLA; `warn` from 80 to 95; `fail` below 80 |
| 11 | Patch management tracking | `qualys_assess_vulnerability_management` | `QUALYS-C11` | `fail` when more than 25 percent of patchable detections are past SLA; `warn` when any are; otherwise `pass` |
| 12 | Report template and distribution | `qualys_assess_administration` | `QUALYS-C12` | `fail` with no active scheduled reports; `warn` when no report finished in the lookback window; otherwise `pass`. Recipient appropriateness is manual evidence |
| 13 | User role and permission audit | `qualys_assess_administration` | `QUALYS-C13` | `fail` when Manager accounts exceed `max_managers` (default 5) or emails are shared; `warn` for generic account names or inactive users; otherwise `pass` |
| 14 | External scanner configuration | `qualys_assess_scan_coverage` | `QUALYS-C14` | `pass` when an active schedule uses Qualys external scanners; `warn` when schedules exist but none are external; `fail` with no schedules |
| 15 | Web application inventory | `qualys_assess_administration` | `QUALYS-C15` | `fail` when web apps lack a finished scan in the lookback window; `warn` for stale WAS auth records or an empty inventory; `manual` when WAS is not subscribed |
| 16 | Exclusion list review | `qualys_assess_scan_coverage` | `QUALYS-C16` | `fail` for excluded ranges covering more than 256 addresses; `warn` when any host or QID exclusions exist; otherwise `pass` |
| 17 | Vulnerability prioritization (QDS) | `qualys_assess_vulnerability_management` | `QUALYS-C17` | `pass` when 90 percent or more of open detections carry a QDS; `warn` for partial coverage or no detections; `fail` when none do |
| 18 | Tag-based asset management | `qualys_assess_asset_inventory` | `QUALYS-C18` | `fail` when no tags exist or more than 20 percent of hosts are untagged; `warn` for any untagged hosts; otherwise `pass` |
| 19 | Activity log monitoring | `qualys_assess_administration` | `QUALYS-C19` | `warn` when sensitive actions (user, policy, schedule, deletion) need reviewer sign-off or the log is empty; `pass` otherwise. Retention and review cadence are manual evidence |
| 20 | Network segmentation scanning | `qualys_assess_scan_coverage` | `QUALYS-C20` | `pass` when active schedules span at least two target sets and two scanners; `warn` for a single flat target or scanner; `fail` with no schedules |

## Framework mappings

Each finding's `mappings` array follows the spec compliance table and feeds the per-framework reports in the audit bundle:

- FedRAMP / NIST 800-53: RA-5 and enhancements, CM-8 and enhancements, CM-6(1), SI-2 and SI-2(2), AC-6(5), AU-6
- CMMC: 3.11.1, 3.11.2, 3.11.3, 3.4.1, 3.4.2, 3.14.1, 3.1.5, 3.3.5
- SOC 2: CC6.1, CC6.3, CC7.1, CC7.2, CC8.1
- CIS Controls: 1.1, 4.1, 7.1 to 7.6, 8.2
- PCI-DSS: 2.2.1, 2.4, 6.1, 6.3.3, 6.4.1, 7.1.1, 10.6.1, 11.3.1, 11.3.2, 11.3.4
- DISA STIG: SRG-APP-000340, SRG-APP-000383, SRG-APP-000384, SRG-APP-000456, SRG-APP-000516
- IRAP / ISM: ISM-0109, ISM-0580, ISM-1143, ISM-1163, ISM-1507, ISM-1599, ISM-1624, ISM-1690
- ISMAP: CPS.RA-5, CPS.CM-8, CPS.CM-6, CPS.SI-2, CPS.AC-6, CPS.AU-6

## Live smoke test

```bash
npm --prefix cli run test:qualys:live
```

The script skips with exit code 0 when no credentials are present. With `QUALYS_USERNAME`, `QUALYS_PASSWORD`, and `QUALYS_PLATFORM` (or `QUALYS_TOKEN`, or a `~/.qcrc` file) it runs `qualys_check_access` followed by the scan coverage assessment against the real subscription.

## Limitations and manual controls

- Control 4 is always `manual`: Qualys has no view of the authoritative CMDB or IPAM. The finding supplies the asset groups without targets and never-scanned hosts to reconcile.
- Controls 12 and 19 pass or warn on API evidence but still require a human to confirm report recipients, log retention, and review cadence.
- Controls 9 and 15 become `manual` when the PC or WAS module is not subscribed; controls 5, 7, and 18 fall back to `manual` when the Asset Management or Cloud Agent QPS endpoints are not licensed for the account.
- Cloud connectors are read from the Asset Management `assetdataconnector` search, which returns AWS, Azure, and GCP connectors together. The CloudView API listed in the spec is not used.
- Users are read from two documented surfaces. The VM/PC User List API (`GET /msp/user_list.php`, `user_list_output.dtd`) supplies `USER_STATUS`, `USER_ROLE`, `CONTACT_INFO/EMAIL`, and `LAST_LOGIN_DATE`, the last of which Qualys returns only to Manager and Unit Manager callers, so a lower-privileged API user demotes control 13 to `warn` with the affected users in `users_without_last_login`. The Administration API (`POST /qps/rest/2.0/search/am/user/`) supplies `roleList` and `scopeTags` and establishes the API user's view scope; it returns Active users only and hides other Managers, so it is never used for status. Control 13 reads both and demotes when either is unreadable. Under the documented Restricted view, `USER_LOGIN` and `USER_ID` are hidden for users outside the caller's business unit; those rows are labeled by `CONTACT_INFO/EMAIL`, counted in `restricted_view_users_without_login`, and disclosed because generic-account and shared-email checks under-report for them.
- Any finding that reads more than one inventory demotes when any of them is unreadable (401, 403, or a `SIMPLE_RETURN` error) and names the dataset and endpoint in its summary.
- Unreadable or never-collected data renders `null` beside a `<field>_status` that names the read, never `0`, `[]`, or `{}`, even where no verdict depends on it. This covers counts, derived lists and maps (for example `option_profiles`, `stale_login_users`, `breaches_by_severity`), percentages, `unknown_buckets`, and the API user scope's `roles` and `scope_tags` when the role could not be verified. Each entry in `collection.sources` carries `endpoint`, `status`, and `count` (`null` with a `reason` when `unreadable` or `not_collected`, otherwise marked `complete` or `partial`). A call skipped because its input was denied, such as the knowledge base lookup without readable detections or the WAS scan history search without a readable bounded scan search, is recorded as `not_collected` with the skipped call and its cause, never as `readable` with count `0`. A ratio whose denominator is `0` renders `null` with an `unknown` status. Control 13 discloses in `active_users_status` whether its population came from the User List API or from the Administration API fallback, which returns Active users only.
- Host and detection sampling is capped by `host_limit` and `detection_limit` (default 5000 each, up to 25 pages per list). Very large subscriptions should raise these limits or scope with asset groups.
- Option profile exclusion counts are the `VULNERABILITY_DETECTION/DETECTION_EXCLUDE` custom search lists in `option_profile_info.dtd`; QID exclusion semantics vary by profile type.
- The integration is read-only. It never launches scans, changes schedules, or edits users, tags, or policies.

## Official documentation

- Qualys platform identification (API server and gateway URLs): https://www.qualys.com/platform-identification/
- VM/PC API v2 user guide (scan, schedule, host, asset group, option profile, appliance, auth record, detection, KnowledgeBase, report, activity log, `X-Requested-With`, WARNING/URL pagination): https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf and https://docs.qualys.com/en/vm/api/
- Qualys API limits (`X-RateLimit-*` and `X-Concurrency-Limit-*` headers, 409 responses): https://www.qualys.com/docs/qualys-api-limits.pdf
- Asset Management and Tagging API (QPS 2.0, `ServiceRequest` paging, tags, host assets, connectors): https://docs.qualys.com/en/am/api/
- Cloud Agent API: https://docs.qualys.com/en/ca/api/
- Web Application Scanning API (QPS 3.0): https://docs.qualys.com/en/was/api/
- Administration API (user search): https://docs.qualys.com/en/admin/api/
