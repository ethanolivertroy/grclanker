---
title: CrowdStrike Falcon
description: Read-only Falcon API inspector covering prevention, response, device control, firewall, sensor coverage, RBAC, exclusions, identity protection, and Zero Trust Assessment controls.
---

The CrowdStrike integration inspects a Falcon tenant through the public Falcon API and maps what it finds to the 25 controls in `specs/crowdstrike-sec-inspector.spec.md` (CS-01 through CS-25). Every tool is read-only: the tools never create, update, or delete anything in the tenant.

## What it inspects

- Prevention policies: ML detection and prevention sliders, exploit mitigation, script-based execution control, sensor tampering protection, on-write detection and quarantine
- Response policies and Real Time Response (RTR) audit sessions
- Device control policies (USB, Bluetooth, PCIe/Thunderbolt) and host firewall policies, containers, rule groups, and rules
- Sensor update policies and the published sensor build catalog
- Host inventory, host groups, Falcon Discover unmanaged assets, and Zero Trust Assessment scores
- Users, role grants, API clients and their scopes
- IOA, machine learning, and sensor visibility exclusions
- Identity Protection policy rules
- Critical and high alerts for response SLA measurement and network-contained hosts

## Setup and authentication

Create a Falcon API client (Falcon console > Support and resources > API clients and keys) with read scopes only, then pass its credentials to the tools.

Environment variables:

| Variable | Purpose |
|---|---|
| `CS_CLIENT_ID` | Falcon API client ID (`FALCON_CLIENT_ID` is accepted as a fallback) |
| `CS_CLIENT_SECRET` | Falcon API client secret (`FALCON_CLIENT_SECRET` is accepted as a fallback) |
| `CS_BASE_URL` | Explicit API base URL; overrides the cloud alias |
| `CS_CLOUD` | Regional cloud alias when `CS_BASE_URL` is not set |
| `CS_MEMBER_CID` | Child CID for Falcon Flight Control (MSSP) tenants |
| `CS_CONFIG_FILE` | Optional JSON config file path (defaults to `~/.crowdstrike/config.json`) |
| `CS_TIMEOUT` | HTTP timeout in seconds (default 30) |

Precedence is explicit tool arguments, then environment variables, then the JSON config file. The config file accepts `client_id`, `client_secret`, `base_url`, `cloud`, `member_cid`, and `timeout_seconds`; keep it outside the repository.

Regional clouds:

| Alias | Base URL |
|---|---|
| `us-1` (default) | `https://api.crowdstrike.com` |
| `us-2` | `https://api.us-2.crowdstrike.com` |
| `eu-1` | `https://api.eu-1.crowdstrike.com` |
| `us-gov-1` | `https://api.laggar.gcw.crowdstrike.com` |
| `us-gov-2` | `https://api.us-gov-2.crowdstrike.mil` |

The client exchanges the credentials with `POST /oauth2/token` (form-encoded `client_id`, `client_secret`, optional `member_cid`), caches the bearer token until shortly before `expires_in`, refreshes once on a 401, retries 429 and 5xx responses with exponential backoff while honoring `X-RateLimit-RetryAfter` and `Retry-After`, and passes every error message through a redaction pass that removes the client secret and every bearer token obtained (in their encoded forms too), any value inside a credential carrier (`Authorization` and cookie headers, auth schemes, credential-named fields, assignments, and command-line flags, URL userinfo and query strings), and bare values with a real token shape; the boundary is spelled out under "Limitations and manual controls" below.

Required API client scopes (all Read):

- Prevention policies, Response policies, Device control policies, Sensor update policies
- Firewall management
- Hosts, Host groups
- User management
- API integrations (Api Client Mgmt)
- Alerts
- IOA Exclusions, Machine Learning Exclusions, Sensor Visibility Exclusions
- Real time response audit
- Assets (Falcon Discover), Zero Trust Assessment, Identity Protection Policy Rules: optional; when the module is not licensed the related controls become `manual` findings

`crowdstrike_check_access` probes each of these surfaces and lists the scopes that returned 403.

## Tools

| Tool | Purpose |
|---|---|
| `crowdstrike_check_access` | Probe 19 read surfaces, report readable counts, and list missing API client scopes |
| `crowdstrike_assess_prevention_policies` | CS-01 to CS-05 from prevention policy settings |
| `crowdstrike_assess_response_readiness` | CS-06, CS-07, CS-22, CS-23 from response policies, RTR audit sessions, alerts, and contained hosts |
| `crowdstrike_assess_device_firewall` | CS-08 to CS-11 from device control and firewall policies, containers, rule groups, and rules |
| `crowdstrike_assess_sensor_coverage` | CS-12 to CS-15 and CS-25 from sensor update policies, builds, hosts, host groups, Discover, and ZTA |
| `crowdstrike_assess_access_governance` | CS-16 to CS-21 and CS-24 from users, roles, API clients, exclusions, and Identity Protection rules |
| `crowdstrike_export_audit_bundle` | Run every assessment and write an evidence bundle plus zip archive |

Every tool accepts `client_id`, `client_secret`, `base_url`, `cloud`, `member_cid`, `config_file`, and `timeout_seconds`. Assessment tools also accept thresholds such as `lookback_days`, `stale_sensor_days`, `max_admins`, `max_roles_per_user`, `max_usb_exceptions`, `max_write_clients`, `min_zta_score`, `max_session_minutes`, and `max_concurrent_sessions`, and sample limits such as `host_limit`, `user_limit`, `alert_limit`, `exclusion_limit`, and `rule_limit`.

### Audit bundle layout

`crowdstrike_export_audit_bundle` writes to `./export/crowdstrike/<cloud>[-<member_cid>]-audit-bundle/` by default (override with `output_dir`) and refuses traversal or symlinked parent paths:

- `QUICK_REFERENCE.md` and `metadata.json` (no credentials)
- `core_data/<category>/*.json`: projected and redacted API snapshots. Alerts and RTR audit sessions keep verdict fields only (process command lines, file paths, and RTR command strings are never exported), and the free-text fields of every exclusion (`cl_regex`, `ifn_regex`, `value`, `name`, `description`, `comment`) pass through the credential redaction pass. Every string a snapshot, an evidence list, or a summary keeps from a Falcon response passes the data-side pass at the collector (`collectDataset`): the client's remembered credentials in every form and every carrier (`Authorization`, `Cookie`, `Set-Cookie`, and API key headers, quoted or bare; URL userinfo and query strings, which go whole; credential-named assignments and fields; auth schemes; JWTs; PEM blocks) are removed from a description, a note, a name, or a comment; no bare-token rule runs on data, so identifiers such as `prod-us-east-2026`, a UUID, or a quoted `Content-Type` header stay. A resource nested deeper than 32 levels is replaced by `[REDACTED]` at that depth rather than passed through (the payload is server-controlled). A dataset that was denied, errored, or never requested is written as `{ collected: false, dataset, status, endpoint, error }` instead of an empty array, so `[]` always means a readable list with no items; a dependent read that was skipped carries `not requested: <parent read>` in `error`
- `analysis/findings.json`, `analysis/<category>.json` (summary counts and truncation flags derived from a dataset that was not read render `null`, and `summary.inventories` states each dataset as `read (N items)`, `read, truncated (N of M items)`, `unread (...)`, or `not requested (...)`), `analysis/access_check.json`
- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, `compliance/frameworks/<framework>.md`
- `_errors.log` only when some reads failed
- a sibling `.zip` archive of the bundle

## Control coverage

Status semantics: `pass` means the API evidence satisfies the control across the complete inventory that was read, `warn` means partial or threshold-adjacent evidence, `fail` means the evidence contradicts the control or an inventory the control depends on is empty (for example zero prevention policies), and `manual` means the API cannot verify the control and the summary names the cause and exactly what to collect from the Falcon console.

The verdicts follow these safety rules, each covered by a regression test in `cli/tests/crowdstrike.test.mjs`:

- An unreadable, forbidden (401/403), or errored endpoint never yields `pass`; the affected control becomes `manual` and the summary names the failed read.
- An empty inventory never yields `pass` by default. Zero policies, hosts, host groups, or identity rules `fail`; zero users, API clients, Discover assets, or ZTA scores are `manual` because a live tenant cannot be empty; zero exclusions, zero critical/high alerts in the stated window, and zero contained hosts `pass` because emptiness is compliant, and the summary says so. Each of those verdicts holds only when the read was complete: a truncated page with zero visible rows is a claim about rows that were not read, so CS-19, CS-20, CS-21, CS-22, and CS-23 say the property cannot be confirmed or ruled out from the visible rows and cap at `warn` instead of claiming emptiness, and CS-13, CS-14, and CS-24 set `absence_claim` and render `manual` instead of `fail`. A finding's summary counts over the rows it read (`N users reviewed; ...`), so a capped list never asserts an absence across rows it did not see.
- Falcon Discover, Identity Protection, and Zero Trust Assessment responses of 401, 403, or 404 render as `manual` with an "unlicensed or not applicable" summary.
- Records without a timestamp (`last_seen`, `created_timestamp`, `last_login_at`, `modified_timestamp`) are never counted as fresh or compliant; they are reported in an `undated_items` bucket and cap the verdict at `warn`.
- Every sampled read compares the returned count against `meta.pagination.total`; a truncated or sampled inventory is reported as `partial_inventory` with seen and total counts and caps the verdict at `warn`. Pagination runs to completion within the configured limit, and the client records truncation instead of treating a first page as the population. Single-page queries with no documented pagination parameters (the role catalog and Identity Protection rule ids) still compare the returned ids against the reported total, and count-only reads (Discover and ZTA totals) treat a missing total as unknown rather than zero. An id query followed by an entity lookup that returns fewer records than the ids listed (firewall rule groups and rules, the role catalog, API clients, the three exclusion types, Identity Protection rules) is also recorded as truncated, so a shortfall of deleted or forbidden entities demotes the verdict instead of passing on the subset.
- A `fail` that rests on the absence of something among the visible rows (no enabled and host-assigned prevention or response policy, no firewall policy container) is provable only against the rows that were read: on a partial inventory it renders `manual` with "the absence this verdict rests on cannot be asserted for the unread rows" instead of `fail`. A `fail` observed on a visible row (a disabled slider, a `default_inbound` that is not `DENY`, a stale admin) stands.
- A dependent read is never requested when the read it depends on was denied or errored (device control v2 details, firewall policy containers, sensor build catalogs, Discover managed counts and samples, ZTA below-threshold queries, user details and role grants), and the three id lookups (device control v2 details, firewall policy containers, sensor build catalogs) are also not requested when the parent list was readable but returned no ids or platforms to look up. In every case the dependent's dataset carries `not requested: <reason>` naming the parent and the bundle writes a not-collected marker rather than an empty array. The two parent states lead to different verdicts: a denied or errored parent is the unreadable dataset, so the finding names the parent read as such and renders `manual`; a readable parent that returned no ids is a complete empty read, so the skipped dependent is not treated as unread and the finding takes the parent's complete-empty verdict (zero device control or firewall policies `fail` CS-08 through CS-11, and zero enabled, host-assigned sensor update policies `fail` CS-12 with the build catalogs left unrequested).
- A finding whose primary dataset is unread names the dataset and the error ("The hosts read failed (...), so no API evidence supports this control.") and renders `manual` with `unreadable_dataset` in its evidence; a finding whose secondary dataset is unread (the sensor build catalog for CS-12, Discover unmanaged samples for CS-15, the role catalog for CS-16 and CS-17) keeps its verdict but cannot exceed `warn` and records the read under `unreadable_secondary_reads`.
- Summary counts and truncation flags derived from a dataset that was not read render `null` rather than `0` or `false`, and every summary carries an `inventories` map naming each dataset's state.
- Only policies that are enabled and assigned to host groups (or the `platform_default` policy) count as enforcement; an aggressive setting on a disabled or unassigned policy never supports `pass`, and an `mlslider` missing its `detection` or `prevention` value caps CS-01 at `warn`.
- Re-running an export allocates a new suffixed bundle directory and a zip with the same name (`<bundle>-2/` and `<bundle>-2.zip`) instead of overwriting a prior bundle.
- With `member_cid` set, every summary states that results cover that member CID only.

The `Inputs` column names the datasets each finding reads, using the labels of the summary's `inventories` map; an unread primary input renders the finding `manual`, an unread secondary input caps it at `warn`, and a truncated input caps a pass at `warn` and an absence-driven fail at `manual`.

| Control | Name | Tool | Finding | Inputs | Status semantics |
|---|---|---|---|---|---|
| CS-01 | Prevention Policy - ML Detection Levels | `crowdstrike_assess_prevention_policies` | CS-01 | `prevention policies` | pass when `CloudAntiMalware` and `OnSensorMLSlider` detection and prevention are AGGRESSIVE or higher in every enabled, host-assigned policy and every platform (Windows, Mac, Linux) has one; warn at MODERATE, when a slider or its `detection` or `prevention` value is missing, or when at least one enabled, host-assigned policy exists but some platform has none (`platforms_without_policy` names them); fail at CAUTIOUS or DISABLED on any enabled, host-assigned policy, or when no enabled, host-assigned prevention policy exists on any platform (the policy list is empty, or every policy is disabled or unassigned; manual instead when the policy list is truncated, since the missing policy could be among the unread rows, and the per-platform warn is likewise dropped on a truncated list); manual when the policy list is unread |
| CS-02 | Prevention Policy - Exploit Mitigation | `crowdstrike_assess_prevention_policies` | CS-02 | `prevention policies` | fail when `ForceASLR`, `ForceDEP`, `HeapSprayPreallocation`, `NullPageAllocation`, or `SEHOverwriteProtection` is disabled; warn when only extended mitigations are disabled; manual when the list is unread; a truncated list caps pass at warn and the no-assigned-policy fail at manual |
| CS-03 | Prevention Policy - Script-Based Execution Control | `crowdstrike_assess_prevention_policies` | CS-03 | `prevention policies` | fail when `ScriptBasedExecutionMonitoring`, `InterpreterProtection`, or `EngineProtectionV2` is disabled; manual when the list is unread; a truncated list caps pass at warn and the no-assigned-policy fail at manual |
| CS-04 | Prevention Policy - Sensor Tamper Protection | `crowdstrike_assess_prevention_policies` | CS-04 | `prevention policies` | fail when `SensorTamperingProtection` is disabled in any enabled, host-assigned policy; manual when the list is unread; a truncated list caps pass at warn and the no-assigned-policy fail at manual |
| CS-05 | Prevention Policy - On-Write Detection | `crowdstrike_assess_prevention_policies` | CS-05 | `prevention policies` | fail when `DetectOnWrite` is disabled; warn when `QuarantineOnWrite` is disabled; manual when the list is unread; a truncated list caps pass at warn and the no-assigned-policy fail at manual |
| CS-06 | Response Policy - RTR Enabled | `crowdstrike_assess_response_readiness` | CS-06 | `response policies` | fail when `RealTimeFunctionality` is disabled in every enabled, host-assigned response policy or no such policy exists (manual instead when the list is truncated); warn when `CustomScripts` is allowed; manual when the list is unread |
| CS-07 | Response Policy - Session Limits | `crowdstrike_assess_response_readiness` | CS-07 | `rtr audit sessions` | manual: the API does not expose timeout or concurrency settings; RTR audit sessions longer than `max_session_minutes` or above `max_concurrent_sessions` raise warn; when the session read is unread the summary names that failure instead, and a truncated session page is recorded as `partial_inventory` |
| CS-08 | Device Control - USB Blocking | `crowdstrike_assess_device_firewall` | CS-08 | `device control policies`, `device control policy details` | pass when USB `enforcement_mode` is `MONITOR_ENFORCE` and `MASS_STORAGE` is not `FULL_ACCESS` in every enabled, host-assigned policy; warn above `max_usb_exceptions`; fail otherwise; manual when the policy list or the v2 policy details are unread (the details are not requested when the list was unread or returned no ids); a truncated list or detail lookup caps pass at warn |
| CS-09 | Device Control - Peripheral Restrictions | `crowdstrike_assess_device_firewall` | CS-09 | `device control policies`, `device control policy details` | pass when Bluetooth and PCIe/Thunderbolt enforce and mass storage (SD cards) is blocked; warn when partially configured; fail when none; manual and truncation handling as CS-08 |
| CS-10 | Firewall - Host Firewall Enabled | `crowdstrike_assess_device_firewall` | CS-10 | `firewall policies`, `firewall policy containers`, `firewall rule groups` | pass when every enabled, host-assigned firewall policy has `enforce` true, `test_mode` false, and at least one returned rule group that is enabled and non-empty; warn when referenced rule groups were not returned; manual when policies, containers, or rule groups are unread (containers are not requested when the policy list was unread or held no enabled, host-assigned policy); a truncated policy list or rule group page caps pass at warn |
| CS-11 | Firewall - Default Deny | `crowdstrike_assess_device_firewall` | CS-11 | `firewall policies`, `firewall policy containers`, `firewall rules` | fail when a policy container `default_inbound` is not `DENY`, or when no container was returned for the applied policies (manual instead when the policy list or rule page is truncated); warn when enabled allow rules lack descriptions or zero rules were returned; manual when policies, containers, or rules are unread |
| CS-12 | Sensor Update - Auto-Update Enabled | `crowdstrike_assess_sensor_coverage` | CS-12 | `sensor update policies`; secondary `sensor update builds` per platform | pass for `n`, `n-1`, `n-2` auto builds or pins inside the current N-2 window; fail for updates off or older pins; warn when uninstall protection is disabled, or when a platform's build catalog is unread (pinned builds then cannot be verified and pass is capped at warn); manual when the policy list is unread; the catalogs are not requested when no enabled, host-assigned policy names a platform |
| CS-13 | Sensor Coverage - Deployment Completeness | `crowdstrike_assess_sensor_coverage` | CS-13 | `hosts` | pass when 95% or more dated hosts checked in within `stale_sensor_days`; warn at 85%, when hosts lack `last_seen`, or when the host sample is truncated; fail below 85% or with zero hosts on a complete read; manual when the host read is unread, or when the truncated host page shows zero hosts (`absence_claim`, the summary says coverage cannot be confirmed or ruled out from the visible rows) |
| CS-14 | Sensor Coverage - Host Group Assignment | `crowdstrike_assess_sensor_coverage` | CS-14 | `hosts`, `host groups` | pass when 95% or more sampled hosts belong to a host group; warn at 80% or on a truncated host or group sample; fail below or with zero hosts or host groups on a complete read of that list; manual when hosts or host groups are unread, or when the list that came back empty was truncated (`absence_claim`); an empty complete group list still fails when only the host list is partial |
| CS-15 | Unmanaged Asset Detection | `crowdstrike_assess_sensor_coverage` | CS-15 | `discover unmanaged hosts`, `discover managed hosts`; secondary `discover unmanaged samples` | pass with zero Discover unmanaged assets against a non-zero managed count (both server-side totals present); warn at 5% or less of discovered assets, or when the sample list is unread; fail above; manual when Discover is unlicensed (401, 403, or 404), either count is unread, the tenant reports zero assets, or `meta.pagination.total` is omitted for either count; the managed count and samples are not requested when the unmanaged count was unread |
| CS-16 | RBAC - Admin Count | `crowdstrike_assess_access_governance` | CS-16 | `user uuids`, `users`, `user roles`; secondary `role catalog` | warn above `max_admins`, with shared-looking accounts, or when some role lookups failed, a role grant page or the role catalog is truncated, the user list is truncated, or the role catalog is unread; fail at double the threshold or shared admin accounts; manual with zero users, when the uuid list or user details are unread (details and role grants are then not requested), or when every role lookup failed |
| CS-17 | RBAC - Least Privilege | `crowdstrike_assess_access_governance` | CS-17 | `user uuids`, `users`, `user roles`; secondary `role catalog` | warn for users above `max_roles_per_user`, redundant roles on admins, admins with no `last_login_at`, or when role grants or the role catalog are truncated or the catalog is unread; fail for admins whose last login is older than 90 days; manual as CS-16. The summary counts over the users that were read (`N users reviewed; M carry more than ... and S of A admin accounts ...`), so a truncated user list never asserts an absence over the unread rows |
| CS-18 | RBAC - API Client Permissions | `crowdstrike_assess_access_governance` | CS-18 | `api clients` | reads each scope object's `action` and `group` (the `id` alone carries no read or write verb); warn when clients hold write-action scopes on sensitive groups, expose scopes without an `action`, omit the scopes array, or the client list is truncated; fail above `max_write_clients`; manual with zero clients or when the client list is unread. The public reference documents no last-used field, so the pass summary states that staleness was not evaluated from API data unless the tenant returns one |
| CS-19 | Exclusion Review - IOA Exclusions | `crowdstrike_assess_access_governance` | CS-19 | `ioa exclusions` | lists every exclusion; warn for wildcard-only `ifn_regex` or `cl_regex`; fail when such patterns apply globally; manual when the list is unread; a truncated list caps pass at warn, and with zero visible exclusions it says suppression cannot be confirmed or ruled out from the visible rows instead of claiming emptiness; exclusion regexes and notes pass through the redaction pass before export |
| CS-20 | Exclusion Review - ML Exclusions | `crowdstrike_assess_access_governance` | CS-20 | `ml exclusions` | warn for exclusions under system, program, user, or temp directories; fail when applied globally; manual when the list is unread; a truncated list caps pass at warn, and with zero visible exclusions it says suppression cannot be confirmed or ruled out from the visible rows |
| CS-21 | Exclusion Review - Sensor Visibility | `crowdstrike_assess_access_governance` | CS-21 | `sensor visibility exclusions` | warn for exclusions that hide whole directories; fail when applied globally; manual when the list is unread; a truncated list caps pass at warn, and with zero visible exclusions it says hidden paths cannot be confirmed or ruled out from the visible rows |
| CS-22 | Detection Response SLA | `crowdstrike_assess_response_readiness` | CS-22 | `alerts` | pass when 95% or more dated critical/high alerts in `lookback_days` are within 24h (critical) or 72h (high), including zero alerts when the endpoint was readable and the read was complete; warn at 80%, with undated alerts, or on a truncated alert page (with no dated alert visible the summary says response within the SLA cannot be confirmed or ruled out from the visible rows instead of claiming emptiness); fail below; manual when the alert read is unread |
| CS-23 | Containment Policy | `crowdstrike_assess_response_readiness` | CS-23 | `contained hosts` | pass with no contained hosts when the Hosts API was readable and the containment read was complete; warn when hosts are contained so each can be documented, or when the contained host read is truncated (with no visible match the summary says active containment cannot be confirmed or ruled out from the visible rows instead of claiming emptiness); manual when the read is unread |
| CS-24 | Identity Protection | `crowdstrike_assess_access_governance` | CS-24 | `identity protection rules` | pass when enabled, non-simulation rules enforce; warn when rules exist only in simulation, or when the rule id query is truncated; fail with no rules on a complete read; manual when the truncated rule page shows zero rules (`absence_claim`), when the module is unlicensed (401, 403, or 404) or the read errored |
| CS-25 | Zero Trust Assessment | `crowdstrike_assess_sensor_coverage` | CS-25 | `zero trust assessment totals`, `zero trust assessments below threshold`, `zero trust assessment below-threshold totals` | pass only when exactly zero hosts are below `min_zta_score` and both server-side totals are present; warn when the below-threshold share is above 0% and at most 10% of scored hosts, or, as a separate condition, when the below-threshold query omits its total (the sampled count is then only a lower bound, so a would-be pass renders warn and a computed warn or fail stands); fail above 10%; manual when ZTA is unlicensed (401, 403, or 404), unread, reports zero scored hosts, or omits the scored-host total; the below-threshold query is not requested when the totals count was unread |

## Framework mappings

Every finding carries the framework mappings from the spec's compliance mapping table as strings such as `FedRAMP SI-3`, `CMMC SI.L2-3.14.2`, `SOC 2 CC6.8`, `CIS 10.1`, `PCI-DSS 5.2`, `DISA STIG V-256374`, `IRAP ISM-1417`, and `ISMAP 8.1.1`. The audit bundle writes one report per framework under `compliance/frameworks/` (`fedramp`, `cmmc`, `soc2`, `cis`, `pci_dss`, `disa_stig`, `irap`, `ismap`) plus a unified matrix.

## Live smoke test

```bash
CS_CLIENT_ID=... CS_CLIENT_SECRET=... CS_CLOUD=us-1 npm --prefix cli run test:crowdstrike:live
```

The script prints a skip message and exits 0 when credentials are absent. With credentials it runs `crowdstrike_check_access` and the prevention policy assessment against the tenant.

## Limitations and manual controls

- CS-07 is always `manual` (or `warn` when audit data shows long or concurrent sessions): no Falcon API endpoint exposes the RTR session timeout or concurrent session limit, so capture them from the response policy in the console.
- CS-15, CS-24, and CS-25 depend on Falcon Discover, Identity Protection, and Zero Trust Assessment licensing; a 403 or 404 from those collections produces a `manual` finding with the console evidence to collect.
- CS-23 cannot read when containment started; the finding uses the host record's `modified_timestamp` as a proxy and asks for incident references.
- Host, user, alert, exclusion, and rule reads are sampled up to the configured limits (5000 hosts, 500 users and API clients, 2000 alerts, 500 exclusions per type, 1000 firewall rules by default). When the reported total exceeds the sample, the finding records `partial_inventory` with seen and total counts and cannot exceed `warn`; raise the limit to read the full population.
- Identity Protection GraphQL requires a write scope, so the tools use the REST policy-rules endpoints and parse `enabled`, `simulationMode`, and `action` defensively.
- Thunderbolt and SD card restrictions are evaluated through the PCIe enforcement mode and the `MASS_STORAGE` class because the API exposes no dedicated Thunderbolt or SD card classes.
- Error strings never quote a response body. A body without Falcon's documented `errors[].message`, `error_description`, `error`, or `message` field (a proxy or WAF page, whatever its content type claims, or JSON of another shape) is described as "non-JSON body (text/html, 5120 bytes)" or "JSON body without a documented error field (...)", on every surface including `POST /oauth2/token`. Every error string is passed through one redaction pass when `CrowdstrikeHttpError` is constructed and again when the error is recorded, so `access_check.json`, dataset `error` fields, `unreadable_dataset` and `unreadable_secondary_reads` evidence, `errors` arrays, `_errors.log`, and tool results carry status, path, and shape only. The pass removes the client secret and every bearer token obtained whatever their shape and in their base64, base64url, URL-encoded, and JSON-escaped forms; any value inside a carrier whatever its shape (`Authorization`, `Cookie`, `Set-Cookie`, and API key headers, cookie and session assignments, URL userinfo and query pairs, the `Bearer`, `Basic`, `Digest`, `Token`, and `ApiKey` schemes, credential-named fields and assignments, SOAP credential elements, command-line flags such as `--token VALUE`); and bare values only when they have a real token shape (JWTs, PEM blocks, hex digests, vendor-prefixed keys, and runs of 16 or more characters with base64 symbols, scattered digits, or token casing). A bare name-shaped value standing alone in prose, such as a host group name or `prod-us-east-2026`, is indistinguishable from a resource name and stays. The same pass runs over the operator-authored text of every exclusion (`cl_regex`, `ifn_regex`, `value`, `name`, `description`, `comment`) before it reaches a finding or the bundle; a credential inside a path pattern is removed up to the next path separator, so `D:\Builds\password=VALUE\*.pdb` is exported as `D:\Builds\password=[REDACTED]\*.pdb`.
- Config file errors are fixed text. A file that cannot be read fails with "Unable to read CrowdStrike config file <path> (<CODE>)" (the Node error code only, `ENOENT` included when `config_file` or `CS_CONFIG_FILE` names the path; the default `~/.crowdstrike/config.json` is skipped when absent); a file that cannot be parsed fails with "Unable to parse CrowdStrike config file: invalid JSON in <path> at line N" (the line only when `JSON.parse` reports a position). Neither `JSON.parse`'s message, which quotes a window of the source, nor the filesystem's wording is ever included, so an unquoted `client_secret` value is never echoed.

## Official documentation consulted

The Falcon console documentation requires a login, so endpoint paths, parameters, and response fields were verified against CrowdStrike's public API reference and the public SDKs that mirror the official operation names:

- [API reference collections index](https://developer.crowdstrike.com/api-reference/collections)
- [OAuth2](https://developer.crowdstrike.com/api-reference/collections/oauth2)
- [Prevention Policies](https://developer.crowdstrike.com/api-reference/collections/prevention-policies)
- [Response Policies](https://developer.crowdstrike.com/api-reference/collections/response-policies)
- [Device Control Policies](https://developer.crowdstrike.com/api-reference/collections/device-control-policies)
- [Firewall Policies](https://developer.crowdstrike.com/api-reference/collections/firewall-policies) and [Firewall Management](https://developer.crowdstrike.com/api-reference/collections/firewall-management)
- [Sensor Update Policy](https://developer.crowdstrike.com/api-reference/collections/sensor-update-policy)
- [Hosts](https://developer.crowdstrike.com/api-reference/collections/hosts) and [Host Group](https://developer.crowdstrike.com/api-reference/collections/host-group)
- [User Management](https://developer.crowdstrike.com/api-reference/collections/user-management)
- [API Clients](https://developer.crowdstrike.com/api-reference/collections/api-clients)
- [Discover](https://developer.crowdstrike.com/api-reference/collections/discover)
- [Alerts](https://developer.crowdstrike.com/api-reference/collections/alerts)
- [IOA Exclusions](https://developer.crowdstrike.com/api-reference/collections/ioa-exclusions), [ML Exclusions](https://developer.crowdstrike.com/api-reference/collections/ml-exclusions), [Sensor Visibility Exclusions](https://developer.crowdstrike.com/api-reference/collections/sensor-visibility-exclusions)
- [Zero Trust Assessment](https://developer.crowdstrike.com/api-reference/collections/zero-trust-assessment)
- [Identity Protection](https://developer.crowdstrike.com/api-reference/collections/identity-protection)
- [Real Time Response Audit](https://developer.crowdstrike.com/api-reference/collections/real-time-response-audit)
- [FalconPy documentation](https://www.falconpy.io/) and the [falconpy](https://github.com/CrowdStrike/falconpy) and [gofalcon](https://github.com/CrowdStrike/gofalcon) repositories for regional base URLs, rate limit header names, and response models
- [terraform-provider-crowdstrike](https://github.com/CrowdStrike/terraform-provider-crowdstrike) for prevention, response, sensor update, and device control setting identifiers
