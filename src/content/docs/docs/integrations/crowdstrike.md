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

The client exchanges the credentials with `POST /oauth2/token` (form-encoded `client_id`, `client_secret`, optional `member_cid`), caches the bearer token until shortly before `expires_in`, refreshes once on a 401, retries 429 and 5xx responses with exponential backoff while honoring `X-RateLimit-RetryAfter` and `Retry-After`, and redacts the client secret and bearer token from error messages.

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
- `core_data/<category>/*.json`: raw API snapshots
- `analysis/findings.json`, `analysis/<category>.json`, `analysis/access_check.json`
- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, `compliance/frameworks/<framework>.md`
- `_errors.log` only when some reads failed
- a sibling `.zip` archive of the bundle

## Control coverage

Status semantics: `pass` means the API evidence satisfies the control, `warn` means partial or threshold-adjacent evidence, `fail` means the evidence contradicts the control or the control cannot be enforced (for example no enabled policy), and `manual` means the API cannot verify the control and the summary states exactly what to collect from the Falcon console. Any control whose source endpoint is unreadable also becomes `manual`.

| Control | Name | Tool | Finding | Status semantics |
|---|---|---|---|---|
| CS-01 | Prevention Policy - ML Detection Levels | `crowdstrike_assess_prevention_policies` | CS-01 | pass when `CloudAntiMalware` and `OnSensorMLSlider` detection and prevention are AGGRESSIVE or higher in every enabled policy; warn at MODERATE or missing platform coverage; fail at CAUTIOUS or DISABLED |
| CS-02 | Prevention Policy - Exploit Mitigation | `crowdstrike_assess_prevention_policies` | CS-02 | fail when `ForceASLR`, `ForceDEP`, `HeapSprayPreallocation`, `NullPageAllocation`, or `SEHOverwriteProtection` is disabled; warn when only extended mitigations are disabled |
| CS-03 | Prevention Policy - Script-Based Execution Control | `crowdstrike_assess_prevention_policies` | CS-03 | fail when `ScriptBasedExecutionMonitoring`, `InterpreterProtection`, or `EngineProtectionV2` is disabled |
| CS-04 | Prevention Policy - Sensor Tamper Protection | `crowdstrike_assess_prevention_policies` | CS-04 | fail when `SensorTamperingProtection` is disabled in any enabled policy |
| CS-05 | Prevention Policy - On-Write Detection | `crowdstrike_assess_prevention_policies` | CS-05 | fail when `DetectOnWrite` is disabled; warn when `QuarantineOnWrite` is disabled |
| CS-06 | Response Policy - RTR Enabled | `crowdstrike_assess_response_readiness` | CS-06 | fail when `RealTimeFunctionality` is disabled everywhere; warn when `CustomScripts` is allowed |
| CS-07 | Response Policy - Session Limits | `crowdstrike_assess_response_readiness` | CS-07 | manual: the API does not expose timeout or concurrency settings; RTR audit sessions longer than `max_session_minutes` or above `max_concurrent_sessions` raise warn |
| CS-08 | Device Control - USB Blocking | `crowdstrike_assess_device_firewall` | CS-08 | pass when USB `enforcement_mode` is `MONITOR_ENFORCE` and `MASS_STORAGE` is not `FULL_ACCESS`; warn above `max_usb_exceptions`; fail otherwise |
| CS-09 | Device Control - Peripheral Restrictions | `crowdstrike_assess_device_firewall` | CS-09 | pass when Bluetooth and PCIe/Thunderbolt enforce and mass storage (SD cards) is blocked; warn when partially configured; fail when none |
| CS-10 | Firewall - Host Firewall Enabled | `crowdstrike_assess_device_firewall` | CS-10 | pass when every enabled firewall policy has `enforce` true, `test_mode` false, and active rule groups |
| CS-11 | Firewall - Default Deny | `crowdstrike_assess_device_firewall` | CS-11 | fail when a policy container `default_inbound` is not `DENY`; warn when enabled allow rules lack descriptions |
| CS-12 | Sensor Update - Auto-Update Enabled | `crowdstrike_assess_sensor_coverage` | CS-12 | pass for `n`, `n-1`, `n-2` auto builds or pins inside the current N-2 window; fail for updates off or older pins; warn when uninstall protection is disabled |
| CS-13 | Sensor Coverage - Deployment Completeness | `crowdstrike_assess_sensor_coverage` | CS-13 | pass when 95% or more sampled hosts checked in within `stale_sensor_days`; warn at 85%; fail below |
| CS-14 | Sensor Coverage - Host Group Assignment | `crowdstrike_assess_sensor_coverage` | CS-14 | pass when 95% or more sampled hosts belong to a host group; warn at 80%; fail below or with no host groups |
| CS-15 | Unmanaged Asset Detection | `crowdstrike_assess_sensor_coverage` | CS-15 | pass with zero Discover unmanaged assets; warn at 5% or less of discovered assets; fail above; manual when Discover is not licensed |
| CS-16 | RBAC - Admin Count | `crowdstrike_assess_access_governance` | CS-16 | warn above `max_admins` or with shared-looking accounts; fail at double the threshold or shared admin accounts |
| CS-17 | RBAC - Least Privilege | `crowdstrike_assess_access_governance` | CS-17 | warn for users above `max_roles_per_user` or redundant roles on admins; fail for admins without a login in 90 days |
| CS-18 | RBAC - API Client Permissions | `crowdstrike_assess_access_governance` | CS-18 | warn when clients hold write scopes on sensitive collections; fail above `max_write_clients` |
| CS-19 | Exclusion Review - IOA Exclusions | `crowdstrike_assess_access_governance` | CS-19 | lists every exclusion; warn for wildcard-only `ifn_regex` or `cl_regex`; fail when such patterns apply globally |
| CS-20 | Exclusion Review - ML Exclusions | `crowdstrike_assess_access_governance` | CS-20 | warn for exclusions under system, program, user, or temp directories; fail when applied globally |
| CS-21 | Exclusion Review - Sensor Visibility | `crowdstrike_assess_access_governance` | CS-21 | warn for exclusions that hide whole directories; fail when applied globally |
| CS-22 | Detection Response SLA | `crowdstrike_assess_response_readiness` | CS-22 | pass when 95% or more critical/high alerts in `lookback_days` are within 24h (critical) or 72h (high); warn at 80%; fail below |
| CS-23 | Containment Policy | `crowdstrike_assess_response_readiness` | CS-23 | pass with no contained hosts; warn when hosts are contained so each can be documented |
| CS-24 | Identity Protection | `crowdstrike_assess_access_governance` | CS-24 | pass when enabled, non-simulation rules enforce; warn when rules exist only in simulation; fail with no rules; manual when the module is not licensed |
| CS-25 | Zero Trust Assessment | `crowdstrike_assess_sensor_coverage` | CS-25 | pass with no hosts below `min_zta_score`; warn at 10% or less; fail above; manual when ZTA is not readable |

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
- Host, user, alert, exclusion, and rule reads are sampled up to the configured limits (5000 hosts, 500 users and API clients, 2000 alerts, 500 exclusions per type, 1000 firewall rules by default).
- Identity Protection GraphQL requires a write scope, so the tools use the REST policy-rules endpoints and parse `enabled`, `simulationMode`, and `action` defensively.
- Thunderbolt and SD card restrictions are evaluated through the PCIe enforcement mode and the `MASS_STORAGE` class because the API exposes no dedicated Thunderbolt or SD card classes.

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
