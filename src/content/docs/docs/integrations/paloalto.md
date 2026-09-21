---
title: Palo Alto Networks
description: Read-only security inspection of Prisma Cloud CSPM tenants and PAN-OS firewalls or Panorama with framework-mapped findings and evidence bundles.
---

The Palo Alto Networks integration audits two product surfaces without ever mutating a tenant or a device:

- **Prisma Cloud CSPM** through the REST API (JWT login with an access key): compliance posture, alert rules and open alerts, policies, cloud accounts and account groups, user roles, and integrations.
- **PAN-OS firewalls and Panorama** through the XML API (`type=op` show commands and `type=config&action=show`): security and decryption rulebases, zones, security profiles, GlobalProtect, administrators, log forwarding, system settings, HA state, and software versions.

Every finding carries the FedRAMP, CMMC 2.0, SOC 2, CIS, PCI-DSS 4.0, DISA STIG, IRAP, and ISMAP references from the compliance mapping table in `specs/paloalto-sec-inspector.spec.md`.

## Setup and authentication

Configure one product or both. When only one product is configured, the other product's controls become `manual` findings that state exactly which evidence a human must collect.

### Prisma Cloud

| Variable | Purpose |
|---|---|
| `PRISMA_API_URL` | Regional API URL, for example `https://api2.prismacloud.io` or `https://api.eu.prismacloud.io` (defaults to `https://api.prismacloud.io`). Use the API URL that matches your console URL. |
| `PRISMA_ACCESS_KEY_ID` | Access key ID created under Settings > Access Control > Access Keys. |
| `PRISMA_SECRET_KEY` | Secret key for that access key. |
| `PRISMA_COMPUTE_URL` | Optional Prisma Cloud Compute console path (Compute > Manage > System > Utilities > Path to Console). When unset, the CSPM `GET /meta_info` response field `twistlockUrl` is used; if neither is available, the Compute controls (7 to 11, 24, 25) become manual findings that name this variable. |

The client sends `POST /login` with the access key ID as `username` and the secret key as `password`, then reuses the returned JWT in the `x-redlock-auth` header. Tokens are refreshed by logging in again before the ten-minute expiry, and a `401` triggers one re-login. `429` and `5xx` responses are retried with exponential backoff (honoring `Retry-After`). The access key inherits the permission group of the user who created it; a read-only role such as **Account Group Read Only** or a custom permission group with read access to Compliance, Alerts, Policies, Cloud Accounts, Access Control, and Integrations is sufficient.

#### Prisma Cloud Compute (CWPP)

The Compute console has its own REST API under `/api/v1/`. The client first calls `POST /api/v1/authenticate` with the access key ID and secret key and sends the returned token as `Authorization: Bearer`; when that fails it falls back to the CSPM JWT in `x-redlock-auth`, the alternate method on the PCEE access page. Only System Admin users (mapped to the Compute Administrator role) can call the Compute API. Read endpoints used: `/defenders`, `/policies/runtime/container`, `/policies/compliance/container`, `/policies/compliance/host`, `/policies/vulnerability/images`, `/settings/registry`, `/registry`, `/images`, `/stats/vulnerabilities`, `/stats/compliance`, `/cloud/discovery`, and `/scans`. List endpoints are paged with `limit` and `offset` (50 per page, 500 records per surface) and truncation is recorded and downgrades the verdict.

### PAN-OS firewalls and Panorama

| Variable | Purpose |
|---|---|
| `PANOS_HOST` | One or more management hostnames or IPs, comma-separated. Panorama is detected automatically from `show system info`. |
| `PANOS_API_KEY` | Pre-generated API key. Sent in the `X-PAN-KEY` header, never in the URL. |
| `PANOS_USERNAME`, `PANOS_PASSWORD` | Alternative to the API key: the client generates one with `type=keygen` (credentials are sent in the POST body). |
| `PANOS_VERIFY_TLS` | Defaults to `true`. Set to `false` only for lab devices with self-signed certificates. The opt-out is scoped to the PAN-OS clients, which then use a `node:https` transport with `rejectUnauthorized: false`; Prisma Cloud requests and every other integration in the process keep certificate verification, and `NODE_TLS_REJECT_UNAUTHORIZED` is never touched. Prefer `NODE_EXTRA_CA_CERTS` with the device CA instead. |

Use a read-only administrator (the built-in `superreader` or a custom admin role with XML API `Configuration` and `Operational Requests` read permissions). Nothing in this integration issues `set`, `edit`, `delete`, or `commit`.

### Optional config file

`PALOALTO_CONFIG_FILE` (or `~/.grclanker/paloalto.json`) may hold the same keys as the environment variables in a flat JSON object. Precedence is explicit tool arguments, then environment variables, then the config file. `PALOALTO_TIMEOUT` (seconds) overrides the 30-second HTTP timeout.

## Tools

| Tool | What it does |
|---|---|
| `paloalto_check_access` | Probes every read surface per product (8 Prisma Cloud CSPM endpoints, 8 Compute console surfaces when the console is reachable, `show system info`, `show high-availability state`, and the configuration subtrees for each device) and reports `healthy`, `degraded`, or `unconfigured` with the exact error for each missing permission. |
| `paloalto_assess_cloud_posture` | Prisma Cloud CSPM controls 1 to 6 plus the Compute (CWPP) controls 7 to 11, 24, and 25, evaluated from the Compute API when the console is reachable and reported as manual findings otherwise. |
| `paloalto_assess_firewall_policy` | PAN-OS controls 12 to 14: any/any and shadowed rules, session-end logging, zones and zone protection, default rule actions, decryption coverage, and SSL/TLS service profile minimum versions. |
| `paloalto_assess_threat_prevention` | Controls 16 to 18, 21, and 22: antivirus, anti-spyware, vulnerability, WildFire, URL filtering and credential phishing, data loss prevention (Prisma Cloud data policies plus PAN-OS data filtering), and file blocking. |
| `paloalto_assess_device_hardening` | Controls 15, 19, 20, and 23: GlobalProtect, administrators and password complexity (PAN-OS plus Prisma Cloud roles), logging and SIEM forwarding, system hardening, plus supplementary HA state (`PA-HA-01`) and software version (`PA-SW-01`) findings. |
| `paloalto_export_audit_bundle` | Runs everything and writes `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log` (only on partial failure), and a zip archive under `./export/paloalto` by default. |

All tools accept the same authentication arguments (`prisma_api_url`, `prisma_access_key_id`, `prisma_secret_key`, `panos_hosts`, `panos_api_key`, `panos_username`, `panos_password`, `config_file`, `verify_tls`, `timeout_seconds`). Tunables: `alert_limit` and `min_compliance_pass_rate` (cloud posture, export) and `max_superusers` (device hardening, export).

## Control coverage

Status semantics: `pass` means the evidence satisfied the check, `warn` means partial evidence or a heuristic concern, `fail` means the evidence contradicted the control, and `manual` means the control cannot be verified through the configured APIs and the summary states the evidence a human must collect.

Verdict-safety rules applied to every finding:

- An unreadable, forbidden (401/403), or errored endpoint or PAN-OS error response yields `manual` with the cause and the evidence to collect, never `pass`.
- Empty inventories never pass by default. Each summary states whether emptiness is treated as `fail` (for example zero alert rules, zero cloud accounts, zero Defenders, zero threat profiles) or `manual` (zero evaluated resources, zero IAM policies, zero security rules, zero zones, zero admins, zero registries, zero cloud discovery entries). The one compliant emptiness is control 5: zero open network exposure alerts passes only when enabled network policies exist and the alert list was read completely.
- Scoped-out, disabled, or unlicensed controls (GlobalProtect not configured, IAM Security not visible, Compute console not reachable) render as `manual`.
- Items without a date (Defenders without `lastModified`, images or registry scans without `scanTime`, CI scans without `time`, devices without `sw-version`) are reported in their own bucket and cap the verdict at `warn`.
- Partial inventories (one device of several unreachable, a truncated alert page, a truncated Compute list) flag the partial view with seen and total counts instead of passing.
- Enabling flags are read explicitly: `enabled=true`, `connected=true`, `disabled!=true`, `log-end=yes`, HA `enabled=yes`. An absent or false flag never supports `pass`; an implicit `log-end` default is reported separately and caps at `warn`.
- Alert pagination follows `nextPageToken` to completion or records truncation at `alert_limit` and downgrades the verdict.
- Export reruns allocate a new directory and derive the zip name from it, so a prior bundle is never overwritten.

| # | Control | Tool | Finding | How it is evaluated |
|---|---|---|---|---|
| 1 | CSPM compliance posture | cloud_posture | PA-01 | `GET /v2/compliance/posture` pass rate against `min_compliance_pass_rate` (default 90%). |
| 2 | Alert policy coverage | cloud_posture | PA-02 | `GET /v2/alert/rule` enabled versus disabled rules, open critical alerts from `GET /v2/alert`. |
| 3 | IAM overprivileged access | cloud_posture | PA-03 | IAM policies from `GET /v2/policy` and open alerts with `policyType=iam`; manual when the CIEM module is not visible. |
| 4 | Cloud account governance | cloud_posture | PA-04 | `GET /cloud` and `GET /cloud/group`: disabled accounts, accounts without groups, error status. |
| 5 | Network exposure analysis | cloud_posture | PA-05 | Open alerts with `policyType=network` or exposure keywords; fails on critical or high, manual when no enabled network policy exists. |
| 6 | Encryption at rest | cloud_posture | PA-06 | Enabled encryption policies and open encryption alerts. |
| 7 | Container image vulnerability | cloud_posture | PA-07 | Compute `GET /policies/vulnerability/images` enabled rules with a block or prevent effect, `GET /stats/vulnerabilities` critical CVE count, `GET /images` scan freshness. Manual when the console is unreachable. |
| 8 | Host compliance posture | cloud_posture | PA-08 | Compute `GET /policies/compliance/host` and `/container` enabled rules plus `GET /stats/compliance` compliance rate (below 90% fails). |
| 9 | Runtime protection policies | cloud_posture | PA-09 | Compute `GET /policies/runtime/container` enabled rules; passes only when at least one rule prevents or blocks a process, network, file system, or DNS behavior. |
| 10 | Defender deployment coverage | cloud_posture | PA-10 | Compute `GET /defenders`: any Defender without `connected=true` fails; missing `lastModified` or more than two versions warn. |
| 11 | Registry scanning configuration | cloud_posture | PA-11 | Compute `GET /settings/registry` specifications and `GET /registry` scan results; zero registries is manual, registries without scans fail. |
| 12 | Firewall security rule audit | firewall_policy | PA-12 | Any/any allow rules fail; shadowed rules, `log-end=no`, or rules without an explicit `log-end` warn; zero rules is manual. |
| 13 | Zone segmentation | firewall_policy | PA-13 | Any-zone allow rules fail; `intrazone-default` not denied, `interzone-default` not logged, or zones without a zone protection profile warn. |
| 14 | SSL/TLS decryption coverage | firewall_policy | PA-14 | No enabled `decrypt` rules fails; SSL/TLS service profiles below TLS 1.2 warn. |
| 15 | GlobalProtect VPN configuration | device_hardening | PA-15 | Portals or gateways without an authentication profile fail; no MFA-enabled authentication profile or split tunneling warns; GlobalProtect not configured is manual (scoped out). HIP profiles remain a manual review. |
| 16 | Threat prevention profiles | threat_prevention | PA-16 | Missing antivirus, anti-spyware, or vulnerability profiles, or allow rules without them, fail; lenient critical/high actions warn. |
| 17 | WildFire analysis | threat_prevention | PA-17 | No WildFire profile fails; profiles not forwarding any application and any file type, or uncovered allow rules, warn. Cloud connectivity needs `show wildfire status`. |
| 18 | URL filtering enforcement | threat_prevention | PA-18 | Profiles that do not block malware, phishing, and command-and-control fail; disabled credential enforcement or uncovered allow rules warn. |
| 19 | Admin role and access audit | device_hardening | PA-19 | Superusers above `max_superusers` or password complexity disabled fail; local-password-only admins, excess Prisma Cloud System Admin roles, or a single configured product warn; zero readable admins is manual. |
| 20 | Logging and SIEM integration | device_hardening | PA-20 | Rules with `log-end=no` or no syslog/Panorama forwarding fail; implicit `log-end`, missing log forwarding profiles, no Prisma Cloud SIEM integration, or a single configured product warn. |
| 21 | Data loss prevention | threat_prevention | PA-21 | Prisma Cloud data security policies plus PAN-OS data filtering profiles attached to allow rules. |
| 22 | File blocking policies | threat_prevention | PA-22 | No profile blocking PE or all file types fails; uncovered allow rules warn. |
| 23 | System hardening | device_hardening | PA-23 | Missing NTP, default SNMP community, telnet or HTTP management fail; missing banner, permitted IPs, DNS, or idle timeout over 15 minutes warn. |
| 24 | Cloud discovery and shadow IT | cloud_posture | PA-24 | Compute `GET /cloud/discovery`: entries with more `total` than `defended` resources fail; zero entries is manual (discovery credentials not configured). |
| 25 | CI/CD pipeline security | cloud_posture | PA-25 | Compute `GET /scans` CI results; zero scans fail. Caps at `warn` because the admission control policy has no verified public read endpoint (see limitations). |

## Live smoke test

```bash
npm --prefix cli run test:paloalto:live
```

The script exits 0 with a skip message when neither product is configured. Otherwise it runs `paloalto_check_access` and one assessment (cloud posture when Prisma Cloud is configured, firewall policy otherwise).

## Limitations

- Prisma Cloud Compute (CWPP) controls 7 to 11 and 24 are automated when the console is reachable. Control 25 caps at `warn`: CI scan results come from the documented `GET /scans` endpoint, but no admission control (OPA) read endpoint could be located on the public pan.dev CWPP reference, so admission rules remain a manual review. The CSPM `GET /meta_info` page is also not published on pan.dev; the PCEE access guide documents copying the console path from the UI, which is what `PRISMA_COMPUTE_URL` carries.
- Shadow detection is heuristic: a rule is reported as shadowed when an earlier enabled rule in the same rulebase already allows any source, destination, and application for the same zones.
- Software version evaluation flags PAN-OS 9.x and older and missing content versions; end-of-life dates for current releases must be checked against the Palo Alto Networks end-of-life summary.
- WildFire cloud connectivity, GlobalProtect HIP requirements, admin MFA enforcement, and log retention are reported as review items inside the finding summaries.
- Disabling TLS verification affects only the PAN-OS clients created for that run (a dedicated `node:https` transport). The process-wide `NODE_TLS_REJECT_UNAUTHORIZED` variable is never set.

## Official documentation

- [Prisma Cloud Compute API: Access the PCEE APIs](https://pan.dev/prisma-cloud/api/cwpp/access-api-saas/)
- [Prisma Cloud Compute API: Get Deployed Defenders](https://pan.dev/prisma-cloud/api/cwpp/get-defenders/)
- [Prisma Cloud Compute API: Get Runtime Container Policy](https://pan.dev/prisma-cloud/api/cwpp/get-policies-runtime-container/)
- [Prisma Cloud Compute API: Get Container Compliance Policy](https://pan.dev/prisma-cloud/api/cwpp/get-policies-compliance-container/)
- [Prisma Cloud Compute API: Get Host Compliance Policy](https://pan.dev/prisma-cloud/api/cwpp/get-policies-compliance-host/)
- [Prisma Cloud Compute API: Get Image Vulnerability Policy](https://pan.dev/prisma-cloud/api/cwpp/get-policies-vulnerability-images/)
- [Prisma Cloud Compute API: Get Registry Settings](https://pan.dev/prisma-cloud/api/cwpp/get-settings-registry/)
- [Prisma Cloud Compute API: Get Registry Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-registry/)
- [Prisma Cloud Compute API: Get Image Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-images/)
- [Prisma Cloud Compute API: Get Vulnerability Stats](https://pan.dev/prisma-cloud/api/cwpp/get-stats-vulnerabilities/)
- [Prisma Cloud Compute API: Get Compliance Stats](https://pan.dev/prisma-cloud/api/cwpp/get-stats-compliance/)
- [Prisma Cloud Compute API: Get Cloud Discovery Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-cloud-discovery/)
- [Prisma Cloud Compute API: Get All CI Image Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-scans/)
- [Prisma Cloud CSPM API: Login](https://pan.dev/prisma-cloud/api/cspm/app-login/)
- [Prisma Cloud CSPM API: Refresh Session](https://pan.dev/prisma-cloud/api/cspm/extend-session/)
- [Prisma Cloud CSPM API: API URLs](https://pan.dev/prisma-cloud/api/cspm/api-urls/)
- [Prisma Cloud CSPM API: Rate Limits](https://pan.dev/prisma-cloud/api/cspm/rate-limits/)
- [Prisma Cloud CSPM API: Compliance Posture V2](https://pan.dev/prisma-cloud/api/cspm/get-compliance-posture-v-2/)
- [Prisma Cloud CSPM API: List Alert Rules V2](https://pan.dev/prisma-cloud/api/cspm/get-alert-rules-v-2/)
- [Prisma Cloud CSPM API: List Alerts V2](https://pan.dev/prisma-cloud/api/cspm/get-alerts-v-2/)
- [Prisma Cloud CSPM API: List Policies V2](https://pan.dev/prisma-cloud/api/cspm/get-policies-v-2/)
- [Prisma Cloud CSPM API: Get all Cloud Accounts](https://pan.dev/prisma-cloud/api/cspm/get-cloud-accounts/)
- [Prisma Cloud CSPM API: List Account Groups](https://pan.dev/prisma-cloud/api/cspm/get-account-groups/)
- [Prisma Cloud CSPM API: List User Roles](https://pan.dev/prisma-cloud/api/cspm/get-user-roles/)
- [PAN-OS XML API Request Types and Actions](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-xml-api-request-types)
- [PAN-OS and Panorama API guide](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api)
