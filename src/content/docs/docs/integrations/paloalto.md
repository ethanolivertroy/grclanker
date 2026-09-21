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

The client sends `POST /login` with the access key ID as `username` and the secret key as `password`, then reuses the returned JWT in the `x-redlock-auth` header. Tokens are refreshed by logging in again before the ten-minute expiry, and a `401` triggers one re-login. `429` and `5xx` responses are retried with exponential backoff (honoring `Retry-After`). The access key inherits the permission group of the user who created it; a read-only role such as **Account Group Read Only** or a custom permission group with read access to Compliance, Alerts, Policies, Cloud Accounts, Access Control, and Integrations is sufficient.

### PAN-OS firewalls and Panorama

| Variable | Purpose |
|---|---|
| `PANOS_HOST` | One or more management hostnames or IPs, comma-separated. Panorama is detected automatically from `show system info`. |
| `PANOS_API_KEY` | Pre-generated API key. Sent in the `X-PAN-KEY` header, never in the URL. |
| `PANOS_USERNAME`, `PANOS_PASSWORD` | Alternative to the API key: the client generates one with `type=keygen` (credentials are sent in the POST body). |
| `PANOS_VERIFY_TLS` | Defaults to `true`. Set to `false` only for lab devices with self-signed certificates; the run then records that verification was disabled. Prefer `NODE_EXTRA_CA_CERTS` with the device CA instead. |

Use a read-only administrator (the built-in `superreader` or a custom admin role with XML API `Configuration` and `Operational Requests` read permissions). Nothing in this integration issues `set`, `edit`, `delete`, or `commit`.

### Optional config file

`PALOALTO_CONFIG_FILE` (or `~/.grclanker/paloalto.json`) may hold the same keys as the environment variables in a flat JSON object. Precedence is explicit tool arguments, then environment variables, then the config file. `PALOALTO_TIMEOUT` (seconds) overrides the 30-second HTTP timeout.

## Tools

| Tool | What it does |
|---|---|
| `paloalto_check_access` | Probes every read surface per product (8 Prisma Cloud endpoints, `show system info`, `show high-availability state`, and the configuration subtrees for each device) and reports `healthy`, `degraded`, or `unconfigured` with the exact error for each missing permission. |
| `paloalto_assess_cloud_posture` | Prisma Cloud controls 1 to 6, plus manual findings for the Compute (CWPP) controls 7 to 11, 24, and 25. |
| `paloalto_assess_firewall_policy` | PAN-OS controls 12 to 14: any/any and shadowed rules, session-end logging, zones and zone protection, default rule actions, decryption coverage, and SSL/TLS service profile minimum versions. |
| `paloalto_assess_threat_prevention` | Controls 16 to 18, 21, and 22: antivirus, anti-spyware, vulnerability, WildFire, URL filtering and credential phishing, data loss prevention (Prisma Cloud data policies plus PAN-OS data filtering), and file blocking. |
| `paloalto_assess_device_hardening` | Controls 15, 19, 20, and 23: GlobalProtect, administrators and password complexity (PAN-OS plus Prisma Cloud roles), logging and SIEM forwarding, system hardening, plus supplementary HA state (`PA-HA-01`) and software version (`PA-SW-01`) findings. |
| `paloalto_export_audit_bundle` | Runs everything and writes `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log` (only on partial failure), and a zip archive under `./export/paloalto` by default. |

All tools accept the same authentication arguments (`prisma_api_url`, `prisma_access_key_id`, `prisma_secret_key`, `panos_hosts`, `panos_api_key`, `panos_username`, `panos_password`, `config_file`, `verify_tls`, `timeout_seconds`). Tunables: `alert_limit` and `min_compliance_pass_rate` (cloud posture, export) and `max_superusers` (device hardening, export).

## Control coverage

Status semantics: `pass` means the evidence satisfied the check, `warn` means partial evidence or a heuristic concern, `fail` means the evidence contradicted the control, and `manual` means the control cannot be verified through the configured APIs and the summary states the evidence a human must collect.

| # | Control | Tool | Finding | How it is evaluated |
|---|---|---|---|---|
| 1 | CSPM compliance posture | cloud_posture | PA-01 | `GET /v2/compliance/posture` pass rate against `min_compliance_pass_rate` (default 90%). |
| 2 | Alert policy coverage | cloud_posture | PA-02 | `GET /v2/alert/rule` enabled versus disabled rules, open critical alerts from `GET /v2/alert`. |
| 3 | IAM overprivileged access | cloud_posture | PA-03 | IAM policies from `GET /v2/policy` and open alerts with `policyType=iam`; warns when the CIEM module is not visible. |
| 4 | Cloud account governance | cloud_posture | PA-04 | `GET /cloud` and `GET /cloud/group`: disabled accounts, accounts without groups, error status. |
| 5 | Network exposure analysis | cloud_posture | PA-05 | Open alerts with `policyType=network` or exposure keywords; fails on critical or high. |
| 6 | Encryption at rest | cloud_posture | PA-06 | Enabled encryption policies and open encryption alerts. |
| 7 | Container image vulnerability | cloud_posture | PA-07 | `manual` (Compute console evidence). |
| 8 | Host compliance posture | cloud_posture | PA-08 | `manual` (Compute console evidence). |
| 9 | Runtime protection policies | cloud_posture | PA-09 | `manual` (Compute console evidence). |
| 10 | Defender deployment coverage | cloud_posture | PA-10 | `manual` (Compute console evidence). |
| 11 | Registry scanning configuration | cloud_posture | PA-11 | `manual` (Compute console evidence). |
| 12 | Firewall security rule audit | firewall_policy | PA-12 | Any/any allow rules fail; shadowed rules and rules without `log-end` warn. |
| 13 | Zone segmentation | firewall_policy | PA-13 | Any-zone allow rules fail; `intrazone-default` not denied, `interzone-default` not logged, or zones without a zone protection profile warn. |
| 14 | SSL/TLS decryption coverage | firewall_policy | PA-14 | No enabled `decrypt` rules fails; SSL/TLS service profiles below TLS 1.2 warn. |
| 15 | GlobalProtect VPN configuration | device_hardening | PA-15 | Portals or gateways without an authentication profile fail; no MFA-enabled authentication profile or split tunneling warns. HIP profiles remain a manual review. |
| 16 | Threat prevention profiles | threat_prevention | PA-16 | Missing antivirus, anti-spyware, or vulnerability profiles, or allow rules without them, fail; lenient critical/high actions warn. |
| 17 | WildFire analysis | threat_prevention | PA-17 | No WildFire profile fails; profiles not forwarding any application and any file type, or uncovered allow rules, warn. Cloud connectivity needs `show wildfire status`. |
| 18 | URL filtering enforcement | threat_prevention | PA-18 | Profiles that do not block malware, phishing, and command-and-control fail; disabled credential enforcement or uncovered allow rules warn. |
| 19 | Admin role and access audit | device_hardening | PA-19 | Superusers above `max_superusers` or password complexity disabled fail; local-password-only admins or excess Prisma Cloud System Admin roles warn. |
| 20 | Logging and SIEM integration | device_hardening | PA-20 | Rules without `log-end` or no syslog/Panorama forwarding fail; missing log forwarding profiles or no Prisma Cloud SIEM integration warn. |
| 21 | Data loss prevention | threat_prevention | PA-21 | Prisma Cloud data security policies plus PAN-OS data filtering profiles attached to allow rules. |
| 22 | File blocking policies | threat_prevention | PA-22 | No profile blocking PE or all file types fails; uncovered allow rules warn. |
| 23 | System hardening | device_hardening | PA-23 | Missing NTP, default SNMP community, telnet or HTTP management fail; missing banner, permitted IPs, DNS, or idle timeout over 15 minutes warn. |
| 24 | Cloud discovery and shadow IT | cloud_posture | PA-24 | `manual` (Compute console evidence). |
| 25 | CI/CD pipeline security | cloud_posture | PA-25 | `manual` (Compute console evidence). |

## Live smoke test

```bash
npm --prefix cli run test:paloalto:live
```

The script exits 0 with a skip message when neither product is configured. Otherwise it runs `paloalto_check_access` and one assessment (cloud posture when Prisma Cloud is configured, firewall policy otherwise).

## Limitations

- Prisma Cloud Compute (CWPP) is not queried: controls 7 to 11, 24, and 25 are always manual findings. The Compute console URL and its separate API are not part of the spec's environment variables.
- Shadow detection is heuristic: a rule is reported as shadowed when an earlier enabled rule in the same rulebase already allows any source, destination, and application for the same zones.
- Software version evaluation flags PAN-OS 9.x and older and missing content versions; end-of-life dates for current releases must be checked against the Palo Alto Networks end-of-life summary.
- WildFire cloud connectivity, GlobalProtect HIP requirements, admin MFA enforcement, and log retention are reported as review items inside the finding summaries.
- Disabling TLS verification applies to the whole grclanker process for that run.

## Official documentation

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
