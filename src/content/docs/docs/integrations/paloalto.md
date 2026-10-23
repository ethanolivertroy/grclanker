---
title: Palo Alto Networks
description: Read-only security inspection of Prisma Cloud CSPM tenants and PAN-OS firewalls or Panorama with framework-mapped findings and evidence bundles.
---

The Palo Alto Networks integration audits two product surfaces without ever mutating a tenant or a device:

- **Prisma Cloud CSPM** through the REST API (JWT login with an access key): Compliance posture, alert rules and open alerts, policies, cloud accounts and account groups, user roles, and tenant integrations (push channels such as Splunk, Amazon SQS, webhooks, and ServiceNow).
- **PAN-OS firewalls and Panorama** through the XML API (`type=op` show commands and `type=config&action=show`): Security and decryption rulebases, zones, security profiles, GlobalProtect, administrators, log forwarding, system settings, HA state, and software versions.

Every finding carries the references from the compliance mapping table in the [Palo Alto Networks Security Inspector spec](/specs/paloalto-sec-inspector/): FedRAMP, CMMC 2.0, SOC 2, CIS, PCI-DSS 4.0, DISA STIG, IRAP, and ISMAP.

## Setup and authentication

Configure one product or both. When only one product is configured, the other product's controls become `manual` findings that state exactly which evidence a human must collect. The three [cross-product controls](#cross-product-controls) are the exception.

### Prisma Cloud

| Variable | Purpose |
|---|---|
| `PRISMA_API_URL` | Regional API URL, for example `https://api2.prismacloud.io` or `https://api.eu.prismacloud.io` (defaults to `https://api.prismacloud.io`). Use the API URL that matches your console URL. |
| `PRISMA_ACCESS_KEY_ID` | Access key ID created under Settings > Access Control > Access Keys. |
| `PRISMA_SECRET_KEY` | Secret key for that access key. |
| `PRISMA_COMPUTE_URL` | Optional Prisma Cloud Compute console path (Compute > Manage > System > Utilities > Path to Console). When unset, the CSPM `GET /meta_info` response field `twistlockUrl` is used; if neither is available, the Compute controls (7 to 11, 24, 25) become manual findings that name this variable. |

The client sends `POST /login` with the access key ID as `username` and the secret key as `password`. It then reuses the returned JWT in the `x-redlock-auth` header.

Tokens are refreshed by logging in again before the ten-minute expiry, and a `401` triggers one re-login. Rate-limited, failing, and timed-out requests are retried a bounded number of times; see [Retries and rate limits](#retries-and-rate-limits).

The access key inherits the permission group of the user who created it. Either of these is sufficient:

- A read-only role such as Account Group Read Only.
- A custom permission group with read access to Compliance, Alerts, Policies, Cloud Accounts, Access Control, and Integrations.

#### Prisma Cloud Compute (CWPP)

The Compute console has its own REST API under `/api/v1/`.

The client first calls `POST /api/v1/authenticate` with the access key ID and secret key, and sends the returned token as `Authorization: Bearer`. When that request answers without a token, it falls back to the CSPM JWT in `x-redlock-auth`, the alternate method on the PCEE access page. When it gets no answer at all after its retries, the Compute read that needed it fails and that surface is unreadable.

Only System Admin users (mapped to the Compute Administrator role) can call the Compute API.

Read endpoints used: `/defenders`, `/policies/runtime/container`, `/policies/compliance/container`, `/policies/compliance/host`, `/policies/vulnerability/images`, `/settings/registry`, `/registry`, `/images`, `/stats/vulnerabilities`, `/stats/compliance`, `/cloud/discovery`, and `/scans`.

### PAN-OS firewalls and Panorama

| Variable | Purpose |
|---|---|
| `PANOS_HOST` | One or more management hostnames or IPs, comma-separated. Panorama is detected automatically from `show system info`. |
| `PANOS_API_KEY` | Pre-generated API key. Sent in the `X-PAN-KEY` header, never in the URL. |
| `PANOS_USERNAME`, `PANOS_PASSWORD` | Alternative to the API key: the client generates one with `type=keygen` (credentials are sent in the POST body). |
| `PANOS_VERIFY_TLS` | Defaults to `true`. Set to `false` only for lab devices with self-signed certificates. The opt-out is scoped to the PAN-OS clients, which then use a `node:https` transport with `rejectUnauthorized: false`; Prisma Cloud requests and every other integration in the process keep certificate verification, and `NODE_TLS_REJECT_UNAUTHORIZED` is never touched. Prefer `NODE_EXTRA_CA_CERTS` with the device CA instead. |

Use a read-only administrator: the built-in `superreader`, or a custom admin role with XML API `Configuration` and `Operational Requests` read permissions. Nothing in this integration issues `set`, `edit`, `delete`, or `commit`.

### Optional config file

`PALOALTO_CONFIG_FILE` (or `~/.grclanker/paloalto.json`) may hold the endpoint, credential, host, and TLS keys listed below in a flat JSON object.

Precedence is explicit tool arguments, then environment variables, then the config file, resolved per value. When `PANOS_USERNAME` and `PANOS_PASSWORD` both come from a higher-precedence source than `PANOS_API_KEY`, the client runs keygen and ignores the key. For example, both are arguments while the key sits in the environment.

The HTTP timeout defaults to 30 seconds and covers reading the response body as well as the headers. It comes only from the `timeout_seconds` argument or the `PALOALTO_TIMEOUT` environment variable (seconds). The config file does not set it.

The file accepts exactly these keys. The environment variable spelling is read first, and the lowercase argument spelling is the fallback.

- `PRISMA_API_URL` or `prisma_api_url`
- `PRISMA_ACCESS_KEY_ID` or `prisma_access_key_id`
- `PRISMA_SECRET_KEY` or `prisma_secret_key`
- `PRISMA_COMPUTE_URL` or `prisma_compute_url`
- `PANOS_HOST` or `panos_hosts` (not `panos_host`)
- `PANOS_API_KEY` or `panos_api_key`
- `PANOS_USERNAME` or `panos_username`
- `PANOS_PASSWORD` or `panos_password`
- `PANOS_VERIFY_TLS` or `verify_tls`

When the file has both TLS keys, `PANOS_VERIFY_TLS` is used.

The `PANOS_VERIFY_TLS` environment value and either config-file TLS key accept these case-insensitive spellings: `true`/`false`, `1`/`0`, `yes`/`no`, `enabled`/`disabled`, and `on`/`off`. Config files also accept native JSON booleans, so `"verify_tls": false` disables verification for a self-signed lab device.

An invalid value at any source keeps TLS verification enabled instead of falling through to a lower-precedence opt-out.

A file named explicitly (the `config_file` argument or `PALOALTO_CONFIG_FILE`) must be readable and parse. The default path is skipped silently when absent.

Loader errors use fixed text and never quote the file:

- A read failure reports `Unable to read Palo Alto config file <path> (<CODE>)` with only the errno code (`ENOENT`, `EACCES`, `EISDIR`).
- A parse failure reports `Unable to parse Palo Alto config file: invalid JSON in <path> at line N (INVALID_JSON)`, with the line derived from the parser's position only.
- A file that is not a JSON object reports `INVALID_CONFIG_SHAPE`.

Neither the filesystem message nor the `JSON.parse` message is ever interpolated. The `JSON.parse` message quotes a window of the source around the failure. Because neither is interpolated, an unquoted or misplaced credential in a malformed file cannot leak through the error.

## Run it

After setup, start `grclanker` and ask in plain words. The agent calls the matching tools, for example:

```text
Check whether my Palo Alto credentials can read everything grclanker needs.
Run the Palo Alto assessments and list the failing findings first.
Export a Palo Alto audit bundle.
```

For a posture readout or a framework mapping, use the [assess](/docs/workflows/assess/) or [audit](/docs/workflows/audit/) workflow, for example `grclanker assess "our Prisma Cloud tenant and PAN-OS firewalls"`. Both start with `paloalto_check_access`, then run the assessments or `paloalto_export_audit_bundle`.

## Tools

<!-- The probe counts and surface names in the paloalto_check_access row are asserted against checkPaloaltoAccess (cli/extensions/grc-tools/paloalto.ts) by cli/tests/paloalto.test.mjs; change the code and this row together. -->

| Tool | What it does |
|---|---|
| `paloalto_check_access` | Probes every read surface per product and reports `healthy`, `degraded`, or `unconfigured` with the scrubbed error for each missing permission. It reports `failed` instead when every probe is refused for its credential: Prisma Cloud answers `401`, at `POST /login` or on each probe, and PAN-OS answers `401` or its documented `Invalid Credential` error (code `403`), at keygen or on each probe. The `failed` next step names each refused credential and the variables to fix. The probes are the 8 Prisma Cloud CSPM endpoints (`compliance_posture`, `alert_rules`, `open_alerts`, `policies`, `cloud_accounts`, `account_groups`, `user_roles`, `integrations`), the 9 Compute console surfaces when the console is reachable (`defenders`, `runtime_container_policy`, `compliance_container_policy`, `compliance_host_policy`, `vulnerability_image_policy`, `registry_settings`, `vulnerability_stats`, `cloud_discovery`, `ci_scans`), and, per PAN-OS device, `show system info`, `show high-availability state`, and the configuration subtrees for its platform. Paged Compute probes (`defenders`, `cloud_discovery`, `ci_scans`) that stop at the page cap are marked `partial`, their counts render with a trailing `+` as lower bounds, and a note says so; the counts are never presented as inventory totals. |
| `paloalto_assess_cloud_posture` | Prisma Cloud CSPM controls 1 to 6 plus the Compute (CWPP) controls 7 to 11, 24, and 25, evaluated from the Compute API when the console is reachable and reported as manual findings otherwise. |
| `paloalto_assess_firewall_policy` | PAN-OS controls 12 to 14: any/any and shadowed rules, session-end logging, zones and zone protection, default rule actions, decryption coverage, and SSL/TLS service profile minimum versions. |
| `paloalto_assess_threat_prevention` | Controls 16 to 18, 21, and 22: antivirus, anti-spyware, vulnerability, WildFire, URL filtering and credential phishing, data loss prevention (Prisma Cloud data policies plus PAN-OS data filtering), and file blocking. |
| `paloalto_assess_device_hardening` | Controls 15, 19, 20, and 23: GlobalProtect, administrators and password complexity (PAN-OS plus Prisma Cloud roles), logging and SIEM forwarding, system hardening, plus supplementary HA state (`PA-HA-01`) and software version (`PA-SW-01`) findings. |
| `paloalto_export_audit_bundle` | Runs everything and writes the audit bundle and a zip archive. |

`paloalto_export_audit_bundle` writes these outputs under `./export/paloalto` by default:

- `core_data/`
- `analysis/`
- `compliance/`
- `QUICK_REFERENCE.md`
- `_errors.log` (only on partial failure)
- A zip archive

`core_data/` is not a verbatim dump:

- The PAN-OS configuration is stored with credential-bearing nodes (`phash`, `password`, `secret`, `key` and `pre-shared-key`, `private-key`, `passphrase`, `token`, SNMPv3 `authpwd` and `privpwd`, `snmp-community-string`, and similar names) replaced by `[REDACTED]`.
  - Names are matched in kebab-case, snake_case, camelCase, and attribute forms.
  - Settings such as `password-complexity` and `public-key` are kept.
  - The assessments still evaluate the raw values in memory.
- The Prisma Cloud and Compute JSON in `core_data/prisma_cloud.json` is redacted as it is collected.
  - Every property whose name's last segment denotes a credential (`authToken`, `password`, `clientSecret`, `api_key`, `secret_key`, `private_key`, `credentials`, and similar, in snake_case or camelCase) is replaced whole. A bare `key` and `public_key` are kept.
  - Because the property is replaced whole, an integration's `integrationConfig` secrets, a Compute registry credential block, or an image `secrets` list never leak a nested child.
  - `{key, value}` header pairs flagged `secure` lose their `value`. So do pairs labelled with a credential name in either the walker's vocabulary (`Authorization`, `X-Api-Key`) or the error-text rules' (`x-redlock-auth`, `X-Auth`, `Cookie`, `X-PAN-KEY`), whatever the `secure` flag says. A benign unflagged pair (`X-Trace`, `Content-Type`) keeps its `value`.
  - Every remaining string is scrubbed of URL query credentials (the parameters named `token` and `api_key`, among others) and of the user-and-secret prefix before the host in a URL. It is also scrubbed of Slack, Discord, and Teams token-in-path webhook URLs and of JSON-encoded credential fields.
  - The assessments read the same redacted copy, so nothing a finding or tool result carries can differ from the bundle.

### Arguments and tunables

All tools accept the same authentication arguments: `prisma_api_url`, `prisma_access_key_id`, `prisma_secret_key`, `panos_hosts`, `panos_api_key`, `panos_username`, `panos_password`, `config_file`, `verify_tls`, and `timeout_seconds`.

Tunables:

- `alert_limit` (default 500, clamped to 1-10000): For cloud posture and export.
- `min_compliance_pass_rate` (default 90, clamped to 1-100): For cloud posture and export.
- `max_superusers` (default 3, clamped to 0-1000): For device hardening and export.

`paloalto_export_audit_bundle` also takes `output_dir` (default `./export/paloalto`).

### Audit bundle naming

The bundle directory is named `<host>-audit-bundle` (for example `api.prismacloud.io-audit-bundle`), with `<name>.zip` beside it. The host is the Prisma Cloud API hostname when Prisma Cloud is configured, and otherwise the first PAN-OS host.

A repeat run takes the suffixes `-2` through `-6`, skipping any name whose directory or zip already exists. It fails once all six are taken.

## Control coverage

Verdicts on unread, partial, or truncated data follow the [verdict-safety rules](#verdict-safety-rules).

Status semantics:

- `pass`: The evidence satisfied the check.
- `warn`: Partial evidence or a heuristic concern.
- `fail`: The evidence contradicted the control.
- `manual`: The control cannot be verified through the configured APIs, and the summary states the evidence a human must collect.

### Cross-product controls

Most controls read one product and become `manual` when that product is not configured. The cross-product controls, PA-19 (admin roles), PA-20 (logging and SIEM), and PA-21 (data loss prevention), evaluate whichever product is configured and cap at `warn` when only one is. As a result, a single configured product that is compliant renders `warn`, not `manual` and not `pass`.

The verdict for a non-compliant product depends on the finding:

- **PA-21:** Fails when no configured product is compliant, whichever product that is.
  - A Prisma Cloud tenant alone with no enabled data security policy fails.
  - A PAN-OS estate alone with no data filtering profile attached to an allow rule fails too.
  - PA-21 warns when one of two configured products is compliant.
- **PA-19 and PA-20:** Fail only on their PAN-OS half. A non-compliant Prisma Cloud half warns, so a Prisma Cloud tenant alone never renders worse than `warn` on those two.
  - PAN-OS half: Superusers above the threshold or password complexity disabled (PA-19), and rules with `log-end=no` or no syslog or Panorama forwarding (PA-20).
  - Prisma Cloud half: System Admin roles above the threshold or zero roles returned (PA-19), and no SIEM integration (PA-20).

The `manual` cases are:

- The absence of both products.
- A failed read of a surface the finding depends on (the partial-view rule under [Unreadable surfaces](#unreadable-surfaces)).
- For PA-19, zero readable PAN-OS administrators.

### Per-control evaluation

| # | Control | Tool | Finding | How it is evaluated |
|---|---|---|---|---|
| 1 | CSPM compliance posture | cloud_posture | PA-01 | `GET /v2/compliance/posture` pass rate against `min_compliance_pass_rate` (default 90%). |
| 2 | Alert policy coverage | cloud_posture | PA-02 | `GET /v2/alert/rule` and open alerts from `GET /v2/alert`: zero alert rules or zero rules with `enabled=true` fail; disabled rules or open critical alerts warn; a truncated alert list caps at `warn`; manual when either read fails. |
| 3 | IAM overprivileged access | cloud_posture | PA-03 | IAM policies from `GET /v2/policy` and open alerts with `policyType=iam`; manual when the CIEM module is not visible. The documented `POST /api/v1/permission` query is not used because it needs a caller-written IAM RQL definition of "overprivileged" (see limitations). |
| 4 | Cloud account governance | cloud_posture | PA-04 | `GET /cloud` and `GET /cloud/group`: zero accounts, accounts without `enabled=true`, or accounts in no account group fail; accounts whose `status` reports an error or warning warn; manual when either read fails, with the account or group counts rendered `null`. |
| 5 | Network exposure analysis | cloud_posture | PA-05 | Open alerts with `policyType=network` or exposure keywords; fails on critical or high, manual when no enabled network policy exists. Zero such alerts passes only over an alert walk read to completion; over a truncated walk it is `warn`, the summary says emptiness is not asserted, and the alert counts render `null` in place of `0`. |
| 6 | Encryption at rest | cloud_posture | PA-06 | Policies from `GET /v2/policy` whose name or labels match encryption at rest, and open alerts from `GET /v2/alert`: zero enabled encryption policies or any open encryption alert fails; enabled policies alongside disabled ones warn; a truncated alert list caps at `warn`; manual when either read fails. |
| 7 | Container image vulnerability | cloud_posture | PA-07 | Compute `GET /policies/vulnerability/images` enabled rules with a block or prevent effect; critical and high CVE counts summed from the `cves` distribution of each `images`, `registryImages`, `containers`, `hosts`, and `functions` member in the `GET /stats/vulnerabilities` array, combined with `vulnerabilityDistribution` on `GET /images` scan results (the stricter count is used); any critical CVE fails, images without `scanTime` warn, no distribution at all warns. Manual when the console is unreachable. |
| 8 | Host compliance posture | cloud_posture | PA-08 | Compute `GET /policies/compliance/host` and `/container` enabled rules, `GET /defenders` connected population, and `GET /stats/compliance` where the rate is derived from `rules[]` (or `categories[]`) `failed` versus `total`; below 90% or zero connected Defenders fails, zero recorded evaluations warns. Zero connected Defenders over a truncated Defender walk is `warn` (PA-09 likewise), with `connected_defenders` rendered `null`. |
| 9 | Runtime protection policies | cloud_posture | PA-09 | Compute `GET /policies/runtime/container` enabled rules and `GET /defenders`; passes only when at least one rule prevents or blocks a process, network, file system, or DNS behavior and at least one Defender is connected to enforce it. |
| 10 | Defender deployment coverage | cloud_posture | PA-10 | Compute `GET /defenders`: zero Defenders or any Defender without `connected=true` fails; missing `lastModified` or more than two versions warn. Zero Defenders over a truncated walk is `warn`, and while the walk is truncated or the page carried an unevaluable record the `versions`, `disconnected`, and `without_timestamp` lists render `null` beside their `_count` lower bounds. |
| 11 | Registry scanning configuration | cloud_posture | PA-11 | Compute `GET /settings/registry` specifications and `GET /registry` scan results; zero registries is manual, registries without scans fail (`warn` when the scan walk was truncated before any result arrived). |
| 12 | Firewall security rule audit | firewall_policy | PA-12 | Any/any allow rules fail; shadowed rules, `log-end=no`, or rules without an explicit `log-end` warn; zero rules is manual. |
| 13 | Zone segmentation | firewall_policy | PA-13 | Any-zone allow rules fail; `intrazone-default` not denied, `interzone-default` not logged, or zones without a zone protection profile warn. |
| 14 | SSL/TLS decryption coverage | firewall_policy | PA-14 | No enabled `decrypt` rules fails; SSL/TLS service profiles below TLS 1.2 warn. |
| 15 | GlobalProtect VPN configuration | device_hardening | PA-15 | Portals and gateways are read from the vsys, network, and template trees; the authentication profiles whose `multi-factor-auth/mfa-enable` flag the MFA check reads live there and under `/config/shared`. Portals or gateways without an authentication profile fail; no MFA-enabled authentication profile or split tunneling warns; GlobalProtect not configured is manual (scoped out); manual when any vsys, network, template, or shared configuration read fails on any device, with `mfa_authentication_profiles` rendered `null`. HIP profiles remain a manual review. |
| 16 | Threat prevention profiles | threat_prevention | PA-16 | Missing antivirus, anti-spyware, or vulnerability profiles, or allow rules without them, fail; lenient critical/high actions warn. |
| 17 | WildFire analysis | threat_prevention | PA-17 | No WildFire profile fails; profiles not forwarding any application and any file type, or uncovered allow rules, warn. Cloud connectivity needs `show wildfire status`. |
| 18 | URL filtering enforcement | threat_prevention | PA-18 | Profiles that do not block malware, phishing, and command-and-control fail; disabled credential enforcement or uncovered allow rules warn. |
| 19 | Admin role and access audit | device_hardening | PA-19 | Superusers above `max_superusers` or password complexity disabled fail; local-password-only admins, excess Prisma Cloud System Admin roles, or a single configured product warn; zero readable admins is manual. |
| 20 | Logging and SIEM integration | device_hardening | PA-20 | Rules with `log-end=no` or no syslog/Panorama forwarding fail; implicit `log-end`, missing log forwarding profiles, no Prisma Cloud SIEM integration (from `GET /api/v1/tenant/{prismaId}/integration`), or a single configured product warn. |
| 21 | Data loss prevention | threat_prevention | PA-21 | Prisma Cloud policies with `policyType=data` (or DLP-labelled) from `GET /v2/policy` and PAN-OS data filtering profiles attached to allow rules: passes only when both products are configured and both are compliant (at least one enabled data security policy; at least one profile attached to an allow rule); one compliant product, or a single configured product that is compliant, warns (the exception to the one-product rule above: the unconfigured product does not make this finding `manual`); neither compliant fails; manual when neither product is configured or when the policy list or a rulebase read fails. |
| 22 | File blocking policies | threat_prevention | PA-22 | No profile blocking PE or all file types fails; uncovered allow rules warn. |
| 23 | System hardening | device_hardening | PA-23 | Missing NTP, default SNMP community, telnet or HTTP management fail; missing banner, permitted IPs, DNS, or idle timeout over 15 minutes warn. Supplementary `PA-HA-01` (HA state) and `PA-SW-01` (software and content versions) share control 23 and its CM-6/CM-7 mappings; they appear in a separate section of the unified compliance matrix so the matrix keeps one row per numbered control. |
| 24 | Cloud discovery and shadow IT | cloud_posture | PA-24 | Compute `GET /cloud/discovery`: entries with more `total` than `defended` resources fail; an entry that reports neither `total` nor `defended` is unevaluable and caps the verdict at warn with the count named (`unevaluable_entries`), as does a record without any documented member (`unevaluable_records`); entries reporting `err` warn; zero entries is manual (discovery credentials not configured); an array of records without the documented members is an unreadable surface and renders manual. |
| 25 | CI/CD pipeline security | cloud_posture | PA-25 | Compute `GET /scans` CI results; zero scans fail (`warn` when the scan walk was truncated before any result arrived). Caps at `warn` because the admission control policy has no verified public read endpoint (see limitations). |

## Live smoke test

```bash
npm --prefix cli run test:paloalto:live
```

The script exits 0 with a skip message unless `PRISMA_ACCESS_KEY_ID` and `PRISMA_SECRET_KEY`, or `PANOS_HOST` with `PANOS_API_KEY` (or `PANOS_USERNAME` and `PANOS_PASSWORD`), are set in the environment; a configuration file alone does not start it. Otherwise it runs `paloalto_check_access` and one assessment: cloud posture when Prisma Cloud is configured, firewall policy otherwise. If the access check reports `failed`, the script stops with exit 1 before the assessment and prints the check's next step. It also stops with exit 1 when the check reports `unconfigured`.

## Limitations

- Prisma Cloud Compute (CWPP) controls 7 to 11 and 24 are automated when the console is reachable.
- Control 25 caps at `warn`.
  - CI scan results come from the documented `GET /scans` endpoint.
  - No admission control (OPA) read endpoint could be located on the public pan.dev CWPP reference, so admission rules remain a manual review.
- The CSPM `GET /meta_info` page is also not published on pan.dev. The PCEE access guide documents copying the console path from the UI, which is what `PRISMA_COMPUTE_URL` carries.
- Control 3 uses the tenant's IAM policies and open `iam` alerts as the overprivilege signal.
  - The documented `POST /api/v1/permission` endpoint runs a caller-supplied IAM RQL query and returns raw permission rows.
  - Using it would require this tool to hard-code its own RQL definition of "overprivileged" that cannot be validated without a licensed CIEM tenant.
  - The built-in IAM policies already encode those detections.
  - `GET /api/v1/permission/alert/search` only returns the RQL behind one alert ID.
- Control 2 reads alert rules from `GET /v2/alert/rule`. `GET /alert/policy` (List Alert Counts By Policy) is documented but only returns open alert counts grouped by policy, not rule configuration.
- Control 20 reads push integrations from `GET /api/v1/tenant/{prismaId}/integration`, with the `prismaId` from the login response. `GET /integration` only lists Okta, Qualys, and Tenable pull integrations. It is used as a fallback when no `prismaId` is returned.
- Shadow detection is heuristic. A rule is reported as shadowed when an earlier enabled rule in the same rulebase already allows any source, destination, and application for the same zones.
- Software version evaluation flags PAN-OS 9.x and older, and missing content versions. End-of-life dates for current releases must be checked against the Palo Alto Networks end-of-life summary.
- WildFire cloud connectivity, GlobalProtect HIP requirements, admin MFA enforcement, and log retention are reported as review items inside the finding summaries.
- Disabling TLS verification affects only the PAN-OS clients created for that run (a dedicated `node:https` transport). The process-wide `NODE_TLS_REJECT_UNAUTHORIZED` variable is never set.

## How the tools handle evidence

This section is reference for reviewing findings and bundles: how unread, partial, or truncated data limits a verdict, how the tools page through the API and report incomplete listings, and how credentials are kept out of findings, bundles, and error text. You don't need it to set up or run the integration.

### Redaction and error strings

These configured secrets never appear in tool output, findings, `_errors.log`, or bundle files:

- `PRISMA_SECRET_KEY`, `PRISMA_ACCESS_KEY_ID`, `PANOS_API_KEY`, and `PANOS_PASSWORD`.
- The key `type=keygen` returns.
- The session JWT and Compute token the clients obtain at login.

Every error string is built once and scrubbed at the single sink every collector, access probe, and tool catch block reads through. Redaction runs before any length cap, so a value cut by the cap can never survive as a prefix.

#### Configured URLs

A configured URL (`PRISMA_API_URL`, `PRISMA_COMPUTE_URL`, each `PANOS_HOST`, and the console URL `/meta_info` returns) is reduced at configuration to its scheme, host, port, and path prefix.

- A user-and-secret prefix, query, or fragment is dropped before the first request, so it never leaves in a request URL and never reaches a label.
- Everywhere a configured URL is written, it is written as scheme and host only:
  - `metadata.json` (`prisma_api_url`, `prisma_compute_url`, and the host-and-port labels in `panos_hosts`).
  - The executive summary's `Prisma Cloud:` and `PAN-OS devices:` lines.
  - The access check's `Prisma Cloud API:` and `Prisma Cloud Compute console:` notes and each surface's `target`.
  - `console_url` in `core_data/prisma_cloud.json`.
- The test suite configures both products and the discovered console with a user-and-secret prefix and requires every request, tool result, bundle file, and zip entry free of it.

#### Redaction boundary

The scrub uses one boundary: any value inside a carrier is replaced with `[REDACTED]`, whatever its shape.

Header lines are carriers: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-PAN-KEY`, and `x-redlock-auth` header lines. Each line is redacted by its class:

- **Authorization headers:** An `Authorization` or `Proxy-Authorization` value keeps its scheme word as spelled (`Bearer`, `Basic`, `Digest`, and the other schemes listed below, in any casing). The value loses the one token, or the one quoted string, after the scheme word, so the operator still reads which scheme was replayed. Prose after the token stays.
  - A parameter list after the scheme (`Digest username=..., realm=...`, `AWS4-HMAC-SHA256 Credential=...`) goes whole to the end of the line.
  - A value that opens with anything but a listed scheme word (`GenieKey <token>`, `SharedKey <account>:<signature>`, `Bot <token>`, a bare token) also goes whole to the end of the line, since an unknown first word may be a scheme with its credentials after it.
- **Cookie headers:** A `Cookie`, `Set-Cookie`, or `X-Cookie` line is a list of pairs and goes whole to the end of the line. Cookie attributes such as `Path` and `Expires` therefore go with the cookie.
- **Other headers:** Every other header (`X-Api-Key`, `X-PAN-KEY`, `x-redlock-auth`, `X-Auth-Token`, and the like) carries one token and loses its first token, so a JSON fragment or prose after it on the same line is still read. When its value opens with a listed scheme word (`X-Auth-Token: Bearer <token>`), the header loses the word and the token after it together under one marker.

#### Where a value ends

- In every class, a quoted value (in double, single, or JSON-escaped quotes) ends at its closing quote. It goes with its quotes whatever the name of the cookie or pair that carries it, even when a `; Name:` sits inside the quotes.
- A whole-line value ends at the `;` or `,` before the name of the next header on a compound line, at a line break the stringify left escaped (`\n`, `\r`, `\u000a`), or else at the end of the line. A compound line holds several headers separated by `;` or `,`, and a following header name may hold dots.
  - A quoted value that nothing closes ends as an unquoted one does.
  - The next header keeps its name and gets its own treatment.
  - A `Content-Type` or `Date` after a cookie keeps its name and value.
- A single-token header value, the token after a scheme word, an equals-sign pair value, and a `--flag` value end at whitespace. They also end at any control character the stringify left escaped (`\t`, `\b`, `\f`, `\v`, `\0`, `\u0009` and the other `\u00XX` control codes, `\x09`), as they do at the raw character.
  - A credential pair chained after such an escape (`api_key=<value>\tpassword: <value>`) is read on its own and loses its own value.
  - A count under a plural credential word ends there too (`keys: 3\tcookies: 0` stays).
- Quotes escaped to any depth (`\"` one level down, `\\\"` two) are read at their own depth. A header pair, credential pair, quoted attribute, or quoted assignment inside a JSON body that was stringified into a string value therefore loses its value and keeps its escaped quotes.
- A header name or pair key is read the same right after such an escape (`\nX-PAN-KEY: <value>`, `\tapi_key=<value>`) as at a word boundary.
- A quote inside a token is content of the value it sits in, in a header value, pair value, quoted attribute, or URL query value alike.
  - RFC 6265 lets a cookie name or value carry an apostrophe, so `sid=O'<value>` and a pair named `my'pref` go with their cookie.
  - Only a quote at the end of a token, or one after `=` with nothing but a delimiter or the end behind it (a base64 value ending in `=`), closes the text the line was quoted in. The closing quote and the following members of an enclosing JSON string therefore survive.
- A header line is read before the URL query rule, so a cookie pair whose name holds `&` or `#` goes with its cookie.
- A bare query value never takes a backslash, so `?token=<value>\"` keeps the escaped quote and `?api_key=<value>\nstatus 502` keeps the text after the line break.
- A `;` inside a query value is part of the value, as `URLSearchParams` reads it, so `?token=<value>;<rest>` loses the whole value with no tail. The `;` that ends a cookie pair belongs to the cookie and key-list header lines alone.

#### Other carriers

Values in these carriers are replaced too:

- Cookie and session assignments.
- The user-and-secret prefix before the host in a URL, bare or with its slashes escaped by a stringify (`https:\/\/user:secret@host`). The prefix ends where the authority does, at the first `/`, `?`, or `#`.
  - An `@` inside a query or fragment (`https://h?e=a@x.com&token=<value>`, `https://h#f@x.com`) is not such a prefix.
  - The host `h` stays, and the query is read pair by pair (`&token=` loses its value).
  - A `webhook_url` holding that URL reduces to `https://h/[REDACTED]`.
- The URL query parameters named `token`, `api_key`, `secret`, and `pass`, and the PAN-OS `key` parameter.
- The path and query of a URL under a `webhook` or `webhook_url` key. The URL's origin stays.
- The values after the schemes `Bearer`, `Basic`, `Digest`, `Token`, `OAuth`, `Negotiate`, `NTLM`, `SSWS`, `ApiKey`, `Splunk`, `Snowflake`, and `AWS4-HMAC-SHA256`, in any casing. The scheme word itself stays.
  - Only a listed prose word after the scheme word (`Basic authentication`), an auth-param name (`Bearer realm=`), or, after the nouns `Token`, `OAuth`, `Splunk`, and `Snowflake`, a short plain lowercase word (`Token expired`) is read as prose and stays.
  - A parameter list after the scheme word (`Snowflake Token="<value>"`, `Token token="<value>", nonce="..."`, `Digest username="...", nonce="...", response="..."`) goes whole with the word kept, with or without a header name in front of it and at any escape depth. So a 401 body that echoes the header renders `Snowflake [REDACTED]`.
  - A list made only of challenge parameters (`Bearer realm="api", error="invalid_token"`, the value of a `WWW-Authenticate` header) stays with every value, the `nonce` of `Digest realm="api", qop="auth", nonce="n"` included.
- A parameter list without a scheme word (`realm="api", nonce="n", response="<proof>"`, the value of a `www_authenticate` field or a credential echoed without its scheme word). Such a list is not a challenge when one of its parameters is a proof (`response`, `signature`, `oauth_signature`, `mac`, `sig`).
  - The proof values go whatever their shape and wherever they sit in the list.
  - The challenge parameters beside them keep their values.
  - A list that is a challenge (`realm="api", qop="auth", nonce="n"`) keeps every value.
  - A lone `nonce="..."` is no list and goes as a credential name.
- Credential-named assignment pairs in their three spellings: equals sign, colon, and quoted JSON member.
  - A pair counts wherever the key starts: at a word boundary, after `--`, after a Java `-D`, or after a path slash.
  - The rule also covers `--key value` flags, whose name may open with a letter or an underscore, so `--_zendesk_session <value>` is one.
  - `secret_id`, bearer ids such as `token_id`, and `connection_string` are among the credential names.
- A colon-terminated credential-named key that ends a path segment is a label whose value is at most one token.
  - A singular label (`/etc/app/password: <value> was rejected`, `vault read secret/app/token: <value> has no policy`) takes that token whatever its shape, a random string or a plain word, and whatever follows it, so the text renders `/etc/app/password: [REDACTED] was rejected`.
  - A plural label names a collection (`GET /api/v1/api-tokens: request failed`, `/api/v1/api-tokens: request failed with 403`), so prose continuing after the token means there was no value and the text stays.
  - A lone token after a plural label is removed.
- XML attributes (`password`, `secret`, `token`, `api_key`, `secret_key`, `private_key`, `client_secret`, `phash`, `authpwd`, `privpwd`, `snmp-community-string`, `session_id`, and their camelCase forms).

A scheme word that starts the value of a credential-named key other than `Authorization` (`api_key: Bearer <value>`) is part of the value and goes with it.

#### Configured secrets and token shapes

A configured secret is replaced wherever it appears, whatever its shape, in its base64, base64url, URL-encoded, and JSON-escaped forms too (four characters or longer).

Real token shapes go even when bare in prose:

- Runs of sixteen or more characters with base64 symbols, scattered digits, or token casing.
- Hex digests.
- PAN-OS API keys (the vendor's fixed six-letter prefix followed by the key body).
- JWTs.
- AWS access key ids.
- GitHub, Stripe, and Slack prefixed tokens.
- PEM blocks.

#### Values that stay

These values stay:

- A bare value shaped like a name (words joined by hyphens or underscores with at most one numeric segment, such as `prod-us-east-2026`, `fw-dc1-01`, or `ethernet1/1`) standing alone in prose. It is indistinguishable from a resource name.
- Titles such as `Basic Network Scan`.
- This integration's own vocabulary (`password-complexity`, `credential-enforcement`, `status_code`).
- One value under a credential-named key: a count. A count is a bare integer (digits alone, or digits followed by a space, as in `api_keys: 2 expiring`) under a key whose last word is one of the plural words `tokens`, `secrets`, `keys`, `cookies`, `passwords`, or `credentials`. It stays in each of these spellings:
  - The JSON member spelling (`"api_keys": 2`, `"api_keys": "2"`).
  - The colon spelling (`api_keys: 2`).
  - The equals spelling (`api_keys=2`).

A singular key keeps the rule: `pin: 1234` and `PANOS_PASSWORD=7` lose their values. Any other value under a plural key keeps the rule too: `keys: rotate them` loses its value.

#### Final configured-secret pass

Every bundle file and every tool result passes through the configured-secret pass a final time on its way out. A key echoed by an upstream body therefore cannot survive even where the general scrub would have left evidence alone.

#### Fixed text

The module's own fixed text crosses that boundary intact. The test suite drives every fixed text emitted on refused, failed, and unconfigured paths through the scrub. It requires the text back unchanged.

The fixed texts emitted on those paths are:

- The not-collected markers.
- The non-JSON and non-XML notes.
- The Compute discovery reasons.
- The PAN-OS and Prisma Cloud gate texts.
- The loader messages.

#### Silent-success responses

A 2xx answer that is not the documented document is an unreadable surface, never an empty inventory (the silent-success class).

A Prisma Cloud or Compute 200 with any of the following is described by status, media type, and size only:

- An empty body.
- The HTML page a proxy or SSO portal serves in place of the API.
- A foreign JSON value.
- A JSON object without the documented member (`items`, `policies`, `defenders`, and so on).

For example: `status 200 with a non-JSON text/html response body (1204 bytes, not echoed) where the documented JSON array was expected`.

The answer is recorded with the observed status as a surface that was not read:

- The probe is not readable.
- The dataset carries the not-collected marker.
- The findings that depend on the dataset render manual or capped, never pass on a missing list.

The login answer is held to the same guard. A `POST /login` 200 without the documented `token` member is `status 200 with a JSON response body without the documented "token" member (n bytes, not echoed)`, never a session that silently failed to start.

A PAN-OS 200 without a `<response>` element is the non-XML note above and is treated the same way.

The same guard applies to list records. The array surfaces are alert rules, open alerts, policies, cloud accounts, account groups, user roles, integrations, Defenders, registry scans, images, vulnerability stats, cloud discovery, and CI scans.

Every array surface has a documented member set: the identity and status fields its verdicts read. A 200 array (or one page of a walk) in which no record carries any of them is `status 200 with a JSON array of n records none of which carries any of the documented members "provider", "serviceType", "total", "defended", "err" (n bytes, not echoed)`.

Such an array is an unreadable surface like the shapes above, so `[{"unexpected": true}]` served for cloud discovery leaves PA-24 manual, never pass.

A record without any documented member inside an otherwise documented array is unevaluable:

- The record is kept out of the inventory.
- It is counted in the collection status (`unevaluable_records`).
- It is named by every finding that reads the surface, which caps a pass at warn.
  - For example: `Partial inventory: prisma-compute cloud discovery: 1 of 3 records carry none of the documented members (...) and were not evaluated`.
  - The evidence carries the count under `unevaluable_records`.

The test suite serves each of these in turn to every one of the 39 read surfaces (10 Prisma Cloud, 13 Compute, and 8 per PAN-OS device across two devices):

- An empty 200.
- An HTML 200 carrying credentials.
- A foreign JSON object 200.
- A foreign JSON array 200.

It requires each to leave:

- A not-collected marker with the observed 200.
- An unreadable probe.
- Exactly the verdicts a refusal of the same surface leaves.
- Nothing of the page in any file.

The test suite then serves each of the 13 array surfaces a documented list with one foreign record. It requires the record out of the inventory, the count in the collection status, and every dependent verdict capped with the count named.

#### Error strings

Response bodies are never echoed.

- A Prisma Cloud or Compute error with a non-JSON body (an HTML error page, an SSO interstitial, a WAF block) is described only as `failed ({status}): non-JSON {content-type} response body ({n} bytes, not echoed)`, whatever content type the server claimed.
- A JSON body contributes only Prisma Cloud's documented error fields: `message`, `i18nKey`, `error.message`, Compute's `err`, and the `i18nKey`, `message`, or `subject` entries of the `x-redlock-status` header. Each field is scrubbed before it is shortened to 200 characters.
- A JSON body without those fields is described by length only.
- A PAN-OS response without a `<response>` element is described as `returned a non-XML {content-type} response (status {n}, {n} bytes, not echoed)`.
- An XML error contributes only the `<msg>` or `<line>` text and the response `code`, scrubbed before the 300-character cap.
- A request that ended on a 429, 500, 502, 503, or 504 also names its attempt count, as in `failed after 4 attempts ({status})`, or `(status {n}, {n} bytes, not echoed) after 4 attempts` in the PAN-OS non-XML note. A refused `Retry-After` is named after the detail.
- A timeout or network error that outlasts the retries is described as `failed after 4 attempts (timed out after {n} ms)` or `failed after 4 attempts (network error: {message})`. The error names the request, never its URL.
- A PAN-OS read skipped because its device gave no answer is described as `was not attempted because {host} did not answer an earlier request ({timeout or network error}, after 4 attempts)`; see [Retries and rate limits](#retries-and-rate-limits).

### Retries and rate limits

Every Prisma Cloud, Compute, and PAN-OS request is retried when it gets a 429, 500, 502, 503, or 504, times out, or fails with a network error, up to 3 times after the first attempt. That includes the Prisma Cloud login, the Compute authentication, and PAN-OS keygen.

- The wait before each retry is the server's `Retry-After`, as seconds or an HTTP date, when the response carries one. Otherwise it is 500 milliseconds, doubled after each retry and capped at 8 seconds.
- A `Retry-After` above 30 seconds is not waited out. The request fails at once, and its error names the wait the server asked for.
- Any other 4xx answer, such as 400, 403, or 404, is not retried. A PAN-OS error response is retried only when it arrives with one of those five statuses, so an error reply on a `200` fails at once. A Prisma Cloud `401` triggers the one re-login described under [Prisma Cloud](#prisma-cloud) instead.

A request that runs out of retries fails with the request, the attempt count, and the last status, timeout, or network error, for example `Prisma Cloud GET /v2/policy failed after 4 attempts (503): Service temporarily unavailable`. Its surface is then unreadable and follows the rules below, so no finding that reads it passes:

- A page that fails partway through the alert walk or a Compute walk fails the whole walk, so the pages already read are not reported as the inventory.
- A PAN-OS read that fails on one device leaves that subtree on that device unreadable, and the findings that need it name the device.

Because a timeout is retried, a request to a host that never answers takes four timeouts and 3.5 seconds of waits, about two minutes at the 30-second default, before its surface is reported unreadable.

When a PAN-OS request, keygen included, runs out of retries on a timeout or a network error, that device is not asked again for the rest of the tool call:

- Each of its later reads fails at once without being sent, for example `PAN-OS config show /config/shared was not attempted because fw1.example.com did not answer an earlier request (timed out after 30000 ms, after 4 attempts).`
- Each skipped read is unreadable like any failed read. Its not-collected marker names the request that got no answer, with a `null` status, and no finding passes on that device.
- An HTTP answer of any status skips nothing. A 403, an `Invalid Credential`, a 5xx after its retries, or a refused `Retry-After` means the device answered, so its other reads are still sent.
- Other devices are not affected.

A device that never answers therefore costs about two minutes at the 30-second default in each tool call that reads it (`paloalto_check_access`, an assessment, or `paloalto_export_audit_bundle`), rather than two minutes for each of its reads. The export pays it once, in its access probe, because it collects through the same clients. Lower `timeout_seconds` or `PALOALTO_TIMEOUT` to shorten that wait when a listed device may be offline.

### Verdict-safety rules

These rules apply to every finding.

- An unreadable, forbidden (401/403), or errored endpoint, or a PAN-OS error response, yields `manual` with the cause and the evidence to collect, never `pass`.
- Empty inventories never pass by default. Each summary states whether emptiness is treated as `fail` or `manual`.
  - `fail`: For example zero alert rules, zero cloud accounts, zero Defenders, zero threat profiles.
  - `manual`: Zero evaluated resources, zero IAM policies, zero security rules, zero zones, zero admins, zero registries, zero cloud discovery entries.
  - The one compliant emptiness is control 5. Zero open network exposure alerts passes only when enabled network policies exist and the alert list was read completely.
- Scoped-out, disabled, or unlicensed controls (GlobalProtect not configured, IAM Security not visible, Compute console not reachable) render as `manual`.
- Items without a date are reported in their own bucket and cap the verdict at `warn`:
  - Defenders without `lastModified`
  - Images or registry scans without `scanTime`
  - CI scans without `time`
  - Devices without `sw-version`
- Partial inventories (one device of several unreachable, a truncated alert page, a truncated Compute list) flag the partial view with seen and total counts instead of passing.

#### Incomplete inventories

A truncated walk is an incomplete inventory. So is a surface some of whose records were kept out as unevaluable (records without any documented member, counted under `unevaluable_records`). A verdict over either says only what the records seen support.

A count over an incomplete surface is a lower bound. A positive count renders as observed. A count of zero renders `null` rather than `0`, because the unread or unevaluated remainder may hold what the seen records did not:

- `defenders: null` under a truncated Defender walk that delivered no record.
- `open_alerts.count: null` under a truncated alert walk that delivered none.
- `critical_cves: null` when zero critical CVEs were counted over a truncated image walk.
- `disconnected_count: null` and `open_alerts.critical: null` when the Defender or alert page that showed none also carried an unevaluable record.

Item-level detail is withheld as `null` while the surface is incomplete, so no consumer reads a partial list as the population. These render `null`, with the lower bound beside them under a `_count` key (`disconnected_count`, `without_timestamp_count`, `images_without_scan_time_count`, `unprotected_count`):

- PA-10's `versions`, `disconnected`, and `without_timestamp`.
- PA-07's `images_without_scan_time`.
- PA-24's `unprotected` and `errors`.
- The `top_policies` breakdown of PA-02, PA-03, PA-05, and PA-06.

A verdict that rests on the absence of records becomes `warn` when the walk that found none was truncated. The summary then says the records were not delivered before the walk stopped, rather than that none exist. This applies to:

- Zero Defenders or zero connected Defenders for PA-08, PA-09, and PA-10.
- Zero registry scan results for PA-11.
- Zero CI scan results for PA-25.
- Zero network exposure alerts for PA-05 (`emptiness is not asserted`).

Over a walk read to completion, the same zero is asserted. The counts render `0`, the lists render `[]`, and the absence verdicts stay `fail` (or `pass` for PA-05).

The status counts of an assessment summary (`pass`, `warn`, `fail`, `manual`) follow the same rule. When a surface the findings read was unreadable, truncated, or delivered unevaluable records:

- A count of zero renders `null`, since a finding over that surface may be undetermined.
- A positive count renders as observed.

The quick reference renders such a count as `none seen` and says the count is not asserted.

#### Flags and pagination

Enabling flags are read explicitly: `enabled=true`, `connected=true`, `disabled!=true`, `log-end=yes`, HA `enabled=yes`. An absent or false flag never supports `pass`. An implicit `log-end` default is reported separately and caps at `warn`.

Alert pagination follows `nextPageToken` to completion. The loop records truncation, with the reason, when any of these happens:

- `alert_limit` is reached while a token remains.
- A page is empty but still carries a token.
- A token repeats (a stuck cursor).
- `totalRows` exceeds what was read.

Compute list endpoints (`/defenders`, `/registry`, `/images`, `/cloud/discovery`, `/scans`) are paged with `limit` and `offset` (50 per page, 500 records per surface). The loop records truncation, with the reason, when either of these happens:

- The 500-record cap is reached while full pages are still being returned.
- The console answers consecutive offsets with the same page (a stuck offset).

Truncation caps these findings at `warn`: PA-02, PA-03, PA-05, PA-06 (alerts), and the Compute findings that read the truncated list. The summary and `partial_inventory` evidence name the reason.

#### Unreadable surfaces

A finding that reads several surfaces never passes on a partial view. It is `manual` when any surface it reads is unreadable:

- `GET /v2/alert` for PA-02, PA-03, PA-05, and PA-06.
- `GET /cloud/group` for PA-04.
- `GET /defenders` for PA-08, PA-09, and PA-10.
- `GET /images` and `GET /stats/vulnerabilities` for PA-07.
- `GET /registry` for PA-11.
- `/config/shared` for PA-15's authentication profiles.
- `GET /user/role` and the `/mgt-config` device tree for PA-19.
- The Prisma Cloud integration list for PA-20.
- The policy rulebases for PA-21.

In that case, the summary starts with `Evidence unavailable (...)`, and `unreadable_sources` names each failed read.

Evidence derived from an unreadable surface renders `null`, never `0` or an empty list. `accounts: null` means the account list was not read. `accounts: 0` means it was read and is empty.

The collection status block of each assessment summary follows the same rule. `cloud_accounts`, `open_alerts_sampled`, and `open_alerts_truncated` render `null` when their surface failed. `unreadable_surfaces` and `truncated_surfaces` name the reads that did not complete.

A surface that was refused, failed, or never reached is never written as an empty list or `null`.

- Its place in `core_data/prisma_cloud.json` and in the per-device PAN-OS snapshot holds a marker: `{ "collected": false, "status": <observed HTTP status or null>, "dataset_status": "forbidden" | "not_found" | "error" | "unavailable", "endpoint": "GET /...", "error": "<scrubbed message>" }`.
- An unreachable Compute console writes an `unavailable` marker naming the `GET /meta_info` request that could not resolve it.
- Each assessment summary carries a `collection` object with one entry per surface (`status`, `endpoint`, `http_status`, `seen`, `truncated`, `error`). The PAN-OS block is keyed by device host.
- `truncated` is derived from the observed walk, never from a default:
  - A token still present after the alert limit.
  - An empty page or a repeated token.
  - `totalRows` above the records read.
  - The Compute record cap.
  - A stuck offset.
- `seen` and `truncated` render `null` for a surface that was not read.
- `seen` renders `null` for a truncated walk that delivered no record, because `0` would read as an empty inventory.

Every endpoint or status code named anywhere in a finding, summary, tool result, or `_errors.log` line is the request that was actually made and the status it actually returned. The method and path are taken from the thrown error. A transport failure records a `null` status. A PAN-OS read that was not attempted names the earlier request its device did not answer, also with a `null` status.

#### Export reruns

Export reruns allocate a new directory and derive the zip name from it, so a prior bundle is never overwritten.

- Allocation skips a name when either `<name>/` or `<name>.zip` exists. A zip left without its directory, or a dangling symlink at either path, counts as taken.
- The zip is created exclusively, so an existing file at that path fails the export instead of being replaced.

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
- [Prisma Cloud CSPM API: List Integrations (tenant scoped)](https://pan.dev/prisma-cloud/api/cspm/get-all-integrations-v-1/)
- [Prisma Cloud CSPM API: List All Integrations (Okta, Qualys, Tenable pull integrations)](https://pan.dev/prisma-cloud/api/cspm/get-all-integrations/)
- [Prisma Cloud CSPM API: List Alert Counts By Policy](https://pan.dev/prisma-cloud/api/cspm/get-alerts-grouped/)
- [Prisma Cloud CSPM API: Get Permissions](https://pan.dev/prisma-cloud/api/cspm/get-permissions-with-post/)
- [Prisma Cloud CSPM API: Get IAM Query](https://pan.dev/prisma-cloud/api/cspm/get-rql-with-get/)
- [PAN-OS XML API Request Types and Actions](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-xml-api-request-types)
- [PAN-OS and Panorama API guide](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api)
