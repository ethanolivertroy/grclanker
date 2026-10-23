---
title: Splunk
description: Read-only Splunk Enterprise and Splunk Cloud Platform security inspector covering authentication, RBAC, TLS, HEC, audit logging, and platform hardening.
---

The Splunk integration inspects a Splunk Enterprise or Splunk Cloud Platform deployment through the splunkd management REST API. When configured, it also uses the Splunk Cloud Admin Config Service (ACS).

The integration is read-only. The only POST requests it issues are:

- The session-key login (`/services/auth/login`), when you supply a username and password.
- A single read-only oneshot search against `index=_audit` that confirms audit events are flowing.

Every finding carries the framework mappings from the [Splunk Security Inspector spec](/specs/splunk-sec-inspector/): FedRAMP / NIST 800-53 r5, CMMC 2.0, SOC 2, CIS Splunk Benchmark, PCI-DSS 4.0, DISA STIG, IRAP, and ISMAP.

## What it inspects

| Area | Sources read |
|------|--------------|
| Authentication and identity | `authentication.conf` (`[authentication] authType`, `authSettings`, `externalTwoFactorAuthVendor`, `[splunk_auth]` password settings), `/services/authentication/providers/SAML` and `/LDAP`, `/services/admin/Duo-MFA` and `/Rsa-MFA`, `web.conf tools.sessions.timeout`, `server.conf [general] sessionTimeout`, `/services/authorization/tokens` |
| Authorization and access control | `/services/authorization/roles` (capabilities, imported roles, `srchIndexesAllowed`, `srchIndexesDefault`, `srchFilter`), `/services/authentication/users` (role assignments), `/servicesNS/-/-/saved/searches` and `/servicesNS/-/-/data/lookup-table-files` ACLs |
| Data protection | `server.conf [sslConfig]` (`enableSplunkdSSL`, `sslVersions`, `cipherSuite`, `requireClientCert`), `web.conf [settings] enableSplunkWebSSL`, `outputs.conf` (`[tcpout]`, `[tcpout:*]`, and `[tcpout-server://*]` `useSSL` and `clientCert`), `inputs.conf [SSL]` (`serverCert`, `requireClientCert`), `/services/data/inputs/http` (global `[http]` `disabled` and `enableSSL`, per-token `indexes`, `sourcetype`, `useACK`, `disabled`), ACS `/inputs/http-event-collectors` on Splunk Cloud |
| Audit and monitoring | `/services/data/indexes` (`_audit` `disabled`, `totalEventCount`, `frozenTimePeriodInSecs`), `audit.conf [auditTrail] queueing`, a read-only `index=_audit \| stats count by action` oneshot search over the last 24 hours, roles holding `delete_by_keyword` with `_audit` access |
| Platform hardening | ACS `/access/{search-api,hec,s2s,search-ui}/ipallowlists`, `/services/apps/local` provenance, roles with `install_apps`, `edit_local_apps`, or `rest_apps_management`, `/servicesNS/-/-/storage/collections/config` ACLs, scheduled saved searches (`dispatchAs`, owner roles, index scope, `dispatch.earliest_time`), `/services/data/inputs/tcp/cooked` enabled listeners matched against `inputs.conf [splunktcp-ssl:*]`, `[splunktcp://*]`, and `[SSL]` stanzas |

The deployment type is detected from `/services/server/info` (`product_type`, `instance_type`, `server_roles`). A `*.splunkcloud.com` URL heuristic is the fallback.

When ACS is not configured, Splunk Cloud specific controls become `manual` findings that say so.

## Setup and authentication

### Create an audit token (recommended)

1. In Splunk Web, go to **Settings > Tokens** and create a token for a dedicated audit user. Token authentication must be enabled on the deployment first. See [Create authentication tokens](https://docs.splunk.com/Documentation/Splunk/latest/Security/CreateAuthTokens).
2. Give the audit user a role with the read capabilities listed below. An `admin` (Enterprise) or `sc_admin` (Splunk Cloud) token works, but it is more privilege than the inspector needs.
3. Export `SPLUNK_URL` (the management port, usually `https://<host>:8089`) and `SPLUNK_TOKEN`. The token is sent as `Authorization: Bearer <token>` ([Use authentication tokens](https://docs.splunk.com/Documentation/Splunk/latest/Security/UseAuthTokens)).

Alternatively, set `SPLUNK_USERNAME` and `SPLUNK_PASSWORD`. The client posts them to `/services/auth/login` and keeps the returned `sessionKey` in memory. It sends the session key as `Authorization: Splunk <sessionKey>` ([REST API basic concepts](https://docs.splunk.com/Documentation/Splunk/latest/RESTUM/RESTusing)).

### Required role capabilities

`splunk_check_access` reads `/services/authentication/current-context` and reports any of these that are missing:

| Capability | Used for |
|------------|----------|
| `edit_user` | listing users and their roles (`/services/authentication/users`) |
| `list_tokens_all` | listing every authentication token, not only the caller's own |
| `rest_properties_get` | reading configuration files through `/services/configs/conf-*` |
| `list_settings` | reading server settings |
| `list_inputs` | listing HEC and TCP inputs |
| `rest_apps_view` | listing installed apps |
| `search` | the read-only `index=_audit` confirmation search (the role also needs `_audit` in its searchable indexes) |

Capability names come from the [authorize.conf reference](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Authorizeconf) and [Define roles with capabilities](https://docs.splunk.com/Documentation/Splunk/latest/Security/Rolesandcapabilities).

The access check reports endpoints the credential cannot read as `not_readable`. The assessments render them as `manual` findings, never as `pass`.

### Splunk Cloud ACS

For Splunk Cloud Platform, set `SPLUNK_STACK` to the stack name, the `<stack>` in `<stack>.splunkcloud.com`. Set `SPLUNK_ACS_TOKEN` to a JWT for a user holding `sc_admin`. When `SPLUNK_ACS_TOKEN` is not set, `SPLUNK_TOKEN` is reused for ACS.

ACS calls go to `https://admin.splunk.com/{stack}/adminconfig/v2/...` with `Authorization: Bearer <token>`. See [About the Admin Config Service API](https://docs.splunk.com/Documentation/SplunkCloud/latest/Config/ACSIntro) and [Basic setup and usage concepts](https://docs.splunk.com/Documentation/SplunkCloud/latest/Config/ACSusage).

### Environment variables and config file

Precedence is explicit tool arguments, then environment variables, then the JSON config file at `~/.config/grclanker/splunk.json`. Override the path with `SPLUNK_CONFIG_FILE` or the `config_file` argument.

Config file handling:

- A missing config file is skipped.
- A file that cannot be read stops the tool with `Unable to read Splunk config file <path> (<errno code>)`.
- A file that is not valid JSON stops the tool with `Unable to parse Splunk config file: invalid JSON in <path> at line N, column M (INVALID_JSON)`.
  - The message includes the position only when `JSON.parse` reports an offset.
  - The message never repeats the `JSON.parse` text, which quotes a window of the file around the failure.

| Variable | Config key | Purpose |
|----------|------------|---------|
| `SPLUNK_URL` | `url` | splunkd management URL, for example `https://splunk.example.com:8089` (required) |
| `SPLUNK_TOKEN` | `token` | Authentication token sent as `Authorization: Bearer` |
| `SPLUNK_USERNAME` | `username` | Username for session-key login |
| `SPLUNK_PASSWORD` | `password` | Password for session-key login |
| `SPLUNK_STACK` | `stack` | Splunk Cloud stack name for ACS |
| `SPLUNK_ACS_TOKEN` | `acs_token` | JWT for ACS (defaults to `SPLUNK_TOKEN`) |
| `SPLUNK_ACS_BASE_URL` | `acs_base_url` | ACS base URL (defaults to `https://admin.splunk.com`) |
| `SPLUNK_VERIFY_SSL` | `verify_ssl` | Set to `false` to skip TLS certificate verification for the inspector's own requests only (opt-out, not recommended) |
| `SPLUNK_TIMEOUT` | `timeout_seconds` | HTTP timeout in seconds (default 30) |
| `SPLUNK_CONFIG_FILE` | n/a | Alternate config file path |

Either `SPLUNK_TOKEN` or both `SPLUNK_USERNAME` and `SPLUNK_PASSWORD` are required.

The TLS verification opt-out is implemented with a per-request `node:https` agent (`rejectUnauthorized: false`). The inspector never sets `process.env.NODE_TLS_REJECT_UNAUTHORIZED`, so other tools in the same process keep verifying certificates.

Error messages are scrubbed by the [error text rules](#error-text-carriers).

## Run it

After setup, start `grclanker` and ask in plain words. The agent calls the matching tools, for example:

```text
Check whether my Splunk credentials can read everything grclanker needs.
Run the Splunk assessments and list the failing findings first.
Export a Splunk audit bundle.
```

For a posture readout or a framework mapping, use the [assess](/docs/workflows/assess/) or [audit](/docs/workflows/audit/) workflow, for example `grclanker assess "our Splunk deployment"`. Both start with `splunk_check_access`, then run the assessments or `splunk_export_audit_bundle`.

## Tools

All tools accept the shared connection arguments (`url`, `token`, `username`, `password`, `stack`, `acs_token`, `acs_base_url`, `verify_ssl`, `config_file`, `timeout_seconds`).

| Tool | Controls | Extra arguments |
|------|----------|-----------------|
| `splunk_check_access` | n/a | none. Probes 15 audit surfaces, reports the authenticated user, capabilities, missing capabilities, and whether ACS is configured. Status is `healthy` when the core surfaces (`server_info`, `users`, `roles`, `conf_authentication`, `conf_server`, `indexes`) and at least 11 of the 15 surfaces are readable, `failed` when Splunk rejected the credentials (every probe or the session login request returned 401, and so did the ACS request when ACS is configured), and `limited` otherwise. A failed check marks the attempted surfaces `unauthorized`, lists no missing capabilities, and names the variables to fix in the next step. |
| `splunk_assess_authentication` | 1-6 | `max_token_age_days` (default 90), `max_session_minutes` (default 60) |
| `splunk_assess_access_control` | 7-12 | `max_admins` (default 3) |
| `splunk_assess_data_protection` | 13-16 | none |
| `splunk_assess_audit_monitoring` | 17-18 | `run_searches` (default true), `min_audit_retention_days` (default 365) |
| `splunk_assess_platform_hardening` | 19-23 | none |
| `splunk_export_audit_bundle` | 1-23 | `output_dir` (default `./export/splunk`) plus every assessment threshold above |

Each assessment returns findings shaped as `{ id, control, title, severity, status, summary, evidence, mappings }`, with `status` in `pass`, `warn`, `fail`, or `manual`.

`manual` means the tool could not verify the control (endpoint unreadable, control out of scope for the deployment type, or evidence that only a human can collect). The summary states exactly what to collect.

### Export bundle layout

`splunk_export_audit_bundle` allocates a fresh directory under `output_dir`, named `<host>-splunk-audit-<timestamp>`. If that directory or its zip already exists, the name gets a numeric suffix, so a rerun never overwrites a prior bundle. The tool writes:

- `metadata.json` with the target URL, ACS state, configuration source chain, and TLS verification flag.
- `core_data/` snapshots of `server_info`, `current_context`, `users`, `roles`, `tokens`, `conf_authentication`, `conf_server`, `conf_web`, `conf_outputs`, `conf_inputs`, `indexes`, `hec_inputs`, `saved_searches`, `apps`, `kv_collections`, and `tcp_cooked_inputs`, plus `access_check.json`.
  - Every snapshot passes a deny list that keeps key names and replaces values with `[REDACTED]`:
    - Keys whose normalized name (lowercased, dots, underscores, and hyphens removed) ends in `password`, `passwd`, `passphrase`, or `token`, or contains `secret`, `pass4symmkey`, `accesskey`, `apikey`, `authkey`, `privatekey`, `sessionkey`, `integrationkey`, `routingkey`, `webhook`, or `credential`.
    - The `value` of a `{name, value}` or `{key, value}` pair whose name matches.
    - Every `$1$` or `$7$` ciphertext and JWT-shaped string.
    - The userinfo and query string of every URL-valued string. URL-shaped stanza names without either stay verbatim.
  - `saved_searches.json` is a projection that keeps the ACL (app, owner, sharing, read and write permissions), `is_scheduled`, `disabled`, `dispatchAs`, `dispatch.earliest_time`, `cron_schedule`, enabled action names, and an `all_indexes` or `index_bound` classification of the SPL. The SPL text is `[REDACTED]`, and every `action.<name>.param.*` value is dropped (`action_params_dropped` counts them).
- When a snapshot was denied, errored, or timed out, it is still written as a marker object `{ collected: false, status, endpoint, error }`.
  - The marker names the endpoint the failed request went to and its observed HTTP status (`null` when there was no response).
- A readable-but-empty list keeps `entries: []`.
- `access_check.json` carries the same nulls per surface:
  - `count`, `total`, `truncated`, and `httpStatus` are `null` on a probe that did not succeed or a surface that is not configured.
  - `total` is `null` when splunkd omitted `paging.total`.
  - `capabilities` is `null` when `current-context` was unreadable.
- `analysis/findings.json`, one JSON file per assessment area, and `analysis/summary.md`, all passed through the same redactor.
- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, and one report per framework (`fedramp.md`, `cmmc.md`, `soc2.md`, `cis.md`, `pci.md`, `stig.md`, `irap.md`, `ismap.md`).
- `QUICK_REFERENCE.md`.
- `_errors.log` when any collection step failed. It lists one `[<dataset>] <error>` line per failed read, with every message scrubbed by the [error text rules](#error-text-carriers).
  - The dataset sits in brackets because `tokens: Splunk ...` would read as a session-key carrier to that rule.
- A `.zip` archive named after the allocated directory.

#### Output paths

Output paths are resolved with traversal and symlink-parent protection. A path that escapes `output_dir` is rejected.

## Control coverage

Verdicts on unread, partial, or truncated data follow the [common verdict rules](#common-verdict-rules).

| # | Control | Tool | Finding id | Status semantics |
|---|---------|------|------------|------------------|
| 1 | Authentication method enforcement | `splunk_assess_authentication` | `SPLUNK-AUTH-01` | `pass` when `authType` is SAML or LDAP with an enabled provider stanza and at most 3 local accounts; `warn` when the provider endpoint or user list is unreadable or more than 3 local accounts remain; `fail` when `authType` is Splunk or the referenced provider is disabled or missing; `manual` for ProxySSO/Scripted or when `authentication.conf` is unreadable |
| 2 | Password policy compliance | `splunk_assess_authentication` | `SPLUNK-AUTH-02` | `pass` only when every evaluated `[splunk_auth]` setting is explicitly present and compliant; `warn` when settings are absent (absent is not treated as compliant); `fail` on any non-compliant value; `manual` when the stanza is unreadable |
| 3 | Multi-factor authentication | `splunk_assess_authentication` | `SPLUNK-AUTH-03` | `pass` when `externalTwoFactorAuthVendor` is Duo or RSA and the `/services/admin/Duo-MFA` or `Rsa-MFA` stanza exists; `fail` when no vendor is set and authType is not SAML; `manual` for SAML (MFA lives at the IdP) or unreadable config |
| 4 | Session timeout configuration | `splunk_assess_authentication` | `SPLUNK-AUTH-04` | `pass` when `web.conf tools.sessions.timeout` and `server.conf sessionTimeout` are within `max_session_minutes` (documented defaults are assumed and stated when a setting is absent); `fail` when either exceeds the threshold; `manual` when the stanzas are unreadable |
| 5 | Concurrent session limits | `splunk_assess_authentication` | `SPLUNK-AUTH-05` | always `manual`: Splunk exposes no per-user concurrent session limit through the REST API; role search quotas are attached as related evidence |
| 6 | Authentication token hygiene | `splunk_assess_authentication` | `SPLUNK-AUTH-06` | `pass` when every token expires, is newer than `max_token_age_days`, and maps to a known user in a readable user list; `warn` for stale tokens, tokens missing `iat`/`exp` claims, or a partial list (`seen N of M tokens` or total unknown); `fail` for non-expiring or orphaned tokens; `manual` when the token list is unreadable or empty; when the user list is unreadable the subject-to-user check is skipped, a pass is capped at `warn`, and the summary and `evidence.caveats` say so with the observed cause (`subject_not_in_user_list` renders `null`); when the user list is only partially retrieved a subject missing from it is not shown to be orphaned, so the finding never turns `fail` on that ground and names no token or subject: a pass is capped at `warn`, the summary and `evidence.caveats` state `The user list was only partially retrieved (seen N of M users)` with the count of token subjects not among the users seen (`subjects_not_among_seen_users`, names withheld, `subject_not_in_user_list` renders `null`, `users_inventory` carries seen, total, and truncated), and a non-expiring token still fails on the token list's own evidence |
| 7 | Role-based access control | `splunk_assess_access_control` | `SPLUNK-AC-07` | `pass` when no non-admin role holds `admin_all_objects`, `delete_by_keyword`, `edit_tcp`, `edit_user`, `edit_roles`, `edit_roles_grantable`, `change_authentication`, or `edit_server` (built-in `admin`, `sc_admin`, `splunk-system-role`, and `can_delete` are treated as admin roles); `fail` otherwise; `manual` when roles are unreadable or empty |
| 8 | Admin role minimization | `splunk_assess_access_control` | `SPLUNK-AC-08` | `pass` when 1 to `max_admins` users hold `admin` or `sc_admin`; `fail` above the threshold; `manual` when users are unreadable, empty, or show zero admins (a partial view) |
| 9 | Search head access controls | `splunk_assess_access_control` | `SPLUNK-AC-09` | `pass` when every non-admin role exposes `srchIndexesAllowed` and none contains `*` without an `srchFilter`; `warn` when some roles do not expose the field (their scope is unknown and is not counted as unrestricted); `fail` when a role has unrestricted scope; `manual` when no role exposes the field |
| 10 | Index access control | `splunk_assess_access_control` | `SPLUNK-AC-10` | `pass` when every non-admin role exposes `srchIndexesAllowed` (imported roles included) and none covers `_audit` or `_internal`; `warn` when some roles do not expose the field (their access is unknown and is not counted as granted); `fail` when a non-admin role can search those indexes; `manual` when no role exposes the field |
| 11 | Knowledge object permissions | `splunk_assess_access_control` | `SPLUNK-AC-11` | `pass` when no globally shared saved search or lookup grants write to `*` or `user`; `warn` when lookups were unreadable; `fail` otherwise; `manual` when the inventory is unreadable or empty |
| 12 | User capabilities audit | `splunk_assess_access_control` | `SPLUNK-AC-12` | `pass` when no non-admin role holds an elevated platform capability (`edit_server`, `change_authentication`, `run_debug_commands`, `edit_forwarders`, `edit_deployment_server`, `edit_deployment_client`, `restart_splunkd`, `edit_tokens_all`, `edit_httpauths`, `edit_storage_passwords`, `list_storage_passwords`, `install_apps`, `edit_local_apps`, `rest_apps_management`, `edit_indexer_cluster`, `edit_search_server`); `fail` otherwise. The spec's `run_commands_on_forwarder` is not a documented capability, so `edit_forwarders` and `run_debug_commands` are checked instead |
| 13 | TLS/SSL configuration | `splunk_assess_data_protection` | `SPLUNK-DP-13` | `pass` when `enableSplunkdSSL` and `enableSplunkWebSSL` are on, `sslVersions` is set explicitly and excludes TLS below 1.2, and `requireClientCert=true`; `warn` when `requireClientCert` is not enabled or `sslVersions` is absent (its documented default varies by release, so it is reported as unknown rather than assumed); `fail` when SSL is off, `enableSplunkWebSSL` is absent (documented default false), or legacy TLS is allowed; `manual` when `[sslConfig]` or `web.conf` is unreadable |
| 14 | Data encryption at rest | `splunk_assess_data_protection` | `SPLUNK-DP-14` | always `manual`: Splunk Enterprise has no index-level encryption setting (collect volume encryption evidence for `homePath`/`coldPath`), and the ACS EMEK endpoints (`/emek/key-policy`, `/emek/waiver`, `/emek/key`) generate onboarding artifacts rather than reporting whether EMEK is active (collect the EMEK provisioning record or encryption attestation); when `/services/server/info` could not be read, the summary states that the Cloud or Enterprise classification came from the URL heuristic and why that read failed |
| 15 | Forwarding encryption | `splunk_assess_data_protection` | `SPLUNK-DP-15` | `useSSL` is resolved per target through the documented levels (`[tcpout-server://*]`, then `[tcpout:*]`, then the global `[tcpout]`); `pass` only when every target resolves to an explicit `useSSL=true` and `inputs.conf` was readable; `warn` when a target relies on `legacy` mode (or an unset `useSSL`) with a `clientCert`, because TLS then depends on a certificate file the REST view cannot verify, and when `inputs.conf [SSL]` could not be read (the pass is capped at `warn` and the summary names the failed read, since the receiving-side `serverCert` and `requireClientCert` went unchecked); `fail` when any target has an explicit `useSSL=false` (a `clientCert` never overrides it) or `legacy` mode without a `clientCert`; `sslPassword` is the CA certificate password and is never TLS evidence; `manual` on Splunk Cloud, when `outputs.conf` is unreadable, or when the node has no `[tcpout:*]` groups; a failed `server/info` read is named as the URL-heuristic caveat |
| 16 | HEC token security | `splunk_assess_data_protection` | `SPLUNK-DP-16` | on Splunk Cloud with ACS, judged on `acs:/inputs/http-event-collectors`: `pass` when every enabled token restricts indexes, enables `useACK`, and sets a default sourcetype; `warn` for missing `useACK`/sourcetype or a truncated token list (seen count, total unknown); `fail` for any-index tokens; `manual` when ACS returns no tokens. Otherwise judged on `/services/data/inputs/http`: `pass` when `[http] enableSSL=true` is read explicitly and every enabled token restricts indexes, enables `useACK`, and sets a sourcetype (or when HEC is globally disabled with no tokens); `warn` for missing `useACK`/sourcetype, absent `enableSSL`, or a partial list; `fail` for `enableSSL=false` or any-index tokens; `manual` when the inputs are unreadable (the summary names whichever of the ACS and local endpoints failed), the global `[http]` entry is missing, or no tokens are visible. When ACS was requested but unreadable and the local list was readable, the local verdict is capped at `warn` and the summary names the ACS failure; a failed `server/info` read is named as the URL-heuristic caveat |
| 17 | Audit logging enabled | `splunk_assess_audit_monitoring` | `SPLUNK-AUD-17` | `pass` when `_audit` is enabled, the last 24 hours contain login and search events, and `audit.conf [auditTrail] queueing` is true or absent (there is no default `audit.conf`, so the documented default is assumed and stated); `warn` when the confirmation search was skipped, failed, or coverage is incomplete, when `queueing=false`, or when `audit.conf` is forbidden; `fail` when `_audit` is disabled or empty; `manual` when indexes are unreadable or `_audit` is not visible |
| 18 | Audit log integrity | `splunk_assess_audit_monitoring` | `SPLUNK-AUD-18` | `pass` when only unassigned admin-like roles can delete `_audit` events, the user list was readable, and `frozenTimePeriodInSecs` meets `min_audit_retention_days`; `warn` when users hold delete-capable roles, retention is unreadable (the summary says whether the index list itself failed), the role list is partial, or the user list is unreadable (role assignments could not be enumerated, the summary names the cause, and `users_with_delete_roles` renders `null`); `fail` when a non-admin role can delete audit events or retention is below the minimum; `manual` when roles are unreadable or empty |
| 19 | IP allow listing | `splunk_assess_platform_hardening` | `SPLUNK-PLAT-19` | Splunk Cloud with ACS: `pass` when `search-api`, `hec`, `s2s`, and `search-ui` all have explicit subnets; `warn` when `search-api` returns no subnets (documented closed by default); `fail` for `0.0.0.0/0` or an empty list on a feature documented open by default; `manual` on Splunk Enterprise, when ACS is not configured, or when any feature's allow list could not be read; a failed `server/info` read caps a pass at `warn` and the summary states that the classification came from the URL heuristic |
| 20 | App installation restrictions | `splunk_assess_platform_hardening` | `SPLUNK-PLAT-20` | `pass` when every app is Splunk core or Splunkbase-linked and only admin roles hold `install_apps`, `edit_local_apps`, or `rest_apps_management`; `warn` for apps without provenance; `fail` when a non-admin role can install apps; `manual` when apps are unreadable or empty |
| 21 | KV Store access controls | `splunk_assess_platform_hardening` | `SPLUNK-PLAT-21` | `pass` when no collection is globally shared with `*` read or write; `warn` for global read; `fail` for global write; `manual` when collections are unreadable or empty |
| 22 | Saved search permissions | `splunk_assess_platform_hardening` | `SPLUNK-PLAT-22` | `pass` when no scheduled search dispatches as an admin owner over all indexes with an unbounded time range, or when none are scheduled, judged on a complete saved search list with the user list readable; `warn` when admin-owned searches dispatch as owner, when the list is partial, or when the user list is unreadable (the summary reads `Owner roles of the N scheduled searches could not be verified because the user list could not be read (...)` with no admin-owner count, and with no scheduled searches the pass is capped at `warn` naming the failed user read); `fail` when a scheduled search runs as its admin owner, or as its unverified owner when the user list was unreadable, over all indexes with no time bound (the summary says which and names the failed user read); `manual` when saved searches are unreadable or empty |
| 23 | Splunk-to-Splunk port security | `splunk_assess_platform_hardening` | `SPLUNK-PLAT-23` | enabled listeners are the union of `/services/data/inputs/tcp/cooked` entries and `inputs.conf` receiver stanzas, keyed by port; the cooked REST view does not report TLS and listener names are never used as evidence; `serverCert` and `requireClientCert` are resolved per port, from the `[splunktcp-ssl:<port>]` stanza first (inputs.conf: "Specify any TLS setting that deviates from the global setting here") and the global `[SSL]` stanza second; `pass` when every listener has an enabled `[splunktcp-ssl:<port>]` stanza and resolves to a `serverCert` with `requireClientCert=true`; `warn` when any port resolves `requireClientCert` to a non-true value (a per-port `false` overrides a global `true`) or to no value at all (inputs.conf documents the default as `false` if using self-signed and third-party certificates and `true` if using the default certificates, which the REST view cannot distinguish, so absent is reported as unknown), or when no `serverCert` is set at either level; `fail` when any enabled `[splunktcp://]` plaintext receiver exists; `manual` on Splunk Cloud, when this node has no enabled receiving ports, when the cooked input list or `inputs.conf` is unreadable (the summary names the endpoint and cause), or when a listener has no matching stanza; evidence carries the resolved `serverCert`, `requireClientCert`, and `sslVersions` values rather than the raw stanza; a failed `server/info` read caps a pass at `warn` with the URL-heuristic caveat |

## Framework mappings

Each finding's `mappings` array contains one entry per framework, for example `FedRAMP (NIST 800-53 r5): IA-2, IA-8`.

The mapping table is the one in section 5 of the spec. It is embedded in `SPLUNK_CONTROLS` inside `cli/extensions/grc-tools/splunk.ts`.

The export bundle renders the same data as `compliance/unified_compliance_matrix.md` and one markdown report per framework.

## Live smoke test

```bash
export SPLUNK_URL="https://splunk.example.com:8089"
export SPLUNK_TOKEN="..."
npm --prefix cli run test:splunk:live
```

The script skips with exit code 0 when no credentials or config file are present.

With credentials, it:

1. Runs `splunk_check_access`.
2. Stops with a non-zero exit unless the access check is `healthy`.
3. Otherwise runs the authentication assessment and prints each finding.

## Limitations and manual controls

- Controls 5 (concurrent session limits) and 14 (encryption at rest) are always `manual` because Splunk does not expose them through a read-only API.
- Control 19 (IP allow listing) needs Splunk Cloud plus ACS. On Splunk Enterprise, it asks for firewall or load balancer evidence.
- Controls 15 and 23 (forwarder and S2S TLS) read `outputs.conf` and `inputs.conf` on the node you connect to.
  - On Splunk Cloud, or on a search head that neither forwards nor receives, they are `manual` and name the forwarder or indexer files to collect.
  - A documented explicit value always beats an inference. `useSSL=false` fails even with a `clientCert`, and a listener name containing `ssl` proves nothing.
- Control 3 is `manual` for SAML deployments without Splunk-native Duo or RSA, because MFA is enforced by the identity provider.
- Control 17's confirmation search creates one search job. Pass `run_searches: false` to skip it, which caps the verdict at `warn`.
- Enterprise Security correlation searches, deployment server clients, and Splunk version currency are recorded as evidence where visible but are not separate verdicts.
- The spec describes "auditTrail enabled in audit.conf". The documented `[auditTrail]` stanza has no enabled flag.
  - The stanza's `queueing` setting (default true) controls whether audit events reach the index queue.
  - That setting is therefore read through `/services/configs/conf-audit`, and a missing file is reported as the assumed default.
- The spec lists `sslCertPath` and `sslPassword` for forwarder TLS.
  - Current `outputs.conf` documents `clientCert`. The deprecated `sslCertPath` is also accepted.
  - In current `outputs.conf`, `sslPassword` is the CA certificate password. The password is recorded but never counts as TLS evidence.
- `/services/data/inputs/tcp/ssl` and `/services/data/inputs/tcp/cooked` do not document `serverCert`, `requireClientCert`, or a per-listener `SSL` value in their GET responses, so those values are read from `/services/configs/conf-inputs` instead.

## How the tools handle evidence

This section is reference for reviewing findings and bundles: how unread, partial, or truncated data limits a verdict, how the tools page through the API and report incomplete listings, and how credentials are kept out of findings, bundles, and error text. You don't need it to set up or run the integration.

### Paging and truncation

Every splunkd list endpoint is paged with `output_mode=json`, `count` (100), and `offset` against the configured URL until `paging.total` is reached.

The `links` and entry `id` URLs in a payload are never requested, so a server-supplied link cannot send the token or session key to another origin. The `id` serves the repeated-page check only.

A listing is recorded as truncated when:

- The 5,000-entry cap is hit.
- A page repeats the previous one (the server ignored `offset`).
  - A page repeats only when the same entries come back, identified by the entry `id` or, without one, by name within `acl.app` and `acl.owner`.
  - Saved searches that share a name across apps or owners are therefore distinct objects rather than a repeated page.
- A full page arrives with no `paging.total`. Then `totalKnown` is false and the total is unknown.
- A known total is larger than the entries retrieved.

ACS lists (`acsListAll`) are truncated on a repeated page or the entry cap. An ACS payload without the expected list key is an error rather than an empty inventory.

### Truncated lists in findings

A finding judged on a truncated list never passes.

- The summary states `seen N of M entries` or `N entries (total unknown)`.
- For a pass demoted by `Downgraded: the <list> inventory was only partially retrieved`, `evidence.partial_sources` names the list.

The demotion reaches only the findings that read the truncated list. Each assessor associates every inventory with the findings whose verdict reads it, for example:

- The user list: `SPLUNK-AUTH-01`, `SPLUNK-AUTH-06`, `SPLUNK-AC-08`, `SPLUNK-AUD-18`, and `SPLUNK-PLAT-22`.
- The role list: `SPLUNK-AC-07`, `09`, `10`, `12`, `SPLUNK-AUD-18`, and `SPLUNK-PLAT-20`.
- The saved search list: `SPLUNK-AC-11` and `SPLUNK-PLAT-22`.
- `conf-authentication`: `SPLUNK-AUTH-01`, `02`, and `03`.
- `conf-web` and `conf-server`: `SPLUNK-AUTH-04` and `SPLUNK-DP-13`.
- `conf-inputs`: `SPLUNK-DP-15` and `SPLUNK-PLAT-23`.

So a capped saved search walk leaves `SPLUNK-AUTH-02` and `SPLUNK-AUTH-04` at their own verdict. `partial_sources` lists only the truncated inventories that finding read.

A count judged over a partially retrieved list renders `null` in evidence, never the count of the part read. The list's `{ seen, total, total_known, truncated }` note sits beside it.

- `SPLUNK-AUTH-01` renders `provider_stanzas_in_conf` `null` beside `conf_authentication` while `authentication.conf` was partially read.
- `SPLUNK-DP-16` renders these `null` beside the HEC list note or the ACS `{ source, seen, total, total_known, truncated }` note:
  - `tokens` and `enabled`.
  - `global_entry_present`, when the global stanza was not among the entries read.
- `SPLUNK-PLAT-23` renders `ssl_stanza_present` and `ssl_stanza` `null` beside `inputs_conf` while `inputs.conf` was partially read.

No verdict calls a stanza, token, or setting absent when it may sit in the unread part.

- `SPLUNK-AUTH-01` renders `manual` with `no provider stanza was among the N of M stanzas read from authentication.conf` when the provider endpoint also could not settle it.
- `SPLUNK-DP-16` renders `manual` with `no token was among the N of M entries read from the HEC input list, so the token inventory is unread rather than empty` (or `ACS returned no HEC tokens before its page walk stopped`).
- `SPLUNK-PLAT-23` renders `manual` with `[splunktcp-ssl:*] listeners leave serverCert or requireClientCert to the [SSL] stanza, which was not among the N of M stanzas read from inputs.conf, so neither setting can be called present or absent`.
  - Each unresolved listener setting's source is recorded as `unresolved: [SSL] was not among the inputs.conf stanzas read` rather than `unset`.

A complete read keeps its real zeros and its absence wording.

### Error text carriers

Error text follows its own rule. The rule is applied when an API error is constructed, and again wherever an error string is recorded: marker objects, `_errors.log`, finding evidence, the access check, and tool error payloads.

- A value inside a carrier is removed whatever its shape:
  - The value of a credential-named header (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, and similar). So `Authorization: Splunk <session key>` keeps the scheme word and loses the key.
  - A cookie or session assignment.
  - URL userinfo and query pairs. The query string collapses to `?[REDACTED]`.
  - The value after a scheme word (`Bearer`, `Basic`, `Digest`, `Token`, `OAuth`, `Negotiate`, `NTLM`, `SSWS`, `ApiKey`, `Splunk`, `Snowflake`, and `HMAC`, in any casing). The scheme word stays.
  - The value of every credential-named `key=value` or `key: value` pair.
- The credential-named pair is read before any scheme word. A key that names a credential loses its value whatever word it starts with:
  - `sslPassword=splunk rejected` renders `sslPassword=[REDACTED] rejected`.
  - `pass4SymmKey: splunk rejected` renders `pass4SymmKey: [REDACTED] rejected`.
  - `db_password: token` renders `db_password: [REDACTED]`.

### Scheme words

A scheme word acts under an Authorization-style key (`Authorization`, `Proxy-Authorization`, `WWW-Authenticate`) and bare in prose.

- Under an Authorization-style key, the run after the scheme word goes whatever its shape or the scheme's casing:
  - `Authorization: splunk <session key>` renders `Authorization: splunk [REDACTED]`.
  - `Authorization: SSWS prod-us-east-2026` renders `Authorization: SSWS [REDACTED]`.
- Under such a key, a pair list after the scheme (under a request header or a challenge) is read pair by pair as described below. `WWW-Authenticate: Bearer realm="api"` stays.
- Bare in prose, the word after a scheme word is ordinary text when it is a mechanism word (`authentication`, `credentials`, `challenge`), a version (`OAuth 2.0`), an auth-param (`realm="api"`), or one plain word after a lowercase spelling or a product name.
  - `Basic authentication failed`, `the bearer presented an expired token`, `Splunk Enterprise rejected the request`, and `Snowflake statement failed` stay.
- Bare in prose, a header-cased pure scheme followed by a run of 8 or more characters loses the run whatever its shape:
  - `Bearer abcdefghijkl rejected` renders `Bearer [REDACTED] rejected`.
  - `replayed BASIC <token> upstream` renders `replayed BASIC [REDACTED] upstream`.
  - `replayed splunk <token> upstream` renders `replayed splunk [REDACTED] upstream`.

### Credential-named pairs

- The pair rule holds whatever the value's shape and length and wherever the pair sits. It holds in the `=`, `: `, `:`, and JSON forms, in prose and inside a JSON string alike:
  - `upstream echoed DB_PASSWORD: monkey while proxying` renders `DB_PASSWORD: [REDACTED] while proxying`.
  - `InvalidAuthenticationToken: Access token has expired` renders `InvalidAuthenticationToken: [REDACTED] token has expired`.
- A credential word anywhere in the key makes it a pair key (`DB_PASSWORD`, `SPLUNK_PASSWORD`, `OKTA_CLIENT_TOKEN`).
- Three key classes refine that rule, tested in this order:
  - **Bearer ids:** A key carries a bearer credential, and loses its value whatever the shape (a UUID included), when it does either of these:
    - Ends in `secret_id`, `session_id`, or `token_id` in any prefix, casing, or separator (`VAULT_SECRET_ID`, `role_secret_id`, `token_id`, `tokenId`).
    - Names a session id (`sid`, `jsessionid`).
  - **Webhook keys:** A URL-valued webhook key keeps its origin and loses its path and query.
    - A URL-valued webhook key is the bare word `webhook` or `hook`, or a `webhook*`, `*hook_*`, or `callback_*` key whose final segment is `url`, `uri`, or `endpoint`.
    - A webhook key that is not URL-valued follows the rule for its own final segment. `webhook_count=3` stays, and `webhook_secret=<value>` goes whole.
  - **Setting keys:** A credential-named key names a setting when its final segment is one of the segments listed below. It keeps a value that is neither token-shaped nor a configured secret.
    - The final segments are `url`, `uri`, `endpoint`, `method`, `algorithm`, `audience`, `issuer`, `shape`, `type`, `mode`, `path`, `file`, `dir`, `limit`, `count`, `id`, `name`, `policy`, `policies`, `ttl`, `uses`, `cidrs`, and `accessor`.
    - Setting keys include `token_endpoint`, `auth_method`, `token_type`, `api_key_id`, `access_key_id`, `key_id`, `private_key_id`, `secret_name`, `secret_id_ttl`, `token_max_ttl`, `secret_id_num_uses`, `token_bound_cidrs`, and `secret_id_accessor`.
    - `secret_id_ttl=3600`, `key_id=kid-primary`, and `secret_name=db-credentials-prod` stay. `token_type=<token>` goes.
- A key without a credential word (`OKTA_CLIENT_ID`, `client_id`, `tenant_id`, `SUMO_ACCESS_ID`, `SNOWFLAKE_ACCOUNT`, `X-Request-Id`) is an identifier rather than a pair key, so its value is judged by shape alone.
- A credential-named command-line flag is a pair too, with a space or `=` before its value:
  - `psql --password <value> -h db` renders `psql --password [REDACTED] -h db`.
  - `helm --set db.password=<value> upgrade` renders `helm --set db.password=[REDACTED] upgrade`.
  - `-Dspring.datasource.password=<value>` renders `-Dspring.datasource.password=[REDACTED]`.

### Quoted values and pair lists

- A quoted value in any of the carriers above is removed with its quotes kept. The rule holds for plain, single, or JSON-escaped quotes, as in `Cookie: sid="..."`, `Authorization: Bearer "..."`, or `\"Authorization\": \"Bearer ...\"`.
- A quote alone never makes a header value a credential. `Content-Type: "application/json"` stays.
- On a compound header line the reader is quote-aware at every JSON depth. A quoted value ends at the closing quote that matches its opener (the same quote character behind the same run of backslashes). An escaped inner quote is therefore inner content and goes with the value.
  - At the top level and inside a double-escaped raw JSON string alike, `{"Cookie": "sid=\"...\""}` renders `{"Cookie": "[REDACTED]"}`, and `{"X-Api-Key": "\"...\""}` renders `{"X-Api-Key": "[REDACTED]"}`.
- A quoted value that opens with a scheme word keeps the scheme and loses the rest. `{"Authorization": "Bearer \"...\""}` renders `{"Authorization": "Bearer [REDACTED]"}`.
- The exception is a scheme followed by a pair list, which is read pair by pair, under `Authorization`, `Proxy-Authorization`, and `WWW-Authenticate` alike:
  - A quoted value in the list is the credential and goes whatever its key, unless the key is a descriptive parameter (`realm`, `qop`, `algorithm`, `charset`, `error`, `error_description`, `error_uri`, `scope`).
  - A bare value follows its key's own rule.
  - `Authorization: Snowflake Token="<token>"` renders `Authorization: Snowflake Token="[REDACTED]"`.
  - Any other `<Scheme> <Key>="..."` pair renders the same way. `Authorization: Bearer blob="<token>"` renders `Authorization: Bearer blob="[REDACTED]"`.
  - A Digest header keeps `realm="api"`, `qop=auth`, and `nc=00000001`. It loses `username`, `nonce`, `uri`, `cnonce`, `response`, and `opaque`.
  - A challenge's `WWW-Authenticate: Bearer realm="api", error="invalid_token"` stays whole.
  - `"VERACODE-HMAC-SHA-256 id=...,ts=...,nonce=...,sig=..."` renders `"VERACODE-HMAC-SHA-256 [REDACTED],ts=...,nonce=[REDACTED],sig=[REDACTED]"`. An unquoted first run after the scheme goes whole, and the pairs after it follow their keys.
- The same list rule reads a pair list after a scheme word in prose, bare, JSON-escaped, and inside a JSON string alike:
  - `upstream said Bearer blob="<token>"` renders `upstream said Bearer blob="[REDACTED]"`.
  - `{"headers":{"Authorization":"Snowflake Token=\"<token>\""}}` renders `{"headers":{"Authorization":"Snowflake Token=\"[REDACTED]\""}}`.
- A proof parameter (`response`, `signature`, `oauth_signature`, `mac`, `sig`) loses its value wherever its pair sits in a list with a challenge parameter (`realm`, `nonce`, `cnonce`, `opaque`, `qop`, or an `oauth_*` name). The rule holds with or without a scheme word or a header in front of the list, and whatever the value's shape.
  - As a result, a data value such as `realm="api", nonce="n", response="<proof>"` is never read as a bare challenge. It renders `realm="api", nonce="[REDACTED]", response="[REDACTED]"` bare, after a literal escape, and inside a JSON string alike.
  - `realm=api, nonce=n, mac=<proof>` loses its `mac` the same way.
  - Inside a scheme word's list, a bare proof goes whatever its neighbours. `Authorization: Digest username="u", response=<proof>` renders `Authorization: Digest username="[REDACTED]", response=[REDACTED]`.
- A proof-free challenge keeps its descriptive values:
  - `WWW-Authenticate: Bearer realm="api"` stays whole.
  - `Digest realm="api", qop="auth", nonce="n"` keeps `realm="api"` and `qop="auth"`. Its nonce goes as a credential-named pair does everywhere.
- A pair list of another kind keeps its values. `status=500 response=slow` stays.

### Header and cookie boundaries

- An unquoted cookie or header value ends at a `;` or `,` before the next `Name:` token (or at the end of the line). An unterminated quote ends the same way rather than swallowing the following header, so that header keeps its name and gets its own carrier treatment:
  - `Cookie: sid=...; X-Api-Key: ...; Content-Type: application/json` renders `Cookie: [REDACTED]; X-Api-Key: [REDACTED]; Content-Type: application/json`.
  - `Cookie: sid="...; X-Api-Key: "..."; Content-Type: "application/json"` renders `Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"`.
- A `;` inside a URL query value is part of the value (URLSearchParams semantics). So a relative `/api/v1/things?token=hunter2;restofsecret` renders `/api/v1/things?token=[REDACTED]` with no tail, and an absolute URL's query collapses to `?[REDACTED]` as before, in the plain, JSON-escaped, and slash-escaped spellings alike.
- The `;` separator belongs to `Cookie` and `Set-Cookie` parsing alone. The cookie reader runs before the query pass, so `Cookie: &sid=a; pref=b` still renders `Cookie: [REDACTED]`.
- An apostrophe is a cookie character:
  - `Cookie: sid=O'<value>; X-Api-Key: <value>` renders `Cookie: [REDACTED]; X-Api-Key: [REDACTED]`.
  - `Cookie: theme=dark; my'pref=<value>` renders `Cookie: [REDACTED]`.
- The next header's name may carry any RFC 7230 token character, so a dotted or underscored name (`X.Api.Key:`, `X_Api_Key:`) is recognised as the next header and its value is judged by its own key.

### JSON escapes and URLs

- A literal JSON escape is a boundary before every carrier opener. The escapes are `\n`, `\r`, `\t`, `\b`, `\f`, `\/`, and `\uXXXX`: the two- or six-character sequence as it sits inside a JSON string, not the control character.
  - A header name, scheme word, pair key, URL, or token that begins right after one is read on its own, and never as the value of the word before the escape.
  - `request headers:\u000aAuthorization: Splunk <key>` renders `request headers:\u000aAuthorization: Splunk [REDACTED]`, and `proxy:\tpassword: hunter2` renders `proxy:\tpassword: [REDACTED]`.
  - The escape sequence itself stays.
  - A token glued to an escape never takes the escape letter as its first character.
  - A value, URL, or query pair ends at the backslash that opens the next escape.
  - A `\/` escape is a boundary rather than a path separator, so a key or token after it is judged on its own.
- A URL whose slashes are JSON-escaped (`https:\/\/hooks.example.com\/a?token=<value>`) is still read as a URL, so its userinfo and query go the same way (`note https:\/\/hooks.example.com\/a?[REDACTED] next`).
- The userinfo of a URL ends at the first `/`, `?`, or `#`, so an `@` inside a query or fragment never turns the query into the host. In the plain and the slash-escaped spelling alike:
  - `https://h?e=a@x.com&token=s3cr3t` renders `https://h?[REDACTED]`.
  - `https://h#f@x.com` renders `https://h#[REDACTED]`.
- A bare `?` or `#` left before an earlier marker stays as it is, so a second pass adds no second marker.

### Configured secrets and value shapes

- A configured secret (the token, the password, the ACS token, and the session key obtained by logging in) is removed whatever its shape, in its raw, JSON-escaped, URL-encoded, base64, and base64url forms.
- A secret handed to the scrub call is also removed wherever it stands, glued into a longer run included, so a short passphrase does not survive inside another value. A value under four characters is ignored.
- A value with a real token shape is removed bare:
  - PEM blocks
  - JWTs
  - AWS key IDs and secrets
  - Other vendor-prefixed tokens
  - Hex digests of 32 or more characters
  - Runs of 16 or more characters that carry a base64 symbol, more than one digit group, or token casing
- A bare value shaped like a name is indistinguishable from a resource name and stays:
  - Words joined by hyphens or underscores with at most one digit group, such as `prod-us-east-2026`.
  - A camelCase identifier whose words average three or more letters, such as `frozenTimePeriodInSecs`.

### Paths and path labels

- A token-shaped segment of a bare request path or file path (`/servicesNS/-/-/saved/searches`, the config file path) also stays, so the endpoint or file an error names is the one the run used.
- Inside a URL with a scheme, every path segment keeps the rule, because webhook URLs carry their token there.
- The last segment of a bare path used as a label (`core_data/tokens: <error>`, `/oauth/token-request: invalid_client`, `/api/v1/api-tokens: request failed with 403`) is a request target rather than a pair key.
  - The text after that segment stays, unless that segment itself names a credential and the value stands alone on the line. In that case the label is a pair: `kv/password: <value>` renders `kv/password: [REDACTED]`.
  - That segment names a credential when it ends in `password`, `passwd`, `passphrase`, `pwd`, `secret`, `token`, `key`, or `assertion`, alone or followed by an encoding word such as `pem` or `base64` (as in `privateKeyPem`), or when it is a bearer id.
  - Inside a URL with a scheme, the pair rule still applies.

### Data-side rule

Data written to the bundle follows the data-side rule. Every string leaf of a `core_data/` snapshot, an assess payload, and the access check passes through the same carrier and shape rules, with the generic long-run and hex-digest rules left off.

- A vendor-prefixed token (`sk_live_`, `xox*-`, `ghp_`, `AKIA`, and the rest of the vendor set), a JWT, a PEM block, or a credential carrier inside a free-text field (an app description, a saved search description, a stanza comment) is removed there too. `key sk_live_<24 characters> end` renders `key [REDACTED] end`.
- An identifier such as `prod-us-east-2026-cluster` or a bare random run survives as evidence.

### Common verdict rules

These rules apply to every control.

- An unreadable or forbidden endpoint is `manual`.
  - The summary names the endpoint the failed request actually went to and the observed cause (`401`, `403`, `404`, or the scrubbed error text).
  - Evidence carries `endpoint`, `error`, and `http_status` (`null` when there was no HTTP response).
- An empty inventory is `manual` (or `fail` where the control's intent requires the inventory).
- A partial inventory never yields `pass` for the findings that read it.
  - The summary states `seen N of M` or `N (total unknown)`.
  - A pass is demoted to `warn` with `Downgraded:` and `evidence.partial_sources` naming only the truncated inventories that finding read.
  - Findings that never read the truncated list keep their verdict.
- Items without dates are reported separately and cap the verdict at `warn`.
- A finding that read a secondary inventory it could not trust keeps its `warn`, `fail`, or `manual` verdict but never stays at `pass`. Each caveat is appended to the summary and listed in `evidence.caveats`. Secondaries covered:
  - The user list for AUTH-06, AUD-18, and PLAT-22.
  - `inputs.conf` for DP-15.
  - The ACS HEC inventory for DP-16.
  - `/services/server/info` for DP-14, DP-15, DP-16, PLAT-19, and PLAT-23. A failed read means the Cloud or Enterprise classification came from the `*.splunkcloud.com` URL heuristic, and the summary says so.
- Counts and lists derived from an unreadable inventory render `null` in evidence, never `0` or `[]`:
  - `users_with_delete_roles` and `subject_not_in_user_list` when the user list failed.
  - `owner_dispatched_by_admins` and `risky_scheduled_searches` for PLAT-22 when the user list failed. `owner_roles_note` names the cause, and `unverified_owner_searches` lists the owner-dispatched searches that were read.
  - `web_sslVersions` for DP-13 when `web.conf` failed.
  - `ssl_stanza` and `ssl_stanza_present` for PLAT-23 when `inputs.conf` failed.
  - `deployment.serverRoles` in the access check when `/services/server/info` failed.
- Leaves read from a snapshot that was collected keep their real values beside those nulls, for example `sslVersions` from `server.conf` and `scheduled` from the saved searches themselves.

## Official documentation

- [REST API User Manual: basic concepts (authentication, `output_mode`, `count` and `offset` paging)](https://docs.splunk.com/Documentation/Splunk/latest/RESTUM/RESTusing)
- [REST API Reference: access endpoints (`authentication/users`, `authentication/current-context`, `authorization/roles`, `authorization/tokens`, `auth/login`)](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTaccess)
- [REST API Reference: configuration endpoints (`configs/conf-{file}`)](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTconf)
- [REST API Reference: input endpoints (`data/inputs/http`, `data/inputs/tcp/cooked`)](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTinput)
- [REST API Reference: introspection endpoints (`data/indexes`)](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.4/introspection-endpoints/introspection-endpoint-descriptions)
- [REST API Reference: search endpoints (`search/jobs` with `exec_mode=oneshot`)](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch)
- [REST API Reference: knowledge endpoints (`saved/searches`, `data/lookup-table-files`)](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTknowledge)
- [REST API Reference: KV Store endpoints (`storage/collections/config`)](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTkvstore)
- [REST API Reference: application endpoints (`apps/local`)](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTapps)
- [REST API Reference: system endpoints (`server/info`)](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsystem)
- [Create authentication tokens](https://docs.splunk.com/Documentation/Splunk/latest/Security/CreateAuthTokens) and [Use authentication tokens](https://docs.splunk.com/Documentation/Splunk/latest/Security/UseAuthTokens)
- [authentication.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Authenticationconf), [server.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Serverconf), [web.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Webconf), [inputs.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf), [outputs.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Outputsconf), [indexes.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Indexesconf), [authorize.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Authorizeconf), [audit.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/audit.conf)
- [Define roles on the Splunk platform with capabilities](https://docs.splunk.com/Documentation/Splunk/latest/Security/Rolesandcapabilities)
- [Multifactor authentication with Duo Security](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/use-multi-factor-authentication-in-splunk-enterprise-as-an-authentication-scheme/about-multifactor-authentication-with-duo-security) and [RSA Authentication Manager](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/use-multi-factor-authentication-in-splunk-enterprise-as-an-authentication-scheme/about-multifactor-authentication-with-rsa-authentication-manager)
- [Configure single sign-on with SAML](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/use-saml-as-an-authentication-scheme-for-single-sign-on/configure-single-sign-on-with-saml) and [Set up user authentication with LDAP](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/use-ldap-as-an-authentication-scheme/set-up-user-authentication-with-ldap)
- [Introduction to securing the Splunk platform with TLS](https://docs.splunk.com/Documentation/Splunk/latest/Security/AboutsecuringyourSplunkconfigurationwithSSL), [Configure Splunk Web to use TLS certificates](https://docs.splunk.com/Documentation/Splunk/latest/Security/SecureSplunkWebusingasignedcertificate), [Configure Splunk indexing and forwarding to use TLS certificates](https://docs.splunk.com/Documentation/Splunk/latest/Security/ConfigureSplunkforwardingtousesignedcertificates)
- [Auditing activities in a Splunk platform instance](https://docs.splunk.com/Documentation/Splunk/latest/Security/AuditSplunkactivity)
- [Admin Config Service: about the ACS API](https://docs.splunk.com/Documentation/SplunkCloud/latest/Config/ACSIntro), [basic setup and usage](https://docs.splunk.com/Documentation/SplunkCloud/latest/Config/ACSusage), [configure IP allow lists](https://docs.splunk.com/Documentation/SplunkCloud/latest/Config/ConfigureIPAllowList), [manage HEC tokens](https://docs.splunk.com/Documentation/SplunkCloud/latest/Config/ManageHECtokens), and the [ACS OpenAPI specification](https://admin.splunk.com/service/info/specs/v2/openapi.json)
- [Splunk Cloud Platform service details (encryption at rest)](https://help.splunk.com/en/splunk-cloud-platform/get-started/service-terms-and-policies/10.5.2605/information-about-the-service/splunk-cloud-platform-service-details)
