---
title: Splunk
description: Read-only Splunk Enterprise and Splunk Cloud Platform security inspection covering authentication, RBAC, TLS, HEC, audit logging, and platform hardening with compliance mappings.
---

The Splunk integration inspects a Splunk Enterprise or Splunk Cloud Platform deployment through the splunkd management REST API and, when configured, the Splunk Cloud Admin Config Service (ACS). It is read-only: the only POST requests it issues are the session-key login (`/services/auth/login`, when you supply a username and password) and a single read-only oneshot search against `index=_audit` that confirms audit events are flowing.

Every finding carries the framework mappings from the [Splunk security inspector spec](https://github.com/hackIDLE/grclanker/blob/main/specs/splunk-sec-inspector.spec.md) (FedRAMP / NIST 800-53 r5, CMMC 2.0, SOC 2, CIS Splunk Benchmark, PCI-DSS 4.0, DISA STIG, IRAP, ISMAP).

## What it inspects

| Area | Sources read |
|------|--------------|
| Authentication and identity | `authentication.conf` (`[authentication] authType`, `authSettings`, `externalTwoFactorAuthVendor`, `[splunk_auth]` password settings), `/services/authentication/providers/SAML` and `/LDAP`, `/services/admin/Duo-MFA` and `/Rsa-MFA`, `web.conf tools.sessions.timeout`, `server.conf [general] sessionTimeout`, `/services/authorization/tokens` |
| Authorization and access control | `/services/authorization/roles` (capabilities, imported roles, `srchIndexesAllowed`, `srchIndexesDefault`, `srchFilter`), `/services/authentication/users` (role assignments), `/servicesNS/-/-/saved/searches` and `/servicesNS/-/-/data/lookup-table-files` ACLs |
| Data protection | `server.conf [sslConfig]` (`enableSplunkdSSL`, `sslVersions`, `cipherSuite`, `requireClientCert`), `web.conf [settings] enableSplunkWebSSL`, `outputs.conf` (`[tcpout]`, `[tcpout:*]`, and `[tcpout-server://*]` `useSSL` and `clientCert`), `inputs.conf [SSL]` (`serverCert`, `requireClientCert`), `/services/data/inputs/http` (global `[http]` `disabled` and `enableSSL`, per-token `indexes`, `sourcetype`, `useACK`, `disabled`), ACS `/inputs/http-event-collectors` on Splunk Cloud |
| Audit and monitoring | `/services/data/indexes` (`_audit` `disabled`, `totalEventCount`, `frozenTimePeriodInSecs`), `audit.conf [auditTrail] queueing`, a read-only `index=_audit | stats count by action` oneshot search over the last 24 hours, roles holding `delete_by_keyword` with `_audit` access |
| Platform hardening | ACS `/access/{search-api,hec,s2s,search-ui}/ipallowlists`, `/services/apps/local` provenance, roles with `install_apps`, `edit_local_apps`, or `rest_apps_management`, `/servicesNS/-/-/storage/collections/config` ACLs, scheduled saved searches (`dispatchAs`, owner roles, index scope, `dispatch.earliest_time`), `/services/data/inputs/tcp/cooked` enabled listeners matched against `inputs.conf [splunktcp-ssl:*]`, `[splunktcp://*]`, and `[SSL]` stanzas |

The deployment type is detected from `/services/server/info` (`product_type`, `instance_type`, `server_roles`) with a `*.splunkcloud.com` URL heuristic as fallback. Splunk Cloud specific controls become `manual` findings that say so when ACS is not configured.

## Setup and authentication

### Create an audit token (recommended)

1. In Splunk Web go to **Settings > Tokens** and create a token for a dedicated audit user. Token authentication must be enabled on the deployment first (see [Create authentication tokens](https://docs.splunk.com/Documentation/Splunk/latest/Security/CreateAuthTokens)).
2. Give the audit user a role with the read capabilities listed below. An `admin` (Enterprise) or `sc_admin` (Splunk Cloud) token works but is more privilege than the inspector needs.
3. Export `SPLUNK_URL` (the management port, usually `https://<host>:8089`) and `SPLUNK_TOKEN`. The token is sent as `Authorization: Bearer <token>` ([Use authentication tokens](https://docs.splunk.com/Documentation/Splunk/latest/Security/UseAuthTokens)).

Alternatively, set `SPLUNK_USERNAME` and `SPLUNK_PASSWORD`. The client posts them to `/services/auth/login`, keeps the returned `sessionKey` in memory, and sends it as `Authorization: Splunk <sessionKey>` ([REST API basic concepts](https://docs.splunk.com/Documentation/Splunk/latest/RESTUM/RESTusing)).

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

Capability names come from the [authorize.conf reference](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Authorizeconf) and [Define roles with capabilities](https://docs.splunk.com/Documentation/Splunk/latest/Security/Rolesandcapabilities). Endpoints the credential cannot read are reported as `not_readable` by the access check and render as `manual` findings in the assessments, never as `pass`.

### Splunk Cloud ACS

For Splunk Cloud Platform, set `SPLUNK_STACK` to the stack name (the `<stack>` in `<stack>.splunkcloud.com`) and `SPLUNK_ACS_TOKEN` to a JWT for a user holding `sc_admin`. ACS calls go to `https://admin.splunk.com/{stack}/adminconfig/v2/...` with `Authorization: Bearer <token>`. When `SPLUNK_ACS_TOKEN` is not set, `SPLUNK_TOKEN` is reused for ACS. See [About the Admin Config Service API](https://docs.splunk.com/Documentation/SplunkCloud/latest/Config/ACSIntro) and [Basic setup and usage concepts](https://docs.splunk.com/Documentation/SplunkCloud/latest/Config/ACSusage).

### Environment variables and config file

Precedence is explicit tool arguments, then environment variables, then the JSON config file at `~/.config/grclanker/splunk.json` (override the path with `SPLUNK_CONFIG_FILE` or the `config_file` argument). A missing config file is skipped. One that cannot be read stops the tool with `Unable to read Splunk config file <path> (<errno code>)`, and one that is not valid JSON stops it with `Unable to parse Splunk config file: invalid JSON in <path> at line N, column M (INVALID_JSON)`, with the position only when `JSON.parse` reports an offset. The message never repeats the `JSON.parse` text, which quotes a window of the file around the failure.

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

Either `SPLUNK_TOKEN` or both `SPLUNK_USERNAME` and `SPLUNK_PASSWORD` are required. TLS verification opt-out is implemented with a per-request `node:https` agent (`rejectUnauthorized: false`); the inspector never sets `process.env.NODE_TLS_REJECT_UNAUTHORIZED`, so other tools in the same process keep verifying certificates. Tokens and session keys are redacted from error messages.

## Tools

All tools accept the shared connection arguments (`url`, `token`, `username`, `password`, `stack`, `acs_token`, `acs_base_url`, `verify_ssl`, `config_file`, `timeout_seconds`). Every splunkd list endpoint is paged with `output_mode=json`, `count` (100), and `offset` until `paging.total` is reached. A listing is recorded as truncated when the 5,000-entry cap is hit, when a page repeats the previous one (the server ignored `offset`), when a full page arrives with no `paging.total` (then `totalKnown` is false and the total is unknown), or when a known total is larger than the entries retrieved. ACS lists (`acsListAll`) are truncated on a repeated page or the entry cap, and an ACS payload without the expected list key is an error rather than an empty inventory. A finding judged on a truncated list never passes: the summary states `seen N of M entries` or `N entries (total unknown)` and, for a pass demoted by `Downgraded: the <list> inventory was only partially retrieved`, `evidence.partial_sources` names the list.

| Tool | Controls | Extra arguments |
|------|----------|-----------------|
| `splunk_check_access` | n/a | none. Probes 15 audit surfaces, reports the authenticated user, capabilities, missing capabilities, and whether ACS is configured. Status is `healthy` when the core surfaces are readable and `limited` otherwise. |
| `splunk_assess_authentication` | 1-6 | `max_token_age_days` (default 90), `max_session_minutes` (default 60) |
| `splunk_assess_access_control` | 7-12 | `max_admins` (default 3) |
| `splunk_assess_data_protection` | 13-16 | none |
| `splunk_assess_audit_monitoring` | 17-18 | `run_searches` (default true), `min_audit_retention_days` (default 365) |
| `splunk_assess_platform_hardening` | 19-23 | none |
| `splunk_export_audit_bundle` | 1-23 | `output_dir` (default `./export/splunk`) plus every assessment threshold above |

Each assessment returns findings shaped as `{ id, control, title, severity, status, summary, evidence, mappings }` with `status` in `pass`, `warn`, `fail`, or `manual`. `manual` means the tool could not verify the control (endpoint unreadable, control out of scope for the deployment type, or evidence that only a human can collect) and the summary states exactly what to collect.

### Export bundle layout

`splunk_export_audit_bundle` allocates a fresh directory under `output_dir` (`<host>-splunk-audit-<timestamp>`, with a numeric suffix if that directory or its zip already exists, so a rerun never overwrites a prior bundle) and writes:

- `metadata.json` with the target URL, ACS state, configuration source chain, and TLS verification flag
- `core_data/` snapshots of `server_info`, `current_context`, `users`, `roles`, `tokens`, `conf_authentication`, `conf_server`, `conf_web`, `conf_outputs`, `conf_inputs`, `indexes`, `hec_inputs`, `saved_searches`, `apps`, `kv_collections`, and `tcp_cooked_inputs`, plus `access_check.json`. Every snapshot passes a deny list that keeps key names and replaces values with `[REDACTED]`: keys whose normalized name (lowercased, dots, underscores, and hyphens removed) ends in `password`, `passwd`, `passphrase`, or `token` or contains `secret`, `pass4symmkey`, `accesskey`, `apikey`, `authkey`, `privatekey`, `sessionkey`, `integrationkey`, `routingkey`, `webhook`, or `credential`; the `value` of a `{name, value}` or `{key, value}` pair whose name matches; every `$1$` or `$7$` ciphertext and JWT-shaped string; and the userinfo and query string of every URL-valued string (URL-shaped stanza names without either stay verbatim). `saved_searches.json` is a projection that keeps the ACL (app, owner, sharing, read and write permissions), `is_scheduled`, `disabled`, `dispatchAs`, `dispatch.earliest_time`, `cron_schedule`, enabled action names, and an `all_indexes` or `index_bound` classification of the SPL; the SPL text is `[REDACTED]` and every `action.<name>.param.*` value is dropped (`action_params_dropped` counts them)
- a snapshot that was denied, errored, or timed out is still written, as a marker object `{ collected: false, status, endpoint, error }` naming the endpoint the failed request went to and its observed HTTP status (`null` when there was no response); a readable-but-empty list keeps `entries: []`. `access_check.json` carries the same nulls per surface: `count`, `total`, `truncated`, and `httpStatus` are `null` on a probe that did not succeed or a surface that is not configured, `total` is `null` when splunkd omitted `paging.total`, and `capabilities` is `null` when `current-context` was unreadable
- `analysis/findings.json`, one JSON file per assessment area, and `analysis/summary.md`, all passed through the same redactor
- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, and one report per framework (`fedramp.md`, `cmmc.md`, `soc2.md`, `cis.md`, `pci.md`, `stig.md`, `irap.md`, `ismap.md`)
- `QUICK_REFERENCE.md`
- `_errors.log` when any collection step failed, one `<dataset>: <error>` line per failed read (tokens, session keys, and the ACS token are removed from every message)
- a `.zip` archive named after the allocated directory

Output paths are resolved with traversal and symlink-parent protection; a path that escapes `output_dir` is rejected.

## Control coverage

| # | Control | Tool | Finding id | Status semantics |
|---|---------|------|------------|------------------|
| 1 | Authentication method enforcement | `splunk_assess_authentication` | `SPLUNK-AUTH-01` | `pass` when `authType` is SAML or LDAP with an enabled provider stanza and at most 3 local accounts; `warn` when the provider endpoint or user list is unreadable or more than 3 local accounts remain; `fail` when `authType` is Splunk or the referenced provider is disabled or missing; `manual` for ProxySSO/Scripted or when `authentication.conf` is unreadable |
| 2 | Password policy compliance | `splunk_assess_authentication` | `SPLUNK-AUTH-02` | `pass` only when every evaluated `[splunk_auth]` setting is explicitly present and compliant; `warn` when settings are absent (absent is not treated as compliant); `fail` on any non-compliant value; `manual` when the stanza is unreadable |
| 3 | Multi-factor authentication | `splunk_assess_authentication` | `SPLUNK-AUTH-03` | `pass` when `externalTwoFactorAuthVendor` is Duo or RSA and the `/services/admin/Duo-MFA` or `Rsa-MFA` stanza exists; `fail` when no vendor is set and authType is not SAML; `manual` for SAML (MFA lives at the IdP) or unreadable config |
| 4 | Session timeout configuration | `splunk_assess_authentication` | `SPLUNK-AUTH-04` | `pass` when `web.conf tools.sessions.timeout` and `server.conf sessionTimeout` are within `max_session_minutes` (documented defaults are assumed and stated when a setting is absent); `fail` when either exceeds the threshold; `manual` when the stanzas are unreadable |
| 5 | Concurrent session limits | `splunk_assess_authentication` | `SPLUNK-AUTH-05` | always `manual`: Splunk exposes no per-user concurrent session limit through the REST API; role search quotas are attached as related evidence |
| 6 | Authentication token hygiene | `splunk_assess_authentication` | `SPLUNK-AUTH-06` | `pass` when every token expires, is newer than `max_token_age_days`, and maps to a known user in a readable user list; `warn` for stale tokens, tokens missing `iat`/`exp` claims, or a partial list (`seen N of M tokens` or total unknown); `fail` for non-expiring or orphaned tokens; `manual` when the token list is unreadable or empty; when the user list is unreadable the subject-to-user check is skipped, a pass is capped at `warn`, and the summary and `evidence.caveats` say so with the observed cause (`subject_not_in_user_list` renders `null`) |
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
| 22 | Saved search permissions | `splunk_assess_platform_hardening` | `SPLUNK-PLAT-22` | `pass` when no scheduled search dispatches as an admin owner over all indexes with an unbounded time range, or when none are scheduled, judged on a complete saved search list with the user list readable; `warn` when admin-owned searches dispatch as owner, when the list is partial, or when the user list is unreadable (owner roles could not be verified; with no scheduled searches the pass is capped at `warn` and the summary names the failed user read); `fail` when a scheduled search runs as its admin or unverified owner over all indexes with no time bound; `manual` when saved searches are unreadable or empty |
| 23 | Splunk-to-Splunk port security | `splunk_assess_platform_hardening` | `SPLUNK-PLAT-23` | enabled listeners are the union of `/services/data/inputs/tcp/cooked` entries and `inputs.conf` receiver stanzas, keyed by port; the cooked REST view does not report TLS and listener names are never used as evidence; `serverCert` and `requireClientCert` are resolved per port, from the `[splunktcp-ssl:<port>]` stanza first (inputs.conf: "Specify any TLS setting that deviates from the global setting here") and the global `[SSL]` stanza second; `pass` when every listener has an enabled `[splunktcp-ssl:<port>]` stanza and resolves to a `serverCert` with `requireClientCert=true`; `warn` when any port resolves `requireClientCert` to a non-true value (a per-port `false` overrides a global `true`) or to no value at all (inputs.conf documents the default as `false` if using self-signed and third-party certificates and `true` if using the default certificates, which the REST view cannot distinguish, so absent is reported as unknown), or when no `serverCert` is set at either level; `fail` when any enabled `[splunktcp://]` plaintext receiver exists; `manual` on Splunk Cloud, when this node has no enabled receiving ports, when the cooked input list or `inputs.conf` is unreadable (the summary names the endpoint and cause), or when a listener has no matching stanza; evidence carries the resolved `serverCert`, `requireClientCert`, and `sslVersions` values rather than the raw stanza; a failed `server/info` read caps a pass at `warn` with the URL-heuristic caveat |

Common verdict rules apply to every control:

- An unreadable or forbidden endpoint is `manual`. The summary names the endpoint the failed request actually went to and the observed cause (`401`, `403`, `404`, or the scrubbed error text), and evidence carries `endpoint`, `error`, and `http_status` (`null` when there was no HTTP response). An empty inventory is `manual` (or `fail` where the control's intent requires the inventory).
- A partial inventory never yields `pass`: the summary states `seen N of M` or `N (total unknown)`, and a pass is demoted to `warn` with `Downgraded:` and `evidence.partial_sources`. Items without dates are reported separately and cap the verdict at `warn`.
- A finding that read a secondary inventory it could not trust keeps its `warn`, `fail`, or `manual` verdict but never stays at `pass`: each caveat is appended to the summary and listed in `evidence.caveats`. Secondaries covered: the user list for AUTH-06, AUD-18, and PLAT-22; `inputs.conf` for DP-15; the ACS HEC inventory for DP-16; and `/services/server/info` for DP-14, DP-15, DP-16, PLAT-19, and PLAT-23, where a failed read means the Cloud or Enterprise classification came from the `*.splunkcloud.com` URL heuristic and the summary says so.
- Counts derived from an unreadable inventory render `null` in evidence (for example `users_with_delete_roles`, `subject_not_in_user_list`), never `0` or `[]`.

## Framework mappings

Each finding's `mappings` array contains one entry per framework, for example `FedRAMP (NIST 800-53 r5): IA-2, IA-8`. The mapping table is the one in section 5 of the spec and is embedded in `SPLUNK_CONTROLS` inside `cli/extensions/grc-tools/splunk.ts`. The export bundle renders the same data as `compliance/unified_compliance_matrix.md` and one markdown report per framework.

## Live smoke test

```bash
export SPLUNK_URL="https://splunk.example.com:8089"
export SPLUNK_TOKEN="..."
npm --prefix cli run test:splunk:live
```

The script skips with exit code 0 when no credentials or config file are present. With credentials it runs `splunk_check_access`, stops with a non-zero exit if the credential is `limited`, and otherwise runs the authentication assessment and prints each finding.

## Limitations and manual controls

- Controls 5 (concurrent session limits) and 14 (encryption at rest) are always `manual` because Splunk does not expose them through a read-only API.
- Control 19 (IP allow listing) needs Splunk Cloud plus ACS; on Splunk Enterprise it asks for firewall or load balancer evidence.
- Controls 15 and 23 (forwarder and S2S TLS) read `outputs.conf` and `inputs.conf` on the node you connect to. On Splunk Cloud, or on a search head that neither forwards nor receives, they are `manual` and name the forwarder or indexer files to collect. A documented explicit value always beats an inference: `useSSL=false` fails even with a `clientCert`, and a listener name containing `ssl` proves nothing.
- Control 3 is `manual` for SAML deployments without Splunk-native Duo or RSA, because MFA is enforced by the identity provider.
- Control 17's confirmation search creates one search job; pass `run_searches: false` to skip it, which caps the verdict at `warn`.
- Enterprise Security correlation searches, deployment server clients, and Splunk version currency are recorded as evidence where visible but are not separate verdicts.
- The spec describes "auditTrail enabled in audit.conf". The documented `[auditTrail]` stanza has no enabled flag; its `queueing` setting (default true) controls whether audit events reach the index queue, so that setting is read through `/services/configs/conf-audit` and a missing file is reported as the assumed default.
- The spec lists `sslCertPath` and `sslPassword` for forwarder TLS; current `outputs.conf` documents `clientCert` (the deprecated `sslCertPath` is also accepted) and defines `sslPassword` as the CA certificate password, so the password is recorded but never counts as TLS evidence.
- `/services/data/inputs/tcp/ssl` and `/services/data/inputs/tcp/cooked` do not document `serverCert`, `requireClientCert`, or a per-listener `SSL` value in their GET responses, so those values are read from `/services/configs/conf-inputs` instead.

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
