---
title: Sumo Logic
description: Read-only Sumo Logic organization security inspector covering SSO, MFA, RBAC, access keys, audit index, retention, collectors, content sharing, and alert routing.
---

The Sumo Logic tools inspect an organization's Management API configuration and map the results to the 20 controls in `specs/sumologic-sec-inspector.spec.md`. Every tool is read-only: no PUT, POST, or DELETE requests are ever issued.

## What it inspects

- Identity: SAML identity providers, the SAML bypass allowlist, password policy strength and expiration, and MFA enforcement plus per-user MFA coverage.
- Access control: role capabilities and admin concentration, access key age and last use, the IP service allowlist, and the maximum web session timeout.
- Data governance: audit and search audit policies, the audit index partition, outbound connections and data forwarding, collector health and versions, ingest budgets, and partition retention.
- Content sharing and alerting: the Data Access Level policy, org-wide content shares, scheduled search and monitor run identities, lookup table exposure, external dashboard sharing, and monitor notification routing.

## Setup and authentication

1. In Sumo Logic, open Administration > Security > Access Keys and create an access key for a dedicated audit user (or service account). Copy the key once; it is not shown again.
2. Give that user a role with the read capabilities the surfaces need. `sumologic_check_access` reports which capability is likely missing for each unreadable surface: `viewAccountOverview`, `manageUsersAndRoles` (users and roles), `manageAccessKeys` (org-wide keys; `createAccessKeys` only exposes the caller's own keys), `manageSaml`, `managePasswordPolicy`, `ipAllowlisting`, `manageOrgSettings` (policies), `viewPartitions`, `viewScheduledViews`, `manageBudgets`, `viewConnections`, `viewCollectors`, `viewMonitorsV2`, and `manageContent`.
3. Export the credentials:

```bash
export SUMOLOGIC_ACCESS_ID="suXXXXXXXX"
export SUMOLOGIC_ACCESS_KEY="..."
export SUMOLOGIC_ENDPOINT="us2"   # deployment code or full API URL
```

Configuration precedence is explicit tool arguments, then environment variables (`SUMOLOGIC_ACCESS_ID`, `SUMOLOGIC_ACCESS_KEY`, `SUMOLOGIC_ENDPOINT` or `SUMOLOGIC_DEPLOYMENT`, `SUMOLOGIC_TIMEOUT`), then a YAML config file at `SUMOLOGIC_CONFIG_FILE` or `~/.sumologic-sec-inspector/config.yaml` with `access_id`, `access_key`, and `endpoint` keys. A missing config file is skipped. One that cannot be read stops the tool with `Unable to read Sumo Logic config file <path> (<errno code>)`, and one that cannot be parsed stops it with `Unable to parse Sumo Logic config file: invalid YAML in <path> at line N, column M (<code>)`, where the code is the yaml package's own (`DUPLICATE_KEY`, `MISSING_CHAR`, `BAD_INDENT`, and so on) or `INVALID_YAML` when the parser threw something else, such as the unresolved alias `key: *value`; the position is omitted when the parser reports none. The message never repeats a line, key, or value from the file.

Requests use HTTP Basic authentication (`Authorization: Basic base64(accessId:accessKey)`). The client follows `token` continuation cursors on paginated endpoints (page size 1000 where the OpenAPI allows it, 100 for `/v2/dashboards` whose `limit` maximum is 100), uses `limit`/`offset` for the Collector Management and monitor search APIs, retries 429 and 5xx responses with backoff (honoring `Retry-After` when present), enforces a request timeout, and scrubs error messages as described under Export bundle.

### Deployments

| Code | API base URL |
|---|---|
| `us1` | `https://api.sumologic.com/api` |
| `us2` | `https://api.us2.sumologic.com/api` |
| `au` | `https://api.au.sumologic.com/api` |
| `ca` | `https://api.ca.sumologic.com/api` |
| `ch` | `https://api.ch.sumologic.com/api` |
| `de` | `https://api.de.sumologic.com/api` |
| `esc` | `https://api.esc.sumologic.com/api` |
| `eu` | `https://api.eu.sumologic.com/api` |
| `fed` | `https://api.fed.sumologic.com/api` |
| `in` | `https://api.in.sumologic.com/api` |
| `jp` | `https://api.jp.sumologic.com/api` |
| `kr` | `https://api.kr.sumologic.com/api` |

A full URL such as `https://api.eu.sumologic.com` is normalized to end in `/api`.

## Tools

| Tool | Purpose |
|---|---|
| `sumologic_check_access` | Probe 18 read surfaces (including `/v1/serviceAllowlist/addresses`) and report unreadable ones with the likely missing role capability. |
| `sumologic_assess_identity` | Controls 1 to 5: SAML SSO, SAML allowlist, password strength, password expiration, MFA. |
| `sumologic_assess_access_control` | Controls 6, 7, 8, 13, 14: RBAC, key rotation, inactive keys, service allowlist, session timeout. |
| `sumologic_assess_data_governance` | Controls 9, 10, 12, 16, 17: audit index, data forwarding, collectors, ingest budgets, retention. |
| `sumologic_assess_content_sharing` | Controls 11, 15, 18, 19, 20: content sharing, scheduled search permissions, lookup tables, dashboard sharing, alert routing. |
| `sumologic_export_audit_bundle` | Run everything and write `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log` (on partial collection), and a zip. |

Every run allocates a fresh output directory and a zip with the same base name, so re-running never overwrites a prior bundle.

### Export bundle

`core_data/<area>.json` and the `rawData` echoed by each assess tool come from the same serializer. Every dataset is written as `{ ok, complete, scope, count, error, http_status, endpoint, data }`:

- `data` is an allowlist projection, not the API record. Connections keep `id`, `name`, `type`, `webhookType`, `connectionSubtype`, audit dates, and `url_host` (host only); `url`, `username`, every `headers[].value` and `customHeaders[].value`, `defaultPayload`, and `resolutionPayload` are `[REDACTED]`. Monitors keep identity, status, `runAs.runAsId`, and per-notification `connectionType`, `connectionId`, and `recipients`; `subject`, `messageBody`, `payloadOverride`, and `resolutionPayloadOverride` are `[REDACTED]`. Access keys keep `label`, `disabled`, dates, `scopes`, a four-character `id_prefix`, and `cors_header_count`. SAML identity providers keep configuration flags and URLs; `x509cert1`, `x509cert2`, `x509cert3`, and `certificate` are `[REDACTED]`. The password policy, users, collectors, dashboards, and the personal folder keep identifying and status fields only.
- When a dataset was denied, errored, or timed out, `data` is a marker object `{ collected: false, status, endpoint, error }` carrying the observed HTTP status (`null` when the request failed before a response) and the path that failed, and `complete`, `scope`, and `count` are `null`. A readable-but-empty list stays `[]` with `count: 0`.
- `content_permissions` hangs off the personal folder listing. When that listing could not be read no permission lookup is issued and the dataset is the marker with `error` starting `Not requested: no content permission lookups were issued because the personal folder could not be read (...)` and `status` and `endpoint` `null`. When every issued lookup failed the dataset is the marker with `error` starting `every content permission lookup failed (N of N):` followed by each item's error (no single status or endpoint stands for the set), and `org_shared_items` renders `null` in the summary and in the evidence of controls 11 and 18. Otherwise it holds one row per sampled item (`id`, `name`, `itemType`, `ok`, `permissions`) and is `complete` only when every lookup succeeded.
- `core_data/access_check.json` carries the same nulls per surface: `count`, `complete`, and `httpStatus` are `null` on a probe that did not succeed, and `httpStatus` is `null` on a readable one.
- `_errors.log` lists `<area>: <dataset>: <error>` with every message scrubbed by the error text rule below; `analysis/<area>.json` holds the assessment summary, findings, and errors; `QUICK_REFERENCE.md` and the `compliance/` reports hold finding text only.

Truncation is reported per list. Token-cursor lists (`/v1/users`, `/v1/roles`, `/v1/accessKeys`, `/v1/partitions`, `/v1/scheduledViews`, `/v2/ingestBudgets`, `/v1/connections`, `/v2/dashboards`) stop with `complete: false` on the 50-page cap, on a `next` token equal to the one just sent, or on an empty page that still carries a `next` token. Offset lists (`/v1/collectors`, `/v1/monitors/search`) stop with `complete: false` on the page cap and are complete on a short page.

Error text follows its own rule, applied when an API error is constructed and again wherever an error string is recorded (dataset markers, `_errors.log`, finding evidence, the access check, and tool error payloads). A value inside a carrier is removed whatever its shape: the value of a credential-named header (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, and similar), a cookie or session assignment, URL userinfo and query pairs (the query string collapses to `?[REDACTED]`), the value after the `Bearer`, `Basic`, `Digest`, `Token`, `OAuth`, `Negotiate`, `NTLM`, `SSWS`, and `ApiKey` schemes (the scheme word stays), and the value of every credential-named `key=value` or `key: value` pair. A quoted value in any of these carriers (plain, single, or JSON-escaped quotes, as in `Cookie: sid="..."`, `Authorization: Bearer "..."`, or `\"Authorization\": \"Bearer ...\"`) is removed with its quotes kept, and a quote alone never makes a header value a credential (`Content-Type: "application/json"` stays). A configured secret (the access ID, the access key, and the base64 Basic credential built from them) is removed whatever its shape, in its raw, JSON-escaped, URL-encoded, base64, and base64url forms. A value with a real token shape is removed bare: PEM blocks, JWTs, AWS key IDs and secrets, other vendor-prefixed tokens, hex digests of 32 or more characters, and runs of 16 or more characters that carry a base64 symbol, more than one digit group, or token casing. A bare value shaped like a name (words joined by hyphens or underscores with at most one digit group, such as `prod-us-east-2026`, or a camelCase identifier whose words average three or more letters, such as `retentionPeriod`, `dataForwardingId`) is indistinguishable from a resource name and stays, and so does a token-shaped segment of a bare request path or file path (`/v2/content/<id>/permissions`, the config file path), so the endpoint or file an error names is the one the run used; inside a URL with a scheme every path segment keeps the rule because webhook URLs carry their token there. The credential-named last segment of a bare path used as a label (`/v1/accessKeys: <detail>`) is a request target rather than a pair key, so the text after it stays; inside a URL with a scheme the pair rule still applies.

## Status semantics

- `pass`: the enabling flag was read and the full population satisfied the control.
- `warn`: partial evidence (incomplete pagination, undated items, secondary flags off) prevented a pass.
- `fail`: the control is violated.
- `manual`: the endpoint was unreadable (401/403/error), the control is not applicable or plan-limited, or the API cannot expose the evidence. The summary names exactly what a human must collect.

Unreadable endpoints, empty inventories, capability-limited views, and unfollowed pagination never produce `pass`:

- A finding that reads several inventories never passes while one of them is unreadable. The summary appends `Not checked: the <inventory> could not be read because <cause>; collect manually: ...`, `evidence.unreadable_inventories` names the inventory, and the pass drops to `warn` when the control can still be judged from the readable inventories or to `manual` when the unreadable inventory is essential (the rows below say which). Existing `warn`, `fail`, and `manual` verdicts keep their status and gain the note.
- A list whose pagination stopped early (`complete: false`) drops a pass judged on it to `warn`; the summary states how many items were seen and that the population is incomplete, and `evidence.incomplete_inventories` names each such list when a finding reads several.
- The cause named in a summary, marker, or evidence field is the observed one: `401` or `403` when that status came back, otherwise the scrubbed error text; `evidence.http_status` and `evidence.endpoint` carry the status and path of the request that actually failed, and are `null` when there was no HTTP response.
- Counts and lists derived from an unreadable inventory render `null` in finding evidence and in the assessment `summary`, never `0` or `[]`; a count derived from per-item lookups (org-wide shares from content permission lookups) renders `null` when every lookup failed and covers only the items whose lookups succeeded otherwise, with `permission_lookups_failed` recording the rest.

## Control coverage

| # | Spec control | Tool | Finding | Status semantics |
|---|---|---|---|---|
| 1 | SAML SSO Enforcement | identity | SUMO-01 | `fail` on zero IdPs; `warn` on debug mode or missing certificate; otherwise `manual` because the API does not expose the SAML lockdown (require SAML sign-in) state |
| 2 | SAML Allowlisted Users Minimized | identity | SUMO-02 | `manual` when the allowlist is unreadable, or when the IdP list was read and is empty (not applicable); `fail` above `max_allowlisted_users`; `warn` on inactive allowlisted users; `pass` at or below the threshold (zero is compliant) only while the SAML identity provider list was readable: with that list unreadable the pass drops to `warn` and the summary names it under `Not checked:` |
| 3 | Password Policy Strength | identity | SUMO-03 | `fail` below `min_password_length` or without lockout; `warn` when complexity or weak-password rejection is incomplete |
| 4 | Password Expiration Policy | identity | SUMO-04 | `fail` when disabled or above `max_password_age_days` |
| 5 | MFA Enforcement | identity | SUMO-05 | `manual` when the password policy or the user list is unreadable (the summary says which and reports per-user coverage as unknown) or zero users were returned; `fail` when `requireMfa` is false or absent; `warn` when active users report `isMfaEnabled=false` or the user list stopped before its last page (seen count stated); `pass` only on a complete user list; evidence lists locked users, dormant users, and users without a `lastLoginTimestamp` (never counted as active) |
| 6 | Role-Based Access Control | access control | SUMO-06 | `manual` when the role list is unreadable or empty; `fail` when admin-capability role members exceed `max_admins`; `warn` on custom roles with admin capabilities, custom roles without a `filterPredicate`, admin members dormant beyond `user_inactive_days` or without a `lastLoginTimestamp`, an unreadable user list, or a user list that stopped before its last page; `pass` only on a complete role list (a page-capped role list drops it to `warn` with the seen count) |
| 7 | Access Key Rotation | access control | SUMO-07 | `manual` when the key inventory is unreadable, on personal-only scope, or on zero keys; `fail` on enabled keys older than `key_max_age_days`; `warn` on keys without `createdAt` or when the access key lifetime policy is `0` (never expire), absent, or unreadable; `pass` only on a complete org-scope key list (a page-capped list drops it to `warn`); every summary states the lifetime policy value |
| 8 | Inactive Access Keys | access control | SUMO-08 | `manual` when the key inventory is unreadable, on personal-only scope, or on zero keys; `fail` on keys idle beyond `key_inactive_days`; `warn` on keys without `lastUsed`; `pass` only on a complete org-scope key list (a page-capped list drops it to `warn`) |
| 9 | Audit Index Enabled | data governance | SUMO-09 | `manual` when the audit policy is unreadable, when the partition list is unreadable (the summary names its error), or when no active AuditIndex partition is visible (plan limitation); `fail` when the audit policy is not enabled; `warn` when the search audit policy was read and is disabled; `pass` only when the audit policy, the search audit policy, and at least one active audit index partition were all read: with the search audit policy unreadable the pass drops to `warn` and the summary names it under `Not checked:` instead of claiming both policies are enabled; a page-capped partition list drops the pass to `warn` with `Pagination stopped before the last page, so only N items were seen and the population is incomplete` |
| 10 | Data Forwarding Destinations Reviewed | data governance | SUMO-10 | `manual` when the connection list is unreadable; `pass` on zero connections and zero forwarding destinations only when the partition and scheduled view lists were both readable and the partition list is non-empty, or when every connection host matches `approved_destination_domains`; `fail` on unapproved hosts; `manual` when no approved list was supplied; a page-capped connection, partition, or scheduled view list drops a pass to `warn` naming the list and its seen count (`evidence.incomplete_inventories`); an unreadable partition or scheduled view list drops a pass to `manual` naming that list under `Not checked:` |
| 11 | Content Sharing Permissions | content sharing | SUMO-11 | `manual` when the Data Access Level policy is unreadable; `fail` when it is off; `warn` on org-wide shares in the sampled folder or when the personal folder holds more items than `content_sample` (total, sampled, and unsampled counts are recorded); `manual` when the personal folder could not be read (named under `Not checked:`) or any permission lookup failed (the failed items and their errors are listed); `pass` only when every folder item was evaluated |
| 12 | Collector Management | data governance | SUMO-12 | `fail` on installed collectors offline beyond `collector_offline_days` or without last-seen; `warn` on offline or mixed versions; `manual` on zero collectors |
| 13 | Service Allowlist Configured | access control | SUMO-13 | `fail` when `loginEnabled` is false or zero CIDRs; `warn` when content allowlisting is off |
| 14 | Session Timeout Policy | access control | SUMO-14 | `manual` when the session timeout policy is unreadable or has no parsable value; `fail` above `max_session_timeout_minutes`; `pass` when the concurrent sessions limit policy was read and is enabled; `warn` when it was read and is not enabled; with that policy unreadable the pass drops to `warn` and the summary names it under `Not checked:` (a 403 is never reported as "not enabled") |
| 15 | Scheduled Search Permissions | content sharing | SUMO-15 | always `manual`: role bindings are not exposed; the summary states monitors seen with `runAs` and scheduled searches in the sampled folder, and names the monitor list or the personal folder under `Not checked:` when either could not be read |
| 16 | Ingest Budget Controls | data governance | SUMO-16 | `fail` on zero budgets; `warn` when none use `stopCollecting` |
| 17 | Data Retention Policies | data governance | SUMO-17 | `fail` when an audit index retains less than `min_retention_days`; `warn` on other short or account-default (`-1`) partitions |
| 18 | Lookup Table Access | content sharing | SUMO-18 | `warn` on org-shared lookup tables in the sampled folder; otherwise `manual` because the API has no lookup table listing; the summary names the personal folder under `Not checked:` when it could not be read and lists failed permission lookups |
| 19 | Dashboard Sharing Restrictions | content sharing | SUMO-19 | `manual` when the policy is unreadable, has no `enabled` flag, or the dashboard list is unreadable or empty; `fail` when sharing outside the org is enabled (the summary states how many seen dashboards are public, or that the dashboard list could not be read); `warn` on `isPublic` dashboards; `pass` only on a complete dashboard list (a page-capped list drops it to `warn`) |
| 20 | Monitor Alert Routing | content sharing | SUMO-20 | `manual` when the monitor list is unreadable, on zero monitors, or when no org email domain could be derived; `fail` on recipients outside org domains or notifications to connections missing from the connection inventory; `warn` on disabled monitors or zero notifications; `pass` only on a complete monitor list with the user and connection lists readable: a page-capped monitor list drops it to `warn`; an unreadable user list drops it to `warn` and names the list even when `approved_email_domains` supplied the domains; an unreadable connection list drops it to `manual` when any webhook notification exists and to `warn` when routing is email-only |

## Framework mappings

Each finding carries the spec's mapping row for FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP (for example SUMO-01 maps to FedRAMP IA-2, CMMC AC.L2-3.1.1, SOC 2 CC6.1, CIS 1.1, PCI-DSS 8.3.1, STIG SRG-APP-000148, IRAP ISM-1557, ISMAP CPS-04). The export bundle writes one report per framework under `compliance/` plus `unified_compliance_matrix.md`.

## Live smoke test

```bash
npm --prefix cli run test:sumologic:live
```

The script skips with exit code 0 when `SUMOLOGIC_ACCESS_ID` or `SUMOLOGIC_ACCESS_KEY` is absent; otherwise it runs the access check and the identity assessment against the configured deployment.

## Limitations and manual controls

- SAML lockdown (require SAML sign-in) has enable and disable endpoints but no status GET, so control 1 cannot pass automatically.
- Scheduled search role bindings (control 15) and lookup table inventories (control 18) are not exposed by list endpoints; the findings state the evidence to collect.
- Audit event flow is not proven by configuration alone; run `_index=sumologic_audit_events` for the last 24 hours as supporting evidence for control 9.
- Content permission sampling covers the key owner's personal folder up to `content_sample` items (default 25); when the folder holds more, control 11 reports the unsampled remainder and yields at most `warn`. Admin Recommended and Global folders require asynchronous job endpoints that this integration does not call.
- The access key lifetime policy (`accessKeysLifetimeInDays`, one of `0`, `30`, `45`, `60`, `90`, `180`, `365`) is read for control 7; `0` means keys never expire and caps the verdict at `warn` even when every key is young.
- Partition retention `-1` means the account default, which the API does not resolve; those partitions are reported separately and yield at most `warn`.
- A key without `manageAccessKeys` sees only its own keys via `/v1/accessKeys/personal`; controls 7 and 8 then render as `manual` with the seen count.

## Official documentation

- [API authentication, endpoints, and rate limits](https://help.sumologic.com/docs/api/about-apis/getting-started/)
- [OpenAPI definition](https://api.sumologic.com/docs/sumologic-api.yaml) and [interactive reference](https://api.sumologic.com/docs/)
- [Collector Management API](https://help.sumologic.com/docs/api/collector-management/collector-api-methods-examples/)
- [Access keys](https://help.sumologic.com/docs/manage/security/access-keys/)
- [Role capabilities](https://help.sumologic.com/docs/manage/users-roles/roles/role-capabilities/)
- [SAML configuration](https://help.sumologic.com/docs/manage/security/saml/)
- [Audit index](https://help.sumologic.com/docs/manage/security/audit-indexes/audit-index/)
