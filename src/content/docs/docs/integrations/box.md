---
title: Box
description: Read-only Box Enterprise security inspection covering identity, sharing, data governance, and Shield monitoring, mapped to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP.
---

The Box integration inspects a Box Enterprise tenant through the Box Content API and reports posture findings for the 25 controls defined in `specs/box-sec-inspector.spec.md`. Every tool is read-only: nothing is created, changed, or deleted in the tenant.

## What it inspects

- **Identity and access**: SSO enforcement, 2-step verification for admins and all users, admin and co-admin sprawl, password policy, session duration, IP allowlisting, and inactive users derived from the enterprise event stream.
- **Sharing and collaboration**: external collaboration mode, collaboration allowlist hygiene, shared link defaults and expiration, shared link passwords, watermarking, app authorization activity, and custom terms of service.
- **Data governance**: device pins, classification labels, retention policies and assignments, legal hold policies and assignments.
- **Shield and monitoring**: Shield rules, information barriers and segments, the `admin_logs` enterprise event stream, and content access anomaly signals.

Findings are normalized as `{ id, control, title, severity, status, summary, evidence, mappings, manualEvidence }` where `severity` is `critical | high | medium | low | info` and `status` is `pass | warn | fail | manual`. A `manual` finding always includes the exact Admin Console evidence a human must collect.

## Setup and authentication

Create a Box Platform app in the Developer Console, enable the scopes below, and authorize it in the Admin Console (Apps > Custom Apps Manager). The inspector supports the three server-side auth flows Box documents.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `BOX_AUTH_METHOD` | `jwt`, `ccg`, or `oauth`. Optional; inferred from the credentials present. |
| `BOX_JWT_CONFIG_PATH` | Path to the JWT app config JSON downloaded from the Developer Console. |
| `BOX_JWT_PASSPHRASE` | Private key passphrase when it is not stored in the config file. |
| `BOX_JWT_ALGORITHM` | `RS256`, `RS384`, or `RS512` (default `RS512`). |
| `BOX_CLIENT_ID`, `BOX_CLIENT_SECRET` | App credentials for Client Credentials Grant, or for refreshing an OAuth token. |
| `BOX_ENTERPRISE_ID` | Enterprise ID for JWT and CCG service-account tokens and for enterprise-scoped endpoints. |
| `BOX_SUBJECT_TYPE`, `BOX_SUBJECT_ID` | Act as a specific managed user instead of the service account (`user` plus a user ID). |
| `BOX_ACCESS_TOKEN` (also `BOX_TOKEN`, `BOX_DEVELOPER_TOKEN`) | Pre-issued OAuth 2.0 access token. |
| `BOX_REFRESH_TOKEN` | OAuth 2.0 refresh token, used with the client ID and secret when a 401 is returned. |
| `BOX_CONFIG_PATH` | YAML config file path (default `~/.box-sec-inspector/config.yaml`). |
| `BOX_API_BASE_URL`, `BOX_TOKEN_URL` | Override `https://api.box.com/2.0` and `https://api.box.com/oauth2/token`. |
| `BOX_TIMEOUT`, `BOX_MAX_RETRIES` | Request timeout in seconds (default 30) and retries for 429 and 5xx responses (default 3). |

Precedence is explicit tool arguments, then environment variables, then the config file. An argument that is not passed never erases an environment value: a tool called with only `timeout_seconds` still uses `BOX_ACCESS_TOKEN` and the file `BOX_CONFIG_PATH` names. A config file named by `config_path` or `BOX_CONFIG_PATH` must exist and hold at least one Box setting (a missing default file at `~/.box-sec-inspector/config.yaml` is simply absent). When a config or JWT file cannot be read or parsed, the tool fails with fixed text that carries only the path, the filesystem's error code (`ENOENT`, `EACCES`, `EISDIR`), and the YAML parser's line or `JSON.parse`'s position (`Unable to parse Box config file: invalid YAML in <path> at line 4`), never the library's own message, which quotes the offending line, and nothing is written. The YAML file accepts the same keys in snake_case, optionally nested under a `box:` section:

```yaml
box:
  auth_method: ccg
  client_id: "abc123"
  client_secret: "..."
  enterprise_id: "123456"
  timeout_seconds: 30
```

### JWT (server authentication)

Point `BOX_JWT_CONFIG_PATH` at the config JSON (`boxAppSettings.clientID`, `clientSecret`, `appAuth.publicKeyID`, `appAuth.privateKey`, `appAuth.passphrase`, and `enterpriseID`). grclanker signs the assertion with `node:crypto` (`alg` RS512 by default, `kid` set to the public key ID, `aud` set to the token URL (`https://api.box.com/oauth2/token` unless `BOX_TOKEN_URL` overrides it), `box_sub_type` `enterprise` or `user`, 45 second expiry) and posts it to the token endpoint with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`. No SDK is required.

### Client Credentials Grant

Set `BOX_CLIENT_ID`, `BOX_CLIENT_SECRET`, and `BOX_ENTERPRISE_ID`. grclanker posts `grant_type=client_credentials` with `box_subject_type=enterprise` and `box_subject_id=<enterprise_id>` (or `box_subject_type=user` when `BOX_SUBJECT_TYPE=user`). Tokens are cached until shortly before `expires_in` elapses and re-requested on 401.

### OAuth 2.0

Set `BOX_ACCESS_TOKEN` for a pre-issued token (for example a Developer Console developer token, or a token minted by your own OAuth flow for an admin or co-admin). When `BOX_REFRESH_TOKEN`, `BOX_CLIENT_ID`, and `BOX_CLIENT_SECRET` are present the client refreshes automatically after a 401. When no enterprise ID is configured it is discovered from `GET /users/me?fields=enterprise`.

### Required Box app scopes

| Application scope | Used for |
| --- | --- |
| Read all files and folders stored in Box | Metadata templates, classification template, terms of service |
| Manage users | `GET /users`, `GET /users/me` |
| Manage groups | `GET /groups` |
| Manage enterprise properties | Enterprise configuration, `admin_logs` events, collaboration allowlist, device pins, Shield lists and rules |
| Manage retention policies | Retention policies and assignments (Box Governance) |
| Manage legal holds | Legal hold policies and assignments (Box Governance) |
| Manage Shield (information barriers) | Shield information barriers and segments (Box Shield) |

Re-authorize the app in the Admin Console after changing scopes. `box_check_access` reports each surface separately so partial grants are visible before you run an assessment.

## Tools

| Tool | Purpose |
| --- | --- |
| `box_check_access` | Resolves credentials, exchanges a token, and probes 15 read surfaces (current user, enterprise configuration, users, groups, enterprise events, device pins, retention, legal holds, Shield barriers and lists, allowlist entries and exemptions, metadata and classification templates, terms of service). Reports `healthy` or `limited` with the next step. |
| `box_assess_identity_access` | Controls 1, 2, 3, 17, 18, 21, 22, 23, 24. Options: `user_limit`, `event_limit`, `lookback_days`, `max_admins`, `min_password_length`, `max_session_hours`. |
| `box_assess_sharing_collaboration` | Controls 4, 5, 6, 7, 8, 9, 19, 20. Options: `event_limit`, `lookback_days`, `stale_allowlist_days`, `list_limit`. |
| `box_assess_data_governance` | Controls 10, 11, 12, 13. Option: `list_limit`. |
| `box_assess_shield_monitoring` | Controls 14, 15, 16, 25. Options: `event_limit`, `lookback_days`. |
| `box_export_audit_bundle` | Runs the access check plus all four assessments and writes an evidence bundle (default `./export/box`). |

Every tool accepts the auth arguments (`auth_method`, `jwt_config_path`, `jwt_passphrase`, `client_id`, `client_secret`, `enterprise_id`, `subject_type`, `subject_id`, `access_token`, `refresh_token`, `config_path`, `base_url`, `token_url`, `timeout_seconds`, `max_retries`).

### Audit bundle layout

```text
<enterprise_id>-audit-bundle/
  QUICK_REFERENCE.md
  metadata.json
  _errors.log                     (only when some reads failed)
  core_data/                      raw API snapshots (users, groups, events, policies, templates, ...)
    collection_status.json        per-snapshot record count, read error, and truncation flag
  analysis/
    findings.json                 all 25 findings with evidence and mappings
    summary.json
    identity_access.json, sharing_collaboration.json, data_governance.json, shield_monitoring.json
  compliance/
    executive_summary.md
    unified_compliance_matrix.md
    fedramp/, cmmc/, soc2/, cis/, pci_dss/, disa_stig/, irap/, ismap/   one report each
<enterprise_id>-audit-bundle.zip
```

Output paths are resolved inside the output root with traversal and symlinked-parent protection, and files are written with `0600` permissions. Credentials are never written into the bundle: every record the client collects passes through one data-side scrub at the collection boundary (and every `core_data/` snapshot through the same scrub again at write time) that replaces the whole subtree under any credential-shaped key (`token`, `tokens`, `secret`, `secrets`, `password`, `passphrase`, `api_key`, `api_keys`, `client_secret`, `credentials`, `authorization`, and their camelCase forms) with `[REDACTED]` while keeping the key, whether the value is a string, a list, or a nested object; blanks the value of `{name, value}` tracking-code pairs with a credential-shaped name; and runs every other string, free text included, through the shared pattern pass (the query of any URL anywhere in the text is replaced by one marker, bearer, cookie, and assignment carriers lose their value, webhook-style paths lose their token segment, and high-entropy or hex tokens are removed). Enterprise events are projected to `event_id`, `event_type`, `created_at`, `created_by`, `source`, `session_id`, and `ip_address` (the free-form `additional_details` bucket is dropped), and terms of service to `id`, `type`, `tos_type`, `status`, `text_length`, `created_at`, and `modified_at` (the agreement text is not written). Non-JSON error bodies are described by content type and length in error text, never echoed. A rerun never overwrites an earlier export: the directory takes the next free `-2`, `-3` suffix (a suffix is also considered taken when only its zip remains), and the zip is named after the directory that was actually allocated.

Recorded error text follows one rule at one place: every dataset error, access surface `error`, assessment `errors` entry, `_errors.log` line, and tool failure message is produced by a single function that passes the thrown message through the module scrubber, and a `SyntaxError` raised by the transport is recorded as its class name plus a fixed note because the parser's message quotes the body. The scrubber removes the configured client secret, access token, refresh token, JWT passphrase, and private key, and every token the client is issued, at full length in plain, base64, base64url, URL-encoded, form-encoded, and JSON-escaped form. It also removes the value of every credential carrier whatever the value's shape: a `key=value`, `key: value`, or `"key": "value"` pair whose key carries a credential word (`client_secret`, `developer_token`, `BOX_CLIENT_SECRET`, and the bearer ids `secret_id`, `session_id`, and `token_id`), also when the key follows a JSON escape (`\"client_secret\": \"v\"`) or a command-line flag (`--password v`, `--password=v`, `-Dpassword=v`); an authorization scheme word in any casing (`Bearer`, `bearer`, `Basic`, `Token`) loses the value after it, and the word itself stays only under `Authorization`, `Proxy-Authorization`, and `WWW-Authenticate`, while an API-key or token header (`X-Api-Key: splunk rejected`) and a credential-named assignment (`token=Bearer v`) lose their whole value; a cookie header loses its value whole; the query of any URL becomes one marker; and a webhook or callback URL keeps its origin alone. A `webhook`-prefixed key is a URL carrier only when its last segment is `url` or `uri` or the key is the bare `webhook`; `webhook_secret`, `webhook_token`, and `webhookSecret` are credential keys and lose their value whatever its shape. A configured secret that is itself a carrier word (`password`, `Authorization`, `Bearer`) is removed after the carriers rather than before them, so the pair or header it names still loses its value. A name after a path slash (`GET /2.0/users/me/token: 403`) is a path segment, not a key, and a key whose last segment names a setting (`BOX_AUTH_METHOD`, `BOX_TOKEN_URL`, `client_id`, `session_duration`, `password_reset_frequency`) keeps a word value and loses only a token-shaped or registered one, so every fixed message and every finding summary, manual-evidence instruction, and bundle document survives the pass unchanged; the test suite sweeps thousands of strings recorded by healthy, weak, and partially denied runs for alterations.

## Control coverage

Status semantics: `pass` means the API evidence satisfies the control, `warn` means partial or threshold-adjacent evidence, `fail` means the API evidence contradicts the control, and `manual` means the API cannot prove the control and the finding lists the Admin Console evidence to collect. Absent data never produces `fail`: a configuration category that Box returns as `null` (the `2025.0` schema allows `security`, `content_and_sharing`, `user_settings`, and `shield` to be null) or an unreadable user list yields `manual` or `warn` with the reason, and a setting that is missing from a readable category yields `warn`. Every configuration item carries an `is_used` flag ("indicates whether a configuration is used for a given enterprise"); an item with `is_used: false` is treated as not enforced, so the finding is `warn` with the reported value under `evidence.unused_settings` and the per-item flags under `evidence.is_used`, and it never supports `pass`. User-level findings (BOX-02, 03, 17, 18, 24) also never `pass` on an empty inventory: a readable `/users` list with zero entries, or one without any `admin` account, is reported as `warn` with the reason under `evidence.inventory_gap`, because a Box enterprise always has at least the primary admin. Paginated lists track truncation from the API's own signal (a `next_marker`, an `offset` short of `total_count`, or a `next_stream_position` remaining once the cap was reached), never from the returned length: a truncated list is reported under `truncated` in every assessment result, under `truncated_datasets` in the bundle summary, and per file in `core_data/collection_status.json`, and any finding whose `pass` depends on the absence of a record (BOX-02, 03, 17, 18, 24 on users; BOX-24 and BOX-25 on events; BOX-05 on the allowlist; BOX-12 and BOX-13 on policies) is downgraded to `warn` with the `user_limit`, `event_limit`, or `list_limit` option to raise. BOX-12 and BOX-13 test the listing's truncation before its emptiness: a retention or legal hold listing that stopped before any active policy was read renders `warn` with the listing's stop reason, never `fail` ("No active retention policies exist" is reserved for a complete listing), and a capped listing whose policies read all have assignments renders `warn`, not `pass`, with the seen count stated against the unknown total ("2/2 active retention policies have assignments among the 2 policies read, but the retention policy listing stopped after 2 records because ..."), both counts as lower bounds, and `retention_policies_truncated` or `legal_hold_policies_truncated` in the evidence.

Evidence derived from a listing that stopped short follows one rule across the four assessments. A count or list whose zero or empty value would read as "none exist" (`admin_users`, `privileged_users`, `active_users`, `active_policies`, `enabled_barriers`, `device_pins`, `allowlist_entries`, a barrier's `segments`, the summary counts) renders `null` when the listing it came from was truncated or unreadable and the count is zero; a positive count from a truncated listing renders as a lower bound beside the listing's `_truncated` flag. Counts named for the read's own size (`sampled_users`, `sampled_events`, `policies_read`, `barriers_read`) always render, zero included, because they report the read rather than the inventory. Item-level detail (user labels under `admins`, `coadmins`, `exempt_privileged_users`, `exempt_users`, `inactive_candidates`; allowlist domains under `allowlist_entries`, `public_email_domains`, `stale_entries`, `undated_entries`; the `retention_policies` and `legal_hold_policies` records; `device_pin_products`) is withheld as `null` while its listing is truncated, with a `_count` lower bound beside it (`coadmin_users`, `exempt_privileged_users_count`, `inactive_candidates_count`, `allowlist_entries_count`, `public_email_domain_count`, `stale_entry_count`, `undated_entry_count`), and rendered in full, empty lists included, once the listing was read to completion. Findings whose `pass` rests on a setting or on a record that was read keep it under a truncated secondary listing and state the stop: BOX-04 passes on the enterprise collaboration mode with the allowlist listing's stop reason in the text and `allowlist_entries_truncated` in the evidence, and BOX-15 passes on a segment that exists with the segment listing's stop in the text and `segments_truncated` in the evidence; an allowlist or segment page that stopped before any entry was read renders `warn` saying the listing stopped, never that the allowlist is empty or the barrier unsegmented. Event-derived breakdowns (`app_events`, `event_types`, `shield_events`, `anomaly_events`) render as `{ observed, sampled_events, events_truncated }` when the event collection stopped at its cap, and `activity_events`, `failed_login_events`, and the summary `app_events` follow the count rule. Every pagination exit that can leave records behind sets the flag: an empty marker page that still carries a `next_marker`, an empty offset page while `offset` is below `total_count`, a `next_stream_position` that is missing or stops advancing while entries keep arriving, and the 50-policy cap on retention, legal hold, and barrier segment sub-listings (reported as `retention_policy_assignments`, `legal_hold_policy_assignments`, or `shield_information_barrier_segments`). Marker-paged lists count a record once by `id`, and the walk ends, reported truncated with the reason, when a page under a fresh marker adds no record that was not already collected or when the server repeats its marker, so a re-served page cannot inflate a count or hold the walk open. The events walk also ends, and is reported truncated with the reason, when a page under a fresh stream position adds no event that was not already collected (an event is counted once by `event_id`, so a server that re-serves collected events cannot hold the walk open or inflate the sample) and when a page cap proportional to `event_limit` is reached whatever the progress; `core_data/collection_status.json` carries the reason per dataset under `truncation_reason`.

Findings that read more than one inventory never `pass` while any of them is unreadable (403, 401, or another read error), even when the readable inventory alone would satisfy the control: BOX-04 and BOX-05 (enterprise configuration, allowlist entries, exempt targets), BOX-12 and BOX-13 (policies plus their assignments), BOX-15 (barriers plus segments), and BOX-25 (Shield configuration plus enterprise events) drop to `warn` with the unreadable dataset and endpoint named in the summary and listed under `evidence.unreadable_inventories`; BOX-02, BOX-03, and BOX-24 already render `manual` when users, the security configuration, or events cannot be read. A success status is not a success by itself: a 2xx whose body is empty, is not JSON (a portal or proxy page), or is JSON of another shape (a list without an `entries` array, a resource without any of its documented keys, a bare array) is recorded as a failed read of that request with status `200` and a fixed status-and-length note (the body is never echoed) in `core_data/collection_status.json`, the dataset's marker file, and the access check, so its dependents go `manual` or `warn` instead of passing or failing on data that was never observed.

| # | Control | Tool | Finding | Status semantics |
| --- | --- | --- | --- | --- |
| 1 | SSO enforcement | identity_access | BOX-01 | pass when `is_enterprise_sso_required` is true and not in testing; warn in testing mode or when the flag is not exposed; fail when it is false; manual when `user_settings` is unreadable or null |
| 2 | 2FA for admins | identity_access | BOX-02 | pass when MFA is required and no admin or co-admin is `is_exempt_from_login_verification`; fail on exempt admins or MFA explicitly not required; warn when only SSO enforces MFA or the flag is not exposed; manual when users or `security` are unreadable |
| 3 | 2FA for all users | identity_access | BOX-03 | pass when MFA is required with no exempt users; warn on exemptions, SSO-only MFA, or an unexposed flag; fail when MFA is explicitly not required without required SSO; manual when users or `security` are unreadable |
| 4 | External collaboration restrictions | sharing_collaboration | BOX-04 | pass for `limit_collaboration_to_users_within_enterprise` or allowlisted domains; fail for `enable_external_collaboration` |
| 5 | Collaboration allowlist audit | sharing_collaboration | BOX-05 | fail on public email domains; warn on entries older than `stale_allowlist_days`, entries whose `created_at` is missing or unparseable (listed under `evidence.undated_entries`), exempt users, or a truncated allowlist; pass otherwise |
| 6 | Sharing link policies | sharing_collaboration | BOX-06 | fail when `shared_link_default_access` is open; warn when open links remain selectable; pass for company or collaborator defaults |
| 7 | Shared link expiration | sharing_collaboration | BOX-07 | pass when `is_shared_links_expiration_enabled`; warn when only public links expire or the flag is not exposed; fail when it is false |
| 8 | Shared link password policy | sharing_collaboration | BOX-08 | manual: the API does not expose the open shared link password requirement |
| 9 | Watermarking enabled | sharing_collaboration | BOX-09 | pass or fail on `is_watermarking_enterprise_feature_enabled`; warn when the flag is absent |
| 10 | Device trust and pins | data_governance | BOX-10 | warn when no device pins exist; manual otherwise because the device trust policy is not exposed |
| 11 | Classification labels | data_governance | BOX-11 | pass when the security classification template defines labels; fail when none exist |
| 12 | Retention policies | data_governance | BOX-12 | pass when active policies have assignments (with the truncation clause and lower-bound counts when the listing stopped at its cap); warn when unassigned, or when the listing stopped before any active policy was read; fail when a complete listing has none; manual without Governance access |
| 13 | Legal hold policies | data_governance | BOX-13 | pass when active holds have assignments (with the truncation clause and lower-bound counts when the listing stopped at its cap); warn when unassigned, when none exist, or when the listing stopped before any active hold was read; manual without Governance access |
| 14 | Shield smart access policies | shield_monitoring | BOX-14 | pass when Shield rules exist in the `shield` configuration category; fail when the category is readable but empty; manual without Shield access or when the category is null |
| 15 | Shield information barriers | shield_monitoring | BOX-15 | pass when enabled barriers have segments; warn when disabled, unsegmented, or absent |
| 16 | Enterprise event streaming | shield_monitoring | BOX-16 | pass when `admin_logs` returns events in the window, stated explicitly as verifying stream readability only (`siem_consumption_verified: false`) with SIEM consumption left to the listed manual evidence; warn when empty; manual when unreadable |
| 17 | Admin role minimization | identity_access | BOX-17 | pass when admin plus co-admin count is at or below `max_admins`; warn above, or when the user inventory is empty or has no admin account |
| 18 | Co-admin permission scoping | identity_access | BOX-18 | pass when no co-admins exist in a non-empty inventory; warn on an empty inventory; manual otherwise because co-admin permission sets are not exposed |
| 19 | App approval process | sharing_collaboration | BOX-19 | manual: reports app authorization events and integration Shield lists, approval policy must be confirmed in the Admin Console |
| 20 | Custom terms of service | sharing_collaboration | BOX-20 | pass when a managed terms of service is enabled; fail when disabled or missing |
| 21 | Password policy strength | identity_access | BOX-21 | pass at or above `min_password_length` with weak password prevention and two character classes; warn between 8 and the target; fail below 8 |
| 22 | Session duration limits | identity_access | BOX-22 | pass when `session_duration` (and any custom duration) carries an explicit unit and is at or below `max_session_hours`; fail above or when unlimited; warn with the raw value when the value has no unit (Box does not document one) or cannot be interpreted |
| 23 | IP allowlisting | identity_access | BOX-23 | manual: reports Shield IP lists, enterprise IP restrictions are not exposed |
| 24 | Inactive user detection | identity_access | BOX-24 | pass when every active managed user has successful login or content activity events in `lookback_days`; warn or fail on inactive users; warn when the event sample is truncated or when the inventory has no active managed users to assess. `FAILED_LOGIN` events are collected as evidence but never count as activity |
| 25 | Content access monitoring | shield_monitoring | BOX-25 | pass when anomaly rules or Shield alerts exist; warn when only raw download events exist, when Shield rules or the event stream are unreadable, or when the event sample was truncated; fail when both are readable and complete and neither signal is present |

## Framework mappings

Each finding carries the eight mappings from the spec's compliance table, rendered as `<framework> <identifier>` (for example `FedRAMP IA-2`, `CMMC AC.L2-3.1.1`, `SOC 2 CC6.1`, `CIS 1.1`, `PCI-DSS 8.3.1`, `STIG SRG-APP-000148`, `IRAP ISM-1557`, `ISMAP CPS-04` for control 1). The export bundle renders them in `compliance/unified_compliance_matrix.md` and in one report per framework.

## Live smoke test

```bash
npm --prefix cli run test:box:live
```

The script exits 0 with a skip message when no Box credentials are present. With credentials it runs `box_check_access` and the identity and access assessment against the real enterprise.

## Limitations and manual controls

- Controls 8, 19, and 23 are always `manual`: the Box API does not expose the open shared link password requirement, the app approval policy, or enterprise IP allowlisting. Controls 10 and 18 are `manual` whenever device pins or co-admins exist because the device trust policy and co-admin permission sets are not exposed.
- Inactive user detection correlates `admin_logs` activity events (`LOGIN`, `ADMIN_LOGIN`, `DOWNLOAD`, `UPLOAD`, and similar) because the user object has no last login field. `FAILED_LOGIN` events are recorded in the evidence (`failed_login_events`, `inactive_candidates_with_failed_logins`) but do not make an account active, so a user who only receives credential-stuffing attempts still counts as inactive. Raise `event_limit` for large enterprises; a sample that hit the cap while a `next_stream_position` remained is reported as `warn`, while a sample that happens to contain exactly `event_limit` events with nothing left on the stream is complete.
- Enterprise configuration, Shield lists, and Shield rules come from the versioned `2025.0` endpoints and require Manage enterprise properties. Retention and legal hold endpoints require Box Governance, Shield endpoints require Box Shield; missing licenses surface as `manual` findings with the reason.
- Box's published rate limit is 1000 API requests per minute per user; the client honors `retry-after` on 429 and applies exponential backoff on 5xx.
- Watermarking and classification are verified at the enterprise feature level; sampled folder reviews remain a human step and are listed in `manualEvidence`. The event stream check (BOX-16) verifies only that `admin_logs` is active and readable; whether a SIEM consumes it is not exposed by the API and stays in `manualEvidence`.

## Official documentation

- [JWT auth without an SDK](https://developer.box.com/guides/authentication/jwt/without-sdk/) and [JWT setup](https://developer.box.com/guides/authentication/jwt/jwt-setup/)
- [Client Credentials Grant setup](https://developer.box.com/guides/authentication/client-credentials/client-credentials-setup/)
- [Refresh an access token](https://developer.box.com/guides/authentication/tokens/refresh/)
- [App authorization](https://developer.box.com/guides/authorization/) and [application scopes](https://developer.box.com/guides/api-calls/permissions-and-errors/scopes/)
- [Rate limits](https://developer.box.com/guides/api-calls/permissions-and-errors/rate-limits/)
- [Marker-based pagination](https://developer.box.com/guides/api-calls/pagination/marker-based/) and [offset-based pagination](https://developer.box.com/guides/api-calls/pagination/offset-based/)
- [Enterprise events](https://developer.box.com/guides/events/enterprise-events/for-enterprise/), [event triggers](https://developer.box.com/guides/events/event-triggers/), and [`GET /events`](https://developer.box.com/reference/get-events/)
- [`GET /users/me`](https://developer.box.com/reference/get-users-me/), [`GET /users`](https://developer.box.com/reference/get-users/), [`GET /groups`](https://developer.box.com/reference/get-groups/)
- [`GET /enterprise_configurations/{id}` (2025.0)](https://developer.box.com/reference/v2025.0/get-enterprise-configurations-id/) and [`GET /shield_lists` (2025.0)](https://developer.box.com/reference/v2025.0/get-shield-lists/)
- [`GET /enterprises/{id}/device_pinners`](https://developer.box.com/reference/get-enterprises-id-device-pinners/)
- [`GET /retention_policies`](https://developer.box.com/reference/get-retention-policies/) and [assignments](https://developer.box.com/reference/get-retention-policies-id-assignments/)
- [`GET /legal_hold_policies`](https://developer.box.com/reference/get-legal-hold-policies/) and [`GET /legal_hold_policy_assignments`](https://developer.box.com/reference/get-legal-hold-policy-assignments/)
- [`GET /shield_information_barriers`](https://developer.box.com/reference/get-shield-information-barriers/) and [segments](https://developer.box.com/reference/get-shield-information-barrier-segments/)
- [`GET /collaboration_whitelist_entries`](https://developer.box.com/reference/get-collaboration-whitelist-entries/) and [exempt targets](https://developer.box.com/reference/get-collaboration-whitelist-exempt-targets/)
- [`GET /metadata_templates/enterprise`](https://developer.box.com/reference/get-metadata-templates-enterprise/), [template schema](https://developer.box.com/reference/get-metadata-templates-id-id-schema/), and [classifications](https://developer.box.com/guides/metadata/classifications/)
- [`GET /terms_of_services`](https://developer.box.com/reference/get-terms-of-services/)
- [Box OpenAPI specification](https://github.com/box/box-openapi)
