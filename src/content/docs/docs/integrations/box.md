---
title: Box
description: Read-only Box Enterprise security inspector covering identity, sharing, data governance, and Shield monitoring, mapped to eight frameworks including FedRAMP.
---

The Box integration inspects a Box Enterprise tenant through the Box Content API. It reports posture findings for the 25 controls defined in the [Box Security Inspector spec](/specs/box-sec-inspector/).

Every tool is read-only. Nothing is created, changed, or deleted in the tenant.

## What it inspects

- **Identity and access:** SSO enforcement, 2-step verification for admins and all users, admin and co-admin sprawl, password policy, session duration, IP allowlisting, and inactive users derived from the enterprise event stream.
- **Sharing and collaboration:** external collaboration mode, collaboration allowlist hygiene, shared link defaults and expiration, shared link passwords, watermarking, app authorization activity, and custom terms of service.
- **Data governance:** device pins, classification labels, retention policies and assignments, legal hold policies and assignments.
- **Shield and monitoring:** Shield rules, information barriers and segments, the `admin_logs` enterprise event stream, and content access anomaly signals.

Findings are normalized as `{ id, control, title, severity, status, summary, evidence, mappings, manualEvidence }`. `severity` is `critical | high | medium | low | info`, and `status` is `pass | warn | fail | manual`.

A `manual` finding always includes the exact Admin Console evidence a human must collect.

## Setup and authentication

1. Create a Box Platform app in the Developer Console.
2. Enable the scopes below.
3. Authorize the app in the Admin Console (Apps > Custom Apps Manager).

The inspector supports the three server-side auth flows Box documents.

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
| `BOX_API_BASE_URL` (also `BOX_BASE_URL`), `BOX_TOKEN_URL` | Override `https://api.box.com/2.0` and `https://api.box.com/oauth2/token`. |
| `BOX_TIMEOUT`, `BOX_MAX_RETRIES` | Request timeout in seconds (default 30) and retries for 429 and 5xx responses (default 3). |

Precedence is explicit tool arguments, then environment variables, then the config file.

An argument that is not passed never erases an environment value. For example, a tool called with only `timeout_seconds` still uses `BOX_ACCESS_TOKEN` and the file `BOX_CONFIG_PATH` names.

A config file named by `config_path` or `BOX_CONFIG_PATH` must exist and hold at least one Box setting. A missing default file at `~/.box-sec-inspector/config.yaml` is simply absent.

When a config or JWT file cannot be read or parsed, the tool fails and nothing is written. The failure message is fixed text that carries only:

- The path.
- The filesystem's error code (`ENOENT`, `EACCES`, `EISDIR`).
- The YAML parser's line or `JSON.parse`'s position (`Unable to parse Box config file: invalid YAML in <path> at line 4`).

It never carries the library's own message, which quotes the offending line.

The YAML file accepts the same keys in snake_case, optionally nested under a `box:` section:

```yaml
box:
  auth_method: ccg
  client_id: "abc123"
  client_secret: "..."
  enterprise_id: "123456"
  timeout_seconds: 30
```

### JWT (server authentication)

Point `BOX_JWT_CONFIG_PATH` at the config JSON. The JSON holds `boxAppSettings.clientID`, `clientSecret`, `appAuth.publicKeyID`, `appAuth.privateKey`, `appAuth.passphrase`, and `enterpriseID`.

grclanker signs the assertion with `node:crypto`:

- `alg` RS512 by default.
- `kid` set to the public key ID.
- `aud` set to the token URL (`https://api.box.com/oauth2/token` unless `BOX_TOKEN_URL` overrides it).
- `box_sub_type` `enterprise` or `user`.
- 45 second expiry.

grclanker then posts the assertion to the token endpoint with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`. No SDK is required.

### Client Credentials Grant

Set `BOX_CLIENT_ID`, `BOX_CLIENT_SECRET`, and `BOX_ENTERPRISE_ID`.

grclanker posts `grant_type=client_credentials` with `box_subject_type=enterprise` and `box_subject_id=<enterprise_id>`, or with `box_subject_type=user` when `BOX_SUBJECT_TYPE=user`.

Tokens are cached until shortly before `expires_in` elapses and re-requested on 401.

### OAuth 2.0

Set `BOX_ACCESS_TOKEN` for a pre-issued token. For example, it can be a Developer Console developer token, or a token minted by your own OAuth flow for an admin or co-admin.

When `BOX_REFRESH_TOKEN`, `BOX_CLIENT_ID`, and `BOX_CLIENT_SECRET` are present, the client refreshes automatically after a 401.

When no enterprise ID is configured, the ID is discovered from `GET /users/me?fields=enterprise`.

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

Re-authorize the app in the Admin Console after changing scopes.

`box_check_access` reports each surface separately, so partial grants are visible before you run an assessment.

## Run it

After setup, start `grclanker` and ask in plain words. The agent calls the matching tools, for example:

```text
Check whether my Box credentials can read everything grclanker needs.
Run the Box assessments and list the failing findings first.
Export a Box audit bundle.
```

For a posture readout or a framework mapping, use the [assess](/docs/workflows/assess/) or [audit](/docs/workflows/audit/) workflow, for example `grclanker assess "our Box enterprise"`. Both start with `box_check_access`, then run the assessments or `box_export_audit_bundle`.

## Tools

| Tool | Purpose |
| --- | --- |
| `box_check_access` | Resolves credentials, exchanges a token, and probes 15 read surfaces (current user, enterprise configuration, users, groups, enterprise events, device pins, retention, legal holds, Shield barriers and lists, allowlist entries and exemptions, metadata and classification templates, terms of service). Reports `healthy` or `limited` with the next step, or `failed` when Box refused the credentials themselves on every probe: a 401, or a 400 `invalid_client`, `invalid_grant`, or `unauthorized_client` from the token exchange (Box also sends these for an app no admin has authorized). A `failed` next step names the credential settings to fix for the auth method in use. |
| `box_assess_identity_access` | Controls 1, 2, 3, 17, 18, 21, 22, 23, 24. Options: `user_limit`, `event_limit`, `lookback_days`, `max_admins`, `min_password_length`, `max_session_hours`. |
| `box_assess_sharing_collaboration` | Controls 4, 5, 6, 7, 8, 9, 19, 20. Options: `event_limit`, `lookback_days`, `stale_allowlist_days`, `list_limit`. |
| `box_assess_data_governance` | Controls 10, 11, 12, 13. Option: `list_limit`. |
| `box_assess_shield_monitoring` | Controls 14, 15, 16, 25. Options: `event_limit`, `lookback_days`. |
| `box_export_audit_bundle` | Runs the access check plus all four assessments and writes an evidence bundle (default `./export/box`). |

Every tool accepts the auth arguments: `auth_method`, `jwt_config_path`, `jwt_passphrase`, `client_id`, `client_secret`, `enterprise_id`, `subject_type`, `subject_id`, `access_token`, `refresh_token`, `config_path`, `base_url`, `token_url`, `timeout_seconds`, and `max_retries`.

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

#### Reruns and output paths

A rerun never overwrites an earlier export.

- The directory takes the next free `-2`, `-3` suffix. A suffix is also considered taken when only its zip remains.
- The zip is named after the directory that was actually allocated.

Output paths are resolved inside the output root with traversal and symlinked-parent protection. Files are written with `0600` permissions.

## Control coverage

Verdicts on unread, partial, or truncated data follow the rules in [How the tools handle evidence](#how-the-tools-handle-evidence).

Status semantics:

- `pass`: The API evidence satisfies the control.
- `warn`: Partial or threshold-adjacent evidence.
- `fail`: The API evidence contradicts the control.
- `manual`: The API cannot prove the control, and the finding lists the Admin Console evidence to collect.

### Status by control

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

Each finding carries the eight mappings from the spec's compliance table, rendered as `<framework> <identifier>`. For example, control 1 carries `FedRAMP IA-2`, `CMMC AC.L2-3.1.1`, `SOC 2 CC6.1`, `CIS 1.1`, `PCI-DSS 8.3.1`, `STIG SRG-APP-000148`, `IRAP ISM-1557`, and `ISMAP CPS-04`.

The export bundle renders them in `compliance/unified_compliance_matrix.md` and in one report per framework.

## Live smoke test

```bash
npm --prefix cli run test:box:live
```

The script exits 0 with a skip message unless one of these is configured: `BOX_JWT_CONFIG_PATH`; `BOX_CLIENT_ID` and `BOX_CLIENT_SECRET` with `BOX_ENTERPRISE_ID` or `BOX_SUBJECT_ID`; `BOX_ACCESS_TOKEN`, `BOX_TOKEN`, or `BOX_DEVELOPER_TOKEN`; `BOX_REFRESH_TOKEN` with `BOX_CLIENT_ID` and `BOX_CLIENT_SECRET`; or a config file at `BOX_CONFIG_PATH` or `~/.box-sec-inspector/config.yaml`. With credentials, it runs `box_check_access` and stops with exit code 1 unless access is `healthy`. When access is `healthy`, it runs the identity and access assessment against the real enterprise.

## Limitations and manual controls

- Controls 8, 19, and 23 are always `manual`. The Box API does not expose the open shared link password requirement, the app approval policy, or enterprise IP allowlisting.
- Controls 10 and 18 are `manual` whenever device pins or co-admins exist, because the device trust policy and co-admin permission sets are not exposed.
- Inactive user detection correlates `admin_logs` activity events (`LOGIN`, `ADMIN_LOGIN`, `DOWNLOAD`, `UPLOAD`, and similar), because the user object has no last login field.
  - `FAILED_LOGIN` events are recorded in the evidence (`failed_login_events`, `inactive_candidates_with_failed_logins`) but do not make an account active, so a user who only receives credential-stuffing attempts still counts as inactive.
  - Raise `event_limit` for large enterprises. A sample that hit the cap while a `next_stream_position` remained is reported as `warn`. A sample that happens to contain exactly `event_limit` events with nothing left on the stream is complete.
- Enterprise configuration, Shield lists, and Shield rules come from the versioned `2025.0` endpoints and require Manage enterprise properties.
- Retention and legal hold endpoints require Box Governance, and Shield endpoints require Box Shield. Missing licenses surface as `manual` findings with the reason.
- Box's published rate limit is 1000 API requests per minute per user. The client honors `retry-after` on 429 and applies exponential backoff on 5xx.
- Watermarking and classification are verified at the enterprise feature level. Sampled folder reviews remain a human step and are listed in `manualEvidence`.
- The event stream check (BOX-16) verifies only that `admin_logs` is active and readable. Whether a SIEM consumes it is not exposed by the API and stays in `manualEvidence`.

## How the tools handle evidence

This section is reference for reviewing findings and bundles: how unread, partial, or truncated data limits a verdict, how the tools page through the API and report incomplete listings, and how credentials are kept out of findings, bundles, and error text. You don't need it to set up or run the integration.

### Redaction and projection

Credentials are never written into the bundle. Every record the client collects passes through one data-side scrub at the collection boundary. Every `core_data/` snapshot passes through the same scrub again at write time.

The scrub:

- Replaces the whole subtree under any credential-shaped key with `[REDACTED]` while keeping the key, whether the value is a string, a list, or a nested object.
  - Credential-shaped keys: `token`, `tokens`, `secret`, `secrets`, `password`, `passphrase`, `api_key`, `api_keys`, `client_secret`, `credentials`, `authorization`, and their camelCase forms.
- Blanks the value of `{name, value}` tracking-code pairs with a credential-shaped name.
- Runs every other string, free text included, through the shared pattern pass:
  - The query of any URL anywhere in the text is replaced by one marker.
  - Bearer, cookie, and assignment carriers lose their value.
  - Webhook-style paths lose their token segment.
  - High-entropy or hex tokens are removed.

Enterprise events are projected to `event_id`, `event_type`, `created_at`, `created_by`, `source`, `session_id`, and `ip_address`. The free-form `additional_details` bucket is dropped.

Terms of service are projected to `id`, `type`, `tos_type`, `status`, `text_length`, `created_at`, and `modified_at`. The agreement text is not written.

Non-JSON error bodies are described by content type and length in error text, never echoed.

### Error text

Recorded error text follows one rule at one place. A single function produces every one of these:

- Dataset error
- Access surface `error`
- Assessment `errors` entry
- `_errors.log` line
- Tool failure message

The function passes the thrown message through the module scrubber. A `SyntaxError` raised by the transport is recorded as its class name plus a fixed note, because the parser's message quotes the body.

The scrubber removes the configured client secret, access token, refresh token, JWT passphrase, and private key, and every token the client is issued. It removes them at full length in plain, base64, base64url, URL-encoded, form-encoded, and JSON-escaped form.

It also removes the value of every credential carrier, whatever the value's shape:

- **Credential pairs:** A `key=value`, `key: value`, or `"key": "value"` pair loses its value when its key carries a credential word (`client_secret`, `developer_token`, `BOX_CLIENT_SECRET`, and the bearer ids `secret_id`, `session_id`, and `token_id`).
  - The same holds when the key follows a JSON escape (`\"client_secret\": \"v\"`) or a command-line flag (`--password v`, `--password=v`, `-Dpassword=v`).
- **Authorization schemes:** An authorization scheme word in any casing (`Bearer`, `bearer`, `Basic`, `Token`) loses the value after it.
  - A bare token and a whole auth-param list (`Snowflake Token="v"`, `Digest username="v", nonce="v", response="v"`) are removed alike.
  - The word itself stays only under `Authorization`, `Proxy-Authorization`, and `WWW-Authenticate`. Under those headers, a challenge's `realm="api"` stays as well.
  - An API-key or token header (`X-Api-Key: splunk rejected`) and a credential-named assignment (`token=Bearer v`) lose their whole value.
- **Cookies:** A cookie header loses its value whole, its `;` separating pairs and attributes.
- **URLs:** The query of any URL becomes one marker.
  - A credential-named parameter of a relative path or bare query string loses its value whole, a `;` inside the value included. For example, `?token=v;rest` renders `?token=[REDACTED]`, as URLSearchParams reads it.
  - A webhook or callback URL keeps its origin alone.

A `webhook`-prefixed key is a URL carrier only when its last segment is `url` or `uri`, or when the key is the bare `webhook`. `webhook_secret`, `webhook_token`, and `webhookSecret` are credential keys and lose their value whatever its shape.

A configured secret that is itself a carrier word (`password`, `Authorization`, `Bearer`) is removed after the carriers rather than before them. So the pair or header it names still loses its value.

A name after a path slash (`GET /2.0/users/me/token: 403`) is a path segment, not a key. A key whose last segment names a setting (`BOX_AUTH_METHOD`, `BOX_TOKEN_URL`, `client_id`, `session_duration`, `password_reset_frequency`) keeps a word value and loses only a token-shaped or registered one.

So every fixed message and every finding summary, manual-evidence instruction, and bundle document survives the pass unchanged. The test suite sweeps thousands of strings recorded by healthy, weak, and partially denied runs for alterations.

### Absent and unused data

Absent data never produces `fail`:

- A configuration category that Box returns as `null` yields `manual` or `warn` with the reason. The `2025.0` schema allows `security`, `content_and_sharing`, `user_settings`, and `shield` to be null.
- An unreadable user list yields `manual` or `warn` with the reason.
- A setting that is missing from a readable category yields `warn`.

Every configuration item carries an `is_used` flag ("indicates whether a configuration is used for a given enterprise"). An item with `is_used: false` is treated as not enforced, so:

- The finding is `warn`, with the reported value under `evidence.unused_settings` and the per-item flags under `evidence.is_used`.
- The item never supports `pass`.

User-level findings (BOX-02, 03, 17, 18, 24) also never `pass` on an empty inventory. A readable `/users` list with zero entries, or one without any `admin` account, is reported as `warn` with the reason under `evidence.inventory_gap`, because a Box enterprise always has at least the primary admin.

### Truncated lists

Paginated lists track truncation from the API's own signal, never from the returned length. The signal is a `next_marker`, an `offset` short of `total_count`, or a `next_stream_position` remaining once the cap was reached.

A truncated list is reported:

- Under `truncated` in every assessment result.
- Under `truncated_datasets` in the bundle summary.
- Per file in `core_data/collection_status.json`.

Any finding whose `pass` depends on the absence of a record is downgraded to `warn`, with the `user_limit`, `event_limit`, or `list_limit` option to raise. This covers:

- BOX-02, 03, 17, 18, 24 on users
- BOX-24 and BOX-25 on events
- BOX-05 on the allowlist
- BOX-12 and BOX-13 on policies

BOX-12 and BOX-13 test the listing's truncation before its emptiness:

- A retention or legal hold listing that stopped before any active policy was read renders `warn` with the listing's stop reason, never `fail`. "No active retention policies exist" is reserved for a complete listing.
- A capped listing whose policies read all have assignments renders `warn`, not `pass`.
  - The seen count is stated against the unknown total: "2/2 active retention policies have assignments among the 2 policies read, but the retention policy listing stopped after 2 records because ..."
  - Both counts are stated as lower bounds.
  - The evidence carries `retention_policies_truncated` or `legal_hold_policies_truncated`.

#### Evidence from a truncated listing

Evidence derived from a listing that stopped short follows one rule across the four assessments.

A count or list whose zero or empty value would read as "none exist" renders `null` when the listing it came from was truncated or unreadable and the count is zero. This covers `admin_users`, `privileged_users`, `active_users`, `active_policies`, `enabled_barriers`, `device_pins`, `allowlist_entries`, a barrier's `segments`, and the summary counts.

A positive count from a truncated listing renders as a lower bound beside the listing's `_truncated` flag.

Counts named for the read's own size (`sampled_users`, `sampled_events`, `policies_read`, `barriers_read`) always render, zero included, because they report the read rather than the inventory.

Item-level detail is withheld as `null` while its listing is truncated, with a `_count` lower bound beside it. Once the listing was read to completion, the detail is rendered in full, empty lists included. Item-level detail covers:

- User labels under `admins`, `coadmins`, `exempt_privileged_users`, `exempt_users`, `inactive_candidates`.
- Allowlist domains under `allowlist_entries`, `public_email_domains`, `stale_entries`, `undated_entries`.
- The `retention_policies` and `legal_hold_policies` records.
- `device_pin_products`.

The `_count` lower bounds are `coadmin_users`, `exempt_privileged_users_count`, `inactive_candidates_count`, `allowlist_entries_count`, `public_email_domain_count`, `stale_entry_count`, and `undated_entry_count`.

Findings whose `pass` rests on a setting or on a record that was read keep that `pass` under a truncated secondary listing, and state the stop:

- BOX-04 passes on the enterprise collaboration mode, with the allowlist listing's stop reason in the text and `allowlist_entries_truncated` in the evidence.
- BOX-15 passes on a segment that exists, with the segment listing's stop in the text and `segments_truncated` in the evidence.

An allowlist or segment page that stopped before any entry was read renders `warn` saying the listing stopped. It never says the allowlist is empty or the barrier unsegmented.

Event-derived breakdowns (`app_events`, `event_types`, `shield_events`, `anomaly_events`) render as `{ observed, sampled_events, events_truncated }` when the event collection stopped at its cap. `activity_events`, `failed_login_events`, and the summary `app_events` follow the count rule.

#### Pagination exits

Every pagination exit that can leave records behind sets the flag:

- An empty marker page that still carries a `next_marker`.
- An empty offset page while `offset` is below `total_count`.
- A `next_stream_position` that is missing or stops advancing while entries keep arriving.
- The 50-policy cap on retention, legal hold, and barrier segment sub-listings, reported as `retention_policy_assignments`, `legal_hold_policy_assignments`, or `shield_information_barrier_segments`.

Marker-paged lists count a record once by `id`. The walk ends, reported truncated with the reason, when a page under a fresh marker adds no record that was not already collected, or when the server repeats its marker. So a re-served page cannot inflate a count or hold the walk open.

The events walk also ends, and is reported truncated with the reason, when:

- A page under a fresh stream position adds no event that was not already collected. An event is counted once by `event_id`, so a server that re-serves collected events cannot hold the walk open or inflate the sample.
- A page cap proportional to `event_limit` is reached, whatever the progress.

`core_data/collection_status.json` carries the reason per dataset under `truncation_reason`.

### Unreadable inventories

Findings that read more than one inventory never `pass` while any of them is unreadable (403, 401, or another read error). That holds even when the readable inventory alone would satisfy the control.

These findings drop to `warn`, with the unreadable dataset and endpoint named in the summary and listed under `evidence.unreadable_inventories`:

- BOX-04 and BOX-05 (enterprise configuration, allowlist entries, exempt targets)
- BOX-12 and BOX-13 (policies plus their assignments)
- BOX-15 (barriers plus segments)
- BOX-25 (Shield configuration plus enterprise events)

BOX-02, BOX-03, and BOX-24 already render `manual` when users, the security configuration, or events cannot be read.

A success status is not a success by itself. A 2xx response is recorded as a failed read of that request when its body is:

- Empty.
- Not JSON (a portal or proxy page).
- JSON of another shape (a list without an `entries` array, a resource without any of its documented keys, a bare array).

The failed read carries status `200` and a fixed status-and-length note. The body is never echoed. So the request's dependents go `manual` or `warn` instead of passing or failing on data that was never observed.

The failed read is recorded in `core_data/collection_status.json`, the dataset's marker file, and the access check.

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
