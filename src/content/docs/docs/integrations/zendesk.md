---
title: Zendesk
description: Read-only Zendesk Support security inspector covering authentication, access control, audit logging, data protection, and integrations, with an audit bundle.
---

The Zendesk integration inspects a Zendesk Support account through the public Support API and renders the 25 controls from `specs/zendesk-sec-inspector.spec.md` as normalized findings. Every tool is read-only: nothing is created, updated, or deleted in the account.

## What it inspects

- **Authentication:** SSO enforcement, account-level two-factor enforcement plus per-agent enrollment, team member password policy, IP restrictions, session expiration, and end-user sign-in methods, all read from the admin-only [Security Settings](https://developer.zendesk.com/api-reference/ticketing/account-configuration/security_settings/) endpoint and the documented per-user `two_factor_auth_enabled` flag.
- **Access control:** custom roles that grant admin-equivalent permissions, admin count and dormant admins, group segmentation, API token exposure with token creation and deletion events enumerated from the audit log, and OAuth client scope, redirect URI, and token hygiene.
- **Data protection:** audit log availability and retention (Enterprise), the HIPAA evidence prompt, active deletion schedules by object, authenticated attachment downloads, attachment limits, and suspended ticket backlog age.
- **Integrations:** marketplace and private app inventories, sandbox provisioning, cross-brand help center consistency, sharing agreements, https-only targets and webhooks, and triggers or automations that deliver ticket data to external destinations.

## Setup and authentication

Zendesk retired email and password access to the API, so the tools support two credential types:

| Mode | How it is sent | When to use |
|------|----------------|-------------|
| API token | `Authorization: Basic` carrying the base64 encoding of the email address, the literal `/token:` separator, and the API token | Quickest to set up. Zendesk is retiring API tokens (unused tokens are deactivated from July 28, 2026 and all API tokens stop working on April 30, 2027), so plan the OAuth migration. |
| OAuth access token | `Authorization: Bearer {token}` | Preferred. Create an OAuth client in Admin Center, grant the `read` scope, and mint an access token. |

Create an API token in Admin Center under Apps and integrations > APIs > Zendesk API. API token access must be enabled.

Use an admin identity:

- Several surfaces are admin-only: security settings, deletion schedules, OAuth clients and tokens, audit logs, owned apps, brands, suspended tickets.
- The assessors cap every verdict at `warn` when the credential is not an admin, because a lower role sees only a partial view of the account.

The audit log and custom roles additionally require an Enterprise plan.

### Environment variables

Configuration precedence is explicit tool arguments, then environment variables, then a JSON config file:

| Environment variable | Purpose |
|----------------------|---------|
| `ZENDESK_SUBDOMAIN` | The `{subdomain}` in `https://{subdomain}.zendesk.com` (a full URL is accepted). |
| `ZENDESK_EMAIL` | Email that owns the API token (API token mode only). |
| `ZENDESK_API_TOKEN` | API token (API token mode). |
| `ZENDESK_OAUTH_TOKEN` or `ZENDESK_ACCESS_TOKEN` | OAuth access token (bearer mode). When both an OAuth token and an API token are present, the credential from the higher-ranked source wins (arguments, then environment, then config file; the API token counts at the lower rank of its `api_token` and `email` sources), and OAuth wins a tie. |
| `ZENDESK_BASE_URL` | Optional API base override. Defaults to `https://{subdomain}.zendesk.com/api/v2`. |
| `ZENDESK_TIMEOUT` | Optional HTTP timeout in seconds. Defaults to 30. |
| `ZENDESK_CONFIG_FILE` | Optional path to a JSON config file. Defaults to `~/.zendesk/config.json`. |

### Configuration file

The config file accepts `subdomain`, `email`, `api_token`, `oauth_token`, `base_url`, and `timeout_seconds`:

```json
{
  "subdomain": "acme",
  "oauth_token": "your-oauth-access-token"
}
```

Loading rules:

- A file named explicitly (the `config_file` argument or `ZENDESK_CONFIG_FILE`) must be readable and parse.
- The default path is skipped silently when absent.
- An empty file contributes no settings.

Loader errors use fixed text and never quote the file:

- A read failure reports `Unable to read Zendesk config file <path> (<CODE>)` with only the errno code (`ENOENT`, `EACCES`, `EISDIR`).
- A parse failure reports `Unable to parse Zendesk config file: invalid JSON in <path> at line N (INVALID_JSON)`, with the line derived from the parser's position only.
- A file that is not a JSON object reports `INVALID_CONFIG_SHAPE`.

Neither the filesystem message nor the `JSON.parse` message is ever interpolated, so an unquoted or misplaced token in a malformed file cannot leak through the error. The `JSON.parse` message quotes a window of the source around the failure.

### Tokens and the configured base URL

Tokens never appear in tool output, bundle files, or error messages. The client redacts them before surfacing any failure.

A configured `ZENDESK_BASE_URL` is reduced at configuration to its scheme, host, port, and path.

- A user-and-secret prefix, query, or fragment is dropped before the first request, so it never leaves in a request URL, never enters the configured origin a next link is compared against, and never reaches an output.
- The guide, summaries, and metadata name the subdomain, not the URL.
- The test suite configures the base URL with a user-and-secret prefix and requires every request, tool result, bundle file, and zip entry free of it.

### Snapshot redaction

Credential-bearing properties inside API records are redacted the same way before a snapshot is kept. These are replaced with `[REDACTED]`:

- `token`, `full_token`, and `refresh_token` on `/oauth/tokens` records.
- `secret` on OAuth clients.
- `password` and `token` on legacy targets.
- Webhook `authentication.data` values, `custom_headers` values, and signing secrets.
- `api_key`, `password`, or `token` values in app installation settings.

Property names are matched on their last segment after splitting `snake_case`, `camelCase`, and header spellings. So `apiKey`, `clientSecret`, `refreshToken`, `accessToken`, `secretKey`, `passphrase`, `Authorization`, `X-Api-Key`, and `X-Auth-Token` are covered too. Ids, scopes, client ids, expiry and creation dates, usernames, header names, `public_key`, and a bare `key` are kept for the assessments.

String and numeric values under those names are replaced. The following lose their `value`, `default`, and `default_value` fields while the name and kind stay:

- A `{name, value}` pair whose `name` is a credential in either the walker's vocabulary (an owned app parameter named `api_token`) or the error-text rules' (a header named `x-redlock-auth`, `X-Auth`, or `Cookie`), whatever its `secure` flag says.
- Any parameter flagged `secure: true`.

A benign pair flagged `secure: false` (`X-Trace`, `region`) keeps its value.

Credentials carried inside other string values are scrubbed too, in every string a snapshot keeps:

- URL query parameters named `token`, `api_key`, `client_secret`, `access_token`, `signature`, or `sig` in `target_url`, `endpoint`, `redirect_uri`, or `url` values keep their name and lose their value to `[REDACTED]`. The scheme, host, path, and other parameters are kept.
- The user-and-secret prefix before the host in a URL is replaced whole by `[REDACTED]`, so only the scheme and host remain.
- Slack, Discord, and Microsoft Teams incoming-webhook URLs whose path is the secret keep only the service prefix.
- Credential fields inside JSON encoded as a string (an app setting holding `{"token":"..."}`) are replaced in place.

The redacted copy is what the assessments read, so ZD-24 and ZD-25 still see the scheme and host of every destination.

### Silent-success responses

A 2xx answer that is not the documented JSON document is an unreadable surface, never an empty inventory (the silent-success class).

A 200 with any of the following is described by status, media type, and size only:

- An empty body.
- The HTML page a proxy or captive portal serves in place of the API.
- A foreign JSON value.
- A JSON object without the documented member (`users`, `webhooks`, `oauth_tokens`, `settings`, and so on).

For example: `200 OK with a JSON response body without the documented "users" array (2 bytes, not echoed)`.

The answer is recorded with the observed status as a surface that was not read:

- The access probe is not readable.
- The dataset carries the not-collected marker.
- The findings that depend on the dataset render manual or capped, never pass on a missing list or read a missing setting as disabled.

### Error strings

Error strings follow the same discipline at the single place they are built and again at every sink.

- A non-2xx response with a non-JSON body (an HTML proxy page, an SSO interstitial, a rate-limit page) is described only as `{status} {statusText}; non-JSON {content-type} response body ({n} bytes, not echoed)`, whatever content type the server claimed.
- A JSON body contributes only Zendesk's documented error fields (`error`, `description`, `message`, `error.title`, `error.message`, `errors[].title` or `detail`). Each field is scrubbed before it is shortened to 200 characters, so a cut can never leave the head of a secret behind.

All of these apply the same unanchored pass:

- The `ZendeskApiError` constructor.
- The transport-failure path.
- The snapshot layer that feeds every finding and `core_data/` file.
- The tool catch blocks.

So a message assembled at a throw site cannot carry a credential into a finding, summary, `_errors.log`, or the bundle.

### Redaction boundary

The unanchored pass draws one boundary. A value inside a carrier is replaced with `[REDACTED]` whatever its shape.

Header lines are carriers: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, and similar header lines. Each line is redacted by its class:

- **Authorization headers:** An `Authorization` or `Proxy-Authorization` value keeps its scheme word as spelled (`Bearer`, `Basic`, `Digest`, and the other schemes listed below, in any casing). The value loses the one token, or the one quoted string, after the scheme word, so the operator still reads which scheme was replayed. Prose after the token stays.
  - A parameter list after the scheme (`Digest username=..., realm=...`, `AWS4-HMAC-SHA256 Credential=...`) goes whole to the end of the line.
  - A value that opens with anything but a listed scheme word (`GenieKey <token>`, `SharedKey <account>:<signature>`, `Bot <token>`, a bare token) also goes whole to the end of the line, since an unknown first word may be a scheme with its credentials after it.
- **Cookie headers:** A `Cookie`, `Set-Cookie`, or `X-Cookie` line is a list of pairs and goes whole to the end of the line. Cookie attributes such as `Path` and `Expires` therefore go with the cookie.
- **Other headers:** Every other header (`X-Api-Key`, `X-Auth-Token`, `X-Vault-Token`, and the like) carries one token and loses its first token, so a JSON fragment or prose after it on the same line is still read. When its value opens with a listed scheme word (`X-Auth-Token: Bearer <token>`), the header loses the word and the token after it together under one marker.

### Where a value ends

- In every class, a quoted value (in double, single, or JSON-escaped quotes) ends at its closing quote. It goes with its quotes whatever the name of the cookie or pair that carries it, even when a `; Name:` sits inside the quotes.
- A whole-line value ends at the `;` or `,` before the name of the next header on a compound line, at a line break the stringify left escaped (`\n`, `\r`, `\u000a`), or else at the end of the line. A compound line holds several headers separated by `;` or `,`, and a following header name may hold dots.
  - A quoted value that nothing closes ends as an unquoted one does.
  - The next header keeps its name and gets its own treatment.
  - A `Content-Type` or `Date` after a cookie keeps its name and value.
- A single-token header value, the token after a scheme word, an equals-sign pair value, and a `--flag` value end at whitespace. They also end at any control character the stringify left escaped (`\t`, `\b`, `\f`, `\v`, `\0`, `\u0009` and the other `\u00XX` control codes, `\x09`), as they do at the raw character.
  - A credential pair chained after such an escape (`api_key=<value>\tpassword: <value>`) is read on its own and loses its own value.
  - A count under a plural credential word ends there too (`keys: 3\tcookies: 0` stays).
- Quotes escaped to any depth (`\"` one level down, `\\\"` two) are read at their own depth. A header pair, credential pair, quoted attribute, or quoted assignment inside a JSON body that was stringified into a string value therefore loses its value and keeps its escaped quotes.
- A header name or pair key is read the same right after such an escape (`\nAuthorization: Bearer <value>`, `\tapi_key=<value>`) as at a word boundary.
- A quote inside a token is content of the value it sits in, in a header value, pair value, quoted attribute, or URL query value alike.
  - RFC 6265 lets a cookie name or value carry an apostrophe, so `sid=O'<value>` and a pair named `my'pref` go with their cookie.
  - Only a quote at the end of a token, or one after `=` with nothing but a delimiter or the end behind it (a base64 value ending in `=`), closes the text the line was quoted in. The closing quote and the following members of an enclosing JSON string therefore survive.
- A header line is read before the URL query rule, so a cookie pair whose name holds `&` or `#` goes with its cookie.
- A bare query value never takes a backslash, so `?token=<value>\"` keeps the escaped quote and `?api_key=<value>\nstatus 502` keeps the text after the line break.
- A `;` inside a query value is part of the value, as `URLSearchParams` reads it, so `?token=<value>;<rest>` loses the whole value with no tail. The `;` that ends a cookie pair belongs to the cookie and key-list header lines alone.

### Other carriers

Values in these carriers are replaced too:

- Cookie and session assignments (the `_zendesk_session` cookie among them).
- The user-and-secret prefix before the host in a URL, bare or with its slashes escaped by a stringify (`https:\/\/user:secret@host`). The prefix ends where the authority does, at the first `/`, `?`, or `#`.
  - An `@` inside a query or fragment (`https://h?e=a@x.com&token=<value>`, `https://h#f@x.com`) is not such a prefix.
  - The host `h` stays, and the query is read pair by pair (`&token=` loses its value).
  - A `webhook_url` holding that URL reduces to `https://h/[REDACTED]`.
- The URL query parameters named `token`, `api_key`, `client_secret`, `access_token`, `signature`, and `pass`.
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
  - A plural label names a collection (`GET /api/v2/oauth/tokens: request failed`, `/api/v1/api-tokens: request failed with 403`), so prose continuing after the token means there was no value and the text stays.
  - A lone token after a plural label is removed.
- XML attributes.

A scheme word that starts the value of a credential-named key other than `Authorization` (`api_key: Bearer <value>`) is part of the value and goes with it.

### Configured secrets and token shapes

A configured secret (the API token, the OAuth token, and the base64 `{email}/token:{api_token}` value the Basic header carries, four characters or longer) is replaced wherever it appears, whatever its shape. Its base64, base64url, URL-encoded, and JSON-escaped forms are replaced too.

Real token shapes go even when bare in prose:

- Runs of sixteen or more characters with base64 symbols, scattered digits, or token casing.
- Hex digests.
- JWTs.
- AWS access key ids.
- GitHub, Stripe, and Slack prefixed tokens.
- PEM blocks.

### Values that stay

These values stay:

- A bare value shaped like a name (words joined by hyphens or underscores with at most one numeric segment, such as `prod-us-east-2026` or `acme-support-01`) standing alone in prose. It is indistinguishable from a resource name.
- Titles such as `Basic Support Plan`.
- This integration's own vocabulary (`api_token_access`, `password_policy`, `status_code`).
- One value under a credential-named key: a count. A count is a bare integer (digits alone, or digits followed by a space, as in `oauth_tokens: 1 active`) under a key whose last word is one of the plural words `tokens`, `secrets`, `keys`, `cookies`, `passwords`, or `credentials`. It stays in each of these spellings:
  - The JSON member spelling (`"oauth_tokens": 1`, `"oauth_tokens": "1"`).
  - The colon spelling (`oauth_tokens: 1`).
  - The equals spelling (`oauth_tokens=1`).

A singular key keeps the redaction rule: `pin: 1234` and `password=7` lose their values. The rule also applies to non-count values under a plural key: `tokens: rotate them` loses its value.

Every bundle file and every tool result passes through the configured-secret pass a final time on its way out. So a token echoed by an upstream body cannot survive even where the general scrub would have left evidence alone.

### Fixed text

The module's own fixed text is worded to cross that boundary intact: an `_errors.log` line reads `oauth_tokens dataset: <error>`, never `oauth_tokens: <error>`, which the pair rule would read as a credential and replace.

The test suite drives every fixed text the module emits on refused, unavailable, failed, and silent-success paths through the scrub. It requires the text back unchanged.

### Missing and partial snapshots

A snapshot that was refused, not on the plan, or failed is never written as an empty list or `null`. Its `core_data/` file holds a marker in its place: `{ "collected": false, "status": <observed HTTP status or null>, "dataset_status": "forbidden" | "not_found" | "error", "endpoint": "GET /api/v2/...", "error": "<scrubbed message>" }`.

Every assessment summary carries a `collection` object with one entry per snapshot it read (`status`, `endpoint`, `http_status`, `seen`, `truncated`, `truncation_reason`, `pages`, `error`).

- `truncated`: Derived from the observed page walk (the reasons listed under the tools below), never from a default.
- `truncation_reason`: Names why paging stopped. It is `null` for a list read to completion.
- `seen`, `truncated`, and `pages`: Render `null` for a snapshot that was not read. `seen` also renders `null` for a truncated list that delivered no item (`0` would read as an empty inventory).

Every endpoint or status code named anywhere in a finding, summary, tool result, or `_errors.log` line is the request that actually failed and the status it actually returned. The request's method and path are taken from the thrown error.

## Tools

| Tool | Purpose |
|------|---------|
| `zendesk_check_access` | Probes 20 read surfaces (current user, account settings, security settings, team members, custom roles, groups, group memberships, audit logs, OAuth clients and tokens, app installations, owned apps, brands, webhooks, targets, triggers, automations, sharing agreements, deletion schedules, suspended tickets) and reports which admin-only or Enterprise-only surfaces the credential cannot read. |
| `zendesk_assess_authentication` | Controls 1-5 and 21. |
| `zendesk_assess_access_control` | Controls 6-8, 13, and 14. |
| `zendesk_assess_data_protection` | Controls 9-12 and 18-20. |
| `zendesk_assess_integrations` | Controls 15-17 and 22-25. |
| `zendesk_export_audit_bundle` | Runs the access check and all four assessments, then writes an audit bundle and a zip archive. |

`zendesk_export_audit_bundle` writes:

- `core_data/`: The redacted API snapshots the assessments read, never the raw responses.
- `analysis/`: `findings.json` and one JSON per category.
- `compliance/`: `executive_summary.md`, `unified_compliance_matrix.md`, and one report per framework.
- `QUICK_REFERENCE.md`.
- `_errors.log` when collection was partial. It holds:
  - One scrubbed error string per failed snapshot, carrying the HTTP status and Zendesk's documented error fields only.
  - One partial-inventory line per list that stopped paging early, naming the reason.
- A paired `.zip`.

Reruns allocate a new directory (`-2`, `-3`, ...) and the zip name follows the directory, so a prior bundle is never overwritten.

### Assessment arguments

Assessment tools accept:

- `admin_threshold` (default 5)
- `stale_days` (default 90)
- `retention_days` (default 365)
- `session_timeout_minutes` (default 480, the longest acceptable team member inactivity timeout)
- `suspended_ticket_age_days` (default 30)
- `max_items` (default 2000, the point at which an inventory is recorded as truncated)

The export tool adds `output_dir` (default `./export/zendesk`). Output paths are resolved inside that root with traversal and symlinked-parent protection.

### Pagination and truncation

Paging rules:

- Cursor-paginated lists follow `links.next` until `meta.has_more` is false. Users and Groups also request `include_boundary_indicators=true`.
- Offset-paginated lists follow `next_page` until it is null or a page comes back short.
- When a full page omits `next_page`, the client requests the next numeric page (`page` incremented by one) rather than treating the omission as the end. The cursor rule is unchanged.

A list is recorded as truncated whenever it stops for any reason other than the server's end marker:

- `max_items`.
- The 100-page cap.
- An empty or fully repeated page returned while `has_more` is true or a `next_page` URL is present.
- A cursor or `next_page` that points back at the page just fetched.
- A next link the client refused to follow.

### Next-link origin check

A server-supplied `links.next` or `next_page` is followed only on the configured origin.

An absolute link is resolved against the configured base URL before any request is built for it. It must match the base URL's scheme, host, and port exactly and carry no user credentials.

- An absolute link is one naming a scheme (`https:` and `javascript:` alike) or opening with two slashes or two backslashes, which a URL parser reads as protocol-relative.
- A relative link is a path on the base URL.

When a link fails that check:

- The credential never leaves for it.
- The pages already read are kept.
- The list stops as truncated with a fixed-text reason.

The reason names only the rejected origin and the configured origin, never the link's path, query, or credentials. It names the rejected origin by its scheme, host, and port, or by the bare scheme of a `javascript:`, `data:`, `blob:`, or `file:` link without a host.

### Truncation reporting

Every truncated list carries its reason as `truncation_reason` in the list result, the `collection` entry, and `core_data/`. The reason also reaches the access check, the finding summaries, and `_errors.log`:

- The access check reports the reason as `truncationReason` on the probe and in a note.
- The finding summaries quote the reason in their truncation sentence.
- `_errors.log` gets one `<name> dataset: partial inventory, paging stopped early because ...` line per list that stopped early.

A truncated inventory downgrades every verdict that depends on it. The access check marks a probe count that hit its sample cap with a trailing `+`.

### Finding shape and status

Every finding has the shape `{id, control, title, severity, status, summary, evidence, mappings}`. Severity is one of `critical | high | medium | low | info`. Status is one of:

- `pass`: Verified from documented API fields, read to completion, by an admin credential.
- `warn`: Verified but needs review, or the evidence was partial (truncated inventory, undated items, non-admin credential).
- `fail`: A verified gap.
- `manual`: The API does not expose the setting, the primary endpoint was forbidden or unavailable on the plan, or the inventory was suspiciously empty. The summary names the cause and the exact Admin Center evidence a reviewer must collect. Manual never counts as passing. Some unreadable secondary inventories only cap a `pass` at `warn`, as listed under [Limitations and manual controls](#limitations-and-manual-controls), and a verified gap still yields `fail`.

## Control coverage

| # | Control | Tool | Finding | Status semantics |
|---|---------|------|---------|------------------|
| 1 | SSO enforcement enabled | `zendesk_assess_authentication` | `ZD-01` | `pass` when `security_settings.authentication.agent.enforce_sso=true`, `zendesk_login=false`, and at least one SSO method (`remote_login`, `google_login`, `office_365_login`) is enabled; `warn` when SSO is enforced but password sign-in stays enabled or no method is on; `fail` when `enforce_sso=false`; `manual` only when Security Settings is forbidden or the flags are absent. `remote_bypass`, `sso_auto_redirect`, and `primary_external_auth` are reported as evidence. |
| 2 | Two-factor authentication required for agents | `zendesk_assess_authentication` | `ZD-02` | `pass` when `security_settings.authentication.agent.two_factor_enforce=true` and every active agent and admin reports `two_factor_auth_enabled=true` with the list read to completion; `warn` when enforcement is on but some members are not yet enrolled, the flag is missing, or the list is truncated; `fail` when `two_factor_enforce=false` (per-user enrollment alone never passes) or, when Security Settings is unreadable, any member reports `false`; `manual` when `two_factor_enforce=false` under enforced SSO (MFA belongs to the identity provider), when the list is forbidden or empty, or when the requirement cannot be read. While the team list is truncated the named lists `without_two_factor` and `two_factor_flag_missing` render `null` and the `without_two_factor_count` and `two_factor_flag_missing_count` lower bounds stand beside them (a zero count renders `null`); the lists return once the inventory is read to completion. |
| 3 | Password policy meets complexity requirements | `zendesk_assess_authentication` | `ZD-03` | `pass` when `authentication.agent.security_policy_name=recommended`, or `custom` with `password.password_length>=12`, `password_complexity>=2`, `password_in_mixed_case=true`, `failed_attempts_allowed<=10`, `disallow_local_part_from_email=true`, and `password_history_length>=5` or null; `warn` for `high` or a custom policy with gaps; `fail` for `medium` or `low`; `manual` only when Security Settings is forbidden or the name is absent. `password_duration` and `max_sequence` are reported as evidence. |
| 4 | IP restrictions configured for agent access | `zendesk_assess_authentication` | `ZD-04` | `pass` when `security_settings.ip.ip_restriction_enabled=true` with at least one `ip_ranges` entry (scope reported from `enable_agent_ip_restrictions`); `warn` when enabled with no ranges; `fail` when disabled; `manual` only when Security Settings is forbidden. |
| 5 | Session timeout configured and reasonable | `zendesk_assess_authentication` | `ZD-05` | `pass` when `security_settings.agent_session_timeout` (and `mobile_app_session_timeout` while `mobile_app_access` is on) is between 1 and `session_timeout_minutes`; `warn` when above the threshold; `fail` when 0 (never expires) or more than three times the threshold; `manual` only when Security Settings is forbidden. `maximum_session_duration_enabled`, `maximum_session_duration`, and `end_user_session_timeout` are reported as evidence. |
| 6 | Agent roles follow least privilege | `zendesk_assess_access_control` | `ZD-06` | `fail` when a custom role with members grants admin-equivalent permissions (`manage_roles=all-except-self`, `manage_team_members=all-with-self-restriction`, `manage_api_credentials=true`, or `ticket_access=all` with business rule and trigger management); `warn` on truncation or when every agent is unrestricted; `manual` when users or custom roles (Enterprise) are unreadable or the team is empty. |
| 7 | No excessive admin accounts | `zendesk_assess_access_control` | `ZD-07` | `fail` above `admin_threshold`; `warn` on dormant or undated `last_login_at` or truncation; `manual` when zero admins are visible (partial view). `seen_admins` is the count observed; while the team list is truncated the `admins` and `dormant_admins` lists render `null` and `dormant_admins_count` and `admins_without_last_login_count` are lower bounds (zero renders `null`). |
| 8 | Group-based access controls configured | `zendesk_assess_access_control` | `ZD-08` | `pass` with two or more groups and memberships read to completion; `warn` with one group or no memberships or truncation; `manual` when unreadable or empty. |
| 9 | Audit logging enabled and accessible | `zendesk_assess_data_protection` | `ZD-09` | `pass` when `/audit_logs` is readable with entries and the 100-entry sample filled or ended at the server's end marker; `warn` when the sample was cut short by a stalled cursor or a refused next link (`sample_cut_short: true`, `actions_seen` withheld); `manual` when forbidden, 404 (plan), empty, or cut short before any entry arrived. |
| 10 | Audit log retention meets compliance requirements | `zendesk_assess_data_protection` | `ZD-10` | `pass` when the oldest entry is at least `retention_days` old; `warn` when younger; `manual` when the oldest entry is undated or unreadable. |
| 11 | HIPAA compliance mode enabled (if applicable) | `zendesk_assess_data_protection` | `ZD-11` | Always `manual`: neither the [Account Settings](https://developer.zendesk.com/api-reference/ticketing/account-configuration/account_settings/) nor the [Security Settings](https://developer.zendesk.com/api-reference/ticketing/account-configuration/security_settings/) reference publishes a HIPAA or Advanced Data Privacy and Protection field. |
| 12 | Data deletion/redaction policies configured | `zendesk_assess_data_protection` | `ZD-12` | `pass` when `/deletion_schedules` is readable to completion and at least one active schedule with conditions targets `zen:ticket`; `warn` when active schedules exist but none targets `zen:ticket`, one has no conditions, or the list is truncated; `fail` when zero schedules exist or none is active; `manual` when the endpoint is forbidden, not on the plan (404), or otherwise unreadable, with the cause named. Evidence lists active schedules by object (`zen:ticket`, `zen:user`, `zen:attachment`, `zen:bot_only_conversation`), `default` schedules, `settings.tickets.agent_ticket_deletion`, and the custom roles allowed to redact or manage deletion schedules; when Account Settings or custom roles could not be read, a `pass` is capped at `warn` naming the unread source and the role counts render as `null`. |
| 13 | API tokens are minimal and reviewed | `zendesk_assess_access_control` | `ZD-13` | `pass` only when `settings.api.api_token_access=false`, and only while the token audit log was readable; with `api_token_access=false` and the audit log unreadable the finding is capped at `warn` naming the failed read. Otherwise token creation and deletion events are enumerated from `/audit_logs?filter[source_type]=apitoken`: `warn` when no token is outstanding (an event history cannot prove an empty inventory, and an assessment authenticated with an API token says so); `manual` listing the outstanding tokens, how many exceed `stale_days`, and how many are undated when tokens exist, or when the audit log is forbidden or not on the plan. Event counts derived from an unreadable audit log render as `null`; over a truncated event history the `tokens_outstanding` counts are lower bounds (zero renders `null`), the `outstanding_tokens` list renders `null`, `token_events_truncated` is `true`, and the summary says older tokens may be missing from the unread remainder of the history. |
| 14 | OAuth application permissions are scoped | `zendesk_assess_access_control` | `ZD-14` | `fail` when a client has no `scope` or an `http://` redirect URI; `warn` for public clients, write or impersonate tokens, non-expiring or stale or undated tokens, truncation of either list, or a token list that could not be read (including a readable zero-client inventory, because tokens issued to global or hidden clients cannot be ruled out without `/oauth/tokens`); `pass` only when both clients and tokens were read to completion, including a zero-client, zero-token inventory with the counts stated. Token counts render as `null` when the token list was unreadable. |
| 15 | Marketplace apps reviewed for permissions | `zendesk_assess_integrations` | `ZD-15` | `pass` when the installation inventory is readable, complete, and empty and the owned-apps list (used to tell private apps from marketplace apps) was readable; `warn` when zero installations were seen but the list was truncated, or when the owned-apps list was unreadable or truncated (the pass is capped and the cause named, and a truncated owned-apps list leaves the split between private and marketplace apps not asserted); `manual` with the inventory when apps are installed (the `apps` list renders `null` while either inventory is truncated or the owned-apps list is unreadable, with the counts as lower bounds beside it). |
| 16 | Private/custom apps have appropriate scope | `zendesk_assess_integrations` | `ZD-16` | `pass` when the readable inventory is empty; `warn` when apps are deprecated or obsolete; otherwise `manual` with the inventory. |
| 17 | Sandbox environment used for testing | `zendesk_assess_integrations` | `ZD-17` | `pass` when `settings.active_features.sandbox=true`; `warn` when `false`; `manual` when absent or unreadable. |
| 18 | CDN security (attachment hosting) configured | `zendesk_assess_data_protection` | `ZD-18` | `pass` when `settings.tickets.private_attachments=true`; `fail` when `false`; `manual` when absent. |
| 19 | File attachment restrictions configured | `zendesk_assess_data_protection` | `ZD-19` | Always `manual`, enriched with `settings.limits.attachment_size` and `settings.tickets.email_attachments`; the Account Settings reference publishes no allowed file type list. |
| 20 | Suspended ticket handling automated | `zendesk_assess_data_protection` | `ZD-20` | `pass` when the readable queue is empty or every ticket is younger than `suspended_ticket_age_days`; `warn` on aged, undated, or truncated tickets; `manual` when forbidden. |
| 21 | End-user authentication required (no anonymous tickets) | `zendesk_assess_authentication` | `ZD-21` | `pass` when `security_settings.authentication.end_user.enforce_sso=true` with an SSO method enabled, when `zendesk_login=true` under the `recommended` or `high` `security_policy_name`, or when only SSO or social methods (`remote_login`, `google_login`, `office_365_login`, `facebook_login`) are enabled; `warn` when SSO is enforced without a method or the password level is `medium` or `low`; `fail` when no sign-in method is enabled; `manual` only when Security Settings is forbidden. When Account Settings could not be read, `settings.api.api_password_access_end_users` is reported as not verified with the cause and a `pass` is capped at `warn`. The "Anybody can submit tickets" toggle is not published by either reference, so every summary names it as the remaining manual capture, together with `settings.api.api_password_access_end_users`. |
| 22 | Brand security settings consistent across brands | `zendesk_assess_integrations` | `ZD-22` | `pass` when an admin read every active brand and they share one `help_center_state`; `warn` for mixed states, a non-admin view (the summary names the role, or says the role could not be read when `/users/me` was unreadable, and never reports an unread role as non-admin), or truncation; `manual` when zero brands are visible or unreadable. |
| 23 | External sharing agreements reviewed | `zendesk_assess_integrations` | `ZD-23` | `pass` when the readable inventory is empty; `warn` when agreements are failed or misconfigured; `manual` when accepted or pending agreements exist. |
| 24 | External notification targets use HTTPS | `zendesk_assess_integrations` | `ZD-24` | `fail` when any active target or webhook is non-https; `warn` when a webhook has no authentication, one endpoint is unreadable, or either inventory (targets or webhooks) is truncated; `manual` when both endpoints are unreadable; `pass` when every destination is https and authenticated (or both readable, complete inventories are empty). Counts for an unreadable half render as `null`. |
| 25 | Triggers/automations do not send data to external URLs | `zendesk_assess_integrations` | `ZD-25` | `fail` when an active rule notifies an `http://` destination; `warn` when rules notify external webhooks, targets, or sharing agreements, or the rule inventory is truncated; `manual` when zero rules are visible; `pass` when the complete rule set has no external actions and the target and webhook lists used to resolve destinations were readable. When targets or webhooks are unreadable or truncated, actions pointing at them are recorded as `unresolved_destinations` (their scheme cannot be checked, so `fail` is not reachable for them), the summary names the unread inventory, `insecure_destinations` renders `null` because the count is unknown rather than zero (`insecure_resolved_destinations` keeps the count among the destinations that did resolve), and a `pass` is capped at `warn`. |

## Framework mappings

Every finding carries the row from the spec's compliance table for its control, prefixed by framework (`FedRAMP`, `CMMC`, `SOC 2`, `CIS`, `PCI-DSS`, `DISA STIG`, `IRAP`, `ISMAP`).

The export bundle renders one report per framework under `compliance/`, filtering each finding's mappings to that framework.

For example, control 2 maps to:

- `FedRAMP IA-2(1)`
- `CMMC IA.L2-3.5.3`
- `SOC 2 CC6.1`
- `CIS 4.5`
- `PCI-DSS 8.3.2`
- `DISA STIG SRG-APP-000149`
- `IRAP ISM-1401`
- `ISMAP 8.2.2`

## Live smoke

Export `ZENDESK_API_TOKEN` from your secrets manager first (the value is never shown here), then run:

```bash
ZENDESK_SUBDOMAIN=acme ZENDESK_EMAIL=admin@example.com \
  npm --prefix cli run test:zendesk:live
```

The script prints a skip message and exits 0 when no credentials are present. With credentials, it runs `zendesk_check_access` and `zendesk_assess_access_control`. It prints the per-surface access status and each finding.

## Limitations and manual controls

- Controls 11 and 19 are always `manual`. Neither the [Account Settings](https://developer.zendesk.com/api-reference/ticketing/account-configuration/account_settings/) nor the [Security Settings](https://developer.zendesk.com/api-reference/ticketing/account-configuration/security_settings/) reference publishes a HIPAA or Advanced Data Privacy field or an allowed attachment file type list. Each finding names the Admin Center page to capture.
- Controls 1, 3, 4, 5, 12, and 21 are verified from the Security Settings and Deletion Schedules endpoints. They render `manual` only when those admin-only endpoints are forbidden. The "Anybody can submit tickets" portion of control 21 stays manual because neither reference publishes it.
- Controls 13, 15, 16, and 23 are `manual` whenever the inventory is non-empty: reviewing token ownership, app permissions, or sharing partners is a human activity. The finding carries the inventory as evidence.
- The API token inventory endpoint is not part of the published API reference and is not called. Token creation and deletion events are reconstructed from the audit log (`filter[source_type]=apitoken`), which needs an Enterprise plan and cannot prove that zero tokens exist.
- Audit logs and custom roles require an Enterprise plan. A 403 or 404 on them never yields a pass: the finding is `manual` with a plan or permission cause, or capped at `warn` where they are a secondary inventory listed below.
- Help Center article visibility, Talk, Chat, and Sell settings are not inspected.
- Non-admin credentials cap every verdict at `warn`.
- A finding that reads several inventories never passes on a partial view.
  - When a secondary inventory the finding needs is unreadable or truncated, the verdict is capped at `warn` with the cause named and `verdict_capped_by_unreadable` listed in evidence.
  - Secondary inventories by finding:
    - Account Settings for ZD-12 and ZD-21.
    - Custom roles for ZD-12.
    - The token audit log for ZD-13, only while `settings.api.api_token_access=false`. Otherwise an unreadable audit log makes ZD-13 `manual`.
    - OAuth tokens for ZD-14.
    - Owned apps for ZD-15.
    - Targets or webhooks for ZD-24 and ZD-25. ZD-24 is `manual` when both are unreadable.
  - Counts and lists derived from an inventory that could not be read render as `null` in finding evidence and assessment summaries, never `0` or `[]`.
- A truncated list is an incomplete inventory, and a verdict over it says only what the seen population supports.
  - A count over a truncated list is a lower bound. A positive count renders as observed, qualified by `inventory_truncated` and the summary's truncation sentence.
  - A count of zero renders `null` rather than `0`, because the unread remainder may hold what the seen records did not.
  - Item-level detail (member names and emails, admin and token lists, app titles, destination hosts) is withheld as `null` while the list is truncated, with the lower bound beside it under a `_count` key. So a partial list is never filed as the review list.
  - The summary says how many items were seen and that the detail is withheld until the inventory is read to completion. A higher `max_items`, a fixed cursor, or the missing permission restores the detail.
  - No finding passes over a truncated inventory it read.
  - A `fail` that rests on the absence of records (zero seen) is `warn` while the list that found none was truncated.
  - The `pass`, `warn`, `fail`, and `manual` counts of a category summary follow the same rule. When an inventory the category's findings read was unreadable or truncated, a count of zero renders `null`. The executive summary renders such a count as `none seen (not asserted: an inventory the findings read was incomplete)`.
  - The 100-entry audit log sample ZD-09 reads stops at its cap by design and is complete when it filled.
    - A sample cut short before that (a stalled cursor or a refused next link) is a truncated list like any other. So ZD-09 renders `warn` with `sample_cut_short: true` and `actions_seen` withheld.
    - A read that stopped before any entry arrived is `manual` rather than a verified empty log.

## Official documentation consulted

- [Security and authentication](https://developer.zendesk.com/api-reference/introduction/security-and-auth/)
- [Pagination](https://developer.zendesk.com/api-reference/introduction/pagination/)
- [Rate limits](https://developer.zendesk.com/api-reference/introduction/rate-limits/)
- [Account Settings](https://developer.zendesk.com/api-reference/ticketing/account-configuration/account_settings/)
- [Security Settings](https://developer.zendesk.com/api-reference/ticketing/account-configuration/security_settings/)
- [Deletion Schedules](https://developer.zendesk.com/api-reference/ticketing/business-rules/deletion_schedules/)
- [Users](https://developer.zendesk.com/api-reference/ticketing/users/users/)
- [Custom Agent Roles](https://developer.zendesk.com/api-reference/ticketing/account-configuration/custom_roles/)
- [Groups](https://developer.zendesk.com/api-reference/ticketing/groups/groups/)
- [Group Memberships](https://developer.zendesk.com/api-reference/ticketing/groups/group_memberships/)
- [Audit Logs](https://developer.zendesk.com/api-reference/ticketing/account-configuration/audit_logs/)
- [OAuth Clients](https://developer.zendesk.com/api-reference/ticketing/oauth/oauth_clients/)
- [OAuth Tokens](https://developer.zendesk.com/api-reference/ticketing/oauth/oauth_tokens/)
- [Apps](https://developer.zendesk.com/api-reference/ticketing/apps/apps/)
- [Brands](https://developer.zendesk.com/api-reference/ticketing/account-configuration/brands/)
- [Webhooks](https://developer.zendesk.com/api-reference/webhooks/webhooks-api/webhooks/)
- [Targets](https://developer.zendesk.com/api-reference/ticketing/targets/targets/)
- [Triggers](https://developer.zendesk.com/api-reference/ticketing/business-rules/triggers/)
- [Automations](https://developer.zendesk.com/api-reference/ticketing/business-rules/automations/)
- [Sharing Agreements](https://developer.zendesk.com/api-reference/ticketing/account-configuration/sharing_agreements/)
- [Suspended Tickets](https://developer.zendesk.com/api-reference/ticketing/tickets/suspended_tickets/)
