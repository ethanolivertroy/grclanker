---
title: Ansible Automation Platform
description: Read-only Ansible Automation Platform controller inspection covering all 30 ansible-sec-inspector controls with verdict-safe findings and an auditor bundle.
---

The Ansible tool family inspects a Red Hat Ansible Automation Platform (AAP) controller, or upstream AWX, through its read-only REST API. It implements every control in the [Ansible AAP Security Inspector spec](/specs/ansible-sec-inspector/):

- Job execution health.
- Host coverage.
- Job template and schedule hygiene.
- Credential hygiene.
- Access control.
- Platform audit settings.

Findings carry:

- The spec control number.
- A stable finding id.
- A status.
- The evidence behind the verdict.
- Mappings to FedRAMP, CMMC, SOC 2, CIS Controls, PCI-DSS, and DISA STIG.

## What it inspects

- Jobs (`/api/v2/jobs/`) filtered to `type=job` inside the lookback window, plus `/api/v2/settings/jobs/` and `/api/v2/instance_groups/`
- Hosts, inventory sources, and per-host job results (`/api/v2/job_host_summaries/`)
- Job templates, schedules, workflow job templates, and survey specs
- Credentials with their `kind`, masked `inputs`, and owners (`summary_fields.owners` or `owner_users/` and `owner_teams/`)
- OAuth2 tokens, organizations and their `admins/`, users with `is_superuser` and `is_system_auditor`, teams, and role assignments
- Projects, execution environments, notification templates and deliveries, the activity stream, and the authentication, system, and logging settings categories

Nothing is written to the controller.

The bundle never records the token or password used to authenticate. It also does not rely on the API's own `$encrypted$` masking. Every `core_data/` snapshot is projected to the fields the verdicts read before it is written, and credential-bearing values are replaced by `[REDACTED]` at that step (see [Bundle redaction](#bundle-redaction)).

## Setup and authentication

| Variable | Purpose |
|---|---|
| `AAP_URL` | Controller base URL, for example `https://controller.example.com`. A trailing `/api` or `/api/v2` is stripped. |
| `AAP_TOKEN` | OAuth2 bearer token for a local or gateway account. Preferred for automation. |
| `AAP_USERNAME` and `AAP_PASSWORD` | Session login for LDAP, SAML, or local accounts. The password is only ever read from the environment; passing it as a tool argument is rejected. |
| `AAP_VERIFY_SSL` | Set to `false` only for approved non-production troubleshooting against a self-signed controller. The opt-out is scoped to the tool's own requests through a dedicated `node:https` agent; `NODE_TLS_REJECT_UNAUTHORIZED` is never touched. Defaults to `true`. |
| `AAP_TIMEOUT` | Request timeout in seconds, for each attempt and including the response body. Defaults to 30. |

Each tool also accepts `url`, `username`, `token`, `timeout_seconds`, and `verify_ssl` arguments that override the environment for that call.

Required roles: grant the audit account the System Auditor role. A plain user or organization member only sees objects in its own organizations, so every would-be `pass` is downgraded to `warn` with a partial-inventory note.

`/api/v2/settings/*` and `/api/v2/activity_stream/` are only readable by superusers and system auditors.

Tokens on AAP 2.5 are issued by the platform gateway. A controller token still works against `/api/v2/`.

## Run it

After setup, start `grclanker` and ask in plain words. The agent calls the matching tools, for example:

```text
Check whether my Ansible credentials can read everything grclanker needs.
Run the Ansible assessments and list the failing findings first.
Export an Ansible audit bundle.
```

For a posture readout or a framework mapping, use the [assess](/docs/workflows/assess/) or [audit](/docs/workflows/audit/) workflow, for example `grclanker assess "our Ansible Automation Platform"`. Both start with `ansible_check_access`, then run the assessments or `ansible_export_audit_bundle`.

## Tools

| Tool | Controls | What it does |
|---|---|---|
| `ansible_check_access` | none | Confirms authentication, reports whether the account has full visibility, and probes 18 audit surfaces for readability. A readable surface carries its `count`; a failed probe carries `count: null`, the observed `http_status`, the endpoint that answered, and the scrubbed error. Run this first. |
| `ansible_assess_job_health` | 1, 2, 3, 4, 5, 28 | Job success rate, chronic template failures, stuck jobs versus each template's average successful runtime, manual launch rate, failed job remediation within 7 days, and concurrency limits. |
| `ansible_assess_host_coverage` | 6 to 15 | Unmanaged and stale hosts, inventory source sync, per-host failure rate, disabled hosts, stale and unscheduled templates, missed and disabled schedules, and workflow coverage. |
| `ansible_assess_platform_security` | 16 to 27, 29, 30 | Credential age, sharing, plaintext secrets, ownership, OAuth2 tokens, org admins, team roles, execute versus admin separation, auditor coverage, external auth, activity stream, notifications, project SCM health, and execution environments. |
| `ansible_export_audit_bundle` | all 30 | Runs the three assessments and writes an evidence bundle plus a zip archive. |

### Bundle layout

`ansible_export_audit_bundle` writes to `./export/ansible-aap/<host>-ansible-aap-audit/` by default (override with `output_dir`). A rerun allocates `-2`, `-3`, and so on instead of overwriting, and the zip is named after the allocated directory.

- `core_data/`: Projected API snapshots, one JSON file per endpoint.
  - A readable list is written as `{ data: { items, complete, total, truncation } }`, and a readable-but-empty page keeps `items: []`.
  - A dataset that could not be read (a list, a per-item probe such as `user_roles.json` or `team_roles.json`, or an object dataset under `settings/`) is written as a not-collected marker, `{ collected: false, status, endpoint, error }`. The marker carries no `items`, `total`, or `complete` beside the error.
  - Per-item files whose parent list failed carry the same marker, with the parent's status and endpoint.
  - A settings category whose body carries none of the category's documented keys (a foreign JSON document, an empty object, a string or array body) is written as the same marker, never as the body. Its marker has `status: null` and the fixed error `<label> (<path>): no documented settings key returned`.
- `analysis/`: `findings.json`, `metadata.json`, and one JSON plus Markdown file per assessment.
- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, and `compliance/<framework>/` reports for FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, and DISA STIG.
- `QUICK_REFERENCE.md` and `README.md`.
- `_errors.log`, written only when some reads failed but the bundle still completed.

## Status semantics

Every finding is `pass`, `warn`, `fail`, or `manual`.

- `manual` means the API cannot prove the control on this deployment or with this account. The summary names the cause (a 403, a missing endpoint, an empty inventory that needs confirmation, a setting the version does not expose) and the evidence to collect from the controller UI.
## Control coverage

Verdicts on unread, partial, or truncated data follow the [verdict safety rules](#verdict-safety-rules).

| Spec control | Tool | Finding id | Status semantics |
|---|---|---|---|
| 1 Job success rate | job health | `AAP-JOB-01` | fail below `min_success_rate` (90) or when zero jobs exist; warn if no job has finished |
| 2 Chronic playbook failures | job health | `AAP-JOB-02` | fail when a template with 3+ runs has more than 3 consecutive failures or over 20% failures; manual on empty history |
| 3 Stuck or long-running jobs | job health | `AAP-JOB-04` | warn when a running or pending job exceeds 2x its template's average successful runtime, has no `started`, or has no baseline |
| 4 Manual job launch rate | job health | `AAP-JOB-03` | warn above `max_manual_rate` (25%) |
| 5 Failed job remediation rate | job health | `AAP-JOB-05` | fail when a failure older than 7 days had no later successful run of the same template; warn on undated failures; pass with no failures |
| 6 Unmanaged hosts | host coverage | `AAP-HOST-01` | fail when any host has `last_job` null; manual when no hosts are visible |
| 7 Stale host coverage | host coverage | `AAP-HOST-02` | fail beyond `stale_host_days` (30), severity critical beyond `critical_stale_host_days` (60); warn when `summary_fields.last_job.finished` is missing |
| 8 Inventory source sync health | host coverage | `AAP-HOST-03` | warn on `last_update_failed`, failed status, stale or missing `last_updated`; manual when no sources exist |
| 9 Host failure rate | host coverage | `AAP-HOST-05` | warn when a host with 3+ runs failed over 30% in the window, or when no host has enough runs |
| 10 Disabled hosts | host coverage | `AAP-HOST-04` | warn above 5% disabled or when `enabled` is missing |
| 11 Stale job templates | host coverage | `AAP-TMPL-01` | warn when `last_job_run` is older than `stale_template_days` (90) or null |
| 12 Unscheduled critical templates | host coverage | `AAP-TMPL-02` | fail when a template matching the critical keyword list has no schedule; manual when none matches |
| 13 Missed scheduled runs | host coverage | `AAP-SCHED-01` | fail when an enabled schedule has a past or null `next_run`, or its template last ran more than 1.5x the rrule interval ago; warn when the rrule or template cannot be evaluated |
| 14 Disabled schedules | host coverage | `AAP-SCHED-02` | warn when any schedule has `enabled=false` or no `enabled` flag |
| 15 Workflow coverage | host coverage | `AAP-TMPL-03` | fail when job templates exist but no workflow does; warn when no workflow matches the critical keywords; manual when nothing is visible |
| 16 Stale credentials | platform security | `AAP-CRED-01` | fail when a non-managed credential was modified more than `stale_credential_days` (90) ago, broken down by `kind`; warn on missing `modified` |
| 17 Shared credential usage | platform security | `AAP-CRED-03` | fail when a credential is attached to more than `max_shared_templates` (5) templates; `ask_credential_on_launch` templates are reported |
| 18 Unvaulted secrets | platform security | `AAP-CRED-04` | fail on plaintext values under secret-like names in template `extra_vars`, survey defaults, inventory or group variables; manual when surveys or variable sources are unreadable; reports Vault credentials and `ask_variables_on_launch` templates. `inventories`, `groups`, and `vault_credentials` evidence render `null` when their list was unreadable, never `0` or `[]` |
| 19 Credential ownership gaps | platform security | `AAP-CRED-05` | warn when a credential has no user or team owner; manual when owners cannot be read |
| 20 OAuth2 token hygiene | platform security | `AAP-CRED-02` | warn when a token has no `expires` or is older than `stale_token_days` (90); pass on zero tokens by intent |
| 21 Organization admin count | platform security | `AAP-RBAC-01` | fail when an organization has more than `max_org_admins` (3) admins; manual when the organizations list is unreadable (evidence carries only the endpoint, HTTP status, and error, never an empty `organizations` list) or when any organization's `admins/` list could not be read (that organization stays listed with `admin_count: null`) |
| 22 Team role audit | platform security | `AAP-RBAC-03` | fail when a team holds Admin on an organization or on every inventory |
| 23 Execute versus admin separation | platform security | `AAP-RBAC-04` | fail when a probed user holds an Execute role together with an Admin-family role or `is_superuser` |
| 24 Audit role coverage | platform security | `AAP-RBAC-05` | pass when a system auditor exists or every organization has a confirmed Auditor role holder among probed users and teams and every probed role list was read; when the teams list or any user or team role list could not be read, no organization is named as uncovered (`uncovered` is `null` and `coverage_unknown_organizations` counts the unconfirmed ones): a system auditor or a confirmed Auditor for every organization still covers the control at warn naming the unread lists, otherwise manual ("coverage is unknown for N organizations"); warn when every list was read and an organization has no Auditor |
| 25 External authentication enforcement | platform security | `AAP-RBAC-02` | fail when the documented LDAP, SAML, or OIDC keys exist but none is populated; manual when the settings category exposes none of them (AAP 2.5 gateway, recognized by the category's session and local-auth keys) or when the body carries none of the documented authentication keys at all (unreadable path, `evidence.keys` absent) |
| 26 Activity stream retention | platform security | `AAP-AUDIT-01` | fail when `ACTIVITY_STREAM_ENABLED` is false, no records are visible, or the newest record is older than 24 hours; warn when the system or logging settings could not be read or carried none of their documented keys |
| 27 Notification coverage | platform security | `AAP-AUDIT-02` | fail with zero notification templates; warn when no critical template has an error notification or recent deliveries failed; manual when the notification templates list is unreadable or a template's notification list could not be read; warn naming the read when the delivery history is unreadable, and `critical_templates`, `critical_templates_eligible`, `covered`, and `unreadable` evidence render `null` when the job templates list was not read |
| 28 Concurrent job limit | job health | `AAP-JOB-06` | warn when an instance group has neither `max_concurrent_jobs` nor `max_forks`; manual when `SCHEDULE_MAX_JOBS` or the group fields are absent |
| 29 Project SCM health | platform security | `AAP-PROJ-01` | warn on manual SCM, `last_update_failed`, or missing `last_updated` |
| 30 Execution environment inventory | platform security | `AAP-PLAT-01` | warn when a template relies on the default execution environment or defers it to launch; manual when the version exposes no execution environments |

## Framework mappings

Each finding's `mappings` array expands the spec's mapping table, for example `FedRAMP CA-7`, `CMMC CM.L2-3.4.1`, `SOC 2 CC7.1`, `CIS 16.12`, `PCI-DSS 6.3.3`, `STIG SRG-APP-000456` for control 1. The bundle writes one report per framework under `compliance/` and a unified matrix listing every control against all six frameworks.

## Live smoke test

```bash
AAP_URL=https://controller.example.com AAP_TOKEN=... npm --prefix cli run test:ansible:live
```

The script exits 0 with a skip message when `AAP_URL` plus credentials are absent. Otherwise it runs `ansible_check_access` and the job health assessment over the last 30 days and prints each finding.

## Limitations and manual controls

- Only the `/api/v2/` controller API is used. AAP 2.5 gateway authenticators, gateway tokens, and Event-Driven Ansible are out of scope.
  - Control 25 is therefore `manual` when the controller settings category exposes none of the documented LDAP, SAML, or OIDC keys.
  - The category's session and local-auth keys (`SESSION_COOKIE_AGE` and its siblings) keep a 2.5 body recognizable, so that case renders the gateway note rather than the unreadable marker.
- Control 18 scans job template `extra_vars`, survey defaults, inventory variables, and group variables. Host variables and launch-time `extra_vars` are not scanned.
- Control 20 cannot flag tokens of disabled users because the user API exposes no active flag.
- Control 23 probes roles for the first 50 users. The rest are reported as unprobed in `evidence`.
- Controls 12, 15, and 27 identify critical templates and workflows by keyword (patch, harden, CIS, STIG, baseline, logging, audit, access, password, compliance, security, firewall). Review the manual findings when your naming differs.
- Controllers without execution environments, without `SCHEDULE_MAX_JOBS`, or without an activity stream render the related controls as `manual`, never `pass`.

## How the tools handle evidence

This section is reference for reviewing findings and bundles: how the tools retry failed requests, how unread, partial, or truncated data limits a verdict, how the tools page through the API and report incomplete listings, and how credentials are kept out of findings, bundles, and error text. You don't need it to set up or run the integration.

### Retries

A request that gets a 429, 500, 502, 503, or 504 answer, times out, or loses its connection is retried up to three times, so it makes at most four attempts.

- Between attempts the client waits as long as the answer's `Retry-After` asks, in seconds or as an HTTP date. Without one, it waits 0.5, 1, then 2 seconds.
- A `Retry-After` longer than 30 seconds is not waited out. The request fails at once and its error names the wait: `AAP request failed: /api/v2/hosts/ (429 Too Many Requests; the server asked to retry after 120 s, more than the 30 s limit)`.
- Each attempt gets the full `AAP_TIMEOUT`, and the timer runs until the response body is read, so a body that stalls times out too.
- When the retries run out, the error names the attempts and the last outcome, for example `AAP request failed after 4 attempts: /api/v2/hosts/ (503 Service Unavailable)`, `AAP request failed after 4 attempts: /api/v2/ping/ (timed out after 30000 ms)`, or `AAP request failed after 4 attempts: /api/v2/ping/ (network error: fetch failed)`.
- Any other status, such as 401, 403, 404, or 501, is not retried, and neither is a 2xx whose body is not JSON.
- The session login's `GET /api/login/` is retried like any read. Its `POST /api/login/` is retried on those statuses but never after a timeout or lost connection: such a login may still have opened a session, and AAP's `SESSIONS_PER_USER` limit expires the user's oldest session when another opens.
- A list whose later page still fails after the retries is not collected at all. Its snapshot is the not-collected marker with the failing page's status and error, and every finding and counter that reads it treats it as unreadable, so the pages already read never stand in for the list.

### Bundle redaction

Credentials never reach the bundle. Each snapshot keeps only the fields the controls read (ids, names, statuses, timestamps, flags, and `summary_fields` references).

The redaction step replaces these with `[REDACTED]`:

- The bodies of `extra_vars`, `extra_data`, inventory, group, and host `variables`, and `source_vars`. The variable names are kept so control 18 evidence stays reviewable.
- Every credential `inputs` value.
- OAuth2 `token` and `refresh_token` values.
- Survey question defaults.
- `notification_configuration` values.
  - Webhook URLs are reduced to scheme and host.
  - Header values and any `{name, value}` pair are redacted.
- The `AWX_TASK_ENV` and `GALAXY_TASK_ENV` dictionaries.
- Activity stream `changes`.
- Any value under a credential-shaped key (`password`, `secret`, `token`, `key`, `passphrase`, `authorization`, and their camelCase and snake_case forms) in a projected settings tree.

The authentication, system, and logging settings categories are projected to the keys the findings read, in their documented types, the way `job_settings.json` is:

- **Authentication** keeps:
  - The category's session and local-auth keys (`SESSION_COOKIE_AGE`, `SESSIONS_PER_USER`, `DISABLE_LOCAL_AUTH`, `AUTH_BASIC_ENABLED`, `ALLOW_OAUTH2_FOR_EXTERNAL_USERS`, `SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL`, the `AUTHENTICATION_BACKENDS` list).
  - The LDAP, SAML, and OIDC keys whose populatedness control 25 reads:
    - `AUTH_LDAP_SERVER_URI`, `AUTH_LDAP_BIND_DN`, `AUTH_LDAP_USER_DN_TEMPLATE`, `AUTH_LDAP_REQUIRE_GROUP`, and `AUTH_LDAP_DENY_GROUP` strings, `AUTH_LDAP_USER_SEARCH` and `AUTH_LDAP_GROUP_SEARCH` string lists, `AUTH_LDAP_USER_ATTR_MAP` a map of scalars, for `AUTH_LDAP_` and the numbered `AUTH_LDAP_1_` to `AUTH_LDAP_5_` servers.
    - `SOCIAL_AUTH_SAML_SP_ENTITY_ID` and `SOCIAL_AUTH_OIDC_OIDC_ENDPOINT` strings.
    - `SOCIAL_AUTH_SAML_ENABLED_IDPS`, a map of `{ entity_id, url }` records.
- **System** keeps `ACTIVITY_STREAM_ENABLED` and `ACTIVITY_STREAM_ENABLED_FOR_INVENTORY_SYNC`.
- **Logging** keeps `LOG_AGGREGATOR_ENABLED`, `LOG_AGGREGATOR_VERIFY_CERT`, and `LOG_AGGREGATOR_INDIVIDUAL_FACTS` booleans, `LOG_AGGREGATOR_TYPE`, `LOG_AGGREGATOR_PROTOCOL`, and `LOG_AGGREGATOR_LEVEL` strings, and the `LOG_AGGREGATOR_LOGGERS` list.

Every other key of the server's dictionary is dropped rather than copied. As a result:

- These are absent from the bundle rather than redacted in it:
  - The LDAP bind password.
  - The SAML certificate and private key.
  - The OIDC client id and secret.
  - The organization and team maps.
  - The Red Hat and log aggregator credentials.
  - The license.
  - The aggregator host and port.
- The keys AWX populates by default (`AUTH_LDAP_GROUP_TYPE`, `AUTH_LDAP_CONNECTION_OPTIONS`, `SAML_AUTO_CREATE_OBJECTS`, `SOCIAL_AUTH_OIDC_VERIFY_SSL`, the SAML callback and metadata URLs) are not carried.

So neither a secret nor a default can stand in for a configured authenticator.

The projection happens when the category is read, so the findings, the summary counters, and the bundle all see the same documented keys.

Project `scm_url` values lose their userinfo and query string.

Every string a snapshot keeps, at every depth of every `core_data/` JSON file, also passes the data-side carrier scrub before it is written. That scrub covers:

- The free-form header carriers.
- `Bearer` and `Basic` scheme values.
- Cookies.
- URL userinfo, query, and fragment strings.
- Credential-named pairs.
- The configured token, password, session cookie, and CSRF token in every encoded form.

The only bare rule on the data side is the vendor prefix: an AWS access key id or STS bearer id (`AKIA`, `ASIA`, `ABIA`, `ACCA`), a Stripe key, a GitHub token, a Slack token, a JWT, or a PEM block. So ids, digests, and key ids that are data stay data.

As a result of the data-side carrier scrub:

- A bearer inside a string that a documented key keeps is scrubbed in place (`Authorization: Bearer [REDACTED]`), with its siblings kept.
- A value under a secret field name (`secret_key`, `secret`, `client_secret`, `password`, `passphrase`, `private_key`, `access_token`, `refresh_token`, `authorization`, `cookie`, `api_key`, and their spelling variants) is `[REDACTED]` whatever its shape.

An object or array nested more than 32 containers below the file's root, or below the value handed to `redactCredentialTree`, is written as `[REDACTED]`, so the depth of a server-supplied tree bounds what is copied.

### Error text

Error strings are scrubbed at one choke point. Every failed request is raised as an `AnsibleApiError` carrying the endpoint, plus the HTTP status when a response arrived (a timeout or network error has none), and its message is passed through `redactErrorText` when the error is created.

The tool-level `errorMessage` helper runs the same pass. So no path from a response body, a login or token exchange, a network error, or a timeout to a finding, summary, `errors` array, access probe, `_errors.log`, or zip entry skips the pass.

The pass replaces:

- The configured token, password, session cookie, and CSRF token.
- `Bearer` and `Basic` authorization values.
- JWT-shaped strings.
- `Set-Cookie` and `Cookie` values.
- Key-value pairs whose key names a credential (`token`, `secret`, `password`, `api_key`, `session`, `sid`, `signature`, and the like).
- AWS key-shaped strings.
- The userinfo, query string, and fragment of any URL, wherever it sits in the message.

A failed response whose body is not JSON (for example a proxy's 502 HTML page) is never quoted. Once the retries run out, the message carries `AAP request failed after 4 attempts: <path> (502 Bad Gateway): non-JSON body (text/html, <n> bytes)`. A JSON error keeps only its structured `detail`.

A `SyntaxError` reaching the error sink from any other path is recorded by name only (`SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body`), because V8's parse message quotes a snippet of the rejected text.

### Scrub boundary

One boundary governs the scrub:

- **Carriers:** A value inside any of these carriers is removed whatever its shape:
  - An `Authorization`, `Cookie`, `Set-Cookie`, `X-Auth-Key`, `X-Auth-Email`, or `x-api-key` header.
  - An authorization scheme value (`Bearer`, `Basic`, `Digest`, `Negotiate`, `NTLM`, `OAuth`, `SSWS`, `Token`, `ApiKey`, `Api-Key`, `Splunk`, `Snowflake`, `AWS4-HMAC-SHA256`).
  - A session or cookie assignment.
  - A URL's userinfo, a query pair, or a fragment.
  - A key-value pair whose key names a credential.
- **URL userinfo:** A URL whose authority is not a host with at most a numeric port, because a raw `?` or `#` sits inside its password, gives up everything to the `@` that follows as userinfo. By contrast, `https://h?e=a@x.com&token=v` keeps its host `h` and loses the query.
- **Credential keys:** A key names a credential when it is any of these:
  - A credential word (`password`, `token`, `skey`).
  - A key that sets a credential word off with `_`, `-`, or `.` (`DB_PASSWORD`, `AZURE_CLIENT_SECRET`, `x-api-key`).
  - A lowerCamelCase or lowercase compound ending in a credential word (`accessToken`).
- **Credential values:** As a result, `password=letmein`, `DB_PASSWORD=Sunshine`, and `AZURE_CLIENT_SECRET: abc12` lose their values unquoted as well as quoted, whatever the value's length or shape.
- **Key position:** The key counts wherever it stands: after a flag prefix, a path segment, a parenthesis, or a comma. So a spawned CLI's echoed command line loses the value and keeps the rest.
  - Flag prefix examples: `--password=v`, `--password v`, `-Dspring.datasource.password=v`.
  - Path segment example: `kv/password: v`. A `path: status` line whose last segment is a credential word loses the status, so the modules join such a status with `returned`.
- **Authorization headers:** Under an `Authorization` or `Proxy-Authorization` header, a scheme word stays in front of the marker.
  - A parameter list after the scheme loses the value of every parameter that is a proof, whatever its name, quoted or bare (`Authorization: Snowflake Token="..."`, `Authorization: Bearer value="..."`, Digest `response`, `nonce`, `cnonce`, and `opaque`, OAuth 1.0 `oauth_token`, `oauth_signature`, and `oauth_nonce`).
  - The parameters that describe the exchange stay (`realm`, `username`, `uri`, `qop`, `nc`, `algorithm`, and a SigV4 list's `Credential=..., SignedHeaders=...` scope, judged pair by pair as before).
- **Challenges:** A `WWW-Authenticate` challenge, which is not an `Authorization` header, keeps its `realm="api"`, `qop`, `algorithm`, `error`, and `error_description` with the rest of it. The same holds for `Bearer realm="api"` in prose.
  - However, a parameter named as a proof (`response`, `signature`, `oauth_signature`, `mac`, `sig`) loses its value in a challenge as well, quoted or bare, before or after the `realm`.
  - A parameter named as a proof in a bare realm-led list (`realm="api", nonce="n", response="..."` as a data value) loses its value too, because a list shaped like a challenge is not exempt from the proof rule.
  - A `response` or `mac` field outside such a list (`"response": 403`, `mac=aa:bb:cc:dd:ee:ff`) is data and stays.
- **Other credential keys:** Under any other credential key, the scheme word is the value (`db_password: token` loses `token`).
- **Error codes:** A PascalCase error code that merely ends in the word (`InvalidAuthenticationToken: Access token has expired`) is prose and stays.
- **Identifier keys:** An identifier-named key (`AWS_ACCESS_KEY_ID`, `AZURE_TENANT_ID`, `CLOUDFLARE_EMAIL`, `AAP_USERNAME`) keeps its value unless the value's own shape removes it. For example, an `AKIA` access key id goes, and a tenant UUID stays.
- **Bearer ids:** The identifier-key rule has one override, for the bearer ids. These keys authenticate rather than identify, so each is a credential key despite its `id` suffix:
  - A key ending in `secret_id` or `token_id`, any prefix, casing, or separator (`secret_id`, `VAULT_SECRET_ID`, `role_secret_id`, `roleSecretId`, a Vault AppRole secret id; `token_id`, `tokenId`, a token id, which is the token).
  - A key naming a session id (`session_id`, `sid`, `sessid`, `jsessionid`, `PHPSESSID`).
- **Bearer-id values:** The value under such a key goes in error text, in a data string, and as a snapshot key, whatever its shape, a UUID included. By contrast, `client_id`, `tenant_id`, `role_id`, `access_key_id`, `key_id`, and `secret_name` keep their values.
- **Quoted values:** A quoted header or pair value is removed whole between its quotes, so a short or name-shaped value never survives inside quotes as prose.
  - Examples: `Authorization: Bearer "value"`, `X-Auth-Key: "value"`, `Cookie: sid='value'`, `X-Api-Key: "value"`.
  - This holds with or without spaces, single or double quotes, plain or JSON-escaped.
- **Compound lines:** A `Cookie`, `Set-Cookie`, `X-Auth-Key`, or `X-Auth-Email` value is free form and follows the compound-line rule.
  - A value that is itself quoted ends at its closing quote. A closed value holding `; Name:` is one value, and the quotes stay around the marker.
  - An unquoted value, or a quoted one that is never closed, ends at the `;` or `,` that introduces the next `Name:` header token on the line, or at the end of the line.
  - So a following header (`Content-Type: "application/json"`, `Date: Tue, 22 Sep 2026 12:30:00 GMT`) keeps its name and value, and a following credential header gets its own carrier treatment (`Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"`).
- **JSON escapes:** The header name counts as a carrier after a JSON escape as it does at a line start.
  - Inside a serialized message, a line follows `\n`, `\t`, `\r\n`, `\u000a`, `\u0009`, or `\u000d\u000a` as backslash text rather than a real line break.
  - The value is still removed whole: `\nCookie: theme=dark; my.tracker=hunter2` becomes `\nCookie: [REDACTED]`, and `\u000aX-Auth-Key: prodkey` becomes `\u000aX-Auth-Key: [REDACTED]`.
  - The value ends at an escaped line break or at the `"}` that closes the carrying JSON string, so the next header keeps its name and value.
- **Quoted non-credential values:** A quoted value that names no credential (`Content-Type: "application/json"`) stays.
- **Configured credentials:** The configured token, password, session cookie, and CSRF token are removed whatever their shape, and in their JSON-escaped, URL-encoded, base64, and base64url forms.
- **Token-shaped runs:** A bare run of 16 or more characters is removed when it is shaped like a token: base64 symbols, digits scattered through letters, camelCase pieces of one or two letters, hex digests, AWS key ids, JWTs, or PEM blocks.
- **Name-shaped values:** A bare value shaped like a name stays, because in prose it is indistinguishable from a resource name. Name shapes are hyphen- or underscore-joined words with at most one digit group each (such as `prod-us-east-2026`), uppercase codes, UUIDs, and camelCase identifiers (such as `GetAccessKeyLastUsed`).
- **Opaque identifiers:** Opaque identifiers whose shape is a token's are therefore removed from error text and travel in structured fields (`endpoint`, `status`, `http_status`).

The tools read no configuration file. Every setting comes from tool arguments and environment variables.

A JSON body that parsed to something other than the documented object (a string, number, or array answered by `/api/v2/ping/` or `/api/v2/me/`) is dropped before any field is read from it. So no `TypeError` whose message quotes the value can reach `ansible_check_access` or the export. The access check's `ping` is absent for such a body, exactly as when the ping endpoint could not be read.

Every projected record keeps its documented keys only in their documented types.

- **Projected records:** The current user, the ping, and every list item and settings document the bundle carries.
- **Documented types:** `id` a number, `username` a string, `is_superuser` a boolean, `version` and `active_node` strings, `instances` and `instance_groups` lists of records projected the same way, `AWX_TASK_ENV` a map of scalars, `ACTIVITY_STREAM_ENABLED` and `LOG_AGGREGATOR_ENABLED` booleans, `AUTH_LDAP_SERVER_URI` a string.

As a result:

- A nested object or array under a documented key is dropped rather than copied verbatim.
- A `me` body whose projection carries neither a string `username` nor a numeric `id` is not a recognizable user.
- A settings body whose projection carries no documented key is not a recognizable settings surface:
  - Its snapshot records the fixed error `<label> (<path>): no documented settings key returned`.
  - The bundle writes the not-collected marker.
  - Control 25 is `manual` through its unreadable path.
  - Control 26 caps at `warn`, naming the unconfirmed setting.
  - No `TypeError` text is recorded.

Every fixed-text message the integration emits is held to the scrub by a test and survives it unchanged:

- The parse and non-JSON notes.
- The retry wordings: the attempt count and the over-limit `Retry-After` note.
- The not-collected and `not attempted` markers.
- The unreadable-view and downgrade wordings.
- The session-login and manual-review prose.

### Verdict safety rules

- An unreadable endpoint never yields `pass`. That holds for every inventory a finding reads, not only its primary one.
  - Secondary inventories: the inventories list for control 22, the system settings for control 26, the notification deliveries for control 27, the job templates for control 13, a user or team role list for control 24.
  - When a secondary inventory answers 403, the finding is `warn` or `manual`. Its summary names the unreadable read and what was not checked. `evidence.partial_view` carries `<inventory>: unreadable (<endpoint>: <error>)`.
  - A settings category whose body carries none of its documented keys is unreadable in the same sense. Control 25 is `manual` and control 26 caps at `warn`, each naming the read and the fixed error, never `pass` on a body the tools do not recognize.
- An unreadable inventory renders `null`, never `0`, `[]`, or `"none"`. Only a list that was read and came back empty renders `0` or `[]`.
  - The summary counters of each assessment, and every evidence count, list, or flag derived from an unread collection, are `null` when that read failed. The status entry carries the endpoint, the HTTP status, and the scrubbed error.
  - Summary counters for platform security: `users`, `tokens`, `teams`, `projects`, `organizations`, `notification_templates`, `job_templates`, `execution_environments`, and `credentials`.
  - Summary counters for job health: `total_jobs`, `successful`, `jobs_total_reported`, and `instance_groups`.
  - Summary counters for host coverage: `total_hosts` and `hosts_total_reported`.
- An empty inventory never yields `pass` by default. Each control states whether emptiness is `fail` (for example, no jobs, no notification templates, no activity records) or `manual` (for example, no hosts visible).
  - The only control where an empty set is compliant by intent is control 20: no OAuth2 tokens means no long-lived API tokens to govern.
- Items without a date (`finished`, `last_job_run`, `modified`, `created`, `next_run`, `last_updated`, `timestamp`) are never counted as fresh and cap the finding at `warn`.
- A partial inventory is recorded in `evidence.partial_view` with seen versus total counts, and downgrades `pass` to `warn`. A partial inventory means any of these:
  - A list cap reached with a next page still available.
  - A last page trimmed to the requested limit.
  - A `next` link that repeats, arrives with an empty page, or leaves the configured base.
  - A `count` above the collected items.
  - An account that is neither superuser nor system auditor.
- A `next` link is followed only when it resolves onto the configured `AAP_URL` origin.
  - AAP's root-relative `/api/v2/...?page=2` form and the same absolute origin pass (in any casing of scheme or host, requested as the URL it is rather than appended to the base as a path).
  - A link to another host, port, or scheme, a protocol-relative `//host/...` link, a userinfo-bearing link, or one that does not parse is refused before any request is made for it. So neither the token nor the session cookie leaves for it.
  - The collection is `complete: false` with a `truncation` reason. The reason names the configured origin and the origin the link resolved onto (scheme, host, and port, or the bare scheme of a `javascript:` or `data:` link), and nothing else of the link.
  - The reason reads `the API advertised a next page on https://other.example rather than the configured origin https://aap.example.com, so the walk was stopped; the link was not followed and no request was made for it`, or one of the userinfo and unparseable variants, which name the configured origin.
  - No path, query, fragment, or userinfo of the link is recorded.
  - The same rule sits in front of the transport, ahead of the session login. A refused target renders as `AAP request refused: the target is not on the configured origin, so no request was made.` with `endpoint` set to `not requested`.
  - The survey spec and error notification probes (50 templates each) report `<n> of <eligible> probed` the same way for controls 18 and 27.

## Official documentation

- [Automation execution API overview (AAP 2.5)](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.5/html/automation_execution_api_overview/index)
- [AWX API Reference](https://docs.ansible.com/projects/awx/en/latest/rest_api/index.html)
- [Using automation execution (AAP 2.5)](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.5/html/using_automation_execution/index)
- [Red Hat Ansible Automation Platform documentation](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/)
- [AWX API serializers](https://github.com/ansible/awx/blob/devel/awx/api/serializers.py) (the upstream source of every field name used by these tools)
