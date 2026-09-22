---
title: Ansible Automation Platform
description: Read-only Ansible Automation Platform controller inspection covering all 30 ansible-sec-inspector controls with verdict-safe findings and an auditor bundle.
---

The Ansible tool family inspects a Red Hat Ansible Automation Platform (AAP) controller, or upstream AWX, through its read-only REST API. It implements every control in `specs/ansible-sec-inspector.spec.md`: job execution health, host coverage, job template and schedule hygiene, credential hygiene, access control, and platform audit settings. Findings carry the spec control number, a stable finding id, a status, the evidence behind the verdict, and mappings to FedRAMP, CMMC, SOC 2, CIS Controls, PCI-DSS, and DISA STIG.

## What it inspects

- Jobs (`/api/v2/jobs/`) filtered to `type=job` inside the lookback window, plus `/api/v2/settings/jobs/` and `/api/v2/instance_groups/`
- Hosts, inventory sources, and per-host job results (`/api/v2/job_host_summaries/`)
- Job templates, schedules, workflow job templates, and survey specs
- Credentials with their `kind`, masked `inputs`, and owners (`summary_fields.owners` or `owner_users/` and `owner_teams/`)
- OAuth2 tokens, organizations and their `admins/`, users with `is_superuser` and `is_system_auditor`, teams, and role assignments
- Projects, execution environments, notification templates and deliveries, the activity stream, and the authentication, system, and logging settings categories

Nothing is written to the controller. The bundle never records the token or password used to authenticate, and it does not rely on the API's own `$encrypted$` masking: every `core_data/` snapshot is projected to the fields the verdicts read before it is written, and credential-bearing values are replaced by `[REDACTED]` at that step (see the bundle layout below).

## Setup and authentication

| Variable | Purpose |
|---|---|
| `AAP_URL` | Controller base URL, for example `https://controller.example.com`. A trailing `/api` or `/api/v2` is stripped. |
| `AAP_TOKEN` | OAuth2 bearer token for a local or gateway account. Preferred for automation. |
| `AAP_USERNAME` and `AAP_PASSWORD` | Session login for LDAP, SAML, or local accounts. The password is only ever read from the environment; passing it as a tool argument is rejected. |
| `AAP_VERIFY_SSL` | Set to `false` only for approved non-production troubleshooting against a self-signed controller. The opt-out is scoped to the tool's own requests through a dedicated `node:https` agent; `NODE_TLS_REJECT_UNAUTHORIZED` is never touched. Defaults to `true`. |
| `AAP_TIMEOUT` | Request timeout in seconds. Defaults to 30. |

Each tool also accepts `url`, `username`, `token`, `timeout_seconds`, and `verify_ssl` arguments that override the environment for that call.

Required roles: grant the audit account the **System Auditor** role. A plain user or organization member only sees objects in its own organizations, so every would-be `pass` is downgraded to `warn` with a partial-inventory note. `/api/v2/settings/*` and `/api/v2/activity_stream/` are only readable by superusers and system auditors. Tokens on AAP 2.5 are issued by the platform gateway; a controller token still works against `/api/v2/`.

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

- `core_data/` projected API snapshots, one JSON file per endpoint. A readable list is written as `{ data: { items, complete, total, truncation } }`, and a readable-but-empty page keeps `items: []`. A dataset that could not be read (a list, a per-item probe such as `user_roles.json` or `team_roles.json`, or an object dataset under `settings/`) is written as a not-collected marker, `{ collected: false, status, endpoint, error }`, with no `items`, `total`, or `complete` beside the error; per-item files whose parent list failed carry the same marker with the parent's status and endpoint
- `analysis/` `findings.json`, `metadata.json`, and one JSON plus Markdown file per assessment
- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, and `compliance/<framework>/` reports for FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, and DISA STIG
- `QUICK_REFERENCE.md` and `README.md`
- `_errors.log`, written only when some reads failed but the bundle still completed

Credentials never reach the bundle. Each snapshot keeps only the fields the controls read (ids, names, statuses, timestamps, flags, and `summary_fields` references), and the redaction step replaces with `[REDACTED]` the bodies of `extra_vars`, `extra_data`, inventory, group, and host `variables`, and `source_vars` (the variable names are kept so control 18 evidence stays reviewable), every credential `inputs` value, OAuth2 `token` and `refresh_token` values, survey question defaults, `notification_configuration` values (webhook URLs are reduced to scheme and host; header values and any `{name, value}` pair are redacted), the `AWX_TASK_ENV` and `GALAXY_TASK_ENV` dictionaries, activity stream `changes`, and any value under a credential-shaped key (`password`, `secret`, `token`, `key`, `passphrase`, `authorization`, and their camelCase and snake_case forms) in the authentication, system, and logging settings trees. Project `scm_url` values lose their userinfo and query string.

Error strings are scrubbed at one choke point. Every failed request is raised as an `AnsibleApiError` carrying the HTTP status and the endpoint, and its message is passed through `redactErrorText` when the error is created; the tool-level `errorMessage` helper runs the same pass, so no path from a response body, a login or token exchange, a network error, or a timeout to a finding, summary, `errors` array, access probe, `_errors.log`, or zip entry skips it. The pass replaces the configured token, password, session cookie, and CSRF token, `Bearer` and `Basic` authorization values, JWT-shaped strings, `Set-Cookie` and `Cookie` values, key-value pairs whose key names a credential (`token`, `secret`, `password`, `api_key`, `session`, `sid`, `signature`, and the like), AWS key-shaped strings, and the userinfo and query string of any URL wherever it sits in the message. A failed response whose body is not JSON (for example a proxy's 502 HTML page) is never quoted: the message carries `AAP request failed: <path> (502 Bad Gateway): non-JSON body (text/html, <n> bytes)`; a JSON error keeps only its structured `detail`. A `SyntaxError` reaching the sink from any other path is recorded by name only (`SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body`), because V8's parse message quotes a snippet of the rejected text. The scrub follows one boundary. A value inside any carrier (an `Authorization`, `Cookie`, `Set-Cookie`, `X-Auth-Key`, `X-Auth-Email`, or `x-api-key` header, a `Bearer`, `Basic`, `Token`, or `ApiKey` scheme, a session or cookie assignment, a URL's userinfo or a query pair, a key-value pair whose key names a credential) is removed whatever its shape. A quoted header or pair value (`Authorization: Bearer "value"`, `X-Auth-Key: "value"`, `Cookie: sid='value'`, `X-Api-Key: "value"`, with or without spaces, single or double quotes, plain or JSON-escaped) is removed whole between its quotes, so a short or name-shaped value never survives inside quotes as prose; the `Cookie`, `Set-Cookie`, `X-Auth-Key`, and `X-Auth-Email` values are consumed through the end of the line, quotes included. A quoted value that names no credential (`Content-Type: "application/json"`) stays. The configured token, password, session cookie, and CSRF token are removed whatever their shape and in their JSON-escaped, URL-encoded, base64, and base64url forms. A bare run of 16 or more characters shaped like a token (base64 symbols, digits scattered through letters, camelCase pieces of one or two letters, hex digests, AWS key ids, JWTs, PEM blocks) is removed. A bare value shaped like a name (hyphen- or underscore-joined words with at most one digit group each, such as `prod-us-east-2026`, uppercase codes, UUIDs, camelCase identifiers such as `GetAccessKeyLastUsed`) stays, because in prose it is indistinguishable from a resource name; opaque identifiers whose shape is a token's are therefore removed from error text and travel in structured fields (`endpoint`, `status`, `http_status`). The tools read no configuration file: every setting comes from tool arguments and environment variables. A JSON body that parsed to something other than the documented object (a string, number, or array answered by `/api/v2/ping/` or `/api/v2/me/`) is dropped before any field is read from it, so no `TypeError` whose message quotes the value can reach `ansible_check_access` or the export; the access check's `ping` is absent for such a body, exactly as when the ping endpoint could not be read. Every projected record (the current user, the ping, and every list item and settings document the bundle carries) keeps its documented keys only in their documented types (`id` a number, `username` a string, `is_superuser` a boolean, `version` and `active_node` strings, `instances` and `instance_groups` lists of records projected the same way, `AWX_TASK_ENV` a map of scalars), so a nested object or array under a documented key is dropped rather than copied verbatim, and a `me` body whose projection carries neither a string `username` nor a numeric `id` is not a recognizable user. Every fixed-text message the integration emits (the parse and non-JSON notes, the not-collected and `not attempted` markers, the unreadable-view and downgrade wordings, the session-login and manual-review prose) is held to the scrub by a test and survives it unchanged.

## Status semantics

Every finding is `pass`, `warn`, `fail`, or `manual`.

- `manual` means the API cannot prove the control on this deployment or with this account. The summary names the cause (a 403, a missing endpoint, an empty inventory that needs confirmation, a setting the version does not expose) and the evidence to collect from the controller UI.
- An unreadable endpoint never yields `pass`. That holds for every inventory a finding reads, not only its primary one: when a secondary inventory answers 403 (the inventories list for control 22, the system settings for control 26, the notification deliveries for control 27, the job templates for control 13, a user or team role list for control 24), the finding is `warn` or `manual`, its summary names the unreadable read and what was not checked, and `evidence.partial_view` carries `<inventory>: unreadable (<endpoint>: <error>)`.
- An unreadable inventory renders `null`, never `0`, `[]`, or `"none"`. The summary counters of each assessment (`users`, `tokens`, `teams`, `projects`, `organizations`, `notification_templates`, `job_templates`, `execution_environments`, and `credentials` for platform security; `total_jobs`, `successful`, `jobs_total_reported`, and `instance_groups` for job health; `total_hosts` and `hosts_total_reported` for host coverage) and every evidence count, list, or flag derived from an unread collection are `null` when that read failed, and the status entry carries the endpoint, the HTTP status, and the scrubbed error. Only a list that was read and came back empty renders `0` or `[]`.
- An empty inventory never yields `pass` by default. Each control states whether emptiness is `fail` (for example no jobs, no notification templates, no activity records) or `manual` (for example no hosts visible). The only control where an empty set is compliant by intent is control 20: no OAuth2 tokens means no long-lived API tokens to govern.
- Items without a date (`finished`, `last_job_run`, `modified`, `created`, `next_run`, `last_updated`, `timestamp`) are never counted as fresh and cap the finding at `warn`.
- A partial inventory (a list cap reached with a next page still available, a last page trimmed to the requested limit, a `next` link that repeats or arrives with an empty page, a `count` above the collected items, or an account that is neither superuser nor system auditor) is recorded in `evidence.partial_view` with seen versus total counts and downgrades `pass` to `warn`. The survey spec and error notification probes (50 templates each) report `<n> of <eligible> probed` the same way for controls 18 and 27.

## Control coverage

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
| 25 External authentication enforcement | platform security | `AAP-RBAC-02` | fail when LDAP, SAML, or OIDC keys exist but none is populated; manual when the settings category exposes none (AAP 2.5 gateway) |
| 26 Activity stream retention | platform security | `AAP-AUDIT-01` | fail when `ACTIVITY_STREAM_ENABLED` is false, no records are visible, or the newest record is older than 24 hours |
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

- Only the `/api/v2/` controller API is used. AAP 2.5 gateway authenticators, gateway tokens, and Event-Driven Ansible are out of scope, so control 25 is `manual` when the controller settings category exposes no LDAP, SAML, or OIDC keys.
- Control 18 scans job template `extra_vars`, survey defaults, inventory variables, and group variables. Host variables and launch-time `extra_vars` are not scanned.
- Control 20 cannot flag tokens of disabled users because the user API exposes no active flag.
- Control 23 probes roles for the first 50 users; the rest are reported as unprobed in `evidence`.
- Controls 12, 15, and 27 identify critical templates and workflows by keyword (patch, harden, CIS, STIG, baseline, logging, audit, access, password, compliance, security, firewall). Review the manual findings when your naming differs.
- Controllers without execution environments, without `SCHEDULE_MAX_JOBS`, or without an activity stream render the related controls as `manual`, never `pass`.

## Official documentation

- [Automation Controller API Guide](https://docs.ansible.com/automation-controller/latest/html/controllerapi/index.html)
- [Automation Controller API Reference](https://docs.ansible.com/automation-controller/latest/html/controllerapi/api_ref.html)
- [Automation Controller User Guide](https://docs.ansible.com/automation-controller/latest/html/userguide/index.html)
- [Red Hat Ansible Automation Platform documentation](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/)
- [AWX API serializers](https://github.com/ansible/awx/blob/devel/awx/api/serializers.py) (the upstream source of every field name used by these tools)
