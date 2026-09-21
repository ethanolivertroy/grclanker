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

Nothing is written to the controller. Secrets are masked by the API (`$encrypted$`) and the bundle never records the token or password used to authenticate.

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
| `ansible_check_access` | none | Confirms authentication, reports whether the account has full visibility, and probes 18 audit surfaces for readability. Run this first. |
| `ansible_assess_job_health` | 1, 2, 3, 4, 5, 28 | Job success rate, chronic template failures, stuck jobs versus each template's average successful runtime, manual launch rate, failed job remediation within 7 days, and concurrency limits. |
| `ansible_assess_host_coverage` | 6 to 15 | Unmanaged and stale hosts, inventory source sync, per-host failure rate, disabled hosts, stale and unscheduled templates, missed and disabled schedules, and workflow coverage. |
| `ansible_assess_platform_security` | 16 to 27, 29, 30 | Credential age, sharing, plaintext secrets, ownership, OAuth2 tokens, org admins, team roles, execute versus admin separation, auditor coverage, external auth, activity stream, notifications, project SCM health, and execution environments. |
| `ansible_export_audit_bundle` | all 30 | Runs the three assessments and writes an evidence bundle plus a zip archive. |

### Bundle layout

`ansible_export_audit_bundle` writes to `./export/ansible-aap/<host>-ansible-aap-audit/` by default (override with `output_dir`). A rerun allocates `-2`, `-3`, and so on instead of overwriting, and the zip is named after the allocated directory.

- `core_data/` raw API snapshots, one JSON file per endpoint, each recording whether the read was complete
- `analysis/` `findings.json`, `metadata.json`, and one JSON plus Markdown file per assessment
- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, and `compliance/<framework>/` reports for FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, and DISA STIG
- `QUICK_REFERENCE.md` and `README.md`
- `_errors.log`, written only when some reads failed but the bundle still completed

## Status semantics

Every finding is `pass`, `warn`, `fail`, or `manual`.

- `manual` means the API cannot prove the control on this deployment or with this account. The summary names the cause (a 403, a missing endpoint, an empty inventory that needs confirmation, a setting the version does not expose) and the evidence to collect from the controller UI.
- An unreadable endpoint never yields `pass`.
- An empty inventory never yields `pass` by default. Each control states whether emptiness is `fail` (for example no jobs, no notification templates, no activity records) or `manual` (for example no hosts visible). The only control where an empty set is compliant by intent is control 20: no OAuth2 tokens means no long-lived API tokens to govern.
- Items without a date (`finished`, `last_job_run`, `modified`, `created`, `next_run`, `last_updated`, `timestamp`) are never counted as fresh and cap the finding at `warn`.
- A partial inventory (a list cap reached with a next page still available, or an account that is neither superuser nor system auditor) is recorded in `evidence.partial_view` and downgrades `pass` to `warn`.

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
| 18 Unvaulted secrets | platform security | `AAP-CRED-04` | fail on plaintext values under secret-like names in template `extra_vars`, survey defaults, inventory or group variables; manual when surveys or variable sources are unreadable; reports Vault credentials and `ask_variables_on_launch` templates |
| 19 Credential ownership gaps | platform security | `AAP-CRED-05` | warn when a credential has no user or team owner; manual when owners cannot be read |
| 20 OAuth2 token hygiene | platform security | `AAP-CRED-02` | warn when a token has no `expires` or is older than `stale_token_days` (90); pass on zero tokens by intent |
| 21 Organization admin count | platform security | `AAP-RBAC-01` | fail when an organization has more than `max_org_admins` (3) admins |
| 22 Team role audit | platform security | `AAP-RBAC-03` | fail when a team holds Admin on an organization or on every inventory |
| 23 Execute versus admin separation | platform security | `AAP-RBAC-04` | fail when a probed user holds an Execute role together with an Admin-family role or `is_superuser` |
| 24 Audit role coverage | platform security | `AAP-RBAC-05` | pass when a system auditor exists or every organization has an Auditor role holder among probed users and teams; otherwise warn |
| 25 External authentication enforcement | platform security | `AAP-RBAC-02` | fail when LDAP, SAML, or OIDC keys exist but none is populated; manual when the settings category exposes none (AAP 2.5 gateway) |
| 26 Activity stream retention | platform security | `AAP-AUDIT-01` | fail when `ACTIVITY_STREAM_ENABLED` is false, no records are visible, or the newest record is older than 24 hours |
| 27 Notification coverage | platform security | `AAP-AUDIT-02` | fail with zero notification templates; warn when no critical template has an error notification or recent deliveries failed |
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
