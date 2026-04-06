---
slug: ansible-sec-inspector
name: Ansible AAP Security Inspector
vendor: Red Hat
category: devops-developer-platforms
language: go
status: spec-only
version: "1.0"
last_updated: "2026-04-03"
source_repo: "TBD"
---

# ansible-sec-inspector — Architecture Specification

## 1. Overview

**Red Hat Ansible Automation Platform (AAP)** is an enterprise automation platform
used to enforce configuration baselines, deploy patches, manage access controls,
and run compliance playbooks across thousands of endpoints. Organizations rely on
AAP to maintain consistent security posture at scale — making it both a critical
security tool and a high-value audit target.

Misconfigurations in AAP — weak credential handling, unmanaged hosts, chronic
playbook failures, stale job templates, overprivileged teams, missing audit
logging, or jobs running outside approved schedules — can undermine the
configuration management program entirely. A correctly configured AAP instance
is evidence that controls are being enforced. A poorly configured one is a gap
that no SSP narrative can paper over.

**ansible-sec-inspector** is an automated compliance inspection tool that
connects to an Ansible Automation Platform instance via its REST API, collects
security-relevant operational and configuration data, evaluates it against
hardened baselines derived from multiple compliance frameworks, and produces
actionable reports with framework-specific control mappings.

The tool answers one question per check: **"Is Ansible actually doing what
the security program says it should be doing?"** It does not replace SSP
evidence collection — it audits the effectiveness of the automation program
that produces that evidence.

**Key inspection areas:**

- Job execution health: success rates, failure patterns, chronic failures
- Host coverage: unmanaged hosts, stale inventory, hosts with no recent job runs
- Credential hygiene: stale credentials, shared credentials, unvaulted secrets
- Schedule compliance: missed scheduled runs, stale templates, manual bypasses
- Access control: team permissions, organization RBAC, least privilege enforcement
- Audit logging: job activity logging, event retention, notification coverage
- Platform security: API token hygiene, LDAP/SSO enforcement, session management

## 2. APIs & SDKs

### 2.1 Ansible Automation Platform REST API

**Base URL:** `https://<aap-instance>/api/v2`

AAP uses a versioned REST API served by the AWX backend. All endpoints are
under `/api/v2/`. Authentication is via session cookie (username/password POST
to `/api/login/`) or Bearer token (for OAuth2 token-capable accounts). LDAP-
federated accounts must use session-based auth as AAP blocks OAuth token
creation for externally-managed accounts.

#### Authentication & User Management

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/login/` | POST | Establish session (LDAP-compatible, returns CSRFTOKEN + sessionid) |
| `/api/v2/me/` | GET | Get current authenticated user (paginated list: `{"count":1,"results":[...]}`) |
| `/api/v2/users/` | GET | List all users |
| `/api/v2/users/{id}/` | GET | Individual user details |
| `/api/v2/users/{id}/tokens/` | GET | OAuth2 tokens belonging to a user |
| `/api/v2/tokens/` | GET | List all OAuth2 tokens (admin only) |
| `/api/v2/tokens/{id}/` | GET | Individual token details (expiration, scope, user) |

#### Organizations & Teams

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v2/organizations/` | GET | List all organizations |
| `/api/v2/organizations/{id}/` | GET | Organization details |
| `/api/v2/organizations/{id}/teams/` | GET | Teams within an organization |
| `/api/v2/organizations/{id}/admins/` | GET | Organization admin users |
| `/api/v2/teams/` | GET | List all teams |
| `/api/v2/teams/{id}/` | GET | Team details |
| `/api/v2/teams/{id}/users/` | GET | Users in a team |
| `/api/v2/teams/{id}/roles/` | GET | Roles granted to a team |

#### Credentials

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v2/credentials/` | GET | List all credentials |
| `/api/v2/credentials/{id}/` | GET | Credential details (type, created, modified, team assignments) |
| `/api/v2/credential_types/` | GET | Credential type definitions |
| `/api/v2/credentials/{id}/owner_teams/` | GET | Teams that own this credential |
| `/api/v2/credentials/{id}/owner_users/` | GET | Users that own this credential |

#### Inventories & Hosts

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v2/inventories/` | GET | List all inventories |
| `/api/v2/inventories/{id}/` | GET | Inventory details (total_hosts, hosts_with_active_failures) |
| `/api/v2/hosts/` | GET | List all hosts across all inventories |
| `/api/v2/hosts/{id}/` | GET | Host details (last_job, last_job_host_summary, enabled) |
| `/api/v2/hosts/{id}/job_host_summaries/` | GET | Job execution history for a specific host |
| `/api/v2/groups/` | GET | Inventory groups |
| `/api/v2/inventory_sources/` | GET | Dynamic inventory source configurations |
| `/api/v2/inventory_sources/{id}/` | GET | Individual inventory source (sync status, last_updated) |

#### Job Templates & Schedules

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v2/job_templates/` | GET | List all job templates |
| `/api/v2/job_templates/{id}/` | GET | Template details (playbook, credential, inventory, last_job_run) |
| `/api/v2/job_templates/{id}/schedules/` | GET | Schedules attached to a template |
| `/api/v2/schedules/` | GET | All schedules across all templates |
| `/api/v2/schedules/{id}/` | GET | Schedule details (rrule, next_run, enabled, dtstart) |
| `/api/v2/workflow_job_templates/` | GET | Workflow job template list |
| `/api/v2/workflow_job_templates/{id}/` | GET | Workflow template details |

#### Jobs & Execution History

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v2/jobs/` | GET | List all jobs (filterable by status, started, template) |
| `/api/v2/jobs/{id}/` | GET | Individual job details (status, started, finished, elapsed, launch_type) |
| `/api/v2/jobs/{id}/job_host_summaries/` | GET | Per-host results for a job run |
| `/api/v2/jobs/{id}/events/` | GET | Detailed job events (stdout, task results) |
| `/api/v2/unified_jobs/` | GET | All job types (jobs, workflow jobs, inventory syncs, project updates) |
| `/api/v2/job_host_summaries/` | GET | Host-level summaries across all jobs |

#### Projects & Execution Environments

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v2/projects/` | GET | List all projects (SCM source, last_updated, status) |
| `/api/v2/projects/{id}/` | GET | Project details (scm_type, scm_url, scm_branch, last_update_failed) |
| `/api/v2/execution_environments/` | GET | Execution environment inventory |
| `/api/v2/execution_environments/{id}/` | GET | EE details (image, pull policy) |

#### Notifications & Audit

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v2/notification_templates/` | GET | Notification configuration inventory |
| `/api/v2/notifications/` | GET | Notification history |
| `/api/v2/activity_stream/` | GET | Audit trail of all platform changes |
| `/api/v2/settings/` | GET | Platform-wide configuration settings |
| `/api/v2/settings/authentication/` | GET | Authentication settings (LDAP, SAML, session timeouts) |
| `/api/v2/settings/logging/` | GET | Logging configuration |
| `/api/v2/settings/jobs/` | GET | Job execution settings (concurrent job limit, isolation) |
| `/api/v2/ping/` | GET | Health check (no auth required) |

### 2.2 Pagination

AAP REST API uses offset-based pagination:

```json
{
  "count": 1482,
  "next": "/api/v2/jobs/?page=2&page_size=100",
  "previous": null,
  "results": [...]
}
```

Follow `next` until null. Use `page_size=100` for efficiency.
Max practical page size is 200.

### 2.3 Filtering

AAP supports query parameter filtering on most list endpoints:

```bash
/api/v2/jobs/?status=failed&started__gt=2026-01-01T00:00:00Z
/api/v2/jobs/?launch_type=manual&order_by=-started
/api/v2/hosts/?last_job__isnull=true
/api/v2/job_templates/?last_job_run__lt=2025-12-01T00:00:00Z
```

Key filter operators: `__gt`, `__lt`, `__gte`, `__lte`, `__isnull`,
`__contains`, `__startswith`. Chain with `&`.

### 2.4 SDKs and CLIs

| Tool | Language | Source | Notes |
|---|---|---|---|
| `awxkit` | Python | `pip install awxkit` | Official AWX Python SDK; wraps all REST endpoints |
| `ansible-navigator` | Python | Red Hat official | CLI for EE-based playbook execution; not an API client |
| `tower-cli` (legacy) | Python | `pip install ansible-tower-cli` | Deprecated in favor of awxkit; still useful as API reference |
| `awx` Go client | Go | Community | Thin Go wrapper; useful as reference for Go implementation |
| Terraform AWX provider | Go/HCL | `mrcrgl/terraform-provider-awx` | IaC reference for AAP resource models |

## 3. Authentication

### 3.1 LDAP / External Auth — Session-based (Primary)

LDAP-federated accounts cannot create OAuth2 tokens in AAP — the platform
blocks token creation for externally-managed users. Session-based auth is
the only option for these accounts.

**Flow:**

1. GET `/api/login/` to obtain CSRF token from cookies
2. POST `/api/login/` with `username`, `password`, and `X-CSRFToken` header
3. Response sets `sessionid` cookie
4. Include `sessionid` cookie and `X-CSRFToken` header on all subsequent requests
5. Session expires per AAP's configured `SESSION_COOKIE_AGE` setting

**Note:** AAP returns `{"count":1,"results":[{...}]}` from `/api/v2/me/`
not a single user object — check `count > 0` and read from `results[0]`.

**Auth failure pattern:** AAP returns HTTP 401 with
`{"detail":"Authentication credentials were not provided. To establish a
login session, visit /api/login/."}` when session is not established.

```bash
export AAP_URL=https://aap.example.com
export AAP_USERNAME=your.username
export AAP_PASSWORD=your.password
```

### 3.2 Local Accounts — OAuth2 Bearer Token

For local (non-LDAP) AAP accounts, OAuth2 tokens can be created:

```bash
POST /api/v2/tokens/
{"description": "inspector-token", "application": null, "scope": "read"}
Authorization: Basic base64(username:password)
```

Response returns `{"token": "..."}`. Pass as `Authorization: Bearer <token>`
on subsequent requests.

```bash
export AAP_URL=https://aap.example.com
export AAP_TOKEN=your-oauth2-token
```

### 3.3 Environment Variables

| Variable | Required | Description |
|---|---|---|
| `AAP_URL` | Yes | Base URL (e.g., `https://aap.mdthink.maryland.gov`) |
| `AAP_USERNAME` | Alt* | Username for session auth (LDAP accounts) |
| `AAP_PASSWORD` | Alt* | Password for session auth (LDAP accounts) |
| `AAP_TOKEN` | Alt* | OAuth2 Bearer token (local accounts only) |
| `AAP_VERIFY_SSL` | Optional | Set `false` to skip TLS verification **only for approved non-production troubleshooting**. Production use requires an explicit risk acknowledgment. Do not normalize TLS bypass in automation. |
| `AAP_TIMEOUT` | Optional | Request timeout in seconds (default: 30) |

*Either `AAP_TOKEN` or both `AAP_USERNAME`/`AAP_PASSWORD` required.

### 3.4 Auth Implementation Note

When building the HTTP client, use the standard library's `SetBasicAuth()` method
for Basic authentication:

```go
req.SetBasicAuth(username, password)
```

This method is RFC 7617 compliant and handles special characters and `@` symbols
in usernames and passwords correctly. Only fall back to manual base64 construction
if a specific, tested AAP interoperability issue is documented with SetBasicAuth().

## 4. Security Controls

### Job Execution Health

| # | Control | Severity | What Is Checked |
|---|---|---|---|
| 1 | **Job Success Rate** | High | Calculate success rate across all jobs in the audit period (default: 90 days), filtering for `type=job` to exclude inventory syncs and project updates. Flag if below 90%. Break down by playbook category. Identify which playbooks are driving failures. |
| 2 | **Chronic Playbook Failures** | High | Identify playbooks with >3 consecutive failures or >20% failure rate over the audit period. These indicate broken automation that is not being remediated. |
| 3 | **Stuck or Long-Running Jobs** | Medium | Flag jobs in `running` or `pending` state for more than 2x their historical average runtime. Stuck jobs may indicate agent connectivity issues or resource exhaustion. |
| 4 | **Manual Job Launch Rate** | Medium | Calculate what percentage of jobs were launched manually (`launch_type=manual`) vs. scheduled. High manual rates indicate the automation program is not functioning as intended. |
| 5 | **Failed Job Remediation Rate** | High | For failed jobs, check whether a subsequent successful run against the same template occurred within 7 days. Flag chronic failures with no follow-up remediation. |

### Host Coverage

| # | Control | Severity | What Is Checked |
|---|---|---|---|
| 6 | **Unmanaged Hosts** | Critical | Identify hosts in inventory that have never had a job run (`last_job__isnull=true`). These hosts are in the system but receiving no automation. |
| 7 | **Stale Host Coverage** | High | Identify hosts whose most recent job run is older than the audit threshold (default: 30 days). Flag by severity: >30 days = High, >60 days = Critical. |
| 8 | **Inventory Source Sync Health** | Medium | Check dynamic inventory sources for sync failures or stale last-sync timestamps. Stale inventory means the host list is inaccurate. |
| 9 | **Host Failure Rate** | Medium | For each host, calculate the ratio of failed to total job runs. Flag hosts with >30% job failure rate — these may have connectivity, credential, or configuration issues. |
| 10 | **Disabled Hosts** | Low | Inventory hosts marked as disabled (`enabled=false`). Flag if count exceeds 5% of total inventory — may indicate bulk disabling to hide coverage gaps. |

### Job Template & Schedule Hygiene

| # | Control | Severity | What Is Checked |
|---|---|---|---|
| 11 | **Stale Job Templates** | Medium | Identify job templates with `last_job_run` older than 90 days or null. Templates that haven't run recently are candidates for cleanup or indicate a broken automation path. |
| 12 | **Unscheduled Critical Templates** | High | Identify job templates covering patching, hardening, logging, and access control playbooks that have no associated schedule. Critical playbooks must run on a defined cadence. |
| 13 | **Missed Scheduled Runs** | High | For scheduled jobs, validate both `next_run` against current time AND the delta between current time and `last_run` timestamp against the expected schedule interval. Flag schedules where the last successful run is more than 1.5x the scheduled interval in the past (scheduler may be stalled). |
| 14 | **Disabled Schedules** | Medium | Flag job templates with schedules that exist but are disabled (`enabled=false`). These represent automation intent that has been turned off without a clear reason. |
| 15 | **Workflow Coverage** | Low | Verify that critical multi-step automation paths (patch → validate → notify) are implemented as workflows, not just individual job templates. Single templates for multi-step processes are fragile. |

### Credential Hygiene

| # | Control | Severity | What Is Checked |
|---|---|---|---|
| 16 | **Stale Credentials** | High | Identify credentials not modified in more than 90 days (machine credentials, vault passwords). Stale credentials may indicate passwords have not been rotated per policy. |
| 17 | **Shared Credential Usage** | High | Identify credentials used by more than 5 different job templates. Broadly shared credentials violate least privilege — if one template is compromised, all share the exposure. |
| 18 | **Unvaulted Secrets in Templates** | Critical | Check job template extra_vars, survey specs, inventory variables, and group_vars/host_vars for patterns matching secrets (passwords, tokens, keys) stored in plaintext. Secrets should be in credential objects or Vault, not in variables or configuration files accessible via API. |
| 19 | **Credential Ownership Gaps** | Medium | Identify credentials with no team owner and no user owner. Orphaned credentials cannot be audited or rotated through normal workflow. |
| 20 | **OAuth2 Token Hygiene** | Medium | List all OAuth2 tokens; flag tokens with no expiration set, tokens older than 90 days, and tokens associated with disabled users. |

### Access Control & RBAC

| # | Control | Severity | What Is Checked |
|---|---|---|---|
| 21 | **Organization Admin Count** | High | Flag organizations with more than 3 admin-role users. Excessive admins indicate poor least-privilege enforcement. |
| 22 | **Team Role Audit** | High | Enumerate roles granted to each team. Flag teams with `admin` role on all organizations or all inventories. Verify team assignments follow separation of duties. |
| 23 | **Execute-Only vs. Admin Separation** | High | Verify that users who execute jobs do not also have admin rights to modify job templates or credentials. Separation between operators and administrators is a core control. |
| 24 | **Audit Role Coverage** | Medium | Verify that at least one team or user has the `auditor` role at the organization level. Without an auditor role, AAP activity cannot be reviewed by a non-admin. |
| 25 | **External Auth Enforcement** | Critical | Verify that LDAP or SAML is configured as the authentication backend. Local-only accounts should be restricted to break-glass scenarios. Check `/api/v2/settings/authentication/` for `AUTH_LDAP_SERVER_URI` or SAML config presence. |

### Platform Security & Audit

| # | Control | Severity | What Is Checked |
|---|---|---|---|
| 26 | **Activity Stream Retention** | High | Verify that the activity stream is enabled and retaining records. Check `/api/v2/activity_stream/` for recent entries. Flag if no activity in 24 hours (may indicate logging is broken). |
| 27 | **Notification Coverage** | Medium | Verify that failure notifications are configured for at least critical job templates. Jobs that fail silently are not being monitored. Check `/api/v2/notification_templates/` and template associations. |
| 28 | **Concurrent Job Limit** | Low | Check `/api/v2/settings/jobs/` and instance group capacity configurations for concurrency limits (e.g., `AD_HOC_COMMANDS_COUNT`, `SCHEDULE_MAX_JOBS`, instance group capacity). Unrestricted concurrent jobs can cause resource exhaustion and execution failures. |
| 29 | **Project SCM Health** | Medium | Verify all projects have a valid SCM configuration and recent successful sync. Projects using `manual` SCM type store playbooks locally — no version control, no audit trail. |
| 30 | **Execution Environment Inventory** | Low | Verify all job templates reference a specific execution environment rather than using defaults. Default EEs may include unnecessary packages or outdated images. |

## 5. Compliance Framework Mappings

| # | Control | FedRAMP (800-53 r5) | CMMC 2.0 | SOC 2 | CIS Controls v8 | PCI-DSS 4.0 | DISA STIG |
|---|---|---|---|---|---|---|---|
| 1 | Job Success Rate | CA-7, SI-2 | CM.L2-3.4.1 | CC7.1, CC7.2 | 16.12 | 6.3.3 | SRG-APP-000456 |
| 2 | Chronic Playbook Failures | SI-2, CA-5 | CM.L2-3.4.1 | CC7.1, CC7.4 | 7.4 | 6.3.3 | SRG-APP-000456 |
| 3 | Stuck / Long-Running Jobs | CA-7, SI-4 | CM.L2-3.4.1 | CC7.1 | 16.12 | 6.3.3 | SRG-APP-000456 |
| 4 | Manual Job Launch Rate | CM-3, CM-5 | CM.L2-3.4.3 | CC8.1 | 4.1 | 6.5.6 | SRG-APP-000380 |
| 5 | Failed Job Remediation Rate | CA-5, SI-2 | CM.L2-3.4.1 | CC7.4 | 7.2 | 6.3.3 | SRG-APP-000456 |
| 6 | Unmanaged Hosts | CM-8, CM-8(1) | CM.L2-3.4.1 | CC6.1 | 1.1 | 11.4 | SRG-APP-000516 |
| 7 | Stale Host Coverage | CM-8, SI-2 | CM.L2-3.4.1 | CC6.1, CC7.1 | 1.1, 7.4 | 11.4 | SRG-APP-000516 |
| 8 | Inventory Source Sync Health | CM-8(2) | CM.L2-3.4.2 | CC6.1 | 1.1 | 11.4 | SRG-APP-000516 |
| 9 | Host Failure Rate | CA-7, SI-4 | CM.L2-3.4.1 | CC7.1 | 7.4 | 11.4 | SRG-APP-000456 |
| 10 | Disabled Hosts | CM-8 | CM.L2-3.4.1 | CC6.1 | 1.1 | 11.4 | SRG-APP-000516 |
| 11 | Stale Job Templates | CM-2, CM-7 | CM.L2-3.4.1 | CC8.1 | 4.1 | 6.5 | SRG-APP-000380 |
| 12 | Unscheduled Critical Templates | CM-3, SI-2 | CM.L2-3.4.3 | CC8.1 | 4.1 | 6.5.6 | SRG-APP-000380 |
| 13 | Missed Scheduled Runs | CA-7, CM-3 | CM.L2-3.4.3 | CC7.1, CC7.2 | 4.1 | 6.5.6 | SRG-APP-000380 |
| 14 | Disabled Schedules | CM-3 | CM.L2-3.4.3 | CC8.1 | 4.1 | 6.5 | SRG-APP-000380 |
| 15 | Workflow Coverage | CM-3, SA-10 | CM.L2-3.4.3 | CC8.1 | 4.1 | 6.5 | SRG-APP-000380 |
| 16 | Stale Credentials | IA-5, IA-5(1) | IA.L2-3.5.7 | CC6.1 | 5.2 | 8.6.3 | SRG-APP-000174 |
| 17 | Shared Credential Usage | AC-6, IA-5 | AC.L2-3.1.5 | CC6.3 | 5.4 | 7.2.2 | SRG-APP-000340 |
| 18 | Unvaulted Secrets | IA-5(6), SC-28 | IA.L2-3.5.10 | CC6.1 | 3.11 | 3.5.1 | SRG-APP-000429 |
| 19 | Credential Ownership Gaps | AC-2, IA-5 | AC.L2-3.1.1 | CC6.3 | 5.1 | 7.2.1 | SRG-APP-000033 |
| 20 | OAuth2 Token Hygiene | IA-5(13), AC-2(3) | IA.L2-3.5.10 | CC6.1 | 5.2 | 8.6.3 | SRG-APP-000174 |
| 21 | Organization Admin Count | AC-6(5) | AC.L2-3.1.6 | CC6.3 | 5.4 | 7.2.2 | SRG-APP-000340 |
| 22 | Team Role Audit | AC-3, AC-6 | AC.L2-3.1.5 | CC6.3 | 5.4, 6.8 | 7.2.1 | SRG-APP-000033 |
| 23 | Execute vs. Admin Separation | AC-5, AC-6 | AC.L2-3.1.2 | CC6.3 | 6.8 | 7.2.2 | SRG-APP-000340 |
| 24 | Audit Role Coverage | AU-2, CA-7 | AU.L2-3.3.1 | CC7.2 | 8.2 | 10.1 | SRG-APP-000095 |
| 25 | External Auth Enforcement | IA-2, IA-8 | IA.L2-3.5.3 | CC6.1 | 5.6 | 8.3 | SRG-APP-000148 |
| 26 | Activity Stream Retention | AU-2, AU-9 | AU.L2-3.3.1 | CC7.2, CC7.3 | 8.2 | 10.1 | SRG-APP-000095 |
| 27 | Notification Coverage | SI-4, IR-5 | SI.L2-3.14.6 | CC7.2 | 8.11 | 10.6 | SRG-APP-000481 |
| 28 | Concurrent Job Limit | SC-5, SI-4 | CM.L2-3.4.1 | CC7.1 | 16.12 | 6.3.3 | SRG-APP-000456 |
| 29 | Project SCM Health | CM-2, SA-10 | CM.L2-3.4.2 | CC8.1 | 4.8 | 6.5 | SRG-APP-000380 |
| 30 | Execution Environment Inventory | CM-7, CM-8 | CM.L2-3.4.1 | CC6.1 | 2.2 | 6.3.2 | SRG-APP-000516 |

## 6. Existing Tools

| Tool | Type | Relevance |
|---|---|---|
| **AAP Analytics** | Native (Web UI) | Built-in dashboards for job success rates, host coverage, and automation savings. Console-only — no CLI export, no compliance framework mapping, no audit-ready output. |
| **awxkit** | Official Python SDK | Comprehensive API wrapper for all AAP REST endpoints. Library-level access only — no analysis, no compliance logic, no reporting. |
| **Ansible Lint** | Static Analysis | Lints playbook YAML for best practices and syntax errors. Analyzes playbook code, not platform configuration or operational health. |
| **ara (ARA Records Ansible)** | Community | Records Ansible playbook execution for reporting and querying. Execution-focused, not platform security configuration focused. |
| **ansible-navigator** | Official CLI | EE-based playbook execution and inspection. Not a platform configuration auditor. |
| **tower-cli** (deprecated) | Community Python | Legacy CLI for AWX/Tower; useful as API reference. Deprecated in favor of awxkit. |
| **Molecule** | Testing Framework | Tests playbook logic against test instances. Development-focused, not production security auditor. |
| **Prometheus + awx_exporter** | Monitoring | Exports AWX metrics to Prometheus. Operational metrics only — no compliance analysis or framework mapping. |

### Differentiation

**ansible-sec-inspector** is the only tool that audits the Ansible Automation
Platform as a security program — not just individual playbooks or operational
metrics. It evaluates whether the automation program itself is configured and
operating in a way that satisfies compliance requirements: host coverage,
schedule compliance, credential hygiene, RBAC enforcement, and audit logging.
Existing tools either analyze playbook code (ansible-lint, molecule) or collect
operational metrics (ara, prometheus) — none produce compliance-mapped findings
about the platform's security posture.

## 7. Architecture

```text
ansible-sec-inspector/
├── cmd/
│   └── ansible-sec-inspector/
│       └── main.go                  # Entrypoint, CLI parsing, orchestration
├── internal/
│   ├── client/
│   │   ├── client.go                # HTTP client with base64 auth header
│   │   ├── auth.go                  # Session auth (LDAP) + Bearer token (local)
│   │   ├── paginate.go              # Offset pagination follower
│   │   └── ratelimit.go             # Rate limiting and retry logic
│   ├── collector/
│   │   ├── collector.go             # Top-level data collection orchestrator
│   │   ├── jobs.go                  # Pull job history, filter by date/status/type
│   │   ├── hosts.go                 # Pull host inventory, last_job timestamps
│   │   ├── inventories.go           # Pull inventories, source sync status
│   │   ├── templates.go             # Pull job templates, last_job_run, schedules
│   │   ├── schedules.go             # Pull all schedules, enabled status, next_run
│   │   ├── credentials.go           # Pull credentials, modified dates, usage counts
│   │   ├── tokens.go                # Pull OAuth2 tokens, expiration, user links
│   │   ├── teams.go                 # Pull teams, role assignments, user membership
│   │   ├── organizations.go         # Pull orgs, admin users, settings
│   │   ├── projects.go              # Pull projects, SCM type, last sync status
│   │   ├── notifications.go         # Pull notification templates, coverage
│   │   ├── activity.go              # Pull activity stream, recent entries
│   │   └── settings.go              # Pull platform settings (auth, logging, jobs)
│   ├── models/
│   │   ├── aapdata.go               # AAPData: container for all collected API data
│   │   ├── finding.go               # ComplianceFinding: individual check result
│   │   ├── severity.go              # CRITICAL / HIGH / MEDIUM / LOW / INFO
│   │   └── result.go                # AuditResult: aggregated findings + summary
│   ├── analyzers/
│   │   ├── base.go                  # Analyzer interface and registry
│   │   ├── common.go                # Shared helpers (date math, threshold checks)
│   │   ├── jobs.go                  # Controls 1-5: Job health and execution analysis
│   │   ├── hosts.go                 # Controls 6-10: Host coverage analysis
│   │   ├── templates.go             # Controls 11-15: Template and schedule hygiene
│   │   ├── credentials.go           # Controls 16-20: Credential hygiene
│   │   ├── access.go                # Controls 21-25: RBAC and auth enforcement
│   │   └── platform.go              # Controls 26-30: Platform security and audit
│   ├── reporters/
│   │   ├── base.go                  # Reporter interface and registry
│   │   ├── table.go                 # Terminal table output (default)
│   │   ├── json.go                  # JSON findings output
│   │   ├── csv.go                   # CSV tabular output
│   │   ├── html.go                  # Styled HTML report with severity breakdown
│   │   ├── executive.go             # Executive summary (pass/fail counts, risk score)
│   │   └── matrix.go                # Cross-framework compliance matrix
│   ├── engine/
│   │   └── engine.go                # AuditEngine: collect → analyze → report → archive
│   └── tui/
│       ├── app.go                   # Bubble Tea TUI application
│       ├── components/
│       │   ├── spinner.go           # Progress spinner during collection
│       │   ├── table.go             # Results table with severity color coding
│       │   └── summary.go           # Summary dashboard (pass/warn/fail counts)
│       └── views/
│           ├── audit.go             # Audit progress view
│           └── results.go           # Results browser with drill-down
├── configs/
│   ├── controls.yaml                # Control definitions and framework mappings
│   └── thresholds.yaml              # Configurable thresholds (stale days, success rate, etc.)
├── testdata/
│   ├── fixtures/                    # Mock API response JSON files
│   │   ├── jobs.json
│   │   ├── hosts.json
│   │   ├── inventories.json
│   │   ├── job_templates.json
│   │   ├── schedules.json
│   │   ├── credentials.json
│   │   ├── tokens.json
│   │   ├── teams.json
│   │   ├── organizations.json
│   │   └── settings.json
│   └── golden/                      # Golden file test outputs
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── .goreleaser.yml
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── COPYING
├── README.md
└── spec.md                          # This file
```

### Data Flow

```text
┌─────────────────┐     ┌──────────────────┐     ┌──────────────┐     ┌────────────┐
│  Client          │────>│  Collector       │────>│  Analyzers   │────>│  Reporters │
│  (AAP REST API)  │     │  (AAPData)       │     │  (Findings)  │     │  (Reports) │
└─────────────────┘     └──────────────────┘     └──────────────┘     └────────────┘
         │                                                │
         │                    ┌──────────┐               │
         └───────────────────>│  Engine  │<──────────────┘
                              │ (Orch.)  │
                              └──────────┘
```

### Key Design Decisions

- **Session auth support:** AAP blocks OAuth2 token creation for LDAP accounts.
  The client must support session-based auth (POST to `/api/login/`, CSRF cookie
  handling) as the primary auth path — not just Bearer token auth.

- **Manual base64 header:** Build `Authorization: Basic base64(user:pass)` manually
  rather than using HTTP library auth helpers. This handles `@` in usernames and
  special characters in passwords more reliably (identical to curl `-u` behavior).

- **Paginated `/api/v2/me/` response:** AAP returns a paginated list from this
  endpoint, not a single user object. Auth validation must check `count > 0` and
  read from `results[0]` — not `result.username` directly.

- **Date-filtered job queries:** Use `started__gt` filter to scope job history
  to the audit period. Pulling all 3,600+ jobs without filtering causes timeouts
  and unnecessary load on the AAP instance.

- **Template-to-schedule mapping:** Schedules are retrieved separately from templates.
  Build a map of `template_id → []schedules` during collection to avoid N+1 queries.

- **Host last-job timestamp:** The `last_job` field on hosts is a related object
  reference, not a timestamp. Retrieve `last_job_host_summary` or the related job's
  `finished` field to get the actual timestamp for stale-host analysis.

- **Credential inspection limits:** AAP does not expose credential secrets via API
  (by design). The inspector checks metadata (age, ownership, usage count) rather
  than attempting to read credential values. Unvaulted secret detection uses
  extra_vars pattern matching on job templates, not credential content inspection.

- **Scalability consideration:** The AAPData monolithic container design may consume
  excessive memory on large instances (>100k job records). Future implementations should
  consider streaming or chunked processing architectures where analyzers consume data
  incrementally rather than loading entire datasets into memory. This is acceptable for
  spec-only phase but should be addressed during implementation if memory becomes a constraint.

## 8. CLI Interface

```bash
# Basic audit with session auth (LDAP accounts)
ansible-sec-inspector audit \
  --url https://aap.example.com \
  --username your.username \
  --password $AAP_PASSWORD

# Audit with Bearer token (local accounts)
ansible-sec-inspector audit \
  --url https://aap.example.com \
  --token $AAP_TOKEN

# Audit last 90 days, all controls, table output (default)
ansible-sec-inspector audit \
  --url https://aap.example.com \
  --username your.username \
  --password $AAP_PASSWORD \
  --days 90

# Specific control categories only
ansible-sec-inspector audit \
  --url https://aap.example.com \
  --username your.username \
  --password $AAP_PASSWORD \
  --controls jobs,hosts,credentials

# JSON output for downstream processing
ansible-sec-inspector audit \
  --url https://aap.example.com \
  --username your.username \
  --password $AAP_PASSWORD \
  --output json \
  --output-file findings.json

# HTML report with executive summary
ansible-sec-inspector audit \
  --url https://aap.example.com \
  --username your.username \
  --password $AAP_PASSWORD \
  --output html \
  --output-file audit-report.html

# Skip TLS verification (Zscaler SSL inspection environments)
ansible-sec-inspector audit \
  --url https://aap.example.com \
  --username your.username \
  --password $AAP_PASSWORD \
  --skip-tls-verify

# Custom thresholds
ansible-sec-inspector audit \
  --url https://aap.example.com \
  --username your.username \
  --password $AAP_PASSWORD \
  --min-success-rate 95 \
  --stale-host-days 14 \
  --stale-template-days 60 \
  --stale-credential-days 90

# Framework-specific compliance matrix
ansible-sec-inspector audit \
  --url https://aap.example.com \
  --username your.username \
  --password $AAP_PASSWORD \
  --output matrix \
  --frameworks fedramp,cmmc,pci-dss

# Interactive TUI mode
ansible-sec-inspector --tui \
  --url https://aap.example.com \
  --username your.username \
  --password $AAP_PASSWORD

# Validate connectivity only
ansible-sec-inspector validate \
  --url https://aap.example.com \
  --username your.username \
  --password $AAP_PASSWORD

# List controls available
ansible-sec-inspector controls list

# Environment variable usage
export AAP_URL=https://aap.example.com
export AAP_USERNAME=your.username
export AAP_PASSWORD=your.password
ansible-sec-inspector audit --output json --output-file findings.json
```

### Flags Reference

```text
Global Flags:
  --url string          AAP base URL (or AAP_URL env var)
  --username string     Username for session auth (or AAP_USERNAME env var)
  --password string     Password for session auth (or AAP_PASSWORD env var)
  --token string        Bearer token for local accounts (or AAP_TOKEN env var)
  --skip-tls-verify     Skip TLS certificate verification
  --timeout int         Request timeout in seconds (default: 30)
  --log-level string    Log level: debug, info, warn, error (default: info)
  --no-color            Disable colored output
  --tui                 Launch interactive TUI mode

Audit Flags:
  --days int            Audit period in days (default: 90)
  --controls string     Comma-separated control categories: jobs,hosts,templates,
                        credentials,access,platform (default: all)
  --severity string     Minimum severity to report: CRITICAL,HIGH,MEDIUM,LOW,INFO
                        (default: LOW)
  --output string       Output format: table,json,csv,html,executive,matrix
                        (default: table)
  --output-file string  Write output to file (default: stdout)
  --frameworks string   Frameworks for matrix output: fedramp,cmmc,soc2,cis,
                        pci-dss,stig (default: all)
  --quiet               Suppress progress output

Threshold Flags:
  --min-success-rate float     Minimum acceptable job success rate % (default: 90)
  --stale-host-days int        Days before host is considered stale (default: 30)
  --stale-template-days int    Days before template is considered stale (default: 90)
  --stale-credential-days int  Days before credential is considered stale (default: 90)
  --stale-token-days int       Days before OAuth2 token is considered stale (default: 90)
  --max-admin-count int        Max org admins before flagging (default: 3)
  --max-shared-credential int  Max templates sharing one credential (default: 5)
  --missed-run-multiplier float Multiplier for missed schedule detection (default: 1.5)
```

## 9. Build Sequence

### Phase 1 — Foundation (Week 1)

- Initialize Go module: `go mod init github.com/your-org/ansible-sec-inspector`
- Add dependencies: cobra, bubbletea, lipgloss, zap, yaml.v3
- Implement `internal/client/` — HTTP client with base64 auth, session cookie
  handling, CSRF token support, paginator
- Implement `internal/models/` — `AAPData`, `ComplianceFinding`, `AuditResult`, severity constants
- Validate auth against `/api/v2/me/` with correct paginated response parsing
- Write unit tests with mock API fixtures in `testdata/fixtures/`

### Phase 2 — Data Collection (Week 2)

- Implement `internal/collector/` — all data collectors
- Priority order: jobs → hosts → inventories → templates → schedules → credentials
  → tokens → teams → organizations → projects → notifications → settings
- Add date filtering to job queries (`started__gt`)
- Build template-to-schedule mapping to avoid N+1
- Implement `internal/engine/engine.go` orchestration

### Phase 3 — Job & Host Analyzers (Week 3)

- Implement controls 1-5: `analyzers/jobs.go` — success rate, chronic failures,
  stuck jobs, manual launch rate, remediation rate
- Implement controls 6-10: `analyzers/hosts.go` — unmanaged hosts, stale coverage,
  inventory sync, host failure rate, disabled hosts
- Unit tests for each analyzer with fixture data
- Golden file tests for finding output stability

### Phase 4 — Template, Credential & Access Analyzers (Week 4)

- Implement controls 11-15: `analyzers/templates.go` — stale templates, unscheduled
  critical templates, missed runs, disabled schedules, workflow coverage
- Implement controls 16-20: `analyzers/credentials.go` — stale creds, shared usage,
  unvaulted secrets, orphaned credentials, token hygiene
- Implement controls 21-25: `analyzers/access.go` — admin count, team roles,
  execute/admin separation, audit role coverage, external auth

### Phase 5 — Platform & Reporting (Week 5)

- Implement controls 26-30: `analyzers/platform.go` — activity stream, notifications,
  concurrent jobs, SCM health, execution environments
- Implement `internal/reporters/` — table, json, csv, html, executive, matrix
- Implement `cmd/ansible-sec-inspector/main.go` — cobra CLI with all flags
- Framework mapping validation against `configs/controls.yaml`

### Phase 6 — TUI & Polish (Week 6)

- Implement `internal/tui/` — Bubble Tea interactive interface with drill-down
- Dockerfile and .goreleaser.yml for cross-platform binaries
- Integration tests against a live AAP trial or sandbox instance
- README, usage examples, threshold documentation

## 10. Status

**Not yet implemented. Spec only.**

Mirrors the grclanker spec format: https://github.com/ethanolivertroy/grclanker
