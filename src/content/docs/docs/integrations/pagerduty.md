---
title: PagerDuty
description: Read-only PagerDuty security inspector covering access control, incident response, on-call coverage, audit logging, and integration security across 25 controls.
---

The PagerDuty integration inspects a PagerDuty account through the REST API v2 and maps what it finds to the 25 controls in `specs/pagerduty-sec-inspector.spec.md`. Every tool is read-only: nothing is created, updated, or deleted in the account.

## What it inspects

- Account abilities (SSO, teams, analytics, audit trail) and user roles, owners, and team membership
- Services, escalation policies, incident urgency rules, acknowledgement and auto-resolve timeouts, priorities, and incident workflows
- On-call schedules, rendered final-schedule coverage, schedule participants, notification rules, and contact methods for current on-call users
- Audit records, documented retention, and the API tokens observed making configuration changes
- Extensions, v3 webhook subscriptions, service integrations, business service dependencies, and change events

## Setup and authentication

Create a read-only API key in the PagerDuty web app (Integrations > API Access Keys, requires the Account Owner or Global Admin role) or use a user API key from User Settings > API Access. A user key only sees what that user can see; account keys see the whole account. Audit records additionally require an admin, account owner, or global API key on a pricing plan with the Audit Trail feature.

Credentials resolve in this order: explicit tool arguments, then environment variables, then the JSON config file at `~/.config/grclanker/pagerduty.json` (override the path with `PAGERDUTY_CONFIG_FILE`).

| Auth mode | Environment variables | Header sent |
|-----------|----------------------|-------------|
| REST API key (recommended) | `PAGERDUTY_API_TOKEN`, or `PAGERDUTY_API_KEY`, `PAGERDUTY_TOKEN`, `PD_API_KEY` | `Authorization: Token token=<key>` |
| OAuth bearer token | `PAGERDUTY_ACCESS_TOKEN` (or `PAGERDUTY_OAUTH_TOKEN`) | `Authorization: Bearer <token>` |
| Scoped OAuth client credentials | `PAGERDUTY_CLIENT_ID`, `PAGERDUTY_CLIENT_SECRET`, `PAGERDUTY_SUBDOMAIN` | Token exchanged at `https://identity.pagerduty.com/oauth/token` with the `as_account-<region>.<subdomain>` scope plus the `*.read` scopes, then `Authorization: Bearer <token>` |

Optional settings:

| Variable | Purpose |
|----------|---------|
| `PAGERDUTY_REGION` (or `PAGERDUTY_SERVICE_REGION`) | `us` (default, `https://api.pagerduty.com`) or `eu` (`https://api.eu.pagerduty.com`) |
| `PAGERDUTY_BASE_URL` (or `PAGERDUTY_API_BASE_URL`) | Explicit REST base URL; overrides the region |
| `PAGERDUTY_USER_EMAIL` (or `PAGERDUTY_FROM_EMAIL`) | Sent as the `From` header |
| `PAGERDUTY_TIMEOUT` | HTTP timeout in seconds (default 30) |
| `PAGERDUTY_CONFIG_FILE` | JSON file with `api_token`, `access_token`, `client_id`, `client_secret`, `subdomain`, `region`, `base_url`, `from_email`, `timeout_seconds` |

Every request carries `Accept: application/vnd.pagerduty+json;version=2`. The client follows classic `limit`/`offset` pagination using the `more` flag (100 per page, capped at the documented 10,000 record ceiling) and cursor pagination (`cursor`, `next_cursor`) on audit records and incident workflow triggers. `GET /change_events` declares no `more` or `total` field, so the client keeps reading offset pages until a page comes back shorter than requested; a full final page at the requested limit is recorded as incomplete. It retries 429 and 5xx responses, waiting for the `ratelimit-reset` or `Retry-After` value when present, and redacts tokens from error messages.

## Tools

| Tool | What it does |
|------|--------------|
| `pagerduty_check_access` | Probes 14 read surfaces (`/abilities`, `/users`, `/teams`, `/services`, `/escalation_policies`, `/schedules`, `/oncalls`, `/audit/records`, `/extensions`, `/webhook_subscriptions`, `/business_services`, `/priorities`, `/incident_workflows`, `/change_events`), reports `healthy` or `limited`, and lists the missing permission for each unreadable surface |
| `pagerduty_assess_access_control` | Controls 1, 2, 3, 4, 24: SSO ability, privileged role counts against `max_admins`, owner count, team membership, analytics access |
| `pagerduty_assess_incident_response` | Controls 5, 6, 7, 10, 19, 20, 22, 23: escalation policy assignment, escalation levels and repeat behavior, incident workflows, urgency rules, priorities, acknowledgement and auto-resolve timeouts |
| `pagerduty_assess_oncall_coverage` | Controls 8, 9, 17, 18: final-schedule coverage gaps over `coverage_days`, single-participant schedules, responder notification rules, contact methods of current on-call users |
| `pagerduty_assess_audit_logging` | Controls 11, 12, 13: recent audit records, 11-to-12 month retention probe against `min_retention_days`, API tokens observed in audit records with the `api_key_max_age_days` rotation target |
| `pagerduty_assess_integration_security` | Controls 14, 15, 16, 21, 25: HTTPS webhook endpoints, legacy versus signed v3 webhooks, legacy and unfiltered service integrations, business service dependencies, change events |
| `pagerduty_export_audit_bundle` | Runs everything and writes an evidence bundle plus `.zip` under `output_dir` (default `./export/pagerduty`) |

All tools accept the auth parameters (`api_token`, `access_token`, `client_id`, `client_secret`, `subdomain`, `region`, `base_url`, `from_email`, `config_file`, `timeout_seconds`). Assessment tools also accept sampling limits (`user_limit`, `team_limit`, `service_limit`, `schedule_limit`, `business_service_limit`) and thresholds (`max_admins`, `coverage_days`, `audit_window_days`, `audit_limit`, `min_retention_days`, `api_key_max_age_days`, `change_event_days`).

### Audit bundle layout

```
pagerduty-<region>-audit-bundle/
  core_data/            projected and redacted API snapshots (users, services, schedules, audit records, ...)
  analysis/             findings.json, metadata.json, one JSON file per assessment category
  compliance/
    executive_summary.md
    unified_compliance_matrix.md
    fedramp/ cmmc/ soc2/ cis/ pci_dss/ disa_stig/ irap/ ismap/   one report per framework
  QUICK_REFERENCE.md
  _errors.log           only when part of the collection failed
pagerduty-<region>-audit-bundle.zip
```

Output paths are resolved inside `output_dir`; traversal outside it and symlinked parent directories are rejected. Files are written with mode `0600` and directories with `0700`.

## Control coverage

Finding ids are `PD-01` through `PD-25`, one per spec control. Status semantics: `pass` means complete API evidence satisfies the control, `warn` means partial or degraded evidence that should be reviewed, `fail` means the API evidence contradicts the control, and `manual` means the API cannot prove the control (or the endpoint was unreadable) and the finding summary states exactly which evidence to collect from the PagerDuty web app.

### Verdict safety rules

Every finding follows these rules so that a `pass` is never issued on missing or partial evidence:

- An unreadable, forbidden (401/403), or errored endpoint yields `manual`; the summary names the failing endpoint and the web app evidence to collect.
- An empty inventory never yields `pass`. Zero users, teams, services, escalation policies, schedules, or on-call entries yield `manual` (the credential is probably not seeing the directory); zero incident workflows, priorities, or business services yield `fail` (the feature is readable but unused); zero webhooks make controls 14 and 15 `manual` (not applicable).
- Plan-gated features (HTTP 402 or a plan message from Audit Trail, Incident Workflows, Priorities, Business Services) yield `manual` with a plan summary, and controls the API cannot observe (1, 13, 24) are always `manual`.
- Records without a date (`execution_time`, change event `timestamp`, schedule entry `start` or `end`) are never counted as recent or as coverage; they are reported in their own evidence bucket and cap the verdict at `warn`.
- The client requests `total=true`, follows `more` and `next_cursor` to completion, and records truncation when a `*_limit` or the 10,000 record ceiling stops it. An empty page served with `more: true` or with a `next_cursor`, a `next_cursor` the API already served, a `more: false` page that leaves the declared `total` unreached, a full page without a `more` flag, and per-team member lists that stop short are all recorded as truncated rather than complete. Any finding that would pass on a truncated inventory is downgraded to `warn` with seen and total counts (or "total unknown") in the summary and `evidence.partial_view`.
- Credentials never reach the bundle: integration keys and inbound integration emails, extension `config` objects, webhook `custom_headers` values, and any secret-named field are replaced with `[REDACTED]`; extension and webhook URLs are reduced to scheme and host (including in `PD-14` evidence); users, services, workflows, change events, and audit records are projected to the fields the findings read; and error strings carry the vendor's structured error message or a body-size note, never the raw response body.
- A finding that depends on a secondary read stops below `pass` while that read fails and names it: `PD-04` is capped at `warn` when `GET /abilities` cannot confirm the `teams` ability, and `PD-10` is capped at `warn` (and drops its response play count) when `GET /services` is unreadable.
- `pagerduty_check_access` and every assessment call `GET /users/me`: a 400 identifies an account-level key (full visibility); a user-level key or OAuth user token with a role other than `owner` or `admin` only sees its own teams, so passing findings are downgraded to `warn` until an account-level key is used.
- Enabling flags must be present and true: `is_enabled` on workflows, an enabled state on workflow triggers (the parent workflow's `is_enabled` resolved through `trigger.workflow.id`, or `is_disabled: false` while that deprecated field is still served), `active` on webhook subscriptions, `enabled` and `blacklisted` on phone and SMS methods, `blacklisted` on push methods (the push schema has no `enabled` flag), `enabled` on email methods, `num_loops` and rule `targets` on escalation policies, `role` on users, `extension_schema` on extensions, and ability names in `/abilities`. An absent or false flag never supports `pass`.
- Re-running the export never overwrites: the bundle directory and the zip share the same allocated name (`pagerduty-us-audit-bundle-2/` and `pagerduty-us-audit-bundle-2.zip`).

| # | Control | Tool | Finding | Status semantics |
|---|---------|------|---------|------------------|
| 1 | SSO enforcement enabled | `pagerduty_assess_access_control` | `PD-01` | `fail` when abilities are readable, non-empty, and lack `sso`; otherwise `manual` (the API does not expose whether SSO login is required; collect Account Settings > Single Sign-On) |
| 2 | User roles follow least privilege | `pagerduty_assess_access_control` | `PD-02` | `pass` when owner plus admin users are within `max_admins` (default 5) and every user has a `role`, `warn` when some users have no role field, `fail` above the threshold, `manual` with zero users |
| 3 | Owner role limited to the account owner | `pagerduty_assess_access_control` | `PD-03` | `pass` for exactly one owner, `warn` for none or for users without a role, `fail` for more than one, `manual` with zero users |
| 4 | Team-based access configured | `pagerduty_assess_access_control` | `PD-04` | `fail` with zero teams, a missing `teams` ability, or more than half of users teamless, `warn` for some teamless users, `pass` when everyone belongs to a team (capped at `warn` while `/abilities` is unreadable or empty, since the `teams` ability cannot be confirmed), `manual` when users or teams are unreadable |
| 5 | Services have escalation policies | `pagerduty_assess_incident_response` | `PD-05` | `pass` when every active service references a policy, `fail` otherwise, `manual` with zero (active) services |
| 6 | Escalation policies have multiple levels | `pagerduty_assess_incident_response` | `PD-06` | `pass` when every attached policy has two or more rules, `warn` otherwise, `manual` with zero policies or none attached to a service |
| 7 | Escalation does not end without notification | `pagerduty_assess_incident_response` | `PD-07` | `fail` for policies without rules or rules without targets, `warn` for attached policies with `num_loops` 0 or absent, else `pass` |
| 8 | Schedules provide 24/7 coverage | `pagerduty_assess_oncall_coverage` | `PD-08` | `pass` when rendered final schedules have no gaps over `coverage_days` (default 30), `warn` when entries missing a start or end were excluded, `fail` on gaps, `manual` with zero or unattached schedules |
| 9 | Schedules have multiple participants | `pagerduty_assess_oncall_coverage` | `PD-09` | `pass` when every attached schedule has two or more distinct users, else `fail`; `manual` with zero or unattached schedules |
| 10 | Incident response automation configured | `pagerduty_assess_incident_response` | `PD-10` | `pass` with at least one `is_enabled: true` workflow, at least one enabled trigger, and no unresolved trigger; a trigger is enabled when its parent workflow (`trigger.workflow.id`) was returned with `is_enabled: true`, or when it carries `is_disabled: false` and no parent is available, and it is disabled whenever `is_disabled` is `true` or the parent has `is_enabled: false`; `warn` when workflows, triggers, or legacy response plays exist but none is verified enabled, or when a trigger without `is_disabled` cannot be matched to a returned workflow (unresolved); `fail` when the readable endpoints return none; `manual` on plan or read errors; capped at `warn` while `/services` is unreadable because legacy response play references cannot be counted; the summary states enabled, disabled, and unresolved trigger counts |
| 11 | Audit logging active | `pagerduty_assess_audit_logging` | `PD-11` | `pass` when records dated inside `audit_window_days` exist, `warn` when readable but empty or undated, `manual` on HTTP 402 (plan lacks Audit Trail) or other errors |
| 12 | Audit log retention | `pagerduty_assess_audit_logging` | `PD-12` | `pass` when the 11-to-12 month probe returns dated records, `warn` when it is empty, undated, or fails, `manual` when `min_retention_days` exceeds the documented 365 days or audit records are unreadable |
| 13 | API keys rotated | `pagerduty_assess_audit_logging` | `PD-13` | Always `manual` (no API key inventory endpoint); evidence lists distinct truncated tokens seen in audit records |
| 14 | Webhook endpoints use HTTPS | `pagerduty_assess_integration_security` | `PD-14` | `pass` when all extension `endpoint_url` and subscription `delivery_method.url` values are `https`, `fail` otherwise, `manual` when no webhooks exist |
| 15 | Webhook signatures verified | `pagerduty_assess_integration_security` | `PD-15` | `warn` when unsigned legacy generic webhook extensions remain, extensions lack a schema, or no subscription has `active: true`; `pass` only when `/extensions` was readable (count stated), none is a legacy webhook, and at least one v3 subscription is active (confirm receivers verify `X-PagerDuty-Signature`); `manual` when no webhooks exist |
| 16 | Integration permissions scoped | `pagerduty_assess_integration_security` | `PD-16` | `pass` when no legacy inbound integrations or unfiltered email integrations exist and every service returned its integrations, else `warn`; `manual` with zero services |
| 17 | Notification rules for all users | `pagerduty_assess_oncall_coverage` | `PD-17` | `pass` when every responder has rules including a high-urgency rule, `fail` when more than a quarter have none, `warn` otherwise or when users lack a role, `manual` with zero users or zero responders |
| 18 | Contact methods for on-call users | `pagerduty_assess_oncall_coverage` | `PD-18` | `fail` when an on-call user has only blocked or disabled methods, `warn` for email-only users or methods whose `enabled`/`blacklisted` flags are absent, `pass` when every on-call user has a phone or SMS method with `enabled: true` and `blacklisted: false` or a push method with `blacklisted: false`, `manual` when nobody is on call |
| 19 | Service urgency rules configured | `pagerduty_assess_incident_response` | `PD-19` | `fail` when a service lacks an urgency rule, `warn` when every service is constant high, else `pass`; `manual` with zero services |
| 20 | Custom incident priorities defined | `pagerduty_assess_incident_response` | `PD-20` | `pass` when priorities exist, `fail` when the readable endpoint returns none, `manual` on plan or read errors |
| 21 | Service dependencies mapped | `pagerduty_assess_integration_security` | `PD-21` | `fail` with zero business services, `warn` when some have no dependencies, else `pass`; `manual` on plan or read errors |
| 22 | Acknowledgement timeouts configured | `pagerduty_assess_incident_response` | `PD-22` | `pass` when every active service sets one, else `warn`; `manual` with zero services |
| 23 | Auto-resolve timeouts configured | `pagerduty_assess_incident_response` | `PD-23` | `pass` when every active service sets one, else `warn`; `manual` with zero services |
| 24 | Analytics access restricted | `pagerduty_assess_access_control` | `PD-24` | Always `manual` (per-role analytics permissions are not exposed); evidence lists analytics abilities and role counts |
| 25 | Change events tracking enabled | `pagerduty_assess_integration_security` | `PD-25` | `pass` when change events with a `timestamp` inside `change_event_days` arrived and the collection is complete, `warn` when events are undated, when Events API v2 integrations exist but no events arrived, or when the change event pages stopped at the limit (`evidence.change_events_complete` is false), `fail` when neither exists, `manual` with zero services |

Any control whose source endpoint cannot be read becomes `manual` with the collection error in the summary and the error recorded in the assessment `errors` list and the bundle `_errors.log`. Every `pass` listed above is downgraded to `warn` when the underlying inventory is partial or the credential is a non-admin user-level key.

## Framework mappings

Each finding carries eight mappings from the spec's compliance table, labelled `FedRAMP`, `CMMC`, `SOC 2`, `CIS`, `PCI-DSS`, `STIG`, `IRAP`, and `ISMAP` (for example `PD-01` maps to `FedRAMP IA-2`, `CMMC IA.L2-3.5.1`, `SOC 2 CC6.1`, `CIS 4.1`, `PCI-DSS 8.3.1`, `STIG SRG-APP-000148`, `IRAP ISM-1557`, `ISMAP 8.2.1`). The audit bundle groups them into `compliance/unified_compliance_matrix.md` and one report per framework.

## Live smoke test

```bash
PAGERDUTY_API_TOKEN=... npm --prefix cli run test:pagerduty:live
```

The script skips with exit code 0 when no credentials are present. With credentials it runs `pagerduty_check_access`, stops if the core abilities, users, services, and escalation policy surfaces are unreadable, and then runs the incident response assessment against up to 100 services.

## Limitations and manual controls

- Controls 1, 13, and 24 always produce `manual` findings: the REST API exposes the `sso` ability but not SSO enforcement, has no endpoint listing API keys or their creation dates, and does not expose per-role analytics permissions.
- Contact method verification status is not exposed, so control 18 checks for enabled, non-blocked phone, SMS, or push methods instead.
- Response plays are no longer in the published REST API reference; control 10 evaluates incident workflows and triggers and only reports legacy `response_play` references on services.
- Webhook signature verification happens on the receiving side; control 15 confirms only that unsigned legacy generic webhook extensions are gone.
- Audit records need the Audit Trail plan feature and an admin, owner, or global API key. PagerDuty retains them for 12 months, so longer retention requirements need SIEM or archive evidence.
- Users and services are read up to `user_limit` and `service_limit` (default 1000 each), audit records up to `audit_limit` (default 2000), all within the classic pagination ceiling of 10,000 records. When a limit stops the collection, the finding records seen and total counts and cannot pass; raise the limit or narrow the window to obtain a complete inventory.
- A user-level API key with a role below `admin` only returns the objects that user can see, so its passing findings are downgraded to `warn`. Use an account-level read-only key for a complete assessment.

## Official documentation

- REST API reference: https://developer.pagerduty.com/api-reference/
- Authentication (`Authorization: Token token=<key>`): https://developer.pagerduty.com/docs/rest-api-v2/authentication/ (source: https://github.com/PagerDuty/developer-docs/blob/main/docs/REST-API/02-Authentication.md)
- Versioning (`Accept: application/vnd.pagerduty+json;version=2`): https://github.com/PagerDuty/developer-docs/blob/main/docs/REST-API/03-Versioning.md
- Rate limits (960 requests per minute, `ratelimit-*` headers): https://developer.pagerduty.com/docs/72d3b724589e3-rest-api-rate-limits
- Pagination (classic and cursor): https://developer.pagerduty.com/docs/rest-api-v2/pagination/
- Includes (`include[]`): https://github.com/PagerDuty/developer-docs/blob/main/docs/REST-API/13-Includes.md
- Audit Records API and 12 month retention: https://developer.pagerduty.com/docs/rest-api-v2/audit-records-api/
- Scoped OAuth app tokens (`client_credentials` grant with the `as_account-{REGION}.{SUBDOMAIN}` scope): https://github.com/PagerDuty/developer-docs/blob/main/docs/app-integration-development/02-Private-Apps.md
- OAuth token endpoint (`https://identity.pagerduty.com/oauth/token`): https://github.com/PagerDuty/developer-docs/blob/main/docs/app-integration-development/06-OAuth-Functionality.md
- Webhooks v3 and signatures: https://developer.pagerduty.com/docs/webhooks/v3-overview/ and https://github.com/PagerDuty/developer-docs/blob/main/docs/webhooks/04-Signatures.md
- OpenAPI schema used to verify endpoint paths and field names: https://github.com/PagerDuty/api-schema
- API Access Keys (web app): https://support.pagerduty.com/docs/api-access-keys
- Service regions (US and EU): https://support.pagerduty.com/docs/service-regions
