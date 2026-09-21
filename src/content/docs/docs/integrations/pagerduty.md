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

Every request carries `Accept: application/vnd.pagerduty+json;version=2`. The client follows classic `limit`/`offset` pagination using the `more` flag (100 per page, capped at the documented 10,000 record ceiling) and cursor pagination (`cursor`, `next_cursor`) on audit records and incident workflow triggers. It retries 429 and 5xx responses, waiting for the `ratelimit-reset` or `Retry-After` value when present, and redacts tokens from error messages.

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
  core_data/            raw API snapshots (users, services, schedules, audit records, ...)
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

Finding ids are `PD-01` through `PD-25`, one per spec control. Status semantics: `pass` means the API evidence satisfies the control, `warn` means partial or degraded evidence that should be reviewed, `fail` means the API evidence contradicts the control, and `manual` means the API cannot prove the control (or the endpoint was unreadable) and the finding summary states exactly which evidence to collect from the PagerDuty web app.

| # | Control | Tool | Finding | Status semantics |
|---|---------|------|---------|------------------|
| 1 | SSO enforcement enabled | `pagerduty_assess_access_control` | `PD-01` | `fail` when the `sso` ability is absent; otherwise always `manual` (the API does not expose whether SSO login is required; collect Account Settings > Single Sign-On) |
| 2 | User roles follow least privilege | `pagerduty_assess_access_control` | `PD-02` | `pass` when owner plus admin users are within `max_admins` (default 5), else `fail` |
| 3 | Owner role limited to the account owner | `pagerduty_assess_access_control` | `PD-03` | `pass` for exactly one owner, `warn` for none in the sample, `fail` for more than one |
| 4 | Team-based access configured | `pagerduty_assess_access_control` | `PD-04` | `fail` with no teams or more than half of users teamless, `warn` for some teamless users, `pass` when everyone belongs to a team |
| 5 | Services have escalation policies | `pagerduty_assess_incident_response` | `PD-05` | `pass` when every active service references a policy, else `fail` |
| 6 | Escalation policies have multiple levels | `pagerduty_assess_incident_response` | `PD-06` | `pass` when every attached policy has two or more rules, else `warn` |
| 7 | Escalation does not end without notification | `pagerduty_assess_incident_response` | `PD-07` | `fail` for rules without targets, `warn` for attached policies with `num_loops` 0, else `pass` |
| 8 | Schedules provide 24/7 coverage | `pagerduty_assess_oncall_coverage` | `PD-08` | `pass` when rendered final schedules have no gaps over `coverage_days` (default 30), else `fail` |
| 9 | Schedules have multiple participants | `pagerduty_assess_oncall_coverage` | `PD-09` | `pass` when every attached schedule has two or more distinct users, else `fail` |
| 10 | Incident response automation configured | `pagerduty_assess_incident_response` | `PD-10` | `pass` with enabled incident workflows and triggers, `warn` when workflows or legacy response plays exist but are inactive, `fail` when none exist |
| 11 | Audit logging active | `pagerduty_assess_audit_logging` | `PD-11` | `pass` when records exist in `audit_window_days`, `warn` when readable but empty, `fail` on HTTP 402 (plan lacks Audit Trail), `manual` on other errors |
| 12 | Audit log retention | `pagerduty_assess_audit_logging` | `PD-12` | `pass` when the 11-to-12 month probe returns records, `warn` when it is empty or fails, `manual` when `min_retention_days` exceeds the documented 365 days |
| 13 | API keys rotated | `pagerduty_assess_audit_logging` | `PD-13` | Always `manual` (no API key inventory endpoint); evidence lists distinct truncated tokens seen in audit records |
| 14 | Webhook endpoints use HTTPS | `pagerduty_assess_integration_security` | `PD-14` | `pass` when all extension `endpoint_url` and subscription `delivery_method.url` values are `https`, else `fail` |
| 15 | Webhook signatures verified | `pagerduty_assess_integration_security` | `PD-15` | `warn` when unsigned legacy generic webhook extensions remain, `pass` when only signed v3 subscriptions are used (confirm receivers verify `X-PagerDuty-Signature`) |
| 16 | Integration permissions scoped | `pagerduty_assess_integration_security` | `PD-16` | `pass` when no legacy inbound integrations or unfiltered email integrations exist, else `warn` |
| 17 | Notification rules for all users | `pagerduty_assess_oncall_coverage` | `PD-17` | `pass` when every responder has rules including a high-urgency rule, `fail` when more than a quarter have none, else `warn` |
| 18 | Contact methods for on-call users | `pagerduty_assess_oncall_coverage` | `PD-18` | `fail` when an on-call user has no enabled contact method, `warn` for email-only users, else `pass` |
| 19 | Service urgency rules configured | `pagerduty_assess_incident_response` | `PD-19` | `fail` when a service lacks an urgency rule, `warn` when every service is constant high, else `pass` |
| 20 | Custom incident priorities defined | `pagerduty_assess_incident_response` | `PD-20` | `pass` when priorities exist, else `fail` |
| 21 | Service dependencies mapped | `pagerduty_assess_integration_security` | `PD-21` | `fail` with no business services, `warn` when some have no dependencies, else `pass` |
| 22 | Acknowledgement timeouts configured | `pagerduty_assess_incident_response` | `PD-22` | `pass` when every active service sets one, else `warn` |
| 23 | Auto-resolve timeouts configured | `pagerduty_assess_incident_response` | `PD-23` | `pass` when every active service sets one, else `warn` |
| 24 | Analytics access restricted | `pagerduty_assess_access_control` | `PD-24` | Always `manual` (per-role analytics permissions are not exposed); evidence lists analytics abilities and role counts |
| 25 | Change events tracking enabled | `pagerduty_assess_integration_security` | `PD-25` | `pass` when change events arrived in `change_event_days`, `warn` when Events API v2 integrations exist but no events arrived, else `fail` |

Any control whose source endpoint cannot be read becomes `manual` with the collection error in the summary and the error recorded in the assessment `errors` list and the bundle `_errors.log`.

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
- Users and services are sampled up to `user_limit` and `service_limit` (default 1000 each) and the classic pagination ceiling of 10,000 records.

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
