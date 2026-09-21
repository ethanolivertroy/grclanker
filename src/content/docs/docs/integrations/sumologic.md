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

Configuration precedence is explicit tool arguments, then environment variables (`SUMOLOGIC_ACCESS_ID`, `SUMOLOGIC_ACCESS_KEY`, `SUMOLOGIC_ENDPOINT` or `SUMOLOGIC_DEPLOYMENT`, `SUMOLOGIC_TIMEOUT`), then a YAML config file at `SUMOLOGIC_CONFIG_FILE` or `~/.sumologic-sec-inspector/config.yaml` with `access_id`, `access_key`, and `endpoint` keys.

Requests use HTTP Basic authentication (`Authorization: Basic base64(accessId:accessKey)`). The client follows `token` continuation cursors on paginated endpoints (page size 1000 where the OpenAPI allows it, 100 for `/v2/dashboards` whose `limit` maximum is 100), uses `limit`/`offset` for the Collector Management and monitor search APIs, retries 429 and 5xx responses with backoff (honoring `Retry-After` when present), enforces a request timeout, and redacts the access key from error messages.

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

## Status semantics

- `pass`: the enabling flag was read and the full population satisfied the control.
- `warn`: partial evidence (incomplete pagination, undated items, secondary flags off) prevented a pass.
- `fail`: the control is violated.
- `manual`: the endpoint was unreadable (401/403/error), the control is not applicable or plan-limited, or the API cannot expose the evidence. The summary names exactly what a human must collect.

Unreadable endpoints, empty inventories, capability-limited views, and unfollowed pagination never produce `pass`.

## Control coverage

| # | Spec control | Tool | Finding | Status semantics |
|---|---|---|---|---|
| 1 | SAML SSO Enforcement | identity | SUMO-01 | `fail` on zero IdPs; `warn` on debug mode or missing certificate; otherwise `manual` because the API does not expose the SAML lockdown (require SAML sign-in) state |
| 2 | SAML Allowlisted Users Minimized | identity | SUMO-02 | `fail` above `max_allowlisted_users`; `warn` on inactive allowlisted users; `pass` at or below threshold (zero is compliant); `manual` when no IdP exists |
| 3 | Password Policy Strength | identity | SUMO-03 | `fail` below `min_password_length` or without lockout; `warn` when complexity or weak-password rejection is incomplete |
| 4 | Password Expiration Policy | identity | SUMO-04 | `fail` when disabled or above `max_password_age_days` |
| 5 | MFA Enforcement | identity | SUMO-05 | `fail` when `requireMfa` is false or absent; `warn` when active users report `isMfaEnabled=false` or the user list is incomplete; evidence lists locked users, dormant users, and users without a `lastLoginTimestamp` (never counted as active) |
| 6 | Role-Based Access Control | access control | SUMO-06 | `fail` when admin-capability role members exceed `max_admins`; `warn` on custom roles with admin capabilities, custom roles without a `filterPredicate`, admin members dormant beyond `user_inactive_days` or without a `lastLoginTimestamp`, or an unreadable user list; `manual` on zero roles |
| 7 | Access Key Rotation | access control | SUMO-07 | `fail` on enabled keys older than `key_max_age_days`; `warn` on keys without `createdAt` or when the access key lifetime policy is `0` (never expire), absent, or unreadable; `manual` on personal-only scope or zero keys; every summary states the lifetime policy value |
| 8 | Inactive Access Keys | access control | SUMO-08 | `fail` on keys idle beyond `key_inactive_days`; `warn` on keys without `lastUsed`; `manual` on personal-only scope or zero keys |
| 9 | Audit Index Enabled | data governance | SUMO-09 | `fail` when the audit policy is not enabled; `manual` when no active AuditIndex partition is visible (plan limitation); `warn` when search audit is off |
| 10 | Data Forwarding Destinations Reviewed | data governance | SUMO-10 | `pass` on zero destinations or when all match `approved_destination_domains`; `fail` on unapproved hosts; otherwise `manual` |
| 11 | Content Sharing Permissions | content sharing | SUMO-11 | `fail` when the Data Access Level policy is off; `warn` on org-wide shares in the sampled folder or when the personal folder holds more items than `content_sample` (total, sampled, and unsampled counts are recorded); `manual` when permissions cannot be sampled; `pass` only when every folder item was evaluated |
| 12 | Collector Management | data governance | SUMO-12 | `fail` on installed collectors offline beyond `collector_offline_days` or without last-seen; `warn` on offline or mixed versions; `manual` on zero collectors |
| 13 | Service Allowlist Configured | access control | SUMO-13 | `fail` when `loginEnabled` is false or zero CIDRs; `warn` when content allowlisting is off |
| 14 | Session Timeout Policy | access control | SUMO-14 | `fail` above `max_session_timeout_minutes`; `warn` when the concurrent sessions limit is off |
| 15 | Scheduled Search Permissions | content sharing | SUMO-15 | always `manual`: role bindings are not exposed; evidence lists monitors with `runAs` and scheduled searches seen |
| 16 | Ingest Budget Controls | data governance | SUMO-16 | `fail` on zero budgets; `warn` when none use `stopCollecting` |
| 17 | Data Retention Policies | data governance | SUMO-17 | `fail` when an audit index retains less than `min_retention_days`; `warn` on other short or account-default (`-1`) partitions |
| 18 | Lookup Table Access | content sharing | SUMO-18 | `warn` on org-shared lookup tables in the sampled folder; otherwise `manual` because the API has no lookup table listing |
| 19 | Dashboard Sharing Restrictions | content sharing | SUMO-19 | `fail` when sharing outside the org is enabled; `warn` on `isPublic` dashboards; `manual` when the flag or dashboards are missing |
| 20 | Monitor Alert Routing | content sharing | SUMO-20 | `fail` on recipients outside org domains or unknown connections; `warn` on disabled monitors; `manual` on zero monitors |

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
