---
title: Google Workspace
description: Read-only Google Workspace compliance inspection over the Admin SDK Directory, Reports, Alert Center, and Cloud Identity Policy APIs, with a multi-framework audit bundle.
---

The Google Workspace inspector (`gws_*` tools) reviews identity, privileged access, third-party OAuth integrations, and security monitoring in a Google Workspace tenant. It is read-only: every request is a GET against a documented Google API, nothing is written back to the tenant, and every verdict follows the verdict-safety rules described below.

Spec: `specs/gws-inspector-go.spec.md`. Implementation: `cli/extensions/grc-tools/gws.ts`. Tests: `cli/tests/gws.test.mjs`.

## What it inspects

| Area | Tool | Google surface |
| --- | --- | --- |
| Identity | `gws_assess_identity` | Directory users, roles, role assignments; Reports login events; Cloud Identity Policy API 2-step verification settings |
| Admin access | `gws_assess_admin_access` | Directory users, roles, role assignments; Reports admin events |
| Integrations | `gws_assess_integrations` | Directory users and roles; per-user `tokens.list`; Reports token events |
| Monitoring | `gws_assess_monitoring` | Alert Center alerts; Reports login, admin, and token events |
| Access probe | `gws_check_access` | One read against each surface above |
| Evidence bundle | `gws_export_audit_bundle` | Collects every surface once and writes the shared bundle layout |

## Setup and authentication

Two auth modes ship today.

### Service account with domain-wide delegation (recommended)

1. Create a service account in a Google Cloud project and download its JSON key.
2. In the Admin console, authorize the service account's client ID for domain-wide delegation with the read-only scopes listed below.
3. Point grclanker at the key and at a Workspace admin whose identity the service account impersonates:

```bash
export GWS_CREDENTIALS_FILE=/path/to/service-account.json   # or GWS_CREDENTIALS_JSON with the inline JSON
export GWS_ADMIN_EMAIL=admin@example.com
export GWS_DOMAIN=example.com          # display label only
export GWS_CUSTOMER_ID=my_customer     # optional, defaults to my_customer
export GWS_LOOKBACK_DAYS=30            # optional audit window, 1-180
```

grclanker signs an RS256 JWT with `sub` set to the admin email and exchanges it at `https://oauth2.googleapis.com/token` with the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant, as documented at [Using OAuth 2.0 for Server to Server Applications](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority). Tokens are cached per scope set and refreshed on 401.

The Cloud Identity Policy API scope is requested with its own token so that a tenant which has not yet delegated it keeps every other surface working; only GWS-ID-005 renders Manual until the scope is added.

### Direct access token

```bash
export GWS_AUTH_MODE=access_token
export GWS_ACCESS_TOKEN="$(gcloud auth print-access-token)"
```

The bearer is used as supplied. Explicit tool arguments (`auth_mode`, `credentials_file`, `credentials_json`, `access_token`, `admin_email`, `domain`, `customer_id`, `lookback_days`) override the environment.

### Scopes

| Scope | Used for | Reference |
| --- | --- | --- |
| `admin.directory.user.readonly` | `users.list` | [users.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list) |
| `admin.directory.rolemanagement.readonly` | `roles.list`, `roleAssignments.list` | [roles.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/roles/list) |
| `admin.directory.user.security` | `tokens.list` | [tokens.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/list) |
| `admin.reports.audit.readonly` | `activities.list` | [activities.list](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list) |
| `apps.alerts` | `alerts.list` | [alerts.list](https://developers.google.com/workspace/admin/alertcenter/reference/rest/v1beta1/alerts/list) |
| `cloud-identity.policies.readonly` | `policies.list` | [policies.list](https://cloud.google.com/identity/docs/reference/rest/v1/policies/list) |

The interactive installed-app OAuth mode described in the spec is not shipped; see Limitations.

## Tools

| Tool | Purpose |
| --- | --- |
| `gws_check_access` | Probes each surface, reports `healthy` or `limited`, and says whether GWS-ID-005 can be evaluated automatically |
| `gws_assess_identity` | GWS-ID-001 to GWS-ID-005 |
| `gws_assess_admin_access` | GWS-ADMIN-001 to GWS-ADMIN-005 |
| `gws_assess_integrations` | GWS-INTEG-001 to GWS-INTEG-004 |
| `gws_assess_monitoring` | GWS-MON-001 to GWS-MON-005 |
| `gws_export_audit_bundle` | Runs all four assessments from one collection pass and writes the bundle; accepts `output_dir` and a `frameworks` filter |

## Control coverage

19 of 19 spec controls are automated. Status semantics: `Pass` means the documented flags support the control on the full inventory; `Partial` means the control holds only partially or the credential saw a partial view; `Fail` means the documented flags contradict the control; `Manual` means the verdict could not be reached automatically (unreadable endpoint, empty inventory, surface not collected) and the summary names the evidence a human must collect.

| # | Control | Tool | Finding | Pass condition | Manual when |
| --- | --- | --- | --- | --- | --- |
| 1 | Privileged users enforce 2-step verification | identity | GWS-ID-001 | Every privileged user has `isEnforcedIn2Sv=true` | Directory unreadable or no privileged user identified |
| 2 | Broad 2-step verification coverage for active users | identity | GWS-ID-002 | 98% or more of active users have `isEnforcedIn2Sv=true` | Directory unreadable or zero active users |
| 3 | Dormant active accounts stay limited | identity | GWS-ID-003 | No active user has `lastLoginTime` older than 90 days; users without a date cap the verdict at Partial | Directory unreadable or zero active users |
| 4 | Super admins stay strongly protected | identity | GWS-ID-004 | Every super admin (`isAdmin=true` or `_SEED_ADMIN_ROLE` assignment) has `isEnforcedIn2Sv=true` | Directory unreadable or no super admin identified |
| 5 | 2-step verification is enforced by organization policy | identity | GWS-ID-005 | Every `security.two_step_verification_enforcement` policy has `enforcedFrom` in the past and no enrollment policy sets `allowEnrollment=false` | Policy API unreadable, not collected, or no enforcement policy returned |
| 6 | Super admin population stays constrained | admin_access | GWS-ADMIN-001 | 4 or fewer super admins | Directory unreadable or no super admin identified |
| 7 | Suspended or archived privileged accounts are removed | admin_access | GWS-ADMIN-002 | No privileged user has `suspended=true` or `archived=true` | Directory unreadable or no privileged user identified |
| 8 | Delegated roles reduce Super Admin dependence | admin_access | GWS-ADMIN-003 | At least one privileged user is not a super admin | Directory unreadable or no delegated admin observed |
| 9 | Privileged activity stays observable | admin_access | GWS-ADMIN-004 | `activities.list` for `admin` returns at least one event in the window | Reports unreadable or zero events |
| 10 | Group-based admin grants get explicit review | admin_access | GWS-ADMIN-005 | Non-empty role assignment list with zero `assigneeType=GROUP` entries | Role assignments unreadable or empty; any group grant needs membership review |
| 11 | Third-party token inventory is readable | integrations | GWS-INTEG-001 | `tokens.list` succeeded for every sampled user and returned at least one token; Partial when `roles.list` or `roleAssignments.list` was unreadable | Directory unreadable, no users sampled, every read denied, or zero tokens |
| 12 | Privileged users avoid excessive third-party token exposure | integrations | GWS-INTEG-002 | Zero tokens on privileged users inside a non-empty inventory; failed per-user reads are named and turn the counts into lower bounds | Directory unreadable, no privileged users, empty inventory, or a failed read with no privileged token in sight |
| 13 | High-scope third-party apps stay limited | integrations | GWS-INTEG-003 | No token requests admin, Gmail, Drive, cloud-platform, groups, directory, Vault, Classroom, Sheets, or Docs scopes or 6 or more scopes; Partial when `roles.list` or `roleAssignments.list` was unreadable | Directory unreadable or empty inventory |
| 14 | Token activity telemetry stays available | integrations | GWS-INTEG-004 | `activities.list` for `token` returns at least one event | Reports unreadable or zero events |
| 15 | Alert Center is available for the tenant | monitoring | GWS-MON-001 | `alerts.list` returns at least one alert | Alert Center unreadable or zero alerts |
| 16 | Suspicious login backlog stays low | monitoring | GWS-MON-002 | Login events present and none match the suspicious event names from the login appendix | Reports unreadable or zero events |
| 17 | Admin audit telemetry stays available | monitoring | GWS-MON-003 | `activities.list` for `admin` returns at least one event | Reports unreadable or zero events |
| 18 | Token audit telemetry stays available | monitoring | GWS-MON-004 | `activities.list` for `token` returns at least one event | Reports unreadable or zero events |
| 19 | Open alert backlog is manageable | monitoring | GWS-MON-005 | 3 or fewer alerts whose `metadata.status` is not `CLOSED`; alerts without a status cap the verdict at Partial | Alert Center unreadable or zero alerts |

## Verdict-safety rules

Every finding applies these rules, and `cli/tests/gws.test.mjs` carries a regression test per rule plus the four-fixture false-pass self-check.

1. An unreadable, 401, 403, or errored endpoint never passes. The finding is Manual, names the endpoint and the missing scope or admin role, and lists the manual evidence. The same holds per item: when `tokens.list` fails for some sampled users, GWS-INTEG-001, GWS-INTEG-002, and GWS-INTEG-003 each name the failed users and the endpoint, GWS-INTEG-002 renders its privileged counts as lower bounds (`Privileged users with readable tokens.list: 1 of 2 (tokens.list failed: super@example.com)`), and the verdict stays below Pass. A listing that only orders the sample is still a dependency: when `roles.list` or `roleAssignments.list` is unreadable, the privileged-first token sample is not known to cover the privileged users, so GWS-INTEG-001 and GWS-INTEG-003 cap at Partial and name that endpoint in the summary.
2. An empty inventory never passes by default. Emptiness is compliant only inside a non-empty parent inventory (zero group grants among returned assignments, zero privileged tokens inside a non-empty token inventory, zero suspicious events inside a non-empty login log, zero dormant users among users with a known last login), and the summary says so.
3. A surface that was not collected in the run renders Manual (for example GWS-ID-005 without the Policy API scope).
4. Users without `lastLoginTime` and alerts without `metadata.status` are reported in a separate bucket and cap the verdict at Partial.
5. A partial view (user cap of 5000, truncated pages, denied per-user reads) is flagged with seen counts and caps the verdict at Partial.
6. Only the documented enabling flag counts: `isEnrolledIn2Sv` without `isEnforcedIn2Sv=true` does not support a pass, and an enforcement policy without a past `enforcedFrom` is not enforced.
7. Pagination follows `nextPageToken` until it is absent or the collection cap is hit; the cap is recorded as truncation.
8. Re-running the export allocates `-2`, `-3`, and so on and never overwrites an earlier directory or zip.
9. Bundle secret hygiene: every `core_data/` object is projected to the documented fields the verdicts read before it is written (Alert Center `data` payloads, `events[].parameters[]`, `actor.key`, and undocumented keys are never stored), then a second pass redacts credential-like keys matched on normalized names (`privateKey`, `refresh_token`, `clientSecret`) and `{name, value}` pairs whose name is credential-like. Every file in the bundle, not only `core_data/`, then passes through one text scrubber before it is written: the query string and fragment of every URL are removed whether the URL is the whole value or sits mid-prose, well-known credential shapes (bearer credentials, `ya29.` and `1//` tokens, `AIza` keys, `GOCSPX-` secrets, JWTs, PEM private keys) and `key=value` or `key: value` pairs naming a credential are replaced, and the run's own bearer token, service-account key, and every token minted during the run (including one a 401 evicted from the cache) are replaced wherever they appear. API error bodies are reduced at the client to the HTTP status plus documented identifiers (`error.status`, `errors[].reason`, `details[].reason`, or the RFC 6749 `error` code); an identifier is a bare `[A-Za-z][A-Za-z0-9_]*` value of at most 63 characters, so dotted, hyphenated, and path-shaped values are dropped, the HTTP reason phrase comes from a fixed RFC 9110 table rather than the server, the server's free-text `message` is never stored, and `_errors.log` names the failing endpoint on each line. Third-party OAuth `displayText` is scrubbed and paired with the documented `clientId` wherever a finding renders it. The tool path carries the same guarantee: every error string is scrubbed at the point it is created (`GwsApiError` scrubs its message in its constructor and `summarizeError` scrubs every other error, so dataset statuses, evidence lines, access probes, and tool error results inherit it), the `gws_check_access` and `gws_assess_*` results are redacted as objects before they are rendered, and a successful response whose body is not JSON is reported as `<status> with non-JSON <content type> body (N bytes) withheld` beside the endpoint rather than through a parser message that quotes the body.
10. Every cap exit reports `truncated: true`: the collection caps, a `nextPageToken` equal to the previous one (a stalled cursor), and a 1000-page ceiling all end the listing as truncation, and privileged verdicts (GWS-ID-001, GWS-ID-004, GWS-ADMIN-001 to 003, GWS-ADMIN-005, GWS-INTEG-002) cap at Partial when the user, role, or role-assignment listing was truncated.
11. Unreadable or never-collected data renders `null` with a status naming the read, never `0`, `[]`, or a default. Every count in the four assessment snapshot summaries carries a `<field>_status` companion that reads `complete: Directory users.list returned 4 record(s) across 1 page(s)`, `partial: at least 4; Directory users.list stopped at the collection cap after 3 page(s) with 4 seen, more pages exist`, `unreadable: Directory roles.list (403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions))`, or `not collected: Directory tokens.list was not called because Directory users.list was unreadable (...)`. A count is only as readable as its weakest source: one derived from users, roles, and role assignments is null when any of the three failed, and the rendered summary shows the status word (`- privileged_users: unreadable`) or the bound (`- active_users: at least 4`) instead of a number. `users_seen_partial_view` reads from the same collection status (`no`, `yes`, or `unreadable (Directory users.list (...))`), so a failed listing never renders as `no`. Evidence lines take the same form: `Token records collected: at least 1 (Directory tokens.list failed for 1 of 4 sampled users (user@example.com: 403 Forbidden ...))` whenever any per-user read failed, and `Token records collected: unreadable (Directory tokens.list failed for all 4 sampled users (...))` when none succeeded. `core_data/` files write an explicit marker for a failed read (see the bundle layout). `cli/tests/gws.test.mjs` sweeps 34 denial scenarios (eleven surfaces by three failure kinds plus the never-collected Policy API dataset) over every finding line, snapshot field, and `core_data/` file with two generic guards: no `0` or `[]` beside an unreadable, not collected, or unknown status, and no complete or partial status naming an endpoint the run never requested.

## Framework mappings

Each finding maps to FedRAMP (NIST 800-53), CMMC 2.0 (NIST 800-171), SOC 2, CIS Google Workspace Benchmark, PCI-DSS 4.0.1, DISA STIG SRG, IRAP (ISM), and ISMAP (ISO 27001). The full matrix is written to `compliance/unified_compliance_matrix.md` in every bundle. Examples:

| Finding | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GWS-ID-001 | IA-2, IA-2(1) | 3.5.3 | CC6.1 | 1.2 | 8.4.2 | SRG-APP-000149 | ISM-1504 | CPS.IA-2 |
| GWS-ID-005 | IA-2, IA-2(1), CM-6 | 3.5.3 | CC6.1 | 1.1 | 8.4.2 | SRG-APP-000149 | ISM-1504 | CPS.IA-2 |
| GWS-ADMIN-001 | AC-5, AC-6 | 3.1.5 | CC6.2 | 2.1 | 7.2.5 | SRG-APP-000033 | ISM-0414 | CPS.AC-6 |
| GWS-INTEG-002 | AC-6, SA-9 | 3.1.5 | CC6.2 | 4.2 | 7.2.5 | SRG-APP-000033 | ISM-0414 | CPS.AC-6 |
| GWS-MON-005 | IR-5, SI-4 | 3.6.2 | CC7.4 | 5.5 | 12.10.5 | SRG-APP-000516 | ISM-1807 | CPS.IR-5 |

## Audit bundle layout

`gws_export_audit_bundle` writes `<domain>-gws-audit/` under `output_dir` (default `./export/gws`) and a zip with the same name:

- `core_data/` API snapshots (`users.json`, `roles.json`, `role_assignments.json`, `login_activities.json`, `admin_activities.json`, `token_activities.json`, `token_inventory.json`, `alerts.json`, `two_step_verification_policies.json`), each a `{status, endpoint, data, seen, pages, truncated}` object whose `status` names the endpoint and reads `complete`, `partial`, `unreadable`, or `not collected`. A read that failed or never happened writes `error` and `errorKind` with `data`, `seen`, `pages`, and `truncated` all `null`, never `[]`, `0`, or `false` (verdict-safety rule 11). `token_inventory.json` adds `total`, `failed`, `failures` (per-user `userId`, `primaryEmail`, and the projected error), and `readable_users` (`3 of 4`); its `data` is null when every sampled read failed or the sample was never drawn, and its `truncated` is null whenever any read failed because the sample cap no longer describes completeness. Every record is projected to the documented fields listed under the endpoint reference and credential-like values are redacted (verdict-safety rule 9)
- `analysis/` `findings.json` plus one JSON and one Markdown summary per category
- `compliance/` `executive_summary.md`, `unified_compliance_matrix.md`, and one report per framework (`fedramp/`, `cmmc/`, `soc2/`, `disa_stig/`, `irap/`, `ismap/`, `pci_dss/`, `cis/`)
- `QUICK_REFERENCE.md`
- `_errors.log` only when at least one collection failed, one `<endpoint>: <status and reasons>` line per failure

Findings and collection errors are redacted as objects before any Markdown or JSON is rendered, and every file above passes through the same text scrubber on its way to disk (verdict-safety rule 9), so `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log`, and the zip entries carry the same guarantees as `core_data/`.

Pass `frameworks` (for example `["soc2", "cis"]`) to limit the per-framework reports. Output paths are validated against traversal and symlinked parents.

## Live smoke

```bash
npm --prefix cli run test:gws:live
```

Runs `gws_check_access`, all four assessments, and the export into a temp directory. Without `GWS_ACCESS_TOKEN` or a service-account file plus `GWS_ADMIN_EMAIL`, it prints a skip message and exits 0.

## Limitations and deferrals

- Installed-app OAuth (client secrets plus a stored refresh token) is deferred; use a delegated service account or a pre-obtained access token.
- Token inventory samples privileged users first and then active users, up to 50 users per run; the finding reports `seen` versus `total` and caps at Partial when the sample is smaller than the active population. The privileged-first ordering depends on `roles.list` and `roleAssignments.list`; when either is unreadable, only the `isAdmin` and `isDelegatedAdmin` flags order the sample, and GWS-INTEG-001 and GWS-INTEG-003 cap at Partial for that reason.
- Error projection keeps any bare identifier of at most 63 characters found in `error.status`, `errors[].reason`, `details[].reason`, or the RFC 6749 `error` code, because those fields are documented as identifiers. A server-controlled value in one of those fields that has no `.`, `-`, or `/` and matches no credential shape would be rendered verbatim into `_errors.log`, `analysis/`, `compliance/executive_summary.md`, and the failing `core_data/` file; the free-text `message` fields and the server's HTTP reason phrase are never rendered.
- The user listing stops at 5000 users, roles at 1000, role assignments at 10000, activity listings at 5000 records, alerts at 1000, and policies at 1000, and no listing follows more than 1000 pages or a cursor that stops advancing; every such exit is recorded as truncation and caps dependent verdicts at Partial.
- GWS-ADMIN-005 does not expand group membership; any group-based admin grant renders Manual for a membership review.
- Chrome Policy API (`chromepolicy/v1`) and Cloud Identity device surfaces listed in the spec are not called; no shipped control depends on them.
- Alert Center `pageSize` has no documented maximum ([alerts.list](https://developers.google.com/workspace/admin/alertcenter/reference/rest/v1beta1/alerts/list)); grclanker requests 100 and follows `nextPageToken`.

## Endpoint reference

| Endpoint | Documentation | Parameters sent | Fields read |
| --- | --- | --- | --- |
| `GET https://admin.googleapis.com/admin/directory/v1/users` | [users.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list), [User](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users) | `customer`, `maxResults=500` (documented maximum), `orderBy=email`, `sortOrder=ASCENDING`, `projection=basic`, `showDeleted=false`, `fields`, `pageToken` | `users[].id`, `primaryEmail`, `isAdmin`, `isDelegatedAdmin`, `suspended`, `archived`, `lastLoginTime`, `isEnrolledIn2Sv`, `isEnforcedIn2Sv`, `orgUnitPath`, `nextPageToken` |
| `GET .../admin/directory/v1/customer/{customer}/roles` | [roles.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/roles/list) | `maxResults=100` (documented maximum), `pageToken` | `items[].roleId`, `roleName`, `isSystemRole`, `isSuperAdminRole`, `rolePrivileges[].privilegeName`, `nextPageToken` |
| `GET .../admin/directory/v1/customer/{customer}/roleassignments` | [roleAssignments.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/roleAssignments/list) | `maxResults=200` (documented maximum), `pageToken` | `items[].roleId`, `assignedTo`, `assigneeType` (`USER` or `GROUP`), `nextPageToken` |
| `GET .../admin/directory/v1/users/{userKey}/tokens` | [tokens.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/list), [Token](https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens) | none | `items[].clientId`, `displayText`, `scopes[]` |
| `GET .../admin/reports/v1/activity/users/all/applications/{login,admin,token}` | [activities.list](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list), [login events](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login) | `startTime` (RFC 3339), `maxResults=1000` (documented maximum), `pageToken` | `items[].events[].name`, `nextPageToken` |
| `GET https://alertcenter.googleapis.com/v1beta1/alerts` | [alerts.list](https://developers.google.com/workspace/admin/alertcenter/reference/rest/v1beta1/alerts/list), [Alert](https://developers.google.com/workspace/admin/alertcenter/reference/rest/v1beta1/alerts) | `pageSize=100`, `pageToken` | `alerts[].metadata.status` (`NOT_STARTED`, `IN_PROGRESS`, `CLOSED`), `nextPageToken` |
| `GET https://cloudidentity.googleapis.com/v1/policies` | [policies.list](https://cloud.google.com/identity/docs/reference/rest/v1/policies/list), [Policy](https://cloud.google.com/identity/docs/reference/rest/v1/policies), [settings catalog](https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings) | `pageSize=100` (documented maximum), `filter=customer == "customers/{customer}" && setting.type.matches('^settings/security\\.two_step_verification.*$')`, `pageToken` | `policies[].type`, `policyQuery.orgUnit`, `policyQuery.group`, `setting.type`, `setting.value.enforcedFrom`, `setting.value.allowEnrollment`, `setting.value.allowedSignInFactorSet`, `nextPageToken` |
| `POST https://oauth2.googleapis.com/token` | [service account delegation](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority) | `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion` | `access_token`, `expires_in` |

`core_data/` stores the fields read above plus these documented identifiers and timestamps from the same resource references, and nothing else: roles `rolePrivileges[].serviceId`; role assignments `roleAssignmentId`, `scopeType`, `orgUnitId`; tokens `anonymous`, `nativeApp`, `userKey`; activities `id.time`, `id.uniqueQualifier`, `id.applicationName`, `id.customerId`, `actor.email`, `actor.profileId`, `actor.callerType`, `actor.applicationInfo.applicationName`, `ipAddress`, `events[].type`; alerts `alertId`, `customerId`, `createTime`, `startTime`, `endTime`, `updateTime`, `type`, `source`, `deleted`, `metadata.alertId`, `metadata.customerId`, `metadata.assignee`, `metadata.updateTime`, `metadata.severity`; policies `name`, `customer`, `policyQuery.query`, `policyQuery.sortOrder`.
