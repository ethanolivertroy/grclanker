---
title: Okta
description: Read-only Okta security inspection covering authentication, admin access, integrations, and monitoring, mapped to FedRAMP, DISA STIG, IRAP, ISMAP, SOC 2, and PCI-DSS, with an OSCAL assessment-results export.
---

The Okta integration inspects an Okta org through the Okta Management API and reports posture findings for the controls defined in `specs/okta-sec-inspector.spec.md`. Every tool is read-only: nothing is created, changed, or deleted in the tenant, and no tenant data is written to disk unless you run `okta_export_audit_bundle`.

## What it inspects

- **Authentication**: phishing-resistant authenticators, ACTIVE admin MFA rules, password complexity, age, history, and lockout, session idle timeout and lifetime, certificate or PIV/CAC readiness, and FIPS or restricted authenticator posture (Okta Verify `compliance.fips`, SMS, voice, security question, and email).
- **Admin access**: SUPER_ADMIN concentration, stale privileged accounts, privileged group size, per-administrator factor enrollment, the full workforce user population (stale, never-activated, suspended, and locked accounts), and Okta Support or third-party administrator access.
- **Integrations**: trusted origins, network zones, OIDC grant types, contextual access rules, application inventory hygiene, and provisioning or deprovisioning automation (app provisioning features plus group rules).
- **Monitoring**: log streams and event hooks, System Log visibility, ThreatInsight, behavior rules, API token age, expiry, inactivity window, and network restriction, device assurance, and security contact routing.

Findings are normalized as `{ id, title, category, status, severity, summary, evidence, recommendation, manualNote, frameworks }` where `status` is `Pass | Partial | Fail | Manual | Info`. A `Manual` finding always names the cause and the evidence to collect.

### Verdict safety

The assessors follow these rules so a verdict never rests on missing or partial evidence:

1. An unreadable, forbidden, or errored endpoint never yields `Pass`; it yields `Manual` naming the HTTP cause (403, 401, 404) and the evidence to collect.
2. An empty inventory never yields `Pass` by default. Inventories Okta always populates (password policies, network zones, apps, privileged users, users, org contacts, the audit SSWS token) render `Manual` because emptiness indicates a scoped read. Inventories whose emptiness is a real gap (authenticators, log streams and hooks) render `Fail`. The only intentional empty `Pass` is zero SSWS API tokens when auditing through an OAuth service app.
3. Controls unavailable on the org edition (Classic Engine authenticators, ThreatInsight, device assurance, behavior detection, Okta Support settings returning 404) render `Manual`.
4. Items missing a date (`lastLogin`, `created`, `expiresAt`, `lastUpdated`) are never counted fresh; they cap the finding at `Partial`.
5. Partial inventories (a truncated user listing, capped factor or group expansion, failed per-item lookups) cap the finding at `Partial` and list the gap in evidence.
6. Every status flag the verdict depends on is read: policy, rule, authenticator, app, user, zone, log stream, event hook, behavior, and factor status.
7. Pagination follows the `Link: rel="next"` header to completion within a 50-page cap per list (200 items per page). The System Log is queried as a bounded window (`since` 30 days ago, `until` now) and capped at 5 pages because OKTA-MON-002 needs only a recent sample. A walk that hits its cap with a next page unread, sees a `rel="next"` cursor it already visited, or gets an empty page that still advertises a next link stops and is recorded as truncated with the note `GET <path> stopped after <pages> pages (<items> items): <reason>, total unknown`; every finding that reads that inventory caps at `Partial`, the note is appended to its summary as `Inventory truncated: ...` and to its evidence as `Partial data: ...`, and `_errors.log` lists it as `Truncated inventory: ...`. `core_data/` records have credential fields (client secrets, passwords, hook header values, tokens) replaced by `[REDACTED]`, event hook URIs reduced to scheme and host, and System Log events projected to identity and outcome fields (see Export bundle).
8. Re-running the export never overwrites a prior bundle; the zip name is derived from the newly allocated directory.
9. A dataset that was denied, errored, or never requested is never confused with an empty one. Its `core_data/` file is a marker object (`{ collected: false, status, endpoint, error }`) rather than `[]`, every counter derived from it renders `null` (the assess tool `snapshot` and `core_data/collection_status.json`, never `0` or `truncated: false`), and every HTTP status or endpoint named anywhere in the output comes from a request the run actually made: markers, probe results, and `Manual` causes carry the failed request's own status and path, and a per-parent list that was skipped because its parent was unreadable says so without inventing a status or endpoint.

## Setup and authentication

Two auth modes are supported, matching the Okta CLI configuration model.

### SSWS API token

Create a read-only administrator (Read-only Administrator or a custom role with the read permissions below) and issue an API token under Security > API > Tokens. Set:

```bash
export OKTA_CLIENT_ORGURL=https://your-org.okta.com
export OKTA_CLIENT_TOKEN=00abc...
```

### OAuth service app with private key JWT

Create an API Services app (Applications > Create App Integration > API Services), enable the scopes below, grant the app a read-only admin role, and register a public key. Set:

```bash
export OKTA_CLIENT_ORGURL=https://your-org.okta.com
export OKTA_CLIENT_AUTHORIZATIONMODE=PrivateKey
export OKTA_CLIENT_CLIENTID=0oa...
export OKTA_CLIENT_PRIVATEKEY="-----BEGIN PRIVATE KEY-----\n..."
export OKTA_CLIENT_PRIVATEKEYID=kid-optional
```

grclanker signs an RS256 client assertion with `node:crypto`, requests `client_credentials` tokens from `/oauth2/v1/token`, caches them until shortly before expiry, and refreshes on 401. Pass `client_assertion` (or `OKTA_CLIENT_CLIENTASSERTION`) to supply a pre-signed JWT instead.

### Config discovery order

Later sources override earlier ones field by field:

1. `~/.okta/okta.yaml`
2. project `.okta.yaml`
3. environment variables (`OKTA_CLIENT_ORGURL`, `OKTA_CLIENT_TOKEN`, `OKTA_CLIENT_AUTHORIZATIONMODE`, `OKTA_CLIENT_CLIENTID`, `OKTA_CLIENT_PRIVATEKEY`, `OKTA_CLIENT_PRIVATEKEYID`, `OKTA_CLIENT_CLIENTASSERTION`, `OKTA_CLIENT_SCOPES`)
4. explicit tool arguments (`org_url`, `auth_mode`, `api_token`, `client_id`, `private_key`, `private_key_id`, `client_assertion`, `scopes`, or `config_file` to bypass the default YAML locations)

```yaml
okta:
  client:
    orgUrl: https://your-org.okta.com
    authorizationMode: PrivateKey
    clientId: 0oa...
    privateKey: |
      -----BEGIN PRIVATE KEY-----
      ...
    scopes:
      - okta.users.read
```

### Default OAuth read scopes

`okta.users.read`, `okta.groups.read`, `okta.apps.read`, `okta.authenticators.read`, `okta.authorizationServers.read`, `okta.idps.read`, `okta.trustedOrigins.read`, `okta.policies.read`, `okta.logs.read`, `okta.eventHooks.read`, `okta.logStreams.read`, `okta.orgs.read`, `okta.networkZones.read`, `okta.behaviors.read`, `okta.deviceAssurance.read`, `okta.roles.read`, `okta.apiTokens.read`, `okta.threatInsights.read`.

Run `okta_check_access` first; it probes users, policies, logs, role assignees, and API tokens and reports each surface separately so partial grants are visible before you run an assessment.

## Tools

| Tool | Purpose |
| --- | --- |
| `okta_check_access` | Resolves configuration, authenticates, and probes five read surfaces. Each probe reports `status` (`ok`, `forbidden`, `unauthorized`, or `error`), the error text, and `httpStatus`: the status code the failed request actually returned, `null` when the probe was readable or the failure carried no status. Reports `healthy` (three or more readable) or `limited` with a recommended next step. |
| `okta_assess_authentication` | OKTA-AUTH-001 through OKTA-AUTH-009. |
| `okta_assess_admin_access` | OKTA-ADMIN-001 through OKTA-ADMIN-006, including the paginated user population and per-admin factor enrollment. |
| `okta_assess_integrations` | OKTA-INTEG-001 through OKTA-INTEG-006. |
| `okta_assess_monitoring` | OKTA-MON-001 through OKTA-MON-009. |
| `okta_export_audit_bundle` | Runs all four assessments and writes `core_data/` (one file per dataset plus `collection_status.json`), `analysis/`, `compliance/` (executive summary, unified matrix, per-framework reports, `fedramp/oscal_assessment_results.json`), `QUICK_REFERENCE.md`, `_errors.log` on partial collection, and a zip archive under `./export/okta` (override with `output_dir`). |

All tools accept the same optional auth arguments listed above.

### Export bundle

`core_data/` holds one JSON file per collected dataset in one of three shapes: a list (`sign_on_policies`, `password_policies`, `mfa_enrollment_policies`, `access_policies`, `authenticators`, `idps`, `authorization_servers`, `org_factors`, `users_with_role_assignments`, `groups`, `users`, `apps`, `trusted_origins`, `network_zones`, `group_rules`, `event_hooks`, `log_streams`, `system_logs_recent`, `behaviors`, `api_tokens`, `device_assurance`, `org_contacts`), a per-parent map keyed by the parent id (`sign_on_policy_rules`, `password_policy_rules`, `access_policy_rules`, `user_roles`, `privileged_group_roles`, `privileged_group_members`, `privileged_user_factors`), or a single object (`default_authorization_server`, `okta_support_access`, `third_party_admin_setting`, `threat_insight`). `analysis/<category>.json` holds each assessment's findings, summary counts, text, and `snapshotSummary`; `analysis/findings.json` merges every finding.

Records are redacted when they are collected and every JSON document is passed through the same scrubber again when it is written. The value of every credential-named key is replaced by `[REDACTED]`: the key is normalized to lowercase with dots, underscores, and hyphens removed and matched on the suffixes `password`, `passwd`, `passphrase`, `secret`, `token`, `apikey`, `privatekey`, `secretkey`, `secrethash`, `clientassertion`, `authorization`, and `answer`, so app `credentials.oauthClient.client_secret`, `credentials.password`, IdP `protocol.credentials.client.client_secret`, and any `secret_hash` are caught while password policy `settings.password.{complexity, age, lockout}` is kept for OKTA-AUTH-003 through 005. `{key, value}` and `{name, value}` pairs whose name is credential-shaped have their value replaced, JWT-shaped and SSWS-token-shaped strings are replaced, and every URL keeps only scheme, host, and path with userinfo and query string replaced. Two datasets are projected rather than stored verbatim: an event hook keeps its record but `channel.config` is rebuilt as `uri` reduced to scheme and host, `method`, `headers[]` with every `value` replaced, and, when present, `authScheme` with `type`, `key`, and a replaced `value`; System Log events keep `uuid`, `published`, `eventType`, `displayMessage`, `severity`, `outcome.result` and `outcome.reason`, `actor` (`id`, `type`, `alternateId`, `displayName`), and `client.ipAddress`, dropping `debugContext`, `request`, `target`, and `securityContext`.

A dataset that was denied, errored, or never requested is written as the marker `{ collected: false, status, endpoint, error }` in place of its list, map, or object, where `status` and `endpoint` are the HTTP status and path of the request that actually failed (both `null` when the client could not issue the request, or when the dataset was skipped because the inventory it hangs off was not collected, in which case `error` starts with `Not requested:` and names the parent's failure). A readable but empty list stays `[]`. In a per-parent map a denied child is omitted from the collected children and recorded as a marker under its parent id; `org_contacts.json` appends a marker with the contact type as `id` for each contact whose assignment lookup failed. `core_data/collection_status.json` has one row per file with `file`, `shape`, `collected`, `complete`, `count`, `truncated`, `truncation_note`, `status`, `endpoint`, and `error`, plus `not_collected` and `truncated` file lists; a dataset that was not collected renders `null` for `complete`, `count`, `truncated`, and `truncation_note` (never `0` or `false`), and a single object renders `null` for `count` and `truncated`. Each assessment's `snapshotSummary` renders `null` for every counter derived from a dataset that was not collected (for example `system_log_events`, `api_tokens`, `device_assurance_policies`, `org_contacts_resolved`) and `not collected` for labels such as `threat_insight_mode`, and adds `datasets_not_collected` beside `dataset_errors`; the assessment text prints those values as `not collected`.

## Control coverage

Every row below is also subject to the truncation demotion of rule 7: when any inventory the finding reads was truncated, a `Pass` caps at `Partial` and the summary and evidence carry the walk's note. The inventories each finding reads for this purpose are: authenticators and org factors for AUTH-001 and AUTH-009; sign-on and access policies, their rules, authenticators, and MFA enrollment policies for AUTH-002; password policies for AUTH-003 through AUTH-005; sign-on policies and rules for AUTH-006 and AUTH-007; IdPs and authenticators for AUTH-008; role assignees and per-user roles for ADMIN-001 and ADMIN-002; groups, privileged groups, their roles, and their members for ADMIN-003; role assignees and per-user factors for ADMIN-004; users for ADMIN-005; trusted origins for INTEG-001; network zones for INTEG-002; apps for INTEG-003 and INTEG-005; sign-on and access policies, their rules, and network zones for INTEG-004; apps and group rules for INTEG-006; event hooks and log streams for MON-001; the System Log sample for MON-002; behaviors for MON-004; API tokens for MON-005 and MON-007; device assurance policies for MON-006; org contacts for MON-008. A `Manual` verdict caused by an unreadable dataset names that dataset's own failure: `the endpoint returned 403 Forbidden`, `401 Unauthorized`, or `404 Not Found` only when the request observed that status, `the collector did not expose this endpoint` when the client has no method for it, and `the inventory it depends on was not collected, so its request was never issued` for a per-parent list whose parent was unreadable.

| Spec control | Tool | Finding | Status semantics |
| --- | --- | --- | --- |
| Phishing-resistant authenticator coverage | `okta_assess_authentication` | OKTA-AUTH-001 | Pass when an ACTIVE WebAuthn, FIDO2, smart card, or certificate authenticator exists; Partial for strong but not phishing-resistant; Fail when none or the inventory is empty; Manual on 403 or Classic Engine. |
| Administrator MFA enforcement | `okta_assess_authentication` | OKTA-AUTH-002 | Manual when both the sign-on and the access policy lists are unreadable (the summary names the observed cause and evidence lists every policy error). Pass only when an ACTIVE Admin Console or Dashboard policy has an ACTIVE rule with `requireFactor` or `factorMode: 2FA`, strong authenticators exist, and every policy and rule dataset was read without error. Partial when admin policies exist but no ACTIVE rule requires MFA, when MFA rules exist but the authenticator list was unreadable (the summary says so and evidence records `Strong authenticators: unknown (authenticator list unreadable)` plus the authenticator error), or when any policy or rule list failed (`Partial policy data: ...`); Partial when MFA enrollment policies or strong authenticators exist without an admin policy; Fail otherwise. |
| Password complexity | `okta_assess_authentication` | OKTA-AUTH-003 | Evaluates ACTIVE password policies only (min length 12, upper, lower, number, symbol); Fail when none are ACTIVE; Manual on 403 or an empty list. |
| Password age and history | `okta_assess_authentication` | OKTA-AUTH-004 | Max age 90 days or less and history of 5 or more on every ACTIVE policy. |
| Password lockout thresholds | `okta_assess_authentication` | OKTA-AUTH-005 | Lockout at 6 attempts or fewer on every ACTIVE policy. |
| Session idle timeout | `okta_assess_authentication` | OKTA-AUTH-006 | 15 minutes or less across ACTIVE sign-on rules; Manual when rules return no session settings; capped at Partial when rule reads partially failed. |
| Session lifetime and persistent cookies | `okta_assess_authentication` | OKTA-AUTH-007 | 18 hours or less and no persistent cookies across ACTIVE sign-on rules. |
| PIV/CAC or certificate readiness | `okta_assess_authentication` | OKTA-AUTH-008 | Manual when both the IdP and the authenticator lists are unreadable (both errors in evidence). Pass on an ACTIVE certificate IdP or authenticator; when only one of the two lists was readable the Pass summary says `(one source was unreadable; see evidence)` and evidence records `IdP data unavailable: ...` or `Authenticator data unavailable: ...`. Fail on federal domains (`okta-gov.com`, `okta.gov`, `okta.mil`) without one; Manual elsewhere; both non-Pass branches also list the unreadable half in evidence. |
| Okta Gov and FIPS heuristics (follow-on) | `okta_assess_authentication` | OKTA-AUTH-009 | Federal domains Pass only with Okta Verify `compliance.fips: REQUIRED` and no ACTIVE SMS, voice, security question, or email authenticator (email limited to recovery is allowed); commercial domains Partial when restricted authenticators are ACTIVE; Manual on Classic Engine or 403. |
| SUPER_ADMIN concentration | `okta_assess_admin_access` | OKTA-ADMIN-001 | 2 or fewer Pass, 3 to 5 Partial, more Fail; Manual on 403 or an empty assignee list; capped at Partial when role lookups fail. |
| Stale or inactive privileged users | `okta_assess_admin_access` | OKTA-ADMIN-002 | Fail on non-ACTIVE status or no sign-in in 90 days; Partial when `lastLogin` is missing; Manual when the assignee list is unavailable. |
| Privileged group hygiene | `okta_assess_admin_access` | OKTA-ADMIN-003 | Partial when a role-bearing group exceeds 25 members or expansion was capped at 25 groups; Manual when no admin-like group name matched. |
| Admin MFA enrollment (follow-on) | `okta_assess_admin_access` | OKTA-ADMIN-004 | Reads `/users/{id}/factors` for up to 50 privileged users; Fail when any has no ACTIVE factor; Partial when any lacks a phishing-resistant factor or the set was truncated. |
| Lifecycle hygiene (follow-on) | `okta_assess_admin_access` | OKTA-ADMIN-005 | Paginates `/users`; Fail on ACTIVE users idle 90 days or PROVISIONED/STAGED accounts older than 30 days; Partial for missing `lastLogin`, suspended, locked, expired, or recovery accounts, or a truncated listing; Manual on 403 or an empty list. |
| Okta Support and third-party admin (follow-on) | `okta_assess_admin_access` | OKTA-ADMIN-006 | Reads `/org/privacy/oktaSupport` (`support`) and `/org/orgSettings/thirdPartyAdminSetting` (`thirdPartyAdmin`). Pass only when support is DISABLED and `thirdPartyAdmin` is false; Partial when support is ENABLED (with expiration in evidence) or when the third-party setting returns 403/404 (the HTTP cause is named); Manual when the Okta Support setting is unreadable or absent. |
| Trusted-origin hygiene | `okta_assess_integrations` | OKTA-INTEG-001 | Fail on ACTIVE `http://` or wildcard origins; Info when none exist; Manual on 403. |
| Custom network-zone coverage | `okta_assess_integrations` | OKTA-INTEG-002 | Pass with an ACTIVE non-system zone; Partial with only system, legacy, or inactive zones; Manual on 403 or an empty list. |
| Risky OIDC grant types | `okta_assess_integrations` | OKTA-INTEG-003 | Fail when an ACTIVE app uses `password` or `implicit`; Partial when only inactive apps do; Manual on 403 or an empty app list. |
| Contextual access conditions | `okta_assess_integrations` | OKTA-INTEG-004 | Pass when an ACTIVE rule under an ACTIVE policy uses risk, device, network, or auth-context conditions; capped at Partial on partial rule data. |
| Inactive application review | `okta_assess_integrations` | OKTA-INTEG-005 | Partial when any app is not ACTIVE; Manual on 403 or an empty list. |
| Lifecycle automation (follow-on) | `okta_assess_integrations` | OKTA-INTEG-006 | Manual when the app list is unreadable (its own status named) or empty. Pass when an ACTIVE app has `PUSH_USER_DEACTIVATION` and the group rule list was readable; with group rules unreadable the Pass caps at Partial, the summary adds `group rules were unreadable, so rule-driven assignment automation could not be confirmed`, and evidence records `ACTIVE group rules: unread (<error>)` instead of a count. Fail when provisioning-enabled apps never push deactivation; Partial when no ACTIVE app exposes provisioning features. |
| Log streaming and SIEM forwarding | `okta_assess_monitoring` | OKTA-MON-001 | Pass with an ACTIVE log stream; Partial with only ACTIVE event hooks; Fail when both inventories are empty; Manual when both are unreadable. |
| System Log visibility | `okta_assess_monitoring` | OKTA-MON-002 | Manual when `/api/v1/logs` could not be read (the observed status is named). Reads a bounded window (`since` 30 days ago, `until` now, 200 events per page, 5 pages at most). Pass when events were returned and the walk finished within the window; when the walk stopped at the 5-page cap, on a repeated cursor, or on an empty page with a next link the verdict caps at Partial and the summary states `Retrieved at least N system log events from the last 30 days (page-capped sample, total unknown)` followed by the walk's note; Partial when zero events were returned. |
| ThreatInsight mode | `okta_assess_monitoring` | OKTA-MON-003 | Manual when `/api/v1/threats/configuration` could not be read (the observed status is named) or returned no object (feature not available on the org edition); `block` Pass, `audit` or `log_only` Partial, any other action Fail; evidence records the action, excluded zone count, and `lastUpdated`. |
| Behavior rule coverage | `okta_assess_monitoring` | OKTA-MON-004 | Pass with an ACTIVE behavior rule; Partial otherwise; Manual on 403 or 404. |
| API token hygiene | `okta_assess_monitoring` | OKTA-MON-005 | Partial when a token is older than 90 days or has no date metadata; Manual on 403 or an empty list in SSWS mode; Pass on an empty list only in OAuth mode. |
| Token expiry and network restriction (follow-on) | `okta_assess_monitoring` | OKTA-MON-007 | Fail on tokens past `expiresAt`; Partial for `network.connection` other than `ZONE`, missing expiry, or `tokenWindow` over 30 days. |
| Device assurance coverage | `okta_assess_monitoring` | OKTA-MON-006 | Manual when `/api/v1/device-assurances` could not be read (the observed status is named, 404 meaning the org edition does not support it); Pass with at least one policy on a complete list (a truncated list caps at Partial); Partial when none. |
| Security contact routing (follow-on) | `okta_assess_monitoring` | OKTA-MON-008 | Manual when the contact type list could not be read (its own status named) or returned zero contact types. Each contact type is resolved through `/api/v1/org/contacts/{type}` and the assigned user; Pass when the TECHNICAL contact resolves to an ACTIVE user and every resolution succeeded. Partial when the TECHNICAL lookup itself failed (reported as a permission gap, `The technical contact lookup failed, so the assignment could not be verified`, never as an unassigned contact), when the contact user's status could not be read, or when any other contact's resolution failed (a Pass caps at Partial and evidence records `Contact resolution errors: ...`); Fail when the TECHNICAL contact is unassigned or its user is not ACTIVE. |
| Admin notification emails (follow-on) | `okta_assess_monitoring` | OKTA-MON-009 | Always Manual; the Management API does not expose Security notification email or Admin notification settings. |

## Framework mappings

Every finding carries FedRAMP / NIST SP 800-53, DISA STIG, IRAP / ISM, ISMAP, SOC 2, PCI-DSS, and general mappings. The bundle renders them as `compliance/unified_compliance_matrix.md`, one markdown report per framework, and `compliance/fedramp/oscal_assessment_results.json`, an OSCAL 1.1.2 assessment-results document whose findings target NIST objective ids (for example `ia-2.11_obj`) with `satisfied` for Pass and `not-satisfied` with a `reason` of `partial`, `fail`, `manual`, or `info` otherwise.

## Live smoke

```bash
npm --prefix cli run test:okta:live
```

The script skips with exit code 0 when no Okta configuration is present. With credentials it runs `okta_check_access`, then all four assess tools, prints every finding, and fails if any Manual finding lacks the evidence to collect.

## Limitations and manual controls

- The default `/api/v1/users` listing excludes DEPROVISIONED users; reviewing deprovisioned accounts requires a status filter.
- The user listing stops after 50 pages (10,000 users) and records the truncation; factor enrollment is read for the first 50 privileged users; admin-like groups are expanded up to 25.
- Admin-like groups are discovered by name pattern (`admin`, `administrator`, `privileged`, `help desk`, `security`, `access`).
- Okta Workflows and HR-driven lifecycle flows are not visible through the Management API; OKTA-INTEG-006 uses app provisioning features and group rules as the observable evidence.
- Security notification emails and admin notification preferences are not exposed by the API (OKTA-MON-009 is always Manual).
- Okta Verify FIPS compliance is only exposed on Identity Engine orgs; Classic Engine orgs render the FIPS finding Manual.
- The org-level factor listing (`GET /api/v1/org/factors`) is a legacy Classic Engine endpoint that is not in Okta's published OpenAPI spec; it is only used to detect Classic Engine orgs, and a 404 on it is counted in the snapshot's `dataset_errors` without changing any finding status.
- Framework mappings are check-level evidence pointers, not attestations.

## Official documentation

- [Okta Management API pagination](https://developer.okta.com/docs/api/#pagination)
- [Users API: list users](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listUsers)
- [User Factors API: list factors](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserFactor/#tag/UserFactor/operation/listFactors)
- [API Tokens API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApiToken/)
- [Org Settings API: third-party admin setting (`OrgSettingAdmin`)](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/OrgSettingAdmin/)
- [Org Settings API: Okta Support access (`OrgSettingSupport`)](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/OrgSettingSupport/)
- [Org Settings API: contacts (`OrgSettingContact`)](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/OrgSettingContact/)
- [Authenticators API (Okta Verify compliance.fips, allowedFor)](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Authenticator/)
- [Log Streams API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/LogStream/)
- [Applications API (features, oauthClient.grant_types)](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/)
- [Group Rules API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/GroupRule/)
- [Policies API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/)
- [OAuth 2.0 for Okta API service apps](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/)
- [OSCAL assessment results model](https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-results/)
