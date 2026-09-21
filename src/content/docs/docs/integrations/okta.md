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
7. Pagination follows the `Link: rel="next"` header to completion within a 50-page cap per list (5 pages for the bounded System Log sample); a walk that hits its cap, sees a repeated cursor, or gets an empty page with a next link is recorded as truncated and every finding that reads it caps at `Partial` with a total-unknown statement. `core_data/` records have credential fields (client secrets, passwords, hook header values, tokens) replaced by `[REDACTED]`, event hook URIs reduced to scheme and host, and System Log events projected to identity and outcome fields.
8. Re-running the export never overwrites a prior bundle; the zip name is derived from the newly allocated directory.

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
| `okta_check_access` | Resolves configuration, authenticates, and probes five read surfaces. Reports `healthy` or `limited` with a recommended next step. |
| `okta_assess_authentication` | OKTA-AUTH-001 through OKTA-AUTH-009. |
| `okta_assess_admin_access` | OKTA-ADMIN-001 through OKTA-ADMIN-006, including the paginated user population and per-admin factor enrollment. |
| `okta_assess_integrations` | OKTA-INTEG-001 through OKTA-INTEG-006. |
| `okta_assess_monitoring` | OKTA-MON-001 through OKTA-MON-009. |
| `okta_export_audit_bundle` | Runs all four assessments and writes `core_data/`, `analysis/`, `compliance/` (executive summary, unified matrix, per-framework reports, `fedramp/oscal_assessment_results.json`), `QUICK_REFERENCE.md`, `_errors.log` on partial collection, and a zip archive under `./export/okta` (override with `output_dir`). |

All tools accept the same optional auth arguments listed above.

## Control coverage

| Spec control | Tool | Finding | Status semantics |
| --- | --- | --- | --- |
| Phishing-resistant authenticator coverage | `okta_assess_authentication` | OKTA-AUTH-001 | Pass when an ACTIVE WebAuthn, FIDO2, smart card, or certificate authenticator exists; Partial for strong but not phishing-resistant; Fail when none or the inventory is empty; Manual on 403 or Classic Engine. |
| Administrator MFA enforcement | `okta_assess_authentication` | OKTA-AUTH-002 | Pass only when an ACTIVE Admin Console or Dashboard policy has an ACTIVE rule with `requireFactor` or `factorMode: 2FA` and strong authenticators exist; Partial when policies exist without an enforcing rule or with partial rule data; Manual when policies are unreadable. |
| Password complexity | `okta_assess_authentication` | OKTA-AUTH-003 | Evaluates ACTIVE password policies only (min length 12, upper, lower, number, symbol); Fail when none are ACTIVE; Manual on 403 or an empty list. |
| Password age and history | `okta_assess_authentication` | OKTA-AUTH-004 | Max age 90 days or less and history of 5 or more on every ACTIVE policy. |
| Password lockout thresholds | `okta_assess_authentication` | OKTA-AUTH-005 | Lockout at 6 attempts or fewer on every ACTIVE policy. |
| Session idle timeout | `okta_assess_authentication` | OKTA-AUTH-006 | 15 minutes or less across ACTIVE sign-on rules; Manual when rules return no session settings; capped at Partial when rule reads partially failed. |
| Session lifetime and persistent cookies | `okta_assess_authentication` | OKTA-AUTH-007 | 18 hours or less and no persistent cookies across ACTIVE sign-on rules. |
| PIV/CAC or certificate readiness | `okta_assess_authentication` | OKTA-AUTH-008 | Pass on an ACTIVE certificate IdP or authenticator; Fail on federal domains (`okta-gov.com`, `okta.gov`, `okta.mil`) without one; Manual elsewhere. |
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
| Lifecycle automation (follow-on) | `okta_assess_integrations` | OKTA-INTEG-006 | Pass when an ACTIVE app has `PUSH_USER_DEACTIVATION`; Fail when provisioning-enabled apps never push deactivation; Partial when no app exposes provisioning features; group rules are supporting evidence. |
| Log streaming and SIEM forwarding | `okta_assess_monitoring` | OKTA-MON-001 | Pass with an ACTIVE log stream; Partial with only ACTIVE event hooks; Fail when both inventories are empty; Manual when both are unreadable. |
| System Log visibility | `okta_assess_monitoring` | OKTA-MON-002 | Pass when events exist in the 30-day window; Partial when zero; Manual on 403. |
| ThreatInsight mode | `okta_assess_monitoring` | OKTA-MON-003 | `block` Pass, `audit` Partial, `none` Fail; Manual when the configuration is unreadable or absent. |
| Behavior rule coverage | `okta_assess_monitoring` | OKTA-MON-004 | Pass with an ACTIVE behavior rule; Partial otherwise; Manual on 403 or 404. |
| API token hygiene | `okta_assess_monitoring` | OKTA-MON-005 | Partial when a token is older than 90 days or has no date metadata; Manual on 403 or an empty list in SSWS mode; Pass on an empty list only in OAuth mode. |
| Token expiry and network restriction (follow-on) | `okta_assess_monitoring` | OKTA-MON-007 | Fail on tokens past `expiresAt`; Partial for `network.connection` other than `ZONE`, missing expiry, or `tokenWindow` over 30 days. |
| Device assurance coverage | `okta_assess_monitoring` | OKTA-MON-006 | Pass with at least one policy; Partial when none; Manual on 403 or 404. |
| Security contact routing (follow-on) | `okta_assess_monitoring` | OKTA-MON-008 | Pass when the TECHNICAL contact resolves to an ACTIVE user; Partial when the user cannot be read; Fail when unassigned or non-ACTIVE. |
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
