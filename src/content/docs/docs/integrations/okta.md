---
title: Okta
description: Read-only Okta security inspector covering authentication, admin access, integrations, and monitoring, with framework mappings and OSCAL assessment results.
---

The Okta integration inspects an Okta org through the Okta Management API. It reports posture findings for the controls defined in `specs/okta-sec-inspector.spec.md`.

Every tool is read-only. Nothing is created, changed, or deleted in the tenant. No tenant data is written to disk unless you run `okta_export_audit_bundle`.

## What it inspects

- **Authentication**
  - Phishing-resistant authenticators
  - ACTIVE admin MFA rules
  - Password complexity, age, history, and lockout
  - Session idle timeout and lifetime
  - Certificate or PIV/CAC readiness
  - FIPS or restricted authenticator posture (Okta Verify `compliance.fips`, SMS, voice, security question, and email)
- **Admin access**
  - SUPER_ADMIN concentration
  - Stale privileged accounts
  - Privileged group size
  - Per-administrator factor enrollment
  - The full workforce user population (stale, never-activated, suspended, and locked accounts)
  - Okta Support or third-party administrator access
- **Integrations**
  - Trusted origins
  - Network zones
  - OIDC grant types
  - Contextual access rules
  - Application inventory hygiene
  - Provisioning or deprovisioning automation (app provisioning features plus group rules)
- **Monitoring**
  - Log streams and event hooks
  - System Log visibility
  - ThreatInsight
  - Behavior rules
  - API token age, expiry, inactivity window, and network restriction
  - Device assurance
  - Security contact routing

Findings are normalized as `{ id, title, category, status, severity, summary, evidence, recommendation, manualNote, frameworks }`. Their `status` is `Pass | Partial | Fail | Manual | Info`.

A `Manual` finding always names the cause and the evidence to collect.

## Setup and authentication

Two auth modes are supported, matching the Okta CLI configuration model. `auth_mode` takes `SSWS` or `PrivateKey` and defaults to `SSWS`. The same setting can be given as `OKTA_CLIENT_AUTHORIZATIONMODE`, or as `authorizationMode` in YAML.

### SSWS API token

Create a read-only administrator and issue an API token under Security > API > Tokens. The administrator can be a Read-only Administrator or hold a custom role with the read permissions below. Set:

```bash
export OKTA_CLIENT_ORGURL=https://your-org.okta.com
export OKTA_CLIENT_TOKEN=00abc...
```

### OAuth service app with private key JWT

Create an API Services app (Applications > Create App Integration > API Services). Then:

- Enable the scopes below.
- Grant the app a read-only admin role.
- Register a public key.

Set:

```bash
export OKTA_CLIENT_ORGURL=https://your-org.okta.com
export OKTA_CLIENT_AUTHORIZATIONMODE=PrivateKey
export OKTA_CLIENT_CLIENTID=0oa...
export OKTA_CLIENT_PRIVATEKEY="-----BEGIN PRIVATE KEY-----\n..."
export OKTA_CLIENT_PRIVATEKEYID=kid-optional
```

grclanker signs an RS256 client assertion with `node:crypto` and requests `client_credentials` tokens from `/oauth2/v1/token`. It caches them until shortly before expiry and refreshes on 401.

To supply a pre-signed JWT instead, pass `client_assertion` (or `OKTA_CLIENT_CLIENTASSERTION`).

### Config discovery order

Later sources override earlier ones field by field:

1. `~/.okta/okta.yaml`
2. Project `.okta.yaml`
3. Environment variables: `OKTA_CLIENT_ORGURL`, `OKTA_CLIENT_TOKEN`, `OKTA_CLIENT_AUTHORIZATIONMODE`, `OKTA_CLIENT_CLIENTID`, `OKTA_CLIENT_PRIVATEKEY`, `OKTA_CLIENT_PRIVATEKEYID`, `OKTA_CLIENT_CLIENTASSERTION`, `OKTA_CLIENT_SCOPES`.
4. Explicit tool arguments: `org_url`, `auth_mode`, `api_token`, `client_id`, `private_key`, `private_key_id`, `client_assertion`, `scopes`, or `config_file` to bypass the default YAML locations.

A missing YAML file is skipped. Other failures are reported as follows:

- **File cannot be read:** The tool stops with `Unable to read Okta config file <path> (<errno code>)`.
- **File cannot be parsed:** The tool stops with `Unable to parse Okta config file: invalid YAML in <path> at line N, column M (<code>)`.
  - The code is the yaml package's own (`DUPLICATE_KEY`, `MISSING_CHAR`, `BAD_INDENT`, and so on).
  - The code is `INVALID_YAML` when the parser threw something else, such as the unresolved alias `token: *value`.
  - The position is omitted when the parser reports none.
- **Private key:** A private key that `node:crypto` cannot load is reported as `Okta PrivateKey auth could not load the configured private key (<ERR_ code>)`.

None of these messages repeats a line, key, value, or key material from the file.

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

Run `okta_check_access` first. It probes users, policies, logs, role assignees, and API tokens. It reports each surface separately, so partial grants are visible before you run an assessment.

## Run it

After setup, start `grclanker` and ask in plain words. The agent calls the matching tools, for example:

```text
Check whether my Okta credentials can read everything grclanker needs.
Run the Okta assessments and list the failing findings first.
Export an Okta audit bundle.
```

For a posture readout or a framework mapping, use the [assess](/docs/workflows/assess/) or [audit](/docs/workflows/audit/) workflow, for example `grclanker assess "our Okta tenant"`. Both start with `okta_check_access`, then run the assessments or `okta_export_audit_bundle`.

## Tools

| Tool | Purpose |
| --- | --- |
| `okta_check_access` | Resolves configuration, authenticates, and probes five read surfaces. Each probe reports `status` (`ok`, `forbidden`, `unauthorized`, or `error`), the error text, and `httpStatus`: the status code the failed request actually returned, `null` when the probe was readable or the failure carried no status. Reports `healthy` (three or more readable) or `limited` with a recommended next step. |
| `okta_assess_authentication` | OKTA-AUTH-001 through OKTA-AUTH-009. |
| `okta_assess_admin_access` | OKTA-ADMIN-001 through OKTA-ADMIN-006, including the paginated user population and per-admin factor enrollment. |
| `okta_assess_integrations` | OKTA-INTEG-001 through OKTA-INTEG-006. |
| `okta_assess_monitoring` | OKTA-MON-001 through OKTA-MON-009. |
| `okta_export_audit_bundle` | Runs all four assessments and writes an audit bundle and a zip archive. |

`okta_export_audit_bundle` writes:

- `core_data/` (one file per dataset plus `collection_status.json`)
- `analysis/`
- `compliance/` (executive summary, unified matrix, per-framework reports, `fedramp/oscal_assessment_results.json`)
- `QUICK_REFERENCE.md`
- `_errors.log` on partial collection
- A zip archive under `./export/okta` (override with `output_dir`)

All tools accept the same optional auth arguments listed above.

### Export bundle

`core_data/` holds one JSON file per collected dataset in one of three shapes:

- **List:** `sign_on_policies`, `password_policies`, `mfa_enrollment_policies`, `access_policies`, `authenticators`, `idps`, `authorization_servers`, `org_factors`, `users_with_role_assignments`, `groups`, `users`, `apps`, `trusted_origins`, `network_zones`, `group_rules`, `event_hooks`, `log_streams`, `system_logs_recent`, `behaviors`, `api_tokens`, `device_assurance`, `org_contacts`.
- **Per-parent map keyed by the parent id:** `sign_on_policy_rules`, `password_policy_rules`, `access_policy_rules`, `user_roles`, `privileged_group_roles`, `privileged_group_members`, `privileged_user_factors`.
- **Single object:** `default_authorization_server`, `okta_support_access`, `third_party_admin_setting`, `threat_insight`.

`analysis/<category>.json` holds each assessment's findings, summary counts, text, and `snapshotSummary`. `analysis/findings.json` merges every finding.

## Control coverage

Every row below is also subject to the truncation demotion of rule 7. When any inventory the finding reads was truncated, a `Pass` caps at `Partial`, and the summary and evidence carry the walk's note.

The inventories each finding reads for this purpose are:

- AUTH-001 and AUTH-009: Authenticators and org factors.
- AUTH-002: Sign-on and access policies, their rules, authenticators, and MFA enrollment policies.
- AUTH-003 through AUTH-005: Password policies.
- AUTH-006 and AUTH-007: Sign-on policies and rules.
- AUTH-008: IdPs and authenticators.
- ADMIN-001 and ADMIN-002: Role assignees and per-user roles.
- ADMIN-003: Groups, privileged groups, their roles, and their members.
- ADMIN-004: Role assignees and per-user factors.
- ADMIN-005: Users.
- INTEG-001: Trusted origins.
- INTEG-002: Network zones.
- INTEG-003 and INTEG-005: Apps.
- INTEG-004: Sign-on and access policies, their rules, and network zones.
- INTEG-006: Apps and group rules.
- MON-001: Event hooks and log streams.
- MON-002: The System Log sample.
- MON-004: Behaviors.
- MON-005 and MON-007: API tokens.
- MON-006: Device assurance policies.
- MON-008: Org contacts.

A `Manual` verdict caused by an unreadable dataset names that dataset's own failure:

- `the endpoint returned 403 Forbidden`, `401 Unauthorized`, or `404 Not Found`, only when the request observed that status.
- `the collector did not expose this endpoint`, when the client has no method for it.
- `the inventory it depends on was not collected, so its request was never issued`, for a per-parent list whose parent was unreadable.

| Spec control | Tool | Finding | Status semantics |
| --- | --- | --- | --- |
| Phishing-resistant authenticator coverage | `okta_assess_authentication` | OKTA-AUTH-001 | Pass when an ACTIVE WebAuthn, FIDO2, smart card, or certificate authenticator exists; Partial for strong but not phishing-resistant; Fail when none or the inventory is empty; Manual on 403 or Classic Engine. |
| Administrator MFA enforcement | `okta_assess_authentication` | OKTA-AUTH-002 | Manual when both the sign-on and the access policy lists are unreadable (the summary names the observed cause and evidence lists every policy error). Pass only when an ACTIVE Admin Console or Dashboard policy has an ACTIVE rule with `requireFactor` or `factorMode: 2FA`, strong authenticators exist, and every policy and rule dataset was read without error. Partial when admin policies exist but no ACTIVE rule requires MFA, when MFA rules exist but the authenticator list was unreadable (the summary says so and evidence records `Strong authenticators: unknown (authenticator list unreadable)` plus the authenticator error), or when any policy or rule list failed (`Partial policy data: ...`); Partial when MFA enrollment policies or strong authenticators exist without an admin policy; Fail otherwise. |
| Password complexity | `okta_assess_authentication` | OKTA-AUTH-003 | Evaluates ACTIVE password policies only (min length 12, upper, lower, number, symbol); Fail when none are ACTIVE; Manual on 403 or an empty list. |
| Password age and history | `okta_assess_authentication` | OKTA-AUTH-004 | Max age 90 days or less and history of 5 or more on every ACTIVE policy. |
| Password lockout thresholds | `okta_assess_authentication` | OKTA-AUTH-005 | Lockout at 6 attempts or fewer on every ACTIVE policy. |
| Session idle timeout | `okta_assess_authentication` | OKTA-AUTH-006 | 15 minutes or less across ACTIVE sign-on rules; Manual when rules return no session settings; capped at Partial when rule reads partially failed. |
| Session lifetime and persistent cookies | `okta_assess_authentication` | OKTA-AUTH-007 | 18 hours or less and no persistent cookies across ACTIVE sign-on rules. |
| PIV/CAC or certificate readiness | `okta_assess_authentication` | OKTA-AUTH-008 | Manual when both the IdP and the authenticator lists are unreadable (both errors in evidence). Pass only when an ACTIVE certificate IdP or authenticator was found and both lists were read. When one was found but the other list was unreadable the verdict caps at Partial, the summary names the unread list (`Detected N ACTIVE certificate-oriented IdP or authenticator entries, but the identity provider list was unreadable, so the other half of the certificate inventory could not be verified.`, or `the authenticator list`), and evidence keeps the found `IdP: ...` or `Authenticator: ...` line beside `IdP data unavailable: ...` or `Authenticator data unavailable: ...`. When nothing was found in the readable list and the other list was unreadable the verdict is Manual on every tenant, federal or not, because the denied list alone could disprove the absence: the summary names both halves (`no ACTIVE certificate-oriented entry was found in the authenticator list while the identity provider list was unreadable (the endpoint returned 403 Forbidden ...), so this federal-domain tenant cannot be judged on half of the certificate inventory`, or the reverse), and evidence carries the org URL with the unread list's error. Fail on federal domains (`okta-gov.com`, `okta.gov`, `okta.mil`) only when both lists were read and neither holds a certificate entry; Manual elsewhere. |
| Okta Gov and FIPS heuristics (follow-on) | `okta_assess_authentication` | OKTA-AUTH-009 | Federal domains Pass only with Okta Verify `compliance.fips: REQUIRED` and no ACTIVE SMS, voice, security question, or email authenticator (email limited to recovery is allowed); commercial domains Partial when restricted authenticators are ACTIVE; Manual on Classic Engine or 403. |
| SUPER_ADMIN concentration | `okta_assess_admin_access` | OKTA-ADMIN-001 | 2 or fewer Pass, 3 to 5 Partial, more Fail; Manual on 403 or an empty assignee list; capped at Partial with `some role lookups failed, so the count may be incomplete` when some per-user role lookups fail; Manual with `every lookup of the per-user role lists failed (N of N)` and the observed status when none succeeded, so a count of zero is never reported from lookups that all failed. |
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

Every finding carries FedRAMP / NIST SP 800-53, DISA STIG, IRAP / ISM, ISMAP, SOC 2, PCI-DSS, and general mappings.

The bundle renders them as:

- `compliance/unified_compliance_matrix.md`.
- One markdown report per framework.
- `compliance/fedramp/oscal_assessment_results.json`, an OSCAL 1.1.2 assessment-results document.

The OSCAL document's findings target NIST objective ids, for example `ia-2.11_obj`. A Pass becomes `satisfied`. Any other status becomes `not-satisfied`, with a `reason` of `partial`, `fail`, `manual`, or `info`.

## Live smoke

```bash
npm --prefix cli run test:okta:live
```

The script skips with exit code 0 when no Okta configuration is present.

With credentials it:

1. Runs `okta_check_access`.
2. Runs all four assess tools.
3. Prints every finding.
4. Fails if any Manual finding lacks the evidence to collect.

## Limitations and manual controls

- The default `/api/v1/users` listing excludes DEPROVISIONED users. Reviewing deprovisioned accounts requires a status filter.
- The user listing stops after 50 pages (10,000 users) and records the truncation. Factor enrollment is read for the first 50 privileged users. Admin-like groups are expanded up to 25.
- Admin-like groups are discovered by name pattern (`admin`, `administrator`, `privileged`, `help desk`, `security`, `access`).
- Okta Workflows and HR-driven lifecycle flows are not visible through the Management API. OKTA-INTEG-006 uses app provisioning features and group rules as the observable evidence.
- Security notification emails and admin notification preferences are not exposed by the API (OKTA-MON-009 is always Manual).
- Okta Verify FIPS compliance is only exposed on Identity Engine orgs. Classic Engine orgs render the FIPS finding Manual.
- The org-level factor listing (`GET /api/v1/org/factors`) is a legacy Classic Engine endpoint that is not in Okta's published OpenAPI spec.
  - It is only used to detect Classic Engine orgs.
  - A 404 on it is counted in the snapshot's `dataset_errors` without changing any finding status.
- Framework mappings are check-level evidence pointers, not attestations.

## How the tools handle evidence

This section is reference for reviewing findings and bundles: how unread, partial, or truncated data limits a verdict, how the tools page through the API and report incomplete listings, and how credentials are kept out of findings, bundles, and error text. You don't need it to set up or run the integration.

### Verdict safety

The assessors follow these rules so a verdict never rests on missing or partial evidence:

1. An unreadable, forbidden, or errored endpoint never yields `Pass`.
   - A finding whose own inventory is unreadable yields `Manual`, naming the HTTP cause (403, 401, 404) and the evidence to collect.
   - A finding that reads several inventories caps at `Partial`, naming the unread list, when the readable half still holds evidence.
   - The same finding yields `Manual` when the unread list alone could disprove the verdict, for example OKTA-AUTH-008 with nothing found in the readable list.
   - A `Fail` is never asserted from half an inventory.
2. An empty inventory never yields `Pass` by default.
   - Inventories Okta always populates (password policies, network zones, apps, privileged users, users, org contacts, the audit SSWS token) render `Manual`, because emptiness indicates a scoped read.
   - Inventories whose emptiness is a real gap (authenticators, log streams and hooks) render `Fail`.
   - The only intentional empty `Pass` is zero SSWS API tokens when auditing through an OAuth service app.
3. Controls unavailable on the org edition (Classic Engine authenticators, ThreatInsight, device assurance, behavior detection, Okta Support settings returning 404) render `Manual`.
4. Items missing a date (`lastLogin`, `created`, `expiresAt`, `lastUpdated`) are never counted fresh. They cap the finding at `Partial`.
5. Partial inventories (a truncated user listing, capped factor or group expansion, failed per-item lookups) cap the finding at `Partial` and list the gap in evidence.
6. Every status flag the verdict depends on is read: policy, rule, authenticator, app, user, zone, log stream, event hook, behavior, and factor status.
7. Pagination follows the `Link: rel="next"` header to completion within a 50-page cap per list (200 items per page).
   - **System Log:** Queried as a bounded window (`since` 30 days ago, `until` now) and capped at 5 pages, because OKTA-MON-002 needs only a recent sample.
   - **Next links:** A `rel="next"` URL is followed only when it carries no userinfo and is one of these:
     - A root path on the configured org origin.
     - An absolute URL that resolves, as a browser would, onto that origin. Scheme, host, and port are compared after URL normalization, so casing and a default port never matter.
   - **Refused links:** Anything else is refused before any request, so the SSWS token or bearer credential never leaves for another host. Refused shapes:
     - A URL on another origin (`the Link rel="next" URL is on origin https://other.example, not the configured org origin https://tenant.okta.com`).
     - A URL carrying userinfo on either origin (`carries userinfo for origin <origin> (configured org origin <origin>)`).
     - A protocol-relative (`//host/...`) or backslash (`\\host\...`) form, which resolves to the host it names and is refused as off-origin.
     - The same form when it names the configured host, refused as `a protocol-relative or relative reference rather than a root path on the configured org origin <origin> or an absolute URL on it`. A relative reference such as `api/v1/apps` or `@host/...` earns the same.
     - A URL on a hostless scheme (`javascript:`, `data:`, `blob:`, `file:`), including a `blob:` URL wrapping the configured origin. It is refused by its scheme (`is on origin data:, not the configured org origin <origin>`).
     - A URL that `could not be parsed against the configured org origin <origin>`.
   - **Refusal outcome:** The walk stops as truncated with the refusal reason and `total unknown`.
   - **Request URLs:** The client refuses a request URL of the same shapes with `Okta API request refused: the request URL <reason>, so no request was sent.`
   - **Refusal text:** Every refusal is fixed text naming only the configured origin and the rejected origin. No path, query, fragment, or userinfo of the link reaches any text.
   - **Truncation:** A walk stops and is recorded as truncated when it:
     - Hits its cap with a next page unread.
     - Sees a `rel="next"` cursor it already visited.
     - Gets an empty page that still advertises a next link.
   - **Truncation note:** `GET <path> stopped after <pages> pages (<items> items): <reason>, total unknown`.
   - **Truncation demotion:** Every finding that reads a truncated inventory caps at `Partial`.
     - The note is appended to the finding's summary as `Inventory truncated: ...` and to its evidence as `Partial data: ...`.
     - `_errors.log` lists it as `Truncated inventory: ...`.
     - Every `snapshot` counter derived from that inventory renders `null` rather than the count of the part read, since a `0` there would claim an absence from the unread part. For example, `custom_network_zones` renders `null` while the zone list is truncated.
   - **Redaction:** `core_data/` records have credential fields (client secrets, passwords, hook header values, tokens) replaced by `[REDACTED]`. Event hook URIs are reduced to scheme and host. System Log events are projected to identity and outcome fields (see Export bundle).
8. Re-running the export never overwrites a prior bundle.
   - The bundle directory is `<org host>-audit-bundle`, for example `your-org.okta.com-audit-bundle`.
   - Repeat runs allocate `-2` through `-10` and fail once all ten names are taken.
   - The zip name is derived from the newly allocated directory.
9. A dataset that was denied, errored, or never requested is never confused with an empty one.
   - Its `core_data/` file is a marker object (`{ collected: false, status, endpoint, error }`) rather than `[]`.
   - Every counter derived from it renders `null` in the assess tool `snapshot` and in `core_data/collection_status.json`, never `0` or `truncated: false`.
   - Every HTTP status or endpoint named anywhere in the output comes from a request the run actually made. Markers, probe results, and `Manual` causes carry the failed request's own status and path.
   - A per-parent list that was skipped because its parent was unreadable says so without inventing a status or endpoint.

### Record redaction

Records are redacted when they are collected, and every JSON document is passed through the same scrubber again when it is written.

- The value of every credential-named key is replaced by `[REDACTED]`.
  - The key is normalized to lowercase with dots, underscores, and hyphens removed, and matched on the suffixes `password`, `passwd`, `passphrase`, `secret`, `token`, `apikey`, `privatekey`, `secretkey`, `secrethash`, `clientassertion`, `authorization`, and `answer`.
  - As a result, app `credentials.oauthClient.client_secret`, `credentials.password`, IdP `protocol.credentials.client.client_secret`, and any `secret_hash` are caught, while password policy `settings.password.{complexity, age, lockout}` is kept for OKTA-AUTH-003 through 005.
- `{key, value}` and `{name, value}` pairs whose name is credential-shaped have their value replaced.
- JWT-shaped and SSWS-token-shaped strings are replaced.
- Every URL keeps only scheme, host, and path, with userinfo and query string replaced.

Two datasets are projected rather than stored verbatim:

- An event hook keeps its record, but `channel.config` is rebuilt as:
  - `uri` reduced to scheme and host
  - `method`
  - `headers[]` with every `value` replaced
  - `authScheme`, when present, with `type`, `key`, and a replaced `value`
- System Log events keep `uuid`, `published`, `eventType`, `displayMessage`, `severity`, `outcome.result` and `outcome.reason`, `actor` (`id`, `type`, `alternateId`, `displayName`), and `client.ipAddress`. They drop `debugContext`, `request`, `target`, and `securityContext`.

### Error text carriers

Error text uses a separate rule. It is applied when an API error is constructed and wherever an error string is recorded: `_errors.log`, marker objects, finding evidence, `collection_status.json`, the access check, and tool error payloads.

- A value inside a carrier is removed whatever its shape:
  - The value of a credential-named header (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, and similar).
  - A cookie or session assignment.
  - URL userinfo and query pairs. The query string collapses to `?[REDACTED]`.
  - The value after a scheme word (`Bearer`, `Basic`, `Digest`, `Token`, `OAuth`, `Negotiate`, `NTLM`, `SSWS`, `ApiKey`, `Splunk`, `Snowflake`, and `HMAC`, in any casing). The scheme word stays.
  - The value of every credential-named `key=value` or `key: value` pair.
- The credential-named pair is read before any scheme word. A key that names a credential loses its value whatever word it starts with:
  - `OKTA_CLIENT_SECRET=SSWS rejected` renders `OKTA_CLIENT_SECRET=[REDACTED] rejected`.
  - `sslPassword=splunk rejected` renders `sslPassword=[REDACTED] rejected`.
  - `db_password: token` renders `db_password: [REDACTED]`.

### Scheme words

The scheme-word rule applies under an Authorization-style key (`Authorization`, `Proxy-Authorization`, `WWW-Authenticate`) and in bare prose.

- Under an Authorization-style key, the run after the scheme word goes whatever its shape or the scheme's casing:
  - `Authorization: SSWS <token>` renders `Authorization: SSWS [REDACTED]`.
  - `Authorization: SSWS prod-us-east-2026` renders `Authorization: SSWS [REDACTED]`.
  - `Authorization: bearer <token>` renders `Authorization: bearer [REDACTED]`.
- Under such a key, a pair list after the scheme (under a request header or a challenge) is read pair by pair as described below. `WWW-Authenticate: Bearer realm="api"` stays.
- Bare in prose, the word after a scheme word is ordinary text when it is a mechanism word (`authentication`, `credentials`, `challenge`), a version (`OAuth 2.0`), an auth-param (`realm="api"`), or one plain word after a lowercase spelling or a product name.
  - `Basic authentication failed`, `the bearer presented an expired token`, `Splunk Enterprise rejected the request`, and `Snowflake statement failed` stay.
- Bare in prose, a header-cased pure scheme followed by a run of 8 or more characters loses the run whatever its shape:
  - `Bearer abcdefghijkl rejected` renders `Bearer [REDACTED] rejected`.
  - `replayed BASIC <token> upstream` renders `replayed BASIC [REDACTED] upstream`.

### Credential-named pairs

- The pair rule holds whatever the value's shape and length and wherever the pair sits. It holds in the `=`, `: `, `:`, and JSON forms, in prose and inside a JSON string alike:
  - `upstream echoed DB_PASSWORD: monkey while proxying` renders `DB_PASSWORD: [REDACTED] while proxying`.
  - `InvalidAuthenticationToken: Access token has expired` renders `InvalidAuthenticationToken: [REDACTED] token has expired`.
- A credential word anywhere in the key makes it a pair key (`DB_PASSWORD`, `SPLUNK_PASSWORD`, `OKTA_CLIENT_TOKEN`).
- Three key classes refine that rule, tested in this order:
  - **Bearer ids:** A key carries a bearer credential, and loses its value whatever the shape (a UUID included), when it does either of these:
    - Ends in `secret_id`, `session_id`, or `token_id` in any prefix, casing, or separator (`VAULT_SECRET_ID`, `role_secret_id`, `token_id`, `tokenId`).
    - Names a session id (`sid`, `jsessionid`).
  - **Webhook keys:** A URL-valued webhook key keeps its origin and loses its path and query.
    - A URL-valued webhook key is the bare word `webhook` or `hook`, or a `webhook*`, `*hook_*`, or `callback_*` key whose final segment is `url`, `uri`, or `endpoint`.
    - A webhook key that is not URL-valued follows the rule for its own final segment. `webhook_count=3` stays, and `webhook_secret=<value>` goes whole.
  - **Setting keys:** A credential-named key names a setting when its final segment is one of the segments listed below. It keeps a value that is neither token-shaped nor a configured secret.
    - The final segments are `url`, `uri`, `endpoint`, `method`, `algorithm`, `audience`, `issuer`, `shape`, `type`, `mode`, `path`, `file`, `dir`, `limit`, `count`, `id`, `name`, `policy`, `policies`, `ttl`, `uses`, `cidrs`, and `accessor`.
    - Setting keys include `token_endpoint`, `auth_method`, `token_type`, `api_key_id`, `access_key_id`, `key_id`, `private_key_id`, `secret_name`, `secret_id_ttl`, `token_max_ttl`, `secret_id_num_uses`, `token_bound_cidrs`, and `secret_id_accessor`.
    - `secret_id_ttl=3600`, `key_id=kid-primary`, and `secret_name=db-credentials-prod` stay. `token_type=<token>` goes.
- A key without a credential word (`OKTA_CLIENT_ID`, `client_id`, `tenant_id`, `SUMO_ACCESS_ID`, `SNOWFLAKE_ACCOUNT`, `X-Request-Id`) is an identifier rather than a pair key, so its value is judged by shape alone.
- A credential-named command-line flag is a pair too, with a space or `=` before its value:
  - `psql --password <value> -h db` renders `psql --password [REDACTED] -h db`.
  - `helm --set db.password=<value> upgrade` renders `helm --set db.password=[REDACTED] upgrade`.
  - `-Dspring.datasource.password=<value>` renders `-Dspring.datasource.password=[REDACTED]`.

### Quoted values and pair lists

- A quoted value in any of the carriers above is removed with its quotes kept. The rule holds for plain, single, or JSON-escaped quotes, as in `Cookie: sid="..."`, `Authorization: Bearer "..."`, or `\"Authorization\": \"Bearer ...\"`.
- A quote alone never makes a header value a credential. `Content-Type: "application/json"` stays.
- On a compound header line the reader is quote-aware at every JSON depth. A quoted value ends at the closing quote that matches its opener (the same quote character behind the same run of backslashes). An escaped inner quote is therefore inner content and goes with the value.
  - At the top level and inside a double-escaped raw JSON string alike, `{"Cookie": "sid=\"...\""}` renders `{"Cookie": "[REDACTED]"}`, and `{"X-Api-Key": "\"...\""}` renders `{"X-Api-Key": "[REDACTED]"}`.
- A quoted value that opens with a scheme word keeps the scheme and loses the rest. `{"Authorization": "Bearer \"...\""}` renders `{"Authorization": "Bearer [REDACTED]"}`.
- The exception is a scheme followed by a pair list, which is read pair by pair, under `Authorization`, `Proxy-Authorization`, and `WWW-Authenticate` alike:
  - A quoted value in the list is the credential and goes whatever its key, unless the key is a descriptive parameter (`realm`, `qop`, `algorithm`, `charset`, `error`, `error_description`, `error_uri`, `scope`).
  - A bare value follows its key's own rule.
  - `Authorization: Snowflake Token="<token>"` renders `Authorization: Snowflake Token="[REDACTED]"`.
  - Any other `<Scheme> <Key>="..."` pair renders the same way. `Authorization: Bearer blob="<token>"` renders `Authorization: Bearer blob="[REDACTED]"`.
  - A Digest header keeps `realm="api"`, `qop=auth`, and `nc=00000001`. It loses `username`, `nonce`, `uri`, `cnonce`, `response`, and `opaque`.
  - A challenge's `WWW-Authenticate: Bearer realm="api", error="invalid_token"` stays whole.
  - `"VERACODE-HMAC-SHA-256 id=...,ts=...,nonce=...,sig=..."` renders `"VERACODE-HMAC-SHA-256 [REDACTED],ts=...,nonce=[REDACTED],sig=[REDACTED]"`. An unquoted first run after the scheme goes whole, and the pairs after it follow their keys.
- The same list rule reads a pair list after a scheme word in prose, bare, JSON-escaped, and inside a JSON string alike:
  - `upstream said Bearer blob="<token>"` renders `upstream said Bearer blob="[REDACTED]"`.
  - `{"headers":{"Authorization":"Snowflake Token=\"<token>\""}}` renders `{"headers":{"Authorization":"Snowflake Token=\"[REDACTED]\""}}`.
- A proof parameter (`response`, `signature`, `oauth_signature`, `mac`, `sig`) loses its value wherever its pair sits in a list with a challenge parameter (`realm`, `nonce`, `cnonce`, `opaque`, `qop`, or an `oauth_*` name). The rule holds with or without a scheme word or a header in front of the list, and whatever the value's shape.
  - As a result, a data value such as `realm="api", nonce="n", response="<proof>"` is never read as a bare challenge. It renders `realm="api", nonce="[REDACTED]", response="[REDACTED]"` bare, after a literal escape, and inside a JSON string alike.
  - `realm=api, nonce=n, mac=<proof>` loses its `mac` the same way.
  - Inside a scheme word's list, a bare proof goes whatever its neighbours. `Authorization: Digest username="u", response=<proof>` renders `Authorization: Digest username="[REDACTED]", response=[REDACTED]`.
- A proof-free challenge keeps its descriptive values:
  - `WWW-Authenticate: Bearer realm="api"` stays whole.
  - `Digest realm="api", qop="auth", nonce="n"` keeps `realm="api"` and `qop="auth"`. Its nonce goes as a credential-named pair does everywhere.
- A pair list of another kind keeps its values. `status=500 response=slow` stays.

### Header and cookie boundaries

- An unquoted cookie or header value ends at a `;` or `,` before the next `Name:` token (or at the end of the line). An unterminated quote ends the same way rather than swallowing the following header, so that header keeps its name and gets its own carrier treatment:
  - `Cookie: sid=...; X-Api-Key: ...; Content-Type: application/json` renders `Cookie: [REDACTED]; X-Api-Key: [REDACTED]; Content-Type: application/json`.
  - `Cookie: sid="...; X-Api-Key: "..."; Content-Type: "application/json"` renders `Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"`.
- A `;` inside a URL query value is part of the value (URLSearchParams semantics). So a relative `/api/v1/things?token=hunter2;restofsecret` renders `/api/v1/things?token=[REDACTED]` with no tail, and an absolute URL's query collapses to `?[REDACTED]` as before, in the plain, JSON-escaped, and slash-escaped spellings alike.
- The `;` separator belongs to `Cookie` and `Set-Cookie` parsing alone. The cookie reader runs before the query pass, so `Cookie: &sid=a; pref=b` still renders `Cookie: [REDACTED]`.
- An apostrophe is a cookie character:
  - `Cookie: sid=O'<value>; X-Api-Key: <value>` renders `Cookie: [REDACTED]; X-Api-Key: [REDACTED]`.
  - `Cookie: theme=dark; my'pref=<value>` renders `Cookie: [REDACTED]`.
- The next header's name may carry any RFC 7230 token character, so a dotted or underscored name (`X.Api.Key:`, `X_Api_Key:`) is recognised as the next header and its value is judged by its own key.

### JSON escapes and URLs

- A literal JSON escape is a boundary before every carrier opener. The escapes are `\n`, `\r`, `\t`, `\b`, `\f`, `\/`, and `\uXXXX`: the two- or six-character sequence as it sits inside a JSON string, not the control character.
  - A header name, scheme word, pair key, URL, or token that begins right after one is read on its own, and never as the value of the word before the escape.
  - `request headers:\u000aAuthorization: Splunk <key>` renders `request headers:\u000aAuthorization: Splunk [REDACTED]`, and `proxy:\tpassword: hunter2` renders `proxy:\tpassword: [REDACTED]`.
  - The escape sequence itself stays.
  - A token glued to an escape never takes the escape letter as its first character.
  - A value, URL, or query pair ends at the backslash that opens the next escape.
  - A `\/` escape is a boundary rather than a path separator, so a key or token after it is judged on its own.
- A URL whose slashes are JSON-escaped (`https:\/\/hooks.example.com\/a?token=<value>`) is still read as a URL, so its userinfo and query go the same way (`note https:\/\/hooks.example.com\/a?[REDACTED] next`).
- The userinfo of a URL ends at the first `/`, `?`, or `#`, so an `@` inside a query or fragment never turns the query into the host. In the plain and the slash-escaped spelling alike:
  - `https://h?e=a@x.com&token=s3cr3t` renders `https://h?[REDACTED]`.
  - `https://h#f@x.com` renders `https://h#[REDACTED]`.
- A bare `?` or `#` left before an earlier marker stays as it is, so a second pass adds no second marker.

### Configured secrets and value shapes

- A configured secret (the SSWS API token, the OAuth access token, the private key, and the client assertion) is removed whatever its shape, in its raw, JSON-escaped, URL-encoded, base64, and base64url forms.
- A secret handed to the scrub call is also removed wherever it stands, glued into a longer run included, so a short passphrase does not survive inside another value. A value under four characters is ignored.
- A value with a real token shape is removed bare:
  - PEM blocks
  - JWTs
  - 42-character `00` Okta tokens
  - AWS key IDs and secrets
  - Other vendor-prefixed tokens
  - Hex digests of 32 or more characters
  - Runs of 16 or more characters that carry a base64 symbol, more than one digit group, or token casing
- A bare value shaped like a name is indistinguishable from a resource name and stays:
  - Words joined by hyphens or underscores with at most one digit group, such as `prod-us-east-2026`.
  - A camelCase identifier whose words average three or more letters, such as `preferredLanguage`, `transitioningToStatus`.

### Paths and path labels

- A token-shaped segment of a bare request path or file path (`/api/v1/users/<id>/factors`, the `.okta.yaml` path) also stays, so the endpoint or file an error names is the one the run used.
- Inside a URL with a scheme, every path segment keeps the rule, because webhook URLs carry their token there.
- The last segment of a bare path used as a label (`/api/v1/api-tokens: <detail>`, `/oauth/token-request: invalid_client`) is a request target rather than a pair key.
  - The text after that segment stays, unless that segment itself names a credential and the value stands alone on the line. In that case the label is a pair: `kv/password: <value>` renders `kv/password: [REDACTED]`.
  - That segment names a credential when it ends in `password`, `passwd`, `passphrase`, `pwd`, `secret`, `token`, `key`, or `assertion`, alone or followed by an encoding word such as `pem` or `base64` (as in `privateKeyPem`), or when it is a bearer id.
  - Inside a URL with a scheme, the pair rule still applies.

### Data-side rule

Data written to the bundle follows the data-side rule. Every string leaf of a `core_data/` snapshot, an assess payload, and the access check passes through the same carrier and shape rules, with the generic long-run and hex-digest rules left off.

- A vendor-prefixed token (`sk_live_`, `xox*-`, `ghp_`, `AKIA`, and the rest of the vendor set), a JWT, a PEM block, or a credential carrier inside a free-text field (an app description, an app note, a hook name) is removed there too. `key sk_live_<24 characters> end` renders `key [REDACTED] end`.
- An identifier such as `prod-us-east-2026-cluster` or a bare random run survives as evidence.

### Markers and collection status

A dataset that was denied, errored, or never requested is written as the marker `{ collected: false, status, endpoint, error }` in place of its list, map, or object.

- `status` and `endpoint` are the HTTP status and path of the request that actually failed.
  - Both are `null` when the client could not issue the request.
  - Both are also `null` when the dataset was skipped because the inventory it hangs off was not collected. In that case, `error` starts with `Not requested:` and names the parent's failure.
- A readable but empty list stays `[]`.
- In a per-parent map, a denied child is omitted from the collected children and recorded as a marker under its parent id.
- `org_contacts.json` appends a marker with the contact type as `id` for each contact whose assignment or user lookup failed.
- When every child lookup of a per-parent list failed, the list counts as not collected:
  - The file holds only the per-child markers.
  - Its `collection_status.json` row renders `collected: false`, with `count` and `truncated` `null`.
  - The row's `error` starts with `every lookup of the <list> failed (N of N)` and then names each failed request. No single status or endpoint is invented for the whole list.
  - The findings that read the list say every lookup failed instead of reporting a count.

`core_data/collection_status.json` has one row per file, plus `not_collected` and `truncated` file lists.

- Each row has `file`, `shape`, `collected`, `complete`, `count`, `truncated`, `truncation_note`, `status`, `endpoint`, and `error`.
- A dataset that was not collected renders `null` for `complete`, `count`, `truncated`, and `truncation_note` (never `0` or `false`).
- A single object renders `null` for `count` and `truncated`.

Each assessment's `snapshotSummary` renders `null` for every counter derived from a dataset that was not collected, including a per-parent list none of whose lookups succeeded (for example `system_log_events`, `api_tokens`, `device_assurance_policies`, `org_contacts_resolved`, `super_admins`, `admin_mfa_rules`, `contextual_rules`, `privileged_users_factor_checked`). It also renders `not collected` for labels such as `threat_insight_mode`, and adds `datasets_not_collected` beside `dataset_errors`. The assessment text prints those values as `not collected`.

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
