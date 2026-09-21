---
slug: "okta-sec-inspector"
name: "Okta Security Inspector"
vendor: "Okta"
category: "identity-access-management"
language: "typescript"
status: "implemented"
version: "1.1"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
legacy_repo: "https://github.com/hackIDLE/okta-inspector-py"
reference_repo: "https://github.com/okta/okta-cli-client"
---

# okta-sec-inspector

## 1. Overview

A read-only Okta compliance inspection surface for **grclanker** that assesses tenant authentication posture, privileged access, integration hygiene, and monitoring coverage. The implementation carries forward the assessment intent from the earlier `okta-inspector-py` project while aligning config discovery with the official `okta-cli-client` model and calling the Okta Management API directly from native TypeScript.

The current tool family is designed for GRC engineers who need evidence-backed posture checks without mutating the tenant:

- `okta_check_access`
- `okta_assess_authentication`
- `okta_assess_admin_access`
- `okta_assess_integrations`
- `okta_assess_monitoring`
- `okta_export_audit_bundle`

## 2. APIs & SDKs

### Primary APIs

| Surface | Base URL | Purpose |
| --- | --- | --- |
| Okta Management API | `https://{org}/api/v1/*` | Policies, authenticators, users, roles, apps, zones, hooks, logs, tokens |
| OAuth Token Endpoint | `https://{org}/oauth2/v1/token` | Service-app access tokens for scoped read-only collection |

### Key Endpoints

- `GET /api/v1/policies`
- `GET /api/v1/policies/{policyId}/rules`
- `GET /api/v1/authenticators`
- `GET /api/v1/users` (paginated via `Link: rel="next"`, capped at 50 pages with recorded truncation)
- `GET /api/v1/users/{userId}`
- `GET /api/v1/users/{userId}/factors`
- `GET /api/v1/iam/assignees/users`
- `GET /api/v1/users/{userId}/roles`
- `GET /api/v1/groups`
- `GET /api/v1/groups/rules`
- `GET /api/v1/groups/{groupId}/roles`
- `GET /api/v1/groups/{groupId}/users`
- `GET /api/v1/apps`
- `GET /api/v1/idps`
- `GET /api/v1/trustedOrigins`
- `GET /api/v1/zones`
- `GET /api/v1/authorizationServers`
- `GET /api/v1/authorizationServers/default`
- `GET /api/v1/org/factors`
- `GET /api/v1/eventHooks`
- `GET /api/v1/logStreams`
- `GET /api/v1/logs`
- `GET /api/v1/behaviors`
- `GET /api/v1/threats/configuration`
- `GET /api/v1/api-tokens`
- `GET /api/v1/device-assurances`
- `GET /api/v1/org/contacts`
- `GET /api/v1/org/contacts/{contactType}`
- `GET /api/v1/org/privacy/oktaSupport`
- `GET /api/v1/org/settings/thirdPartyAdminSetting`

### Reference Implementations

- Legacy assessment logic: `hackIDLE/okta-inspector-py`
- Config and endpoint coverage reference: `okta/okta-cli-client`

## 3. Authentication

### Supported Modes

1. **SSWS API token**
2. **OAuth service app with private key JWT**

### Config Discovery Order

The implementation mirrors the Okta CLI-compatible precedence chain:

1. `~/.okta/okta.yaml`
2. project `.okta.yaml`
3. environment variables
4. explicit tool arguments

### Supported Environment Variables

- `OKTA_CLIENT_ORGURL`
- `OKTA_CLIENT_TOKEN`
- `OKTA_CLIENT_AUTHORIZATIONMODE`
- `OKTA_CLIENT_CLIENTID`
- `OKTA_CLIENT_CLIENTASSERTION`
- `OKTA_CLIENT_SCOPES`
- `OKTA_CLIENT_PRIVATEKEY`
- `OKTA_CLIENT_PRIVATEKEYID`

### Default Read Scopes

- `okta.users.read`
- `okta.groups.read`
- `okta.apps.read`
- `okta.authenticators.read`
- `okta.authorizationServers.read`
- `okta.idps.read`
- `okta.trustedOrigins.read`
- `okta.policies.read`
- `okta.logs.read`
- `okta.eventHooks.read`
- `okta.logStreams.read`
- `okta.orgs.read`
- `okta.networkZones.read`
- `okta.behaviors.read`
- `okta.deviceAssurance.read`
- `okta.roles.read`
- `okta.apiTokens.read`
- `okta.threatInsights.read`

## 4. Security Controls

### Authentication

1. Phishing-resistant authenticator coverage
2. Administrator MFA enforcement
3. Password complexity
4. Password age and history
5. Password lockout thresholds
6. Session idle timeout
7. Session lifetime and persistent cookies
8. PIV/CAC or certificate-auth readiness
9. FIPS and restricted authenticator posture (Okta Verify `compliance.fips`, SMS, voice, security question, email; federal-domain detection for `okta-gov.com`, `okta.gov`, `okta.mil`)

### Admin Access

1. SUPER_ADMIN concentration
2. Stale or inactive privileged users
3. Privileged group size and hygiene
4. Privileged user MFA enrollment (per-user factors, ACTIVE status, phishing-resistant preference)
5. Workforce account lifecycle hygiene (paginated user population: stale, never-activated, suspended, locked)
6. Okta Support access and third-party administrator governance

### Integrations

1. Trusted-origin hygiene
2. Custom network-zone coverage
3. Risky OIDC grant types
4. Contextual access conditions
5. Inactive application review
6. Provisioning and deprovisioning automation (app `features` incl. `PUSH_USER_DEACTIVATION`, group rules)

### Monitoring

1. Log streaming and SIEM forwarding
2. System Log visibility
3. ThreatInsight mode
4. Behavior rule coverage
5. API token hygiene
6. Device assurance coverage
7. API token expiry, inactivity window, and network restriction
8. Security contact routing (org TECHNICAL contact resolves to an ACTIVE user)
9. Administrator security notification emails (always Manual; not exposed by the API)

### Verdict Safety Rules

Every finding follows these rules, each covered by a regression test in `cli/tests/okta.test.mjs`:

1. Unreadable, forbidden, or errored endpoints yield `Manual` naming the cause and the evidence to collect, never `Pass`.
2. Empty inventories never yield `Pass` by default. Inventories Okta always populates (password policies, zones, apps, privileged users, users, org contacts, the SSWS audit token) render `Manual`; inventories whose absence is a real gap (authenticators, log streams and hooks) render `Fail`. Zero SSWS tokens in OAuth mode is the one intentional empty `Pass`.
3. Controls unavailable on the org edition (Classic Engine, 404 responses) render `Manual`.
4. Items missing a date are never counted fresh and cap the finding at `Partial`.
5. Partial inventories (truncated pagination, capped expansion, failed per-item lookups) cap the finding at `Partial`.
6. Every documented status flag the verdict depends on is read.
7. Pagination runs to completion or records truncation and downgrades.
8. Re-running the export never overwrites a prior bundle.

## 5. Compliance Framework Mappings

The finding model maps checks across:

- FedRAMP / NIST SP 800-53
- DISA STIG
- IRAP
- ISMAP
- SOC 2
- PCI-DSS
- general security guidance

These mappings are intentionally evidence-backed and check-level, not vague posture labels.

## 6. Bundle Output

`okta_export_audit_bundle` produces:

- `core_data/` raw API snapshots
- `analysis/` normalized findings and category summaries
- `compliance/executive_summary.md`
- `compliance/unified_compliance_matrix.md`
- per-framework markdown reports
- `compliance/fedramp/oscal_assessment_results.json` (OSCAL 1.1.2 assessment-results keyed by NIST SP 800-53 objective ids)
- `QUICK_REFERENCE.md`
- `.zip` archive
- `_errors.log` when partial collection failures occur

## 7. Architecture

```text
cli/extensions/grc-tools/okta.ts
  ├── config discovery and auth resolution
  ├── OktaAuditorClient
  ├── dataset collectors
  ├── normalized finding model
  ├── category assessors
  ├── bundle export helpers
  └── grclanker tool registration
```

### Design Constraints

- Native TypeScript inside grclanker
- Read-only in v1
- No runtime dependency on the Okta CLI binary
- No tenant-data persistence unless the user explicitly exports an audit bundle
- API pagination, rate-limit retry, and OAuth token refresh handled in the client layer

## 8. Status

Shipped (version 1.1, 2026-09-21):

- 30 findings across the four assess tools (22 original controls plus OKTA-AUTH-009, OKTA-ADMIN-004 to 006, OKTA-INTEG-006, OKTA-MON-007 to 009); tool names and exported functions are unchanged
- `listUsers` pagination wired into the admin-access collector with a 50-page cap and recorded truncation; per-admin factor enrollment for up to 50 privileged users; admin-like group expansion capped at 25 with recorded truncation
- Okta Gov and FIPS heuristics: federal-domain detection (`okta-gov.com`, `okta.gov`, `okta.mil`), Okta Verify `compliance.fips`, restricted authenticator detection
- Token governance: age, missing dates, `expiresAt`, `tokenWindow`, `network.connection`
- Lifecycle: workforce population hygiene, provisioning features, group rules, Okta Support and third-party admin settings, org security contacts
- OSCAL 1.1.2 assessment-results export in the bundle
- Verdict-safety rules 1 to 8 applied to every finding with a regression test per rule, plus all-403, all-empty, and partial-inventory self-check fixtures
- Live smoke (`npm --prefix cli run test:okta:live`) runs `okta_check_access` plus all four assess tools and skips cleanly without credentials
- Integration guide at `src/content/docs/docs/integrations/okta.md`

## 9. Gaps / Follow-On Ideas

- Live end-to-end validation against a real Okta Identity Engine tenant and a Classic Engine tenant (the smoke exists; no tenant run has been recorded)
- DEPROVISIONED users are excluded from the default user listing; add a filtered pass for deprovisioned-account review
- Admin security notification emails and admin notification preferences have no Management API surface and remain Manual (OKTA-MON-009)
- Okta Workflows and HR-driven lifecycle flows are not inspectable; OKTA-INTEG-006 relies on app provisioning features and group rules
- Generic truncation metadata for every paginated list (today only the user listing, factor lookups, and group expansion record truncation)
- Trust-center artifact packaging beyond the OSCAL assessment-results document (assessment plan and component definition alignment)
