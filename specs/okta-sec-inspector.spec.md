---
slug: "okta-sec-inspector"
name: "Okta Security Inspector"
vendor: "Okta"
category: "identity-access-management"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-04-14"
source_repo: "https://github.com/hackIDLE/grclanker"
legacy_repo: "https://github.com/ethanolivertroy/okta-inspector-py"
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
- `GET /api/v1/users`
- `GET /api/v1/iam/assignees/users`
- `GET /api/v1/users/{userId}/roles`
- `GET /api/v1/groups`
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

### Reference Implementations

- Legacy assessment logic: `ethanolivertroy/okta-inspector-py`
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

### Admin Access

1. SUPER_ADMIN concentration
2. Stale or inactive privileged users
3. Privileged group size and hygiene

### Integrations

1. Trusted-origin hygiene
2. Custom network-zone coverage
3. Risky OIDC grant types
4. Contextual access conditions
5. Inactive application review

### Monitoring

1. Log streaming and SIEM forwarding
2. System Log visibility
3. ThreatInsight mode
4. Behavior rule coverage
5. API token hygiene
6. Device assurance coverage

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

## 8. Gaps / Follow-On Ideas

- live end-to-end smoke testing with a real Okta tenant
- broader federal/FIPS heuristics for Okta Gov and DoD-adjacent tenants
- more explicit notification, token governance, and lifecycle automation checks
- future trust-center or artifact export alignment with FedRAMP/OSCAL workflows
