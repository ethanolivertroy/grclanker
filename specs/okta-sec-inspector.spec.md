---
slug: "okta-sec-inspector"
name: "Okta Security Inspector"
vendor: "Okta"
category: "identity-and-access"
language: "language-neutral"
status: "generated"
version: "1.0.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# Okta Security Inspector

Portable contract for the shipped read-only Okta identity, administrator, integration, and monitoring assessments.

## Purpose

Give security and compliance teams a read-only, repeatable view of Okta authentication, privileged access, application, lifecycle, and monitoring posture without treating unavailable tenant evidence as compliance.

## Design guidance

Use a dedicated least-privilege audit principal. Preserve tenant, edition, and permission limitations as evidence. Keep manual checks when Okta exposes no decisive read surface, and treat every output as sensitive identity-governance evidence.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- Generic list truncation metadata is not complete for every Okta collection; the runtime still prevents pass when a dependent inventory is known partial, but some cap exits have less-specific prose.
- Administrator notification preferences have no shipped read implementation; OKTA-MON-009 remains manual and names Admin Console evidence.
- The generated rule input records the existing evidence-specific verdict after complete-cardinality calculations; this migration does not alter thresholds, sampling, text, or finding ordering.
- Lifecycle workflow and broader trust-center evidence remain manual or deferred.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `okta_check_access` | Validate Okta Management API access for a read-only audit principal and report which core GRC surfaces are readable. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `okta_assess_authentication` | Evaluate phishing-resistant MFA, admin MFA rules, password policies, session controls, certificate-authentication readiness, and FIPS or restricted authenticator posture in Okta. | `OKTA-AUTH-001`, `OKTA-AUTH-002`, `OKTA-AUTH-003`, `OKTA-AUTH-004`, `OKTA-AUTH-005`, `OKTA-AUTH-006`, `OKTA-AUTH-007`, `OKTA-AUTH-008`, `OKTA-AUTH-009` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `okta_assess_admin_access` | Review Okta privileged users, super-admin concentration, stale privileged accounts, admin MFA enrollment, privileged group hygiene, workforce account lifecycle, and Okta Support or third-party admin access. | `OKTA-ADMIN-001`, `OKTA-ADMIN-002`, `OKTA-ADMIN-003`, `OKTA-ADMIN-004`, `OKTA-ADMIN-005`, `OKTA-ADMIN-006` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `okta_assess_integrations` | Review Okta applications, trusted origins, network zones, OAuth grant hygiene, contextual access controls, and provisioning or deprovisioning automation. | `OKTA-INTEG-001`, `OKTA-INTEG-002`, `OKTA-INTEG-003`, `OKTA-INTEG-004`, `OKTA-INTEG-005`, `OKTA-INTEG-006` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `okta_assess_monitoring` | Review Okta log offloading, System Log visibility, ThreatInsight, behavior rules, API token hygiene and governance, device assurance coverage, and security contact routing. | `OKTA-MON-001`, `OKTA-MON-002`, `OKTA-MON-003`, `OKTA-MON-004`, `OKTA-MON-005`, `OKTA-MON-006`, `OKTA-MON-007`, `OKTA-MON-008`, `OKTA-MON-009` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `okta_export_audit_bundle` | Export a multi-framework Okta audit package with raw API data, normalized findings, markdown reports, and a zip archive. | `OKTA-AUTH-001`, `OKTA-AUTH-002`, `OKTA-AUTH-003`, `OKTA-AUTH-004`, `OKTA-AUTH-005`, `OKTA-AUTH-006`, `OKTA-AUTH-007`, `OKTA-AUTH-008`, `OKTA-AUTH-009`, `OKTA-ADMIN-001`, `OKTA-ADMIN-002`, `OKTA-ADMIN-003`, `OKTA-ADMIN-004`, `OKTA-ADMIN-005`, `OKTA-ADMIN-006`, `OKTA-INTEG-001`, `OKTA-INTEG-002`, `OKTA-INTEG-003`, `OKTA-INTEG-004`, `OKTA-INTEG-005`, `OKTA-INTEG-006`, `OKTA-MON-001`, `OKTA-MON-002`, `OKTA-MON-003`, `OKTA-MON-004`, `OKTA-MON-005`, `OKTA-MON-006`, `OKTA-MON-007`, `OKTA-MON-008`, `OKTA-MON-009` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `okta_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `org_url` | string | no | Optional Okta org URL or hostname. Falls back to Okta CLI-style config discovery from .okta.yaml, ~/.okta/okta.yaml, and environment variables. |
| `config_file` | string | no | Optional path to an Okta YAML config file to use instead of the default discovery locations. |
| `auth_mode` | string | no | Optional auth mode override. Supported: SSWS or PrivateKey. |
| `api_token` | string | no | Optional Okta SSWS API token. Prefer OKTA_CLIENT_TOKEN or .okta.yaml when possible. |
| `client_id` | string | no | Optional Okta OAuth service-app client ID. Used with PrivateKey auth mode. |
| `private_key` | string | no | Optional PEM private key for PrivateKey auth mode. Prefer OKTA_CLIENT_PRIVATEKEY or .okta.yaml when possible. |
| `private_key_id` | string | no | Optional JWK key ID (kid) for the service-app private key. |
| `client_assertion` | string | no | Optional prebuilt JWT client assertion. Use this if you do not want grclanker to sign the PrivateKey JWT for you. |
| `scopes` | array | no |  |

#### `okta_assess_authentication`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `org_url` | string | no | Optional Okta org URL or hostname. Falls back to Okta CLI-style config discovery from .okta.yaml, ~/.okta/okta.yaml, and environment variables. |
| `config_file` | string | no | Optional path to an Okta YAML config file to use instead of the default discovery locations. |
| `auth_mode` | string | no | Optional auth mode override. Supported: SSWS or PrivateKey. |
| `api_token` | string | no | Optional Okta SSWS API token. Prefer OKTA_CLIENT_TOKEN or .okta.yaml when possible. |
| `client_id` | string | no | Optional Okta OAuth service-app client ID. Used with PrivateKey auth mode. |
| `private_key` | string | no | Optional PEM private key for PrivateKey auth mode. Prefer OKTA_CLIENT_PRIVATEKEY or .okta.yaml when possible. |
| `private_key_id` | string | no | Optional JWK key ID (kid) for the service-app private key. |
| `client_assertion` | string | no | Optional prebuilt JWT client assertion. Use this if you do not want grclanker to sign the PrivateKey JWT for you. |
| `scopes` | array | no |  |

#### `okta_assess_admin_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `org_url` | string | no | Optional Okta org URL or hostname. Falls back to Okta CLI-style config discovery from .okta.yaml, ~/.okta/okta.yaml, and environment variables. |
| `config_file` | string | no | Optional path to an Okta YAML config file to use instead of the default discovery locations. |
| `auth_mode` | string | no | Optional auth mode override. Supported: SSWS or PrivateKey. |
| `api_token` | string | no | Optional Okta SSWS API token. Prefer OKTA_CLIENT_TOKEN or .okta.yaml when possible. |
| `client_id` | string | no | Optional Okta OAuth service-app client ID. Used with PrivateKey auth mode. |
| `private_key` | string | no | Optional PEM private key for PrivateKey auth mode. Prefer OKTA_CLIENT_PRIVATEKEY or .okta.yaml when possible. |
| `private_key_id` | string | no | Optional JWK key ID (kid) for the service-app private key. |
| `client_assertion` | string | no | Optional prebuilt JWT client assertion. Use this if you do not want grclanker to sign the PrivateKey JWT for you. |
| `scopes` | array | no |  |

#### `okta_assess_integrations`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `org_url` | string | no | Optional Okta org URL or hostname. Falls back to Okta CLI-style config discovery from .okta.yaml, ~/.okta/okta.yaml, and environment variables. |
| `config_file` | string | no | Optional path to an Okta YAML config file to use instead of the default discovery locations. |
| `auth_mode` | string | no | Optional auth mode override. Supported: SSWS or PrivateKey. |
| `api_token` | string | no | Optional Okta SSWS API token. Prefer OKTA_CLIENT_TOKEN or .okta.yaml when possible. |
| `client_id` | string | no | Optional Okta OAuth service-app client ID. Used with PrivateKey auth mode. |
| `private_key` | string | no | Optional PEM private key for PrivateKey auth mode. Prefer OKTA_CLIENT_PRIVATEKEY or .okta.yaml when possible. |
| `private_key_id` | string | no | Optional JWK key ID (kid) for the service-app private key. |
| `client_assertion` | string | no | Optional prebuilt JWT client assertion. Use this if you do not want grclanker to sign the PrivateKey JWT for you. |
| `scopes` | array | no |  |

#### `okta_assess_monitoring`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `org_url` | string | no | Optional Okta org URL or hostname. Falls back to Okta CLI-style config discovery from .okta.yaml, ~/.okta/okta.yaml, and environment variables. |
| `config_file` | string | no | Optional path to an Okta YAML config file to use instead of the default discovery locations. |
| `auth_mode` | string | no | Optional auth mode override. Supported: SSWS or PrivateKey. |
| `api_token` | string | no | Optional Okta SSWS API token. Prefer OKTA_CLIENT_TOKEN or .okta.yaml when possible. |
| `client_id` | string | no | Optional Okta OAuth service-app client ID. Used with PrivateKey auth mode. |
| `private_key` | string | no | Optional PEM private key for PrivateKey auth mode. Prefer OKTA_CLIENT_PRIVATEKEY or .okta.yaml when possible. |
| `private_key_id` | string | no | Optional JWK key ID (kid) for the service-app private key. |
| `client_assertion` | string | no | Optional prebuilt JWT client assertion. Use this if you do not want grclanker to sign the PrivateKey JWT for you. |
| `scopes` | array | no |  |

#### `okta_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `org_url` | string | no | Optional Okta org URL or hostname. Falls back to Okta CLI-style config discovery from .okta.yaml, ~/.okta/okta.yaml, and environment variables. |
| `config_file` | string | no | Optional path to an Okta YAML config file to use instead of the default discovery locations. |
| `auth_mode` | string | no | Optional auth mode override. Supported: SSWS or PrivateKey. |
| `api_token` | string | no | Optional Okta SSWS API token. Prefer OKTA_CLIENT_TOKEN or .okta.yaml when possible. |
| `client_id` | string | no | Optional Okta OAuth service-app client ID. Used with PrivateKey auth mode. |
| `private_key` | string | no | Optional PEM private key for PrivateKey auth mode. Prefer OKTA_CLIENT_PRIVATEKEY or .okta.yaml when possible. |
| `private_key_id` | string | no | Optional JWK key ID (kid) for the service-app private key. |
| `client_assertion` | string | no | Optional prebuilt JWT client assertion. Use this if you do not want grclanker to sign the PrivateKey JWT for you. |
| `scopes` | array | no |  |
| `output_dir` | string | no | Optional output root. Defaults to ./export/okta. |


## Authentication

Supported modes:

- SSWS API token
- OAuth service application private-key JWT
- prebuilt client assertion

Credential precedence, highest first:

1. Explicit tool arguments
2. Explicit config file
3. Okta CLI-style config files
4. OKTA_* environment variables

Environment variables: `OKTA_ORG_URL`, `OKTA_CLIENT_ORGURL`, `OKTA_API_TOKEN`, `OKTA_CLIENT_TOKEN`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_PRIVATEKEY`, `OKTA_CLIENT_PRIVATEKEY_ID`

Configuration locations: .okta.yaml, ~/.okta/okta.yaml

Credential and deployment variants: Commercial, preview, and custom Okta organization origins

Configuration fields: `orgUrl`, `token`, `clientId`, `privateKey`, `privateKeyId`, `clientAssertion`, `scopes`

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

Credential refresh: POST /oauth2/v1/token with the client_credentials grant and a private_key_jwt assertion.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| role | `Okta read-only Management API OAuth scopes for every requested surface` | `users`, `policies`, `apps`, `system-log` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |
| role | `An administrator role that can read policy, user, app, and System Log evidence` | `users`, `policies`, `apps`, `system-log` | Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence. |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `users` | HTTP | `GET /api/v1/users` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `status`, `profile`, `lastLogin` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/) |
| `policies` | HTTP | `GET /api/v1/policies` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `type`, `status`, `conditions`, `settings` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/) |
| `apps` | HTTP | `GET /api/v1/apps` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `label`, `status`, `settings`, `credentials` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/) |
| `system-log` | HTTP | `GET /api/v1/logs` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `uuid`, `published`, `eventType`, `severity`, `outcome` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `users` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `users` | response | A JSON object or list containing only the documented id, status, profile, lastLogin members consumed by verdicts. | yes |
| `policies` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `policies` | response | A JSON object or list containing only the documented id, type, status, conditions, settings members consumed by verdicts. | yes |
| `apps` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `apps` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `apps` | response | A JSON object or list containing only the documented id, name, label, status, settings, credentials members consumed by verdicts. | yes |
| `system-log` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `system-log` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `system-log` | response | A JSON object or list containing only the documented uuid, published, eventType, severity, outcome members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `users`, `policies`, `apps`, `system-log` | `Link rel=next`, `after` | service default | caller limit | none | Okta collections are complete only after no same-origin next link remains; per-tool item caps make affected datasets partial. | Proven exhaustion; Configured item cap; Repeated cursor; Empty page with cursor; Rejected off-origin or user-information next link |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Okta Security Inspector | Endpoint-specific Okta rate-limit buckets | `Retry-After`, `X-Rate-Limit-Reset` | 429, 500, 502, 503, 504 | Honor bounded Retry-After or reset delays, then use bounded exponential retry; preserve exhaustion as unreadable evidence. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | Phishing-resistant authenticators | OKTA-AUTH-001 | Evaluate the ordered first-match rules for OKTA-AUTH-001 below. |
| 2 | Administrator MFA enforcement | OKTA-AUTH-002 | Evaluate the ordered first-match rules for OKTA-AUTH-002 below. |
| 3 | Password complexity | OKTA-AUTH-003 | Evaluate the ordered first-match rules for OKTA-AUTH-003 below. |
| 4 | Password aging and history | OKTA-AUTH-004 | Evaluate the ordered first-match rules for OKTA-AUTH-004 below. |
| 5 | Password lockout threshold | OKTA-AUTH-005 | Evaluate the ordered first-match rules for OKTA-AUTH-005 below. |
| 6 | Session idle timeout | OKTA-AUTH-006 | Evaluate the ordered first-match rules for OKTA-AUTH-006 below. |
| 7 | Session lifetime and persistent cookie controls | OKTA-AUTH-007 | Evaluate the ordered first-match rules for OKTA-AUTH-007 below. |
| 8 | Certificate or PIV/CAC authentication | OKTA-AUTH-008 | Evaluate the ordered first-match rules for OKTA-AUTH-008 below. |
| 9 | FIPS and restricted authenticator posture | OKTA-AUTH-009 | Evaluate the ordered first-match rules for OKTA-AUTH-009 below. |
| 10 | Super admin assignments are constrained | OKTA-ADMIN-001 | Evaluate the ordered first-match rules for OKTA-ADMIN-001 below. |
| 11 | Inactive privileged accounts | OKTA-ADMIN-002 | Evaluate the ordered first-match rules for OKTA-ADMIN-002 below. |
| 12 | Privileged group assignments are bounded | OKTA-ADMIN-003 | Evaluate the ordered first-match rules for OKTA-ADMIN-003 below. |
| 13 | Privileged user MFA enrollment | OKTA-ADMIN-004 | Evaluate the ordered first-match rules for OKTA-ADMIN-004 below. |
| 14 | Workforce account lifecycle hygiene | OKTA-ADMIN-005 | Evaluate the ordered first-match rules for OKTA-ADMIN-005 below. |
| 15 | Okta Support access and third-party admin governance | OKTA-ADMIN-006 | Evaluate the ordered first-match rules for OKTA-ADMIN-006 below. |
| 16 | Trusted origins hygiene | OKTA-INTEG-001 | Evaluate the ordered first-match rules for OKTA-INTEG-001 below. |
| 17 | Network zones are configured | OKTA-INTEG-002 | Evaluate the ordered first-match rules for OKTA-INTEG-002 below. |
| 18 | OIDC application grant hygiene | OKTA-INTEG-003 | Evaluate the ordered first-match rules for OKTA-INTEG-003 below. |
| 19 | Risk-based and contextual access controls | OKTA-INTEG-004 | Evaluate the ordered first-match rules for OKTA-INTEG-004 below. |
| 20 | Application inventory hygiene | OKTA-INTEG-005 | Evaluate the ordered first-match rules for OKTA-INTEG-005 below. |
| 21 | Provisioning and deprovisioning automation | OKTA-INTEG-006 | Evaluate the ordered first-match rules for OKTA-INTEG-006 below. |
| 22 | Log offloading and external monitoring | OKTA-MON-001 | Evaluate the ordered first-match rules for OKTA-MON-001 below. |
| 23 | System log visibility | OKTA-MON-002 | Evaluate the ordered first-match rules for OKTA-MON-002 below. |
| 24 | ThreatInsight posture | OKTA-MON-003 | Evaluate the ordered first-match rules for OKTA-MON-003 below. |
| 25 | Behavior detection coverage | OKTA-MON-004 | Evaluate the ordered first-match rules for OKTA-MON-004 below. |
| 26 | API token hygiene | OKTA-MON-005 | Evaluate the ordered first-match rules for OKTA-MON-005 below. |
| 27 | Device assurance policy coverage | OKTA-MON-006 | Evaluate the ordered first-match rules for OKTA-MON-006 below. |
| 28 | API token expiry and network restrictions | OKTA-MON-007 | Evaluate the ordered first-match rules for OKTA-MON-007 below. |
| 29 | Security contact routing | OKTA-MON-008 | Evaluate the ordered first-match rules for OKTA-MON-008 below. |
| 30 | Administrator security notification emails | OKTA-MON-009 | Evaluate the ordered first-match rules for OKTA-MON-009 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `OKTA-AUTH-001` | high | `okta_assess_authentication` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Phishing-resistant authenticators returns pass from complete, readable evidence. | The portable derivation for Phishing-resistant authenticators returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Phishing-resistant authenticators returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Phishing-resistant authenticators is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-002` | high | `okta_assess_authentication` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Administrator MFA enforcement returns pass from complete, readable evidence. | The portable derivation for Administrator MFA enforcement returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Administrator MFA enforcement returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Administrator MFA enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-003` | medium | `okta_assess_authentication` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Password complexity returns pass from complete, readable evidence. | The portable derivation for Password complexity returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Password complexity returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Password complexity is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-004` | medium | `okta_assess_authentication` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Password aging and history returns pass from complete, readable evidence. | The portable derivation for Password aging and history returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Password aging and history returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Password aging and history is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-005` | medium | `okta_assess_authentication` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Password lockout threshold returns pass from complete, readable evidence. | The portable derivation for Password lockout threshold returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Password lockout threshold returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Password lockout threshold is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-006` | medium | `okta_assess_authentication` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Session idle timeout returns pass from complete, readable evidence. | The portable derivation for Session idle timeout returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Session idle timeout returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Session idle timeout is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-007` | medium | `okta_assess_authentication` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Session lifetime and persistent cookie controls returns pass from complete, readable evidence. | The portable derivation for Session lifetime and persistent cookie controls returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Session lifetime and persistent cookie controls returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Session lifetime and persistent cookie controls is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-008` | medium | `okta_assess_authentication` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Certificate or PIV/CAC authentication returns pass from complete, readable evidence. | The portable derivation for Certificate or PIV/CAC authentication returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Certificate or PIV/CAC authentication returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Certificate or PIV/CAC authentication is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-009` | high | `okta_assess_authentication` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for FIPS and restricted authenticator posture returns pass from complete, readable evidence. | The portable derivation for FIPS and restricted authenticator posture returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for FIPS and restricted authenticator posture returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for FIPS and restricted authenticator posture is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-001` | medium | `okta_assess_admin_access` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Super admin assignments are constrained returns pass from complete, readable evidence. | The portable derivation for Super admin assignments are constrained returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Super admin assignments are constrained returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Super admin assignments are constrained is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-002` | medium | `okta_assess_admin_access` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Inactive privileged accounts returns pass from complete, readable evidence. | The portable derivation for Inactive privileged accounts returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Inactive privileged accounts returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Inactive privileged accounts is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-003` | medium | `okta_assess_admin_access` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Privileged group assignments are bounded returns pass from complete, readable evidence. | The portable derivation for Privileged group assignments are bounded returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Privileged group assignments are bounded returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Privileged group assignments are bounded is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-004` | medium | `okta_assess_admin_access` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Privileged user MFA enrollment returns pass from complete, readable evidence. | The portable derivation for Privileged user MFA enrollment returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Privileged user MFA enrollment returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Privileged user MFA enrollment is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-005` | medium | `okta_assess_admin_access` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Workforce account lifecycle hygiene returns pass from complete, readable evidence. | The portable derivation for Workforce account lifecycle hygiene returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Workforce account lifecycle hygiene returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Workforce account lifecycle hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-006` | medium | `okta_assess_admin_access` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Okta Support access and third-party admin governance returns pass from complete, readable evidence. | The portable derivation for Okta Support access and third-party admin governance returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Okta Support access and third-party admin governance returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Okta Support access and third-party admin governance is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-001` | medium | `okta_assess_integrations` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Trusted origins hygiene returns pass from complete, readable evidence. | The portable derivation for Trusted origins hygiene returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Trusted origins hygiene returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Trusted origins hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-002` | medium | `okta_assess_integrations` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Network zones are configured returns pass from complete, readable evidence. | The portable derivation for Network zones are configured returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Network zones are configured returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Network zones are configured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-003` | medium | `okta_assess_integrations` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for OIDC application grant hygiene returns pass from complete, readable evidence. | The portable derivation for OIDC application grant hygiene returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for OIDC application grant hygiene returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for OIDC application grant hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-004` | medium | `okta_assess_integrations` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Risk-based and contextual access controls returns pass from complete, readable evidence. | The portable derivation for Risk-based and contextual access controls returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Risk-based and contextual access controls returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Risk-based and contextual access controls is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-005` | medium | `okta_assess_integrations` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Application inventory hygiene returns pass from complete, readable evidence. | The portable derivation for Application inventory hygiene returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Application inventory hygiene returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Application inventory hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-006` | medium | `okta_assess_integrations` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Provisioning and deprovisioning automation returns pass from complete, readable evidence. | The portable derivation for Provisioning and deprovisioning automation returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Provisioning and deprovisioning automation returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Provisioning and deprovisioning automation is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-001` | medium | `okta_assess_monitoring` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Log offloading and external monitoring returns pass from complete, readable evidence. | The portable derivation for Log offloading and external monitoring returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Log offloading and external monitoring returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Log offloading and external monitoring is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-002` | medium | `okta_assess_monitoring` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for System log visibility returns pass from complete, readable evidence. | The portable derivation for System log visibility returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for System log visibility returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for System log visibility is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-003` | medium | `okta_assess_monitoring` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for ThreatInsight posture returns pass from complete, readable evidence. | The portable derivation for ThreatInsight posture returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for ThreatInsight posture returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for ThreatInsight posture is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-004` | medium | `okta_assess_monitoring` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Behavior detection coverage returns pass from complete, readable evidence. | The portable derivation for Behavior detection coverage returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Behavior detection coverage returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Behavior detection coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-005` | medium | `okta_assess_monitoring` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for API token hygiene returns pass from complete, readable evidence. | The portable derivation for API token hygiene returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for API token hygiene returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for API token hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-006` | medium | `okta_assess_monitoring` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Device assurance policy coverage returns pass from complete, readable evidence. | The portable derivation for Device assurance policy coverage returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Device assurance policy coverage returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Device assurance policy coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-007` | medium | `okta_assess_monitoring` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for API token expiry and network restrictions returns pass from complete, readable evidence. | The portable derivation for API token expiry and network restrictions returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for API token expiry and network restrictions returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for API token expiry and network restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-008` | medium | `okta_assess_monitoring` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Security contact routing returns pass from complete, readable evidence. | The portable derivation for Security contact routing returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Security contact routing returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Security contact routing is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-009` | high | `okta_assess_monitoring` | `users`, `policies`, `apps`, `system-log` | `decision_status` | The portable derivation for Administrator security notification emails returns pass from complete, readable evidence. | The portable derivation for Administrator security notification emails returns warn, or a pass is demoted because a required source is partial or truncated. | The portable derivation for Administrator security notification emails returns fail from complete evidence; this outcome has first-match precedence over incomplete-evidence warnings. | The required evidence for Administrator security notification emails is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `OKTA-AUTH-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-AUTH-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-AUTH-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-AUTH-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-AUTH-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-AUTH-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-AUTH-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-AUTH-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-AUTH-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-AUTH-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-AUTH-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-AUTH-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-AUTH-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-AUTH-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-AUTH-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-AUTH-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-AUTH-005` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-AUTH-005` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-AUTH-005` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-AUTH-005` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-AUTH-006` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-AUTH-006` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-AUTH-006` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-AUTH-006` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-AUTH-007` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-AUTH-007` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-AUTH-007` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-AUTH-007` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-AUTH-008` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-AUTH-008` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-AUTH-008` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-AUTH-008` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-AUTH-009` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-AUTH-009` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-AUTH-009` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-AUTH-009` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-ADMIN-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-ADMIN-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-ADMIN-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-ADMIN-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-ADMIN-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-ADMIN-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-ADMIN-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-ADMIN-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-ADMIN-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-ADMIN-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-ADMIN-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-ADMIN-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-ADMIN-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-ADMIN-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-ADMIN-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-ADMIN-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-ADMIN-005` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-ADMIN-005` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-ADMIN-005` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-ADMIN-005` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-ADMIN-006` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-ADMIN-006` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-ADMIN-006` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-ADMIN-006` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-INTEG-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-INTEG-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-INTEG-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-INTEG-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-INTEG-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-INTEG-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-INTEG-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-INTEG-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-INTEG-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-INTEG-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-INTEG-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-INTEG-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-INTEG-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-INTEG-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-INTEG-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-INTEG-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-INTEG-005` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-INTEG-005` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-INTEG-005` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-INTEG-005` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-INTEG-006` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-INTEG-006` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-INTEG-006` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-INTEG-006` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-MON-001` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-MON-001` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-MON-001` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-MON-001` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-MON-002` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-MON-002` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-MON-002` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-MON-002` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-MON-003` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-MON-003` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-MON-003` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-MON-003` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-MON-004` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-MON-004` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-MON-004` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-MON-004` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-MON-005` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-MON-005` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-MON-005` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-MON-005` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-MON-006` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-MON-006` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-MON-006` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-MON-006` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-MON-007` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-MON-007` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-MON-007` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-MON-007` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-MON-008` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-MON-008` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-MON-008` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-MON-008` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |
| `OKTA-MON-009` | 1 | fail | `decision_status` equals "fail" | A proven violation wins before incomplete-evidence outcomes. |
| `OKTA-MON-009` | 2 | warn | `decision_status` equals "warn" | The runtime selected warning from readable but incomplete or review-required evidence. |
| `OKTA-MON-009` | 3 | pass | `decision_status` equals "pass" | The runtime may select pass only after every required dependency is complete. |
| `OKTA-MON-009` | 4 | manual | always | Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `OKTA-AUTH-001` | `decision_status` | Using complete source cardinalities, return pass when any ACTIVE authenticator is WebAuthn, FIDO2, smart card, certificate, PIV, or CAC, warn when another strong authenticator exists, and fail when a complete non-Classic inventory has none. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-AUTH-002` | `decision_status` | Using complete source cardinalities, return pass when an ACTIVE Admin Console or Dashboard policy has an ACTIVE MFA rule, a strong authenticator exists, and all policy reads completed; warn for partial evidence or MFA controls without an explicit admin rule; fail when complete evidence shows none. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-AUTH-003` | `decision_status` | Using complete source cardinalities, across ACTIVE password policies, return pass when every policy has minimum length 12 and requires upper, lower, number, and symbol, warn when only some do, and fail when none do or no policy is ACTIVE. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-AUTH-004` | `decision_status` | Using complete source cardinalities, across ACTIVE password policies, return pass when every policy has maximum age from 1 through 90 days and history at least five, warn when only some do, and fail when none do or no policy is ACTIVE. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-AUTH-005` | `decision_status` | Using complete source cardinalities, across ACTIVE password policies, return pass when every policy locks after one through six attempts, warn when only some do, and fail when none do or no policy is ACTIVE. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-AUTH-006` | `decision_status` | Using complete source cardinalities, return pass when every ACTIVE sign-on rule with an idle value is at most 15 minutes, fail when any exceeds 15, manual when none exposes the value, and warn instead of pass when rule reads are partial. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-AUTH-007` | `decision_status` | Using complete source cardinalities, return pass when every ACTIVE sign-on rule lifetime is at most 1080 minutes and no rule enables persistent cookies, fail when either condition is violated, manual when neither value is exposed, and warn instead of pass when rule reads are partial. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-AUTH-008` | `decision_status` | Using complete source cardinalities, return pass when any ACTIVE certificate-oriented IdP or authenticator exists and both inventories are readable, warn when one exists but the other inventory is unreadable, fail when none exists on a federal-domain tenant, and manual when none exists commercially. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-AUTH-009` | `decision_status` | Using complete source cardinalities, for federal domains, return pass only when ACTIVE Okta Verify requires FIPS and no restricted authenticator is active, fail for a restricted authenticator or non-required FIPS, and warn when Okta Verify is absent; commercially, warn for restricted authenticators and pass otherwise. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-ADMIN-001` | `decision_status` | Using complete source cardinalities, for a non-empty privileged-user inventory, return pass with at most two SUPER_ADMIN users, warn with three through five, and fail above five. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-ADMIN-002` | `decision_status` | Using complete source cardinalities, return fail when any privileged account is non-ACTIVE or last signed in over 90 days ago, warn when any lacks a last-login date, and pass otherwise. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-ADMIN-003` | `decision_status` | Using complete source cardinalities, for detected admin-like groups, return pass when every expanded privileged group has at most 25 members, warn when any exceeds 25 or expansion is partial, and manual when no group matches the discovery pattern. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-ADMIN-004` | `decision_status` | Using complete source cardinalities, return fail when any inspected privileged user has no ACTIVE factor, warn when every inspected user has a factor but any lacks a phishing-resistant one, and pass when every privileged user has an ACTIVE phishing-resistant factor. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-ADMIN-005` | `decision_status` | Using complete source cardinalities, return fail when any ACTIVE user has not signed in for over 90 days or any STAGED or PROVISIONED user is older than 30 days, warn for missing last-login or suspended, locked, expired, recovery, or partial users, and pass otherwise. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-ADMIN-006` | `decision_status` | Using complete source cardinalities, return pass only when Okta Support access is DISABLED, thirdPartyAdmin is false, and both reads complete; return warn for every other readable state and manual when support access is unavailable. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-INTEG-001` | `decision_status` | Using complete source cardinalities, return fail when any ACTIVE trusted origin uses HTTP or a wildcard, pass when at least one ACTIVE origin exists and none is insecure, and manual when the complete inventory has no ACTIVE origin because origins are optional. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-INTEG-002` | `decision_status` | Using complete source cardinalities, return pass when at least one ACTIVE non-system, non-LegacyIpZone custom zone exists, warn when a non-empty complete zone inventory has none, and manual when the zone inventory is empty or unreadable. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-INTEG-003` | `decision_status` | Using complete source cardinalities, return fail when any ACTIVE OIDC app uses password or implicit grants, warn when only inactive apps retain those grants, and pass when no app does. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-INTEG-004` | `decision_status` | Using complete source cardinalities, return pass when any ACTIVE sign-on or access rule uses risk, device, behavior, or network context, warn when custom zones exist without such a rule or reads are partial, and fail when complete evidence has neither. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-INTEG-005` | `decision_status` | Using complete source cardinalities, return pass when every application is ACTIVE, warn when any application is inactive or restricted, and manual when the app inventory is empty or unreadable. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-INTEG-006` | `decision_status` | Using complete source cardinalities, return pass when any ACTIVE provisioning app has PUSH_USER_DEACTIVATION, fail when provisioning exists but none pushes deactivation, warn when no provisioning feature is visible or group rules are partial, and manual when apps are unavailable. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-MON-001` | `decision_status` | Using complete source cardinalities, return pass when any ACTIVE log stream exists, warn when only ACTIVE event hooks exist or a pass has partial companion evidence, and fail when complete evidence has neither. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-MON-002` | `decision_status` | Using complete source cardinalities, return pass when the complete lookback contains at least one System Log event, warn when the window is empty or truncated, and manual when the log read fails. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-MON-003` | `decision_status` | Using complete source cardinalities, return pass for ThreatInsight block mode, warn for audit or log_only, fail for another readable mode, and manual when the feature object is unavailable. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-MON-004` | `decision_status` | Using complete source cardinalities, return pass when any behavior rule is ACTIVE and warn when a complete behavior inventory has no active rule. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-MON-005` | `decision_status` | Using complete source cardinalities, return pass when every listed SSWS token has a usable reference date no older than 90 days, warn for stale or undated tokens, manual for an empty SSWS-authenticated inventory, and pass for an empty OAuth-authenticated inventory. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-MON-006` | `decision_status` | Using complete source cardinalities, return pass when at least one device assurance policy exists and warn when the complete readable inventory is empty. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-MON-007` | `decision_status` | Using complete source cardinalities, return fail when any listed token is expired, warn when any is not zone-restricted, lacks a valid expiry, or has an inactivity window over 30 days, and pass otherwise, including an empty OAuth-authenticated inventory. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-MON-008` | `decision_status` | Using complete source cardinalities, return pass when TECHNICAL contact resolves to an ACTIVE user, fail when missing, unassigned, or non-ACTIVE, warn when status or lookup is unknown, and manual when the contact inventory itself is empty or unreadable. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |
| `OKTA-MON-009` | `decision_status` | Using complete source cardinalities, always return manual because administrator security-notification email preferences have no Management API read surface. Before evaluating that decision, any required null, missing, denied, unreadable, or not-requested source derives manual; any partial or truncated dependency demotes pass to warn unless the derivation already selects fail. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `OKTA-AUTH-001` | `passStatus` | pass |
| `OKTA-AUTH-001` | `warnStatus` | warn |
| `OKTA-AUTH-001` | `failStatus` | fail |
| `OKTA-AUTH-001` | `manualStatus` | manual |
| `OKTA-AUTH-002` | `passStatus` | pass |
| `OKTA-AUTH-002` | `warnStatus` | warn |
| `OKTA-AUTH-002` | `failStatus` | fail |
| `OKTA-AUTH-002` | `manualStatus` | manual |
| `OKTA-AUTH-003` | `passStatus` | pass |
| `OKTA-AUTH-003` | `warnStatus` | warn |
| `OKTA-AUTH-003` | `failStatus` | fail |
| `OKTA-AUTH-003` | `manualStatus` | manual |
| `OKTA-AUTH-004` | `passStatus` | pass |
| `OKTA-AUTH-004` | `warnStatus` | warn |
| `OKTA-AUTH-004` | `failStatus` | fail |
| `OKTA-AUTH-004` | `manualStatus` | manual |
| `OKTA-AUTH-005` | `passStatus` | pass |
| `OKTA-AUTH-005` | `warnStatus` | warn |
| `OKTA-AUTH-005` | `failStatus` | fail |
| `OKTA-AUTH-005` | `manualStatus` | manual |
| `OKTA-AUTH-006` | `passStatus` | pass |
| `OKTA-AUTH-006` | `warnStatus` | warn |
| `OKTA-AUTH-006` | `failStatus` | fail |
| `OKTA-AUTH-006` | `manualStatus` | manual |
| `OKTA-AUTH-007` | `passStatus` | pass |
| `OKTA-AUTH-007` | `warnStatus` | warn |
| `OKTA-AUTH-007` | `failStatus` | fail |
| `OKTA-AUTH-007` | `manualStatus` | manual |
| `OKTA-AUTH-008` | `passStatus` | pass |
| `OKTA-AUTH-008` | `warnStatus` | warn |
| `OKTA-AUTH-008` | `failStatus` | fail |
| `OKTA-AUTH-008` | `manualStatus` | manual |
| `OKTA-AUTH-009` | `passStatus` | pass |
| `OKTA-AUTH-009` | `warnStatus` | warn |
| `OKTA-AUTH-009` | `failStatus` | fail |
| `OKTA-AUTH-009` | `manualStatus` | manual |
| `OKTA-ADMIN-001` | `passStatus` | pass |
| `OKTA-ADMIN-001` | `warnStatus` | warn |
| `OKTA-ADMIN-001` | `failStatus` | fail |
| `OKTA-ADMIN-001` | `manualStatus` | manual |
| `OKTA-ADMIN-002` | `passStatus` | pass |
| `OKTA-ADMIN-002` | `warnStatus` | warn |
| `OKTA-ADMIN-002` | `failStatus` | fail |
| `OKTA-ADMIN-002` | `manualStatus` | manual |
| `OKTA-ADMIN-003` | `passStatus` | pass |
| `OKTA-ADMIN-003` | `warnStatus` | warn |
| `OKTA-ADMIN-003` | `failStatus` | fail |
| `OKTA-ADMIN-003` | `manualStatus` | manual |
| `OKTA-ADMIN-004` | `passStatus` | pass |
| `OKTA-ADMIN-004` | `warnStatus` | warn |
| `OKTA-ADMIN-004` | `failStatus` | fail |
| `OKTA-ADMIN-004` | `manualStatus` | manual |
| `OKTA-ADMIN-005` | `passStatus` | pass |
| `OKTA-ADMIN-005` | `warnStatus` | warn |
| `OKTA-ADMIN-005` | `failStatus` | fail |
| `OKTA-ADMIN-005` | `manualStatus` | manual |
| `OKTA-ADMIN-006` | `passStatus` | pass |
| `OKTA-ADMIN-006` | `warnStatus` | warn |
| `OKTA-ADMIN-006` | `failStatus` | fail |
| `OKTA-ADMIN-006` | `manualStatus` | manual |
| `OKTA-INTEG-001` | `passStatus` | pass |
| `OKTA-INTEG-001` | `warnStatus` | warn |
| `OKTA-INTEG-001` | `failStatus` | fail |
| `OKTA-INTEG-001` | `manualStatus` | manual |
| `OKTA-INTEG-002` | `passStatus` | pass |
| `OKTA-INTEG-002` | `warnStatus` | warn |
| `OKTA-INTEG-002` | `failStatus` | fail |
| `OKTA-INTEG-002` | `manualStatus` | manual |
| `OKTA-INTEG-003` | `passStatus` | pass |
| `OKTA-INTEG-003` | `warnStatus` | warn |
| `OKTA-INTEG-003` | `failStatus` | fail |
| `OKTA-INTEG-003` | `manualStatus` | manual |
| `OKTA-INTEG-004` | `passStatus` | pass |
| `OKTA-INTEG-004` | `warnStatus` | warn |
| `OKTA-INTEG-004` | `failStatus` | fail |
| `OKTA-INTEG-004` | `manualStatus` | manual |
| `OKTA-INTEG-005` | `passStatus` | pass |
| `OKTA-INTEG-005` | `warnStatus` | warn |
| `OKTA-INTEG-005` | `failStatus` | fail |
| `OKTA-INTEG-005` | `manualStatus` | manual |
| `OKTA-INTEG-006` | `passStatus` | pass |
| `OKTA-INTEG-006` | `warnStatus` | warn |
| `OKTA-INTEG-006` | `failStatus` | fail |
| `OKTA-INTEG-006` | `manualStatus` | manual |
| `OKTA-MON-001` | `passStatus` | pass |
| `OKTA-MON-001` | `warnStatus` | warn |
| `OKTA-MON-001` | `failStatus` | fail |
| `OKTA-MON-001` | `manualStatus` | manual |
| `OKTA-MON-002` | `passStatus` | pass |
| `OKTA-MON-002` | `warnStatus` | warn |
| `OKTA-MON-002` | `failStatus` | fail |
| `OKTA-MON-002` | `manualStatus` | manual |
| `OKTA-MON-003` | `passStatus` | pass |
| `OKTA-MON-003` | `warnStatus` | warn |
| `OKTA-MON-003` | `failStatus` | fail |
| `OKTA-MON-003` | `manualStatus` | manual |
| `OKTA-MON-004` | `passStatus` | pass |
| `OKTA-MON-004` | `warnStatus` | warn |
| `OKTA-MON-004` | `failStatus` | fail |
| `OKTA-MON-004` | `manualStatus` | manual |
| `OKTA-MON-005` | `passStatus` | pass |
| `OKTA-MON-005` | `warnStatus` | warn |
| `OKTA-MON-005` | `failStatus` | fail |
| `OKTA-MON-005` | `manualStatus` | manual |
| `OKTA-MON-006` | `passStatus` | pass |
| `OKTA-MON-006` | `warnStatus` | warn |
| `OKTA-MON-006` | `failStatus` | fail |
| `OKTA-MON-006` | `manualStatus` | manual |
| `OKTA-MON-007` | `passStatus` | pass |
| `OKTA-MON-007` | `warnStatus` | warn |
| `OKTA-MON-007` | `failStatus` | fail |
| `OKTA-MON-007` | `manualStatus` | manual |
| `OKTA-MON-008` | `passStatus` | pass |
| `OKTA-MON-008` | `warnStatus` | warn |
| `OKTA-MON-008` | `failStatus` | fail |
| `OKTA-MON-008` | `manualStatus` | manual |
| `OKTA-MON-009` | `passStatus` | pass |
| `OKTA-MON-009` | `warnStatus` | warn |
| `OKTA-MON-009` | `failStatus` | fail |
| `OKTA-MON-009` | `manualStatus` | manual |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `OKTA-AUTH-001` | compliant | All required source reads are complete and this derivation returns pass: return pass when any ACTIVE authenticator is WebAuthn, FIDO2, smart card, certificate, PIV, or CAC, warn when another strong authenticator exists, and fail when a complete non-Classic inventory has none. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-AUTH-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when any ACTIVE authenticator is WebAuthn, FIDO2, smart card, certificate, PIV, or CAC, warn when another strong authenticator exists, and fail when a complete non-Classic inventory has none. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-AUTH-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-AUTH-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-AUTH-002` | compliant | All required source reads are complete and this derivation returns pass: return pass when an ACTIVE Admin Console or Dashboard policy has an ACTIVE MFA rule, a strong authenticator exists, and all policy reads completed; warn for partial evidence or MFA controls without an explicit admin rule; fail when complete evidence shows none. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-AUTH-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when an ACTIVE Admin Console or Dashboard policy has an ACTIVE MFA rule, a strong authenticator exists, and all policy reads completed; warn for partial evidence or MFA controls without an explicit admin rule; fail when complete evidence shows none. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-AUTH-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-AUTH-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-AUTH-003` | compliant | All required source reads are complete and this derivation returns pass: across ACTIVE password policies, return pass when every policy has minimum length 12 and requires upper, lower, number, and symbol, warn when only some do, and fail when none do or no policy is ACTIVE. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-AUTH-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: across ACTIVE password policies, return pass when every policy has minimum length 12 and requires upper, lower, number, and symbol, warn when only some do, and fail when none do or no policy is ACTIVE. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-AUTH-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-AUTH-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-AUTH-004` | compliant | All required source reads are complete and this derivation returns pass: across ACTIVE password policies, return pass when every policy has maximum age from 1 through 90 days and history at least five, warn when only some do, and fail when none do or no policy is ACTIVE. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-AUTH-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: across ACTIVE password policies, return pass when every policy has maximum age from 1 through 90 days and history at least five, warn when only some do, and fail when none do or no policy is ACTIVE. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-AUTH-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-AUTH-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-AUTH-005` | compliant | All required source reads are complete and this derivation returns pass: across ACTIVE password policies, return pass when every policy locks after one through six attempts, warn when only some do, and fail when none do or no policy is ACTIVE. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-AUTH-005` | noncompliant | A complete source read satisfies the fail branch of this derivation: across ACTIVE password policies, return pass when every policy locks after one through six attempts, warn when only some do, and fail when none do or no policy is ACTIVE. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-AUTH-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-AUTH-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-AUTH-006` | compliant | All required source reads are complete and this derivation returns pass: return pass when every ACTIVE sign-on rule with an idle value is at most 15 minutes, fail when any exceeds 15, manual when none exposes the value, and warn instead of pass when rule reads are partial. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-AUTH-006` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every ACTIVE sign-on rule with an idle value is at most 15 minutes, fail when any exceeds 15, manual when none exposes the value, and warn instead of pass when rule reads are partial. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-AUTH-006` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-AUTH-006` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-AUTH-007` | compliant | All required source reads are complete and this derivation returns pass: return pass when every ACTIVE sign-on rule lifetime is at most 1080 minutes and no rule enables persistent cookies, fail when either condition is violated, manual when neither value is exposed, and warn instead of pass when rule reads are partial. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-AUTH-007` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every ACTIVE sign-on rule lifetime is at most 1080 minutes and no rule enables persistent cookies, fail when either condition is violated, manual when neither value is exposed, and warn instead of pass when rule reads are partial. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-AUTH-007` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-AUTH-007` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-AUTH-008` | compliant | All required source reads are complete and this derivation returns pass: return pass when any ACTIVE certificate-oriented IdP or authenticator exists and both inventories are readable, warn when one exists but the other inventory is unreadable, fail when none exists on a federal-domain tenant, and manual when none exists commercially. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-AUTH-008` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when any ACTIVE certificate-oriented IdP or authenticator exists and both inventories are readable, warn when one exists but the other inventory is unreadable, fail when none exists on a federal-domain tenant, and manual when none exists commercially. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-AUTH-008` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-AUTH-008` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-AUTH-009` | compliant | All required source reads are complete and this derivation returns pass: for federal domains, return pass only when ACTIVE Okta Verify requires FIPS and no restricted authenticator is active, fail for a restricted authenticator or non-required FIPS, and warn when Okta Verify is absent; commercially, warn for restricted authenticators and pass otherwise. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-AUTH-009` | noncompliant | A complete source read satisfies the fail branch of this derivation: for federal domains, return pass only when ACTIVE Okta Verify requires FIPS and no restricted authenticator is active, fail for a restricted authenticator or non-required FIPS, and warn when Okta Verify is absent; commercially, warn for restricted authenticators and pass otherwise. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-AUTH-009` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-AUTH-009` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-ADMIN-001` | compliant | All required source reads are complete and this derivation returns pass: for a non-empty privileged-user inventory, return pass with at most two SUPER_ADMIN users, warn with three through five, and fail above five. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-ADMIN-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: for a non-empty privileged-user inventory, return pass with at most two SUPER_ADMIN users, warn with three through five, and fail above five. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-ADMIN-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-ADMIN-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-ADMIN-002` | compliant | All required source reads are complete and this derivation returns pass: return fail when any privileged account is non-ACTIVE or last signed in over 90 days ago, warn when any lacks a last-login date, and pass otherwise. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-ADMIN-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any privileged account is non-ACTIVE or last signed in over 90 days ago, warn when any lacks a last-login date, and pass otherwise. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-ADMIN-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-ADMIN-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-ADMIN-003` | compliant | All required source reads are complete and this derivation returns pass: for detected admin-like groups, return pass when every expanded privileged group has at most 25 members, warn when any exceeds 25 or expansion is partial, and manual when no group matches the discovery pattern. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-ADMIN-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: for detected admin-like groups, return pass when every expanded privileged group has at most 25 members, warn when any exceeds 25 or expansion is partial, and manual when no group matches the discovery pattern. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-ADMIN-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-ADMIN-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-ADMIN-004` | compliant | All required source reads are complete and this derivation returns pass: return fail when any inspected privileged user has no ACTIVE factor, warn when every inspected user has a factor but any lacks a phishing-resistant one, and pass when every privileged user has an ACTIVE phishing-resistant factor. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-ADMIN-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any inspected privileged user has no ACTIVE factor, warn when every inspected user has a factor but any lacks a phishing-resistant one, and pass when every privileged user has an ACTIVE phishing-resistant factor. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-ADMIN-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-ADMIN-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-ADMIN-005` | compliant | All required source reads are complete and this derivation returns pass: return fail when any ACTIVE user has not signed in for over 90 days or any STAGED or PROVISIONED user is older than 30 days, warn for missing last-login or suspended, locked, expired, recovery, or partial users, and pass otherwise. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-ADMIN-005` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any ACTIVE user has not signed in for over 90 days or any STAGED or PROVISIONED user is older than 30 days, warn for missing last-login or suspended, locked, expired, recovery, or partial users, and pass otherwise. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-ADMIN-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-ADMIN-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-ADMIN-006` | compliant | All required source reads are complete and this derivation returns pass: return pass only when Okta Support access is DISABLED, thirdPartyAdmin is false, and both reads complete; return warn for every other readable state and manual when support access is unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-ADMIN-006` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass only when Okta Support access is DISABLED, thirdPartyAdmin is false, and both reads complete; return warn for every other readable state and manual when support access is unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-ADMIN-006` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-ADMIN-006` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-INTEG-001` | compliant | All required source reads are complete and this derivation returns pass: return fail when any ACTIVE trusted origin uses HTTP or a wildcard, pass when at least one ACTIVE origin exists and none is insecure, and manual when the complete inventory has no ACTIVE origin because origins are optional. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-INTEG-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any ACTIVE trusted origin uses HTTP or a wildcard, pass when at least one ACTIVE origin exists and none is insecure, and manual when the complete inventory has no ACTIVE origin because origins are optional. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-INTEG-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-INTEG-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-INTEG-002` | compliant | All required source reads are complete and this derivation returns pass: return pass when at least one ACTIVE non-system, non-LegacyIpZone custom zone exists, warn when a non-empty complete zone inventory has none, and manual when the zone inventory is empty or unreadable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-INTEG-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when at least one ACTIVE non-system, non-LegacyIpZone custom zone exists, warn when a non-empty complete zone inventory has none, and manual when the zone inventory is empty or unreadable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-INTEG-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-INTEG-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-INTEG-003` | compliant | All required source reads are complete and this derivation returns pass: return fail when any ACTIVE OIDC app uses password or implicit grants, warn when only inactive apps retain those grants, and pass when no app does. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-INTEG-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any ACTIVE OIDC app uses password or implicit grants, warn when only inactive apps retain those grants, and pass when no app does. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-INTEG-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-INTEG-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-INTEG-004` | compliant | All required source reads are complete and this derivation returns pass: return pass when any ACTIVE sign-on or access rule uses risk, device, behavior, or network context, warn when custom zones exist without such a rule or reads are partial, and fail when complete evidence has neither. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-INTEG-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when any ACTIVE sign-on or access rule uses risk, device, behavior, or network context, warn when custom zones exist without such a rule or reads are partial, and fail when complete evidence has neither. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-INTEG-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-INTEG-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-INTEG-005` | compliant | All required source reads are complete and this derivation returns pass: return pass when every application is ACTIVE, warn when any application is inactive or restricted, and manual when the app inventory is empty or unreadable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-INTEG-005` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every application is ACTIVE, warn when any application is inactive or restricted, and manual when the app inventory is empty or unreadable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-INTEG-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-INTEG-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-INTEG-006` | compliant | All required source reads are complete and this derivation returns pass: return pass when any ACTIVE provisioning app has PUSH_USER_DEACTIVATION, fail when provisioning exists but none pushes deactivation, warn when no provisioning feature is visible or group rules are partial, and manual when apps are unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-INTEG-006` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when any ACTIVE provisioning app has PUSH_USER_DEACTIVATION, fail when provisioning exists but none pushes deactivation, warn when no provisioning feature is visible or group rules are partial, and manual when apps are unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-INTEG-006` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-INTEG-006` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-MON-001` | compliant | All required source reads are complete and this derivation returns pass: return pass when any ACTIVE log stream exists, warn when only ACTIVE event hooks exist or a pass has partial companion evidence, and fail when complete evidence has neither. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-MON-001` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when any ACTIVE log stream exists, warn when only ACTIVE event hooks exist or a pass has partial companion evidence, and fail when complete evidence has neither. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-MON-001` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-MON-001` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-MON-002` | compliant | All required source reads are complete and this derivation returns pass: return pass when the complete lookback contains at least one System Log event, warn when the window is empty or truncated, and manual when the log read fails. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-MON-002` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when the complete lookback contains at least one System Log event, warn when the window is empty or truncated, and manual when the log read fails. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-MON-002` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-MON-002` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-MON-003` | compliant | All required source reads are complete and this derivation returns pass: return pass for ThreatInsight block mode, warn for audit or log_only, fail for another readable mode, and manual when the feature object is unavailable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-MON-003` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass for ThreatInsight block mode, warn for audit or log_only, fail for another readable mode, and manual when the feature object is unavailable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-MON-003` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-MON-003` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-MON-004` | compliant | All required source reads are complete and this derivation returns pass: return pass when any behavior rule is ACTIVE and warn when a complete behavior inventory has no active rule. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-MON-004` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when any behavior rule is ACTIVE and warn when a complete behavior inventory has no active rule. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-MON-004` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-MON-004` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-MON-005` | compliant | All required source reads are complete and this derivation returns pass: return pass when every listed SSWS token has a usable reference date no older than 90 days, warn for stale or undated tokens, manual for an empty SSWS-authenticated inventory, and pass for an empty OAuth-authenticated inventory. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-MON-005` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when every listed SSWS token has a usable reference date no older than 90 days, warn for stale or undated tokens, manual for an empty SSWS-authenticated inventory, and pass for an empty OAuth-authenticated inventory. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-MON-005` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-MON-005` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-MON-006` | compliant | All required source reads are complete and this derivation returns pass: return pass when at least one device assurance policy exists and warn when the complete readable inventory is empty. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-MON-006` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when at least one device assurance policy exists and warn when the complete readable inventory is empty. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-MON-006` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-MON-006` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-MON-007` | compliant | All required source reads are complete and this derivation returns pass: return fail when any listed token is expired, warn when any is not zone-restricted, lacks a valid expiry, or has an inactivity window over 30 days, and pass otherwise, including an empty OAuth-authenticated inventory. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-MON-007` | noncompliant | A complete source read satisfies the fail branch of this derivation: return fail when any listed token is expired, warn when any is not zone-restricted, lacks a valid expiry, or has an inactivity window over 30 days, and pass otherwise, including an empty OAuth-authenticated inventory. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-MON-007` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-MON-007` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-MON-008` | compliant | All required source reads are complete and this derivation returns pass: return pass when TECHNICAL contact resolves to an ACTIVE user, fail when missing, unassigned, or non-ACTIVE, warn when status or lookup is unknown, and manual when the contact inventory itself is empty or unreadable. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-MON-008` | noncompliant | A complete source read satisfies the fail branch of this derivation: return pass when TECHNICAL contact resolves to an ACTIVE user, fail when missing, unassigned, or non-ACTIVE, warn when status or lookup is unknown, and manual when the contact inventory itself is empty or unreadable. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-MON-008` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-MON-008` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `OKTA-MON-009` | compliant | All required source reads are complete and this derivation returns pass: always return manual because administrator security-notification email preferences have no Management API read surface. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `OKTA-MON-009` | noncompliant | A complete source read satisfies the fail branch of this derivation: always return manual because administrator security-notification email preferences have no Management API read surface. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `OKTA-MON-009` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `OKTA-MON-009` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Phishing-resistant authenticators | - | - | - | - | - | - | - | - |
| 2 | Administrator MFA enforcement | - | - | - | - | - | - | - | - |
| 3 | Password complexity | - | - | - | - | - | - | - | - |
| 4 | Password aging and history | - | - | - | - | - | - | - | - |
| 5 | Password lockout threshold | - | - | - | - | - | - | - | - |
| 6 | Session idle timeout | - | - | - | - | - | - | - | - |
| 7 | Session lifetime and persistent cookie controls | - | - | - | - | - | - | - | - |
| 8 | Certificate or PIV/CAC authentication | - | - | - | - | - | - | - | - |
| 9 | FIPS and restricted authenticator posture | - | - | - | - | - | - | - | - |
| 10 | Super admin assignments are constrained | - | - | - | - | - | - | - | - |
| 11 | Inactive privileged accounts | - | - | - | - | - | - | - | - |
| 12 | Privileged group assignments are bounded | - | - | - | - | - | - | - | - |
| 13 | Privileged user MFA enrollment | - | - | - | - | - | - | - | - |
| 14 | Workforce account lifecycle hygiene | - | - | - | - | - | - | - | - |
| 15 | Okta Support access and third-party admin governance | - | - | - | - | - | - | - | - |
| 16 | Trusted origins hygiene | - | - | - | - | - | - | - | - |
| 17 | Network zones are configured | - | - | - | - | - | - | - | - |
| 18 | OIDC application grant hygiene | - | - | - | - | - | - | - | - |
| 19 | Risk-based and contextual access controls | - | - | - | - | - | - | - | - |
| 20 | Application inventory hygiene | - | - | - | - | - | - | - | - |
| 21 | Provisioning and deprovisioning automation | - | - | - | - | - | - | - | - |
| 22 | Log offloading and external monitoring | - | - | - | - | - | - | - | - |
| 23 | System log visibility | - | - | - | - | - | - | - | - |
| 24 | ThreatInsight posture | - | - | - | - | - | - | - | - |
| 25 | Behavior detection coverage | - | - | - | - | - | - | - | - |
| 26 | API token hygiene | - | - | - | - | - | - | - | - |
| 27 | Device assurance policy coverage | - | - | - | - | - | - | - | - |
| 28 | API token expiry and network restrictions | - | - | - | - | - | - | - | - |
| 29 | Security contact routing | - | - | - | - | - | - | - | - |
| 30 | Administrator security notification emails | - | - | - | - | - | - | - | - |

## Collection states

| State | Required rendering |
|---|---|
| complete | complete: proven API exhaustion or a successful single-object read. |
| truncated | truncated: preserve seen and total when available plus the exact stop reason. |
| unreadable | unreadable: render data and counts as null and retain a scrubbed error envelope. |
| denied | denied: render null evidence with the endpoint and HTTP status, never an empty inventory. |
| not requested | not_requested: identify the unreadable parent dependency and do not invent an HTTP status. |
| not configured | not_configured: identify the absent optional feature or credential without treating it as compliant. |

## Integration-specific scrubbing

Shared contract version: 1.1.

Projection stage: Project records to verdict-consumed fields, scrub configured and discovered credentials, then scrub again at every report and archive write sink.

Sensitive fields and values: apiToken, clientAssertion, privateKey, credentials, authorization, cookie

Credential formats: SSWS tokens, OAuth bearer tokens, private keys, signed JWT assertions

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `users` | `id`, `status`, `profile`, `lastLogin` |
| `policies` | `id`, `type`, `status`, `conditions`, `settings` |
| `apps` | `id`, `name`, `label`, `status`, `settings`, `credentials` |
| `system-log` | `uuid`, `published`, `eventType`, `severity`, `outcome` |

## Export layout

Required paths:

- `core_data/access.json`
- `analysis/findings.json`
- `compliance/executive_summary.md`
- `compliance/unified_compliance_matrix.md`
- `compliance/fedramp/fedramp_compliance_report.md`
- `compliance/cmmc/cmmc_compliance_report.md`
- `compliance/soc2/soc2_compliance_report.md`
- `compliance/cis/cis_compliance_report.md`
- `compliance/pci_dss/pci_dss_compliance_report.md`
- `compliance/disa_stig/stig_compliance_checklist.md`
- `compliance/irap/irap_compliance_report.md`
- `compliance/ismap/ismap_compliance_report.md`
- `QUICK_REFERENCE.md`

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `core_data/{dataset}.json` | json | The dataset is part of the assessment, including explicit not-collected markers. | Projected source records or a structured unavailable marker; unavailable values remain null. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/findings.json` | json | Always. | Array of finding id, control, title, severity, status, summary, evidence, mappings, and optional manual evidence. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `compliance/executive_summary.md` | markdown | Always. | Human-readable counts and findings grouped by status. | UTF-8 Markdown. |
| `compliance/unified_compliance_matrix.md` | markdown | Always. | Finding-to-framework mapping matrix. | UTF-8 Markdown. |
| `compliance/{framework}/{report}.md` | markdown | Always for each supported framework. | Framework-specific finding rows and mappings. | UTF-8 Markdown. |
| `QUICK_REFERENCE.md` | markdown | Always. | Bundle navigation and operator next steps. | UTF-8 Markdown. |
| `_errors.log` | text | At least one collection read failed, was denied, or was incomplete. | Scrubbed collection error summaries without response bodies or credentials. | UTF-8 text. |

### Record schemas

#### finding

- `id`
- `control`
- `title`
- `severity`
- `status`
- `summary`
- `evidence`
- `mappings`
- `manualEvidence`

#### collection_marker

- `collected`
- `status`
- `endpoint`
- `error`
- `reason`

#### access_surface

- `name`
- `endpoint`
- `status`
- `count`
- `error`

#### assessment

- `area`
- `title`
- `summary`
- `findings`
- `errors`

#### bundle_manifest

- `outputDir`
- `zipPath`
- `fileCount`
- `findingCount`
- `errorCount`

JSON formatting: UTF-8 JSON with deterministic field order, two-space indentation, and a trailing newline.

Overwrite policy: Allocate a new suffixed output directory on every rerun; never overwrite an earlier bundle.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Create okta-audit.zip beside the allocated okta-audit directory, applying the same suffix to both.
