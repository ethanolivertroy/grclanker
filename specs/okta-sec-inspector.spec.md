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
| oauth-scope | `okta.users.read` | `users`, `role-assignees`, `user-factors`, `group-members` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.groups.read` | `groups`, `group-roles`, `group-members`, `group-rules` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.apps.read` | `apps` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.authenticators.read` | `authenticators`, `org-factors` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.authorizationServers.read` | `authorization-servers`, `default-authorization-server` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.idps.read` | `idps` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.trustedOrigins.read` | `trusted-origins` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.policies.read` | `sign-on-policies`, `sign-on-policy-rules`, `password-policies`, `mfa-policies`, `access-policies`, `access-policy-rules` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.logs.read` | `system-log` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.eventHooks.read` | `event-hooks` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.logStreams.read` | `log-streams` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.orgs.read` | `okta-support`, `third-party-admin`, `org-contacts` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.networkZones.read` | `network-zones` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.behaviors.read` | `behaviors` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.deviceAssurance.read` | `device-assurance` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.roles.read` | `role-assignees`, `user-roles`, `group-roles` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.apiTokens.read` | `api-tokens` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| oauth-scope | `okta.threatInsights.read` | `threat-insight` | The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner. |
| role | `Okta administrator role granting the same read surfaces for SSWS authentication` | `sign-on-policies`, `sign-on-policy-rules`, `password-policies`, `mfa-policies`, `access-policies`, `access-policy-rules`, `authenticators`, `idps`, `authorization-servers`, `default-authorization-server`, `org-factors`, `users`, `role-assignees`, `user-roles`, `user-factors`, `groups`, `group-roles`, `group-members`, `okta-support`, `third-party-admin`, `apps`, `trusted-origins`, `network-zones`, `group-rules`, `event-hooks`, `log-streams`, `system-log`, `behaviors`, `threat-insight`, `api-tokens`, `device-assurance`, `org-contacts` |  |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `sign-on-policies` | HTTP | `GET /api/v1/policies?type=OKTA_SIGN_ON` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `type`, `status`, `conditions`, `settings` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/) |
| `sign-on-policy-rules` | HTTP | `GET /api/v1/policies/{policyId}/rules` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `status`, `conditions`, `actions` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/) |
| `password-policies` | HTTP | `GET /api/v1/policies?type=PASSWORD` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `status`, `settings.password` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/) |
| `mfa-policies` | HTTP | `GET /api/v1/policies?type=MFA_ENROLL` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `status`, `settings`, `conditions` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/) |
| `access-policies` | HTTP | `GET /api/v1/policies?type=ACCESS_POLICY` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `status`, `conditions`, `settings` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/) |
| `access-policy-rules` | HTTP | `GET /api/v1/policies/{policyId}/rules` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `status`, `conditions`, `actions` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/) |
| `authenticators` | HTTP | `GET /api/v1/authenticators` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `key`, `name`, `type`, `status`, `settings` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Authenticator/) |
| `idps` | HTTP | `GET /api/v1/idps` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `type`, `status`, `protocol` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/IdentityProvider/) |
| `authorization-servers` | HTTP | `GET /api/v1/authorizationServers` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `issuer`, `status`, `audiences` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/AuthorizationServer/) |
| `default-authorization-server` | HTTP | `GET /api/v1/authorizationServers/default` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `issuer`, `audiences` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/AuthorizationServer/) |
| `org-factors` | HTTP | `GET /api/v1/org/factors` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `factorType`, `provider`, `status` | [Official documentation](https://developer.okta.com/docs/reference/api/factors/) |
| `users` | HTTP | `GET /api/v1/users` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `status`, `created`, `lastLogin`, `profile.login`, `profile.email` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/) |
| `role-assignees` | HTTP | `GET /api/v1/iam/assignees/users` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `status`, `profile.login`, `lastLogin` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/) |
| `user-roles` | HTTP | `GET /api/v1/users/{userId}/roles` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `type`, `label`, `status` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/) |
| `user-factors` | HTTP | `GET /api/v1/users/{userId}/factors` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `factorType`, `provider`, `status` | [Official documentation](https://developer.okta.com/docs/reference/api/factors/) |
| `groups` | HTTP | `GET /api/v1/groups` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `type`, `profile.name` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Group/) |
| `group-roles` | HTTP | `GET /api/v1/groups/{groupId}/roles` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `type`, `label` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAGroup/) |
| `group-members` | HTTP | `GET /api/v1/groups/{groupId}/users` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `status`, `profile.login` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Group/) |
| `okta-support` | HTTP | `GET /api/v1/org/privacy/oktaSupport` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `support`, `expiration` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/OrgSetting/) |
| `third-party-admin` | HTTP | `GET /api/v1/org/orgSettings/thirdPartyAdminSetting` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `thirdPartyAdmin` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/OrgSetting/) |
| `apps` | HTTP | `GET /api/v1/apps` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `label`, `status`, `settings`, `credentials`, `features` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/) |
| `trusted-origins` | HTTP | `GET /api/v1/trustedOrigins` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `origin`, `status`, `scopes` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/TrustedOrigin/) |
| `network-zones` | HTTP | `GET /api/v1/zones` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `type`, `status`, `system` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/NetworkZone/) |
| `group-rules` | HTTP | `GET /api/v1/groups/rules` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `status`, `conditions`, `actions` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/GroupRule/) |
| `event-hooks` | HTTP | `GET /api/v1/eventHooks` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `status`, `events` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/EventHook/) |
| `log-streams` | HTTP | `GET /api/v1/logStreams` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `type`, `status` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/LogStream/) |
| `system-log` | HTTP | `GET /api/v1/logs` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `uuid`, `published`, `eventType`, `severity`, `outcome` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/) |
| `behaviors` | HTTP | `GET /api/v1/behaviors` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `type`, `status`, `settings` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/BehaviorRule/) |
| `threat-insight` | HTTP | `GET /api/v1/threats/configuration` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `action`, `mode`, `settings`, `excludeZones` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ThreatInsight/) |
| `api-tokens` | HTTP | `GET /api/v1/api-tokens` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `created`, `lastUpdated`, `expiresAt`, `network`, `userId` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApiToken/) |
| `device-assurance` | HTTP | `GET /api/v1/device-assurances` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `platform`, `status` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/DeviceAssurance/) |
| `org-contacts` | HTTP | `GET /api/v1/org/contacts` | Okta Management API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `contactType`, `userId` | [Official documentation](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/OrgSetting/) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `sign-on-policies` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `sign-on-policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `sign-on-policies` | response | A JSON object or list containing only the documented id, name, type, status, conditions, settings members consumed by verdicts. | yes |
| `sign-on-policy-rules` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `sign-on-policy-rules` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `sign-on-policy-rules` | response | A JSON object or list containing only the documented id, name, status, conditions, actions members consumed by verdicts. | yes |
| `password-policies` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `password-policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `password-policies` | response | A JSON object or list containing only the documented id, name, status, settings.password members consumed by verdicts. | yes |
| `mfa-policies` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `mfa-policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `mfa-policies` | response | A JSON object or list containing only the documented id, name, status, settings, conditions members consumed by verdicts. | yes |
| `access-policies` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `access-policies` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `access-policies` | response | A JSON object or list containing only the documented id, name, status, conditions, settings members consumed by verdicts. | yes |
| `access-policy-rules` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `access-policy-rules` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `access-policy-rules` | response | A JSON object or list containing only the documented id, name, status, conditions, actions members consumed by verdicts. | yes |
| `authenticators` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `authenticators` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `authenticators` | response | A JSON object or list containing only the documented id, key, name, type, status, settings members consumed by verdicts. | yes |
| `idps` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `idps` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `idps` | response | A JSON object or list containing only the documented id, name, type, status, protocol members consumed by verdicts. | yes |
| `authorization-servers` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `authorization-servers` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `authorization-servers` | response | A JSON object or list containing only the documented id, name, issuer, status, audiences members consumed by verdicts. | yes |
| `default-authorization-server` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `default-authorization-server` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `default-authorization-server` | response | A JSON object or list containing only the documented id, issuer, audiences members consumed by verdicts. | yes |
| `org-factors` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `org-factors` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `org-factors` | response | A JSON object or list containing only the documented id, factorType, provider, status members consumed by verdicts. | yes |
| `users` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `users` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `users` | response | A JSON object or list containing only the documented id, status, created, lastLogin, profile.login, profile.email members consumed by verdicts. | yes |
| `role-assignees` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `role-assignees` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `role-assignees` | response | A JSON object or list containing only the documented id, status, profile.login, lastLogin members consumed by verdicts. | yes |
| `user-roles` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `user-roles` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `user-roles` | response | A JSON object or list containing only the documented id, type, label, status members consumed by verdicts. | yes |
| `user-factors` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `user-factors` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `user-factors` | response | A JSON object or list containing only the documented id, factorType, provider, status members consumed by verdicts. | yes |
| `groups` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `groups` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `groups` | response | A JSON object or list containing only the documented id, type, profile.name members consumed by verdicts. | yes |
| `group-roles` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `group-roles` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `group-roles` | response | A JSON object or list containing only the documented id, type, label members consumed by verdicts. | yes |
| `group-members` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `group-members` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `group-members` | response | A JSON object or list containing only the documented id, status, profile.login members consumed by verdicts. | yes |
| `okta-support` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `okta-support` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `okta-support` | response | A JSON object or list containing only the documented support, expiration members consumed by verdicts. | yes |
| `third-party-admin` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `third-party-admin` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `third-party-admin` | response | A JSON object or list containing only the documented thirdPartyAdmin members consumed by verdicts. | yes |
| `apps` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `apps` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `apps` | response | A JSON object or list containing only the documented id, name, label, status, settings, credentials, features members consumed by verdicts. | yes |
| `trusted-origins` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `trusted-origins` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `trusted-origins` | response | A JSON object or list containing only the documented id, name, origin, status, scopes members consumed by verdicts. | yes |
| `network-zones` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `network-zones` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `network-zones` | response | A JSON object or list containing only the documented id, name, type, status, system members consumed by verdicts. | yes |
| `group-rules` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `group-rules` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `group-rules` | response | A JSON object or list containing only the documented id, name, status, conditions, actions members consumed by verdicts. | yes |
| `event-hooks` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `event-hooks` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `event-hooks` | response | A JSON object or list containing only the documented id, name, status, events members consumed by verdicts. | yes |
| `log-streams` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `log-streams` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `log-streams` | response | A JSON object or list containing only the documented id, name, type, status members consumed by verdicts. | yes |
| `system-log` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `system-log` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `system-log` | response | A JSON object or list containing only the documented uuid, published, eventType, severity, outcome members consumed by verdicts. | yes |
| `behaviors` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `behaviors` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `behaviors` | response | A JSON object or list containing only the documented id, name, type, status, settings members consumed by verdicts. | yes |
| `threat-insight` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `threat-insight` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `threat-insight` | response | A JSON object or list containing only the documented action, mode, settings, excludeZones members consumed by verdicts. | yes |
| `api-tokens` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `api-tokens` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `api-tokens` | response | A JSON object or list containing only the documented id, name, created, lastUpdated, expiresAt, network, userId members consumed by verdicts. | yes |
| `device-assurance` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `device-assurance` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `device-assurance` | response | A JSON object or list containing only the documented id, name, platform, status members consumed by verdicts. | yes |
| `org-contacts` | client | Use the configured Okta Management API origin; never follow a server link to a different origin. | yes |
| `org-contacts` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `org-contacts` | response | A JSON object or list containing only the documented contactType, userId members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `sign-on-policies`, `sign-on-policy-rules`, `password-policies`, `mfa-policies`, `access-policies`, `access-policy-rules`, `authenticators`, `idps`, `authorization-servers`, `org-factors`, `users`, `role-assignees`, `user-roles`, `user-factors`, `groups`, `group-roles`, `group-members`, `apps`, `trusted-origins`, `network-zones`, `group-rules`, `event-hooks`, `log-streams`, `system-log`, `behaviors`, `api-tokens`, `device-assurance`, `org-contacts` | `Link rel=next` | 200 | caller limit | 50 | No authoritative total is returned; completion requires the absence of a same-origin Link rel=next. Users use a 50-page cap and System Log uses a five-page cap. | No rel=next; 50-page list cap; five-page System Log cap; Repeated next URL; Empty page with next URL; Rejected cross-origin or user-information URL |

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
| `OKTA-AUTH-001` | high | `okta_assess_authentication` | `authenticators`, `org-factors` | `readable`, `complete`, `classic_engine`, `authenticator_count`, `phishing_resistant_count`, `strong_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when any ACTIVE authenticator is WebAuthn, FIDO2, smart card, certificate, PIV, or CAC, warn when another strong authenticator exists, and fail when a complete non-Classic inventory has none. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when any ACTIVE authenticator is WebAuthn, FIDO2, smart card, certificate, PIV, or CAC, warn when another strong authenticator exists, and fail when a complete non-Classic inventory has none. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when any ACTIVE authenticator is WebAuthn, FIDO2, smart card, certificate, PIV, or CAC, warn when another strong authenticator exists, and fail when a complete non-Classic inventory has none. | The required evidence for Phishing-resistant authenticators is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-002` | high | `okta_assess_authentication` | `sign-on-policies`, `sign-on-policy-rules`, `access-policies`, `access-policy-rules`, `authenticators`, `mfa-policies` | `policy_inventory_readable`, `complete`, `admin_policy_count`, `admin_mfa_rule_count`, `strong_authenticator_count`, `mfa_control_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when an ACTIVE Admin Console or Dashboard policy has an ACTIVE MFA rule, a strong authenticator exists, and all policy reads completed; warn for partial evidence or MFA controls without an explicit admin rule; fail when complete evidence shows none. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when an ACTIVE Admin Console or Dashboard policy has an ACTIVE MFA rule, a strong authenticator exists, and all policy reads completed; warn for partial evidence or MFA controls without an explicit admin rule; fail when complete evidence shows none. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when an ACTIVE Admin Console or Dashboard policy has an ACTIVE MFA rule, a strong authenticator exists, and all policy reads completed; warn for partial evidence or MFA controls without an explicit admin rule; fail when complete evidence shows none. | The required evidence for Administrator MFA enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-003` | medium | `okta_assess_authentication` | `password-policies` | `readable`, `complete`, `inventory_count`, `policy_count`, `compliant_policy_count`, `all_policies_compliant` | Complete readable evidence satisfies the compliant branch of this derivation: across ACTIVE password policies, return pass when every policy has minimum length 12 and requires upper, lower, number, and symbol, warn when only some do, and fail when none do or no policy is ACTIVE. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: across ACTIVE password policies, return pass when every policy has minimum length 12 and requires upper, lower, number, and symbol, warn when only some do, and fail when none do or no policy is ACTIVE. | Complete readable evidence satisfies the violation branch, which has first-match precedence: across ACTIVE password policies, return pass when every policy has minimum length 12 and requires upper, lower, number, and symbol, warn when only some do, and fail when none do or no policy is ACTIVE. | The required evidence for Password complexity is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-004` | medium | `okta_assess_authentication` | `password-policies` | `readable`, `complete`, `inventory_count`, `policy_count`, `compliant_policy_count`, `all_policies_compliant` | Complete readable evidence satisfies the compliant branch of this derivation: across ACTIVE password policies, return pass when every policy has maximum age from 1 through 90 days and history at least five, warn when only some do, and fail when none do or no policy is ACTIVE. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: across ACTIVE password policies, return pass when every policy has maximum age from 1 through 90 days and history at least five, warn when only some do, and fail when none do or no policy is ACTIVE. | Complete readable evidence satisfies the violation branch, which has first-match precedence: across ACTIVE password policies, return pass when every policy has maximum age from 1 through 90 days and history at least five, warn when only some do, and fail when none do or no policy is ACTIVE. | The required evidence for Password aging and history is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-005` | medium | `okta_assess_authentication` | `password-policies` | `readable`, `complete`, `inventory_count`, `policy_count`, `compliant_policy_count`, `all_policies_compliant` | Complete readable evidence satisfies the compliant branch of this derivation: across ACTIVE password policies, return pass when every policy locks after one through six attempts, warn when only some do, and fail when none do or no policy is ACTIVE. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: across ACTIVE password policies, return pass when every policy locks after one through six attempts, warn when only some do, and fail when none do or no policy is ACTIVE. | Complete readable evidence satisfies the violation branch, which has first-match precedence: across ACTIVE password policies, return pass when every policy locks after one through six attempts, warn when only some do, and fail when none do or no policy is ACTIVE. | The required evidence for Password lockout threshold is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-006` | medium | `okta_assess_authentication` | `sign-on-policies`, `sign-on-policy-rules` | `readable`, `complete`, `exposed_value_count`, `over_limit_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every ACTIVE sign-on rule with an idle value is at most 15 minutes, fail when any exceeds 15, manual when none exposes the value, and warn instead of pass when rule reads are partial. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every ACTIVE sign-on rule with an idle value is at most 15 minutes, fail when any exceeds 15, manual when none exposes the value, and warn instead of pass when rule reads are partial. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every ACTIVE sign-on rule with an idle value is at most 15 minutes, fail when any exceeds 15, manual when none exposes the value, and warn instead of pass when rule reads are partial. | The required evidence for Session idle timeout is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-007` | medium | `okta_assess_authentication` | `sign-on-policies`, `sign-on-policy-rules` | `readable`, `complete`, `exposed_value_count`, `over_limit_count`, `persistent_cookie_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every ACTIVE sign-on rule lifetime is at most 1080 minutes and no rule enables persistent cookies, fail when either condition is violated, manual when neither value is exposed, and warn instead of pass when rule reads are partial. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every ACTIVE sign-on rule lifetime is at most 1080 minutes and no rule enables persistent cookies, fail when either condition is violated, manual when neither value is exposed, and warn instead of pass when rule reads are partial. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every ACTIVE sign-on rule lifetime is at most 1080 minutes and no rule enables persistent cookies, fail when either condition is violated, manual when neither value is exposed, and warn instead of pass when rule reads are partial. | The required evidence for Session lifetime and persistent cookie controls is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-008` | medium | `okta_assess_authentication` | `idps`, `authenticators` | `idp_readable`, `authenticator_readable`, `certificate_method_count`, `federal_tenant` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when any ACTIVE certificate-oriented IdP or authenticator exists and both inventories are readable, warn when one exists but the other inventory is unreadable, fail when none exists on a federal-domain tenant, and manual when none exists commercially. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when any ACTIVE certificate-oriented IdP or authenticator exists and both inventories are readable, warn when one exists but the other inventory is unreadable, fail when none exists on a federal-domain tenant, and manual when none exists commercially. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when any ACTIVE certificate-oriented IdP or authenticator exists and both inventories are readable, warn when one exists but the other inventory is unreadable, fail when none exists on a federal-domain tenant, and manual when none exists commercially. | The required evidence for Certificate or PIV/CAC authentication is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-AUTH-009` | high | `okta_assess_authentication` | `authenticators`, `org-factors` | `readable`, `complete`, `classic_engine`, `authenticator_count`, `federal_tenant`, `okta_verify_active`, `fips_required`, `restricted_count` | Complete readable evidence satisfies the compliant branch of this derivation: for federal domains, return pass only when ACTIVE Okta Verify requires FIPS and no restricted authenticator is active, fail for a restricted authenticator or non-required FIPS, and warn when Okta Verify is absent; commercially, warn for restricted authenticators and pass otherwise. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for federal domains, return pass only when ACTIVE Okta Verify requires FIPS and no restricted authenticator is active, fail for a restricted authenticator or non-required FIPS, and warn when Okta Verify is absent; commercially, warn for restricted authenticators and pass otherwise. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for federal domains, return pass only when ACTIVE Okta Verify requires FIPS and no restricted authenticator is active, fail for a restricted authenticator or non-required FIPS, and warn when Okta Verify is absent; commercially, warn for restricted authenticators and pass otherwise. | The required evidence for FIPS and restricted authenticator posture is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-001` | medium | `okta_assess_admin_access` | `role-assignees`, `user-roles` | `readable`, `complete`, `privileged_user_count`, `super_admin_count` | Complete readable evidence satisfies the compliant branch of this derivation: for a non-empty privileged-user inventory, return pass with at most two SUPER_ADMIN users, warn with three through five, and fail above five. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for a non-empty privileged-user inventory, return pass with at most two SUPER_ADMIN users, warn with three through five, and fail above five. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for a non-empty privileged-user inventory, return pass with at most two SUPER_ADMIN users, warn with three through five, and fail above five. | The required evidence for Super admin assignments are constrained is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-002` | medium | `okta_assess_admin_access` | `role-assignees`, `user-roles` | `readable`, `complete`, `privileged_user_count`, `stale_count`, `unknown_activity_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any privileged account is non-ACTIVE or last signed in over 90 days ago, warn when any lacks a last-login date, and pass otherwise. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any privileged account is non-ACTIVE or last signed in over 90 days ago, warn when any lacks a last-login date, and pass otherwise. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any privileged account is non-ACTIVE or last signed in over 90 days ago, warn when any lacks a last-login date, and pass otherwise. | The required evidence for Inactive privileged accounts is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-003` | medium | `okta_assess_admin_access` | `groups`, `group-roles`, `group-members` | `readable`, `complete`, `privileged_group_count`, `oversized_group_count` | Complete readable evidence satisfies the compliant branch of this derivation: for detected admin-like groups, return pass when every expanded privileged group has at most 25 members, warn when any exceeds 25 or expansion is partial, and manual when no group matches the discovery pattern. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: for detected admin-like groups, return pass when every expanded privileged group has at most 25 members, warn when any exceeds 25 or expansion is partial, and manual when no group matches the discovery pattern. | Complete readable evidence satisfies the violation branch, which has first-match precedence: for detected admin-like groups, return pass when every expanded privileged group has at most 25 members, warn when any exceeds 25 or expansion is partial, and manual when no group matches the discovery pattern. | The required evidence for Privileged group assignments are bounded is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-004` | medium | `okta_assess_admin_access` | `role-assignees`, `user-factors` | `readable`, `complete`, `privileged_user_count`, `inspected_user_count`, `unenrolled_count`, `weak_factor_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any inspected privileged user has no ACTIVE factor, warn when every inspected user has a factor but any lacks a phishing-resistant one, and pass when every privileged user has an ACTIVE phishing-resistant factor. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any inspected privileged user has no ACTIVE factor, warn when every inspected user has a factor but any lacks a phishing-resistant one, and pass when every privileged user has an ACTIVE phishing-resistant factor. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any inspected privileged user has no ACTIVE factor, warn when every inspected user has a factor but any lacks a phishing-resistant one, and pass when every privileged user has an ACTIVE phishing-resistant factor. | The required evidence for Privileged user MFA enrollment is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-005` | medium | `okta_assess_admin_access` | `users` | `readable`, `complete`, `user_count`, `stale_active_count`, `never_activated_count`, `unknown_activity_count`, `attention_status_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any ACTIVE user has not signed in for over 90 days or any STAGED or PROVISIONED user is older than 30 days, warn for missing last-login or suspended, locked, expired, recovery, or partial users, and pass otherwise. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any ACTIVE user has not signed in for over 90 days or any STAGED or PROVISIONED user is older than 30 days, warn for missing last-login or suspended, locked, expired, recovery, or partial users, and pass otherwise. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any ACTIVE user has not signed in for over 90 days or any STAGED or PROVISIONED user is older than 30 days, warn for missing last-login or suspended, locked, expired, recovery, or partial users, and pass otherwise. | The required evidence for Workforce account lifecycle hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-ADMIN-006` | medium | `okta_assess_admin_access` | `okta-support`, `third-party-admin` | `support_readable`, `third_party_readable`, `support_present`, `support_disabled`, `third_party_admin` | Complete readable evidence satisfies the compliant branch of this derivation: return pass only when Okta Support access is DISABLED, thirdPartyAdmin is false, and both reads complete; return warn for every other readable state and manual when support access is unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass only when Okta Support access is DISABLED, thirdPartyAdmin is false, and both reads complete; return warn for every other readable state and manual when support access is unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass only when Okta Support access is DISABLED, thirdPartyAdmin is false, and both reads complete; return warn for every other readable state and manual when support access is unavailable. | The required evidence for Okta Support access and third-party admin governance is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-001` | medium | `okta_assess_integrations` | `trusted-origins` | `readable`, `complete`, `active_origin_count`, `insecure_active_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any ACTIVE trusted origin uses HTTP or a wildcard, pass when at least one ACTIVE origin exists and none is insecure, and manual when the complete inventory has no ACTIVE origin because origins are optional. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any ACTIVE trusted origin uses HTTP or a wildcard, pass when at least one ACTIVE origin exists and none is insecure, and manual when the complete inventory has no ACTIVE origin because origins are optional. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any ACTIVE trusted origin uses HTTP or a wildcard, pass when at least one ACTIVE origin exists and none is insecure, and manual when the complete inventory has no ACTIVE origin because origins are optional. | The required evidence for Trusted origins hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-002` | medium | `okta_assess_integrations` | `network-zones` | `readable`, `complete`, `zone_count`, `custom_zone_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when at least one ACTIVE non-system, non-LegacyIpZone custom zone exists, warn when a non-empty complete zone inventory has none, and manual when the zone inventory is empty or unreadable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when at least one ACTIVE non-system, non-LegacyIpZone custom zone exists, warn when a non-empty complete zone inventory has none, and manual when the zone inventory is empty or unreadable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when at least one ACTIVE non-system, non-LegacyIpZone custom zone exists, warn when a non-empty complete zone inventory has none, and manual when the zone inventory is empty or unreadable. | The required evidence for Network zones are configured is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-003` | medium | `okta_assess_integrations` | `apps` | `readable`, `complete`, `app_count`, `risky_active_count`, `risky_inactive_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any ACTIVE OIDC app uses password or implicit grants, warn when only inactive apps retain those grants, and pass when no app does. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any ACTIVE OIDC app uses password or implicit grants, warn when only inactive apps retain those grants, and pass when no app does. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any ACTIVE OIDC app uses password or implicit grants, warn when only inactive apps retain those grants, and pass when no app does. | The required evidence for OIDC application grant hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-004` | medium | `okta_assess_integrations` | `sign-on-policies`, `sign-on-policy-rules`, `access-policies`, `access-policy-rules`, `network-zones` | `policy_readable`, `complete`, `risk_aware_rule_count`, `custom_zone_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when any ACTIVE sign-on or access rule uses risk, device, behavior, or network context, warn when custom zones exist without such a rule or reads are partial, and fail when complete evidence has neither. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when any ACTIVE sign-on or access rule uses risk, device, behavior, or network context, warn when custom zones exist without such a rule or reads are partial, and fail when complete evidence has neither. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when any ACTIVE sign-on or access rule uses risk, device, behavior, or network context, warn when custom zones exist without such a rule or reads are partial, and fail when complete evidence has neither. | The required evidence for Risk-based and contextual access controls is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-005` | medium | `okta_assess_integrations` | `apps` | `readable`, `complete`, `app_count`, `inactive_app_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every application is ACTIVE, warn when any application is inactive or restricted, and manual when the app inventory is empty or unreadable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every application is ACTIVE, warn when any application is inactive or restricted, and manual when the app inventory is empty or unreadable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every application is ACTIVE, warn when any application is inactive or restricted, and manual when the app inventory is empty or unreadable. | The required evidence for Application inventory hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-INTEG-006` | medium | `okta_assess_integrations` | `apps`, `group-rules` | `readable`, `complete`, `app_count`, `provisioning_app_count`, `deactivation_app_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when any ACTIVE provisioning app has PUSH_USER_DEACTIVATION, fail when provisioning exists but none pushes deactivation, warn when no provisioning feature is visible or group rules are partial, and manual when apps are unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when any ACTIVE provisioning app has PUSH_USER_DEACTIVATION, fail when provisioning exists but none pushes deactivation, warn when no provisioning feature is visible or group rules are partial, and manual when apps are unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when any ACTIVE provisioning app has PUSH_USER_DEACTIVATION, fail when provisioning exists but none pushes deactivation, warn when no provisioning feature is visible or group rules are partial, and manual when apps are unavailable. | The required evidence for Provisioning and deprovisioning automation is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-001` | medium | `okta_assess_monitoring` | `event-hooks`, `log-streams` | `streams_readable`, `hooks_readable`, `complete`, `active_stream_count`, `active_hook_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when any ACTIVE log stream exists, warn when only ACTIVE event hooks exist or a pass has partial companion evidence, and fail when complete evidence has neither. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when any ACTIVE log stream exists, warn when only ACTIVE event hooks exist or a pass has partial companion evidence, and fail when complete evidence has neither. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when any ACTIVE log stream exists, warn when only ACTIVE event hooks exist or a pass has partial companion evidence, and fail when complete evidence has neither. | The required evidence for Log offloading and external monitoring is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-002` | medium | `okta_assess_monitoring` | `system-log` | `readable`, `complete`, `event_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when the complete lookback contains at least one System Log event, warn when the window is empty or truncated, and manual when the log read fails. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when the complete lookback contains at least one System Log event, warn when the window is empty or truncated, and manual when the log read fails. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when the complete lookback contains at least one System Log event, warn when the window is empty or truncated, and manual when the log read fails. | The required evidence for System log visibility is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-003` | medium | `okta_assess_monitoring` | `threat-insight` | `readable`, `configuration_present`, `mode` | Complete readable evidence satisfies the compliant branch of this derivation: return pass for ThreatInsight block mode, warn for audit or log_only, fail for another readable mode, and manual when the feature object is unavailable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass for ThreatInsight block mode, warn for audit or log_only, fail for another readable mode, and manual when the feature object is unavailable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass for ThreatInsight block mode, warn for audit or log_only, fail for another readable mode, and manual when the feature object is unavailable. | The required evidence for ThreatInsight posture is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-004` | medium | `okta_assess_monitoring` | `behaviors` | `readable`, `complete`, `active_behavior_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when any behavior rule is ACTIVE and warn when a complete behavior inventory has no active rule. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when any behavior rule is ACTIVE and warn when a complete behavior inventory has no active rule. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when any behavior rule is ACTIVE and warn when a complete behavior inventory has no active rule. | The required evidence for Behavior detection coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-005` | medium | `okta_assess_monitoring` | `api-tokens` | `readable`, `complete`, `token_count`, `ssws_auth`, `stale_count`, `undated_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when every listed SSWS token has a usable reference date no older than 90 days, warn for stale or undated tokens, manual for an empty SSWS-authenticated inventory, and pass for an empty OAuth-authenticated inventory. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when every listed SSWS token has a usable reference date no older than 90 days, warn for stale or undated tokens, manual for an empty SSWS-authenticated inventory, and pass for an empty OAuth-authenticated inventory. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when every listed SSWS token has a usable reference date no older than 90 days, warn for stale or undated tokens, manual for an empty SSWS-authenticated inventory, and pass for an empty OAuth-authenticated inventory. | The required evidence for API token hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-006` | medium | `okta_assess_monitoring` | `device-assurance` | `readable`, `complete`, `policy_count` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when at least one device assurance policy exists and warn when the complete readable inventory is empty. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when at least one device assurance policy exists and warn when the complete readable inventory is empty. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when at least one device assurance policy exists and warn when the complete readable inventory is empty. | The required evidence for Device assurance policy coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-007` | medium | `okta_assess_monitoring` | `api-tokens` | `readable`, `complete`, `token_count`, `ssws_auth`, `expired_count`, `unrestricted_count`, `missing_expiry_count`, `long_window_count` | Complete readable evidence satisfies the compliant branch of this derivation: return fail when any listed token is expired, warn when any is not zone-restricted, lacks a valid expiry, or has an inactivity window over 30 days, and pass otherwise, including an empty OAuth-authenticated inventory. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return fail when any listed token is expired, warn when any is not zone-restricted, lacks a valid expiry, or has an inactivity window over 30 days, and pass otherwise, including an empty OAuth-authenticated inventory. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return fail when any listed token is expired, warn when any is not zone-restricted, lacks a valid expiry, or has an inactivity window over 30 days, and pass otherwise, including an empty OAuth-authenticated inventory. | The required evidence for API token expiry and network restrictions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-008` | medium | `okta_assess_monitoring` | `org-contacts`, `users` | `readable`, `complete`, `contact_count`, `technical_contact_present`, `technical_user_assigned`, `technical_status_known`, `technical_user_active`, `technical_lookup_failed` | Complete readable evidence satisfies the compliant branch of this derivation: return pass when TECHNICAL contact resolves to an ACTIVE user, fail when missing, unassigned, or non-ACTIVE, warn when status or lookup is unknown, and manual when the contact inventory itself is empty or unreadable. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: return pass when TECHNICAL contact resolves to an ACTIVE user, fail when missing, unassigned, or non-ACTIVE, warn when status or lookup is unknown, and manual when the contact inventory itself is empty or unreadable. | Complete readable evidence satisfies the violation branch, which has first-match precedence: return pass when TECHNICAL contact resolves to an ACTIVE user, fail when missing, unassigned, or non-ACTIVE, warn when status or lookup is unknown, and manual when the contact inventory itself is empty or unreadable. | The required evidence for Security contact routing is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `OKTA-MON-009` | high | `okta_assess_monitoring` | None | None | Complete readable evidence satisfies the compliant branch of this derivation: always return manual because administrator security-notification email preferences have no Management API read surface. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: always return manual because administrator security-notification email preferences have no Management API read surface. | Complete readable evidence satisfies the violation branch, which has first-match precedence: always return manual because administrator security-notification email preferences have no Management API read surface. | The required evidence for Administrator security notification emails is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `OKTA-AUTH-001` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `classic_engine` equals true) |  |
| `OKTA-AUTH-001` | 2 | fail | any of (`authenticator_count` equals 0; all of (`phishing_resistant_count` equals 0; `strong_count` equals 0)) |  |
| `OKTA-AUTH-001` | 3 | warn | any of (`complete` does not equal true; all of (`phishing_resistant_count` equals 0; `strong_count` is greater than 0)) |  |
| `OKTA-AUTH-001` | 4 | pass | `phishing_resistant_count` is greater than 0 |  |
| `OKTA-AUTH-001` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-AUTH-002` | 1 | manual | `policy_inventory_readable` does not equal true |  |
| `OKTA-AUTH-002` | 2 | fail | all of (`admin_policy_count` equals 0; `mfa_control_count` equals 0; `strong_authenticator_count` equals 0) |  |
| `OKTA-AUTH-002` | 3 | warn | any of (`complete` does not equal true; `admin_mfa_rule_count` equals 0; `strong_authenticator_count` equals 0) |  |
| `OKTA-AUTH-002` | 4 | pass | all of (`admin_policy_count` is greater than 0; `admin_mfa_rule_count` is greater than 0; `strong_authenticator_count` is greater than 0) |  |
| `OKTA-AUTH-002` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-AUTH-003` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `inventory_count` equals 0) |  |
| `OKTA-AUTH-003` | 2 | fail | `compliant_policy_count` equals 0 |  |
| `OKTA-AUTH-003` | 3 | warn | any of (`complete` does not equal true; `all_policies_compliant` equals false) |  |
| `OKTA-AUTH-003` | 4 | pass | `all_policies_compliant` equals true |  |
| `OKTA-AUTH-003` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-AUTH-004` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `inventory_count` equals 0) |  |
| `OKTA-AUTH-004` | 2 | fail | `compliant_policy_count` equals 0 |  |
| `OKTA-AUTH-004` | 3 | warn | any of (`complete` does not equal true; `all_policies_compliant` equals false) |  |
| `OKTA-AUTH-004` | 4 | pass | `all_policies_compliant` equals true |  |
| `OKTA-AUTH-004` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-AUTH-005` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `inventory_count` equals 0) |  |
| `OKTA-AUTH-005` | 2 | fail | `compliant_policy_count` equals 0 |  |
| `OKTA-AUTH-005` | 3 | warn | any of (`complete` does not equal true; `all_policies_compliant` equals false) |  |
| `OKTA-AUTH-005` | 4 | pass | `all_policies_compliant` equals true |  |
| `OKTA-AUTH-005` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-AUTH-006` | 1 | fail | `over_limit_count` is greater than 0 | A proven violation retains precedence over incomplete companion evidence. |
| `OKTA-AUTH-006` | 2 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `exposed_value_count` equals 0) |  |
| `OKTA-AUTH-006` | 3 | warn | `complete` does not equal true |  |
| `OKTA-AUTH-006` | 4 | pass | `over_limit_count` equals 0 |  |
| `OKTA-AUTH-006` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-AUTH-007` | 1 | fail | any of (`over_limit_count` is greater than 0; `persistent_cookie_count` is greater than 0) | A proven violation retains precedence over incomplete companion evidence. |
| `OKTA-AUTH-007` | 2 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `exposed_value_count` equals 0) |  |
| `OKTA-AUTH-007` | 3 | warn | `complete` does not equal true |  |
| `OKTA-AUTH-007` | 4 | pass | all of (`over_limit_count` equals 0; `persistent_cookie_count` equals 0) |  |
| `OKTA-AUTH-007` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-AUTH-008` | 1 | manual | any of (all of (`idp_readable` equals false; `authenticator_readable` equals false); all of (`certificate_method_count` equals 0; any of (`idp_readable` equals false; `authenticator_readable` equals false)); all of (`certificate_method_count` equals 0; `federal_tenant` equals false)) |  |
| `OKTA-AUTH-008` | 2 | fail | all of (`certificate_method_count` equals 0; `federal_tenant` equals true) |  |
| `OKTA-AUTH-008` | 3 | warn | any of (`idp_readable` equals false; `authenticator_readable` equals false) |  |
| `OKTA-AUTH-008` | 4 | pass | `certificate_method_count` is greater than 0 |  |
| `OKTA-AUTH-008` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-AUTH-009` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `classic_engine` equals true) |  |
| `OKTA-AUTH-009` | 2 | fail | any of (`authenticator_count` equals 0; all of (`federal_tenant` equals true; any of (`restricted_count` is greater than 0; all of (`okta_verify_active` equals true; `fips_required` equals false)))) |  |
| `OKTA-AUTH-009` | 3 | warn | any of (`complete` does not equal true; all of (`federal_tenant` equals true; `okta_verify_active` equals false); all of (`federal_tenant` equals false; `restricted_count` is greater than 0)) |  |
| `OKTA-AUTH-009` | 4 | pass | always |  |
| `OKTA-AUTH-009` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-ADMIN-001` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `privileged_user_count` equals 0) |  |
| `OKTA-ADMIN-001` | 2 | fail | `super_admin_count` is greater than 5 |  |
| `OKTA-ADMIN-001` | 3 | warn | any of (`complete` does not equal true; `super_admin_count` is greater than 2) |  |
| `OKTA-ADMIN-001` | 4 | pass | `super_admin_count` is at most 2 |  |
| `OKTA-ADMIN-001` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-ADMIN-002` | 1 | fail | `stale_count` is greater than 0 | A proven violation retains precedence over incomplete companion evidence. |
| `OKTA-ADMIN-002` | 2 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `privileged_user_count` equals 0) |  |
| `OKTA-ADMIN-002` | 3 | warn | any of (`complete` does not equal true; `unknown_activity_count` is greater than 0) |  |
| `OKTA-ADMIN-002` | 4 | pass | always |  |
| `OKTA-ADMIN-002` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-ADMIN-003` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `privileged_group_count` equals 0) |  |
| `OKTA-ADMIN-003` | 2 | warn | any of (`complete` does not equal true; `oversized_group_count` is greater than 0) |  |
| `OKTA-ADMIN-003` | 3 | pass | `oversized_group_count` equals 0 |  |
| `OKTA-ADMIN-003` | 4 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-ADMIN-004` | 1 | fail | `unenrolled_count` is greater than 0 | A proven violation retains precedence over incomplete companion evidence. |
| `OKTA-ADMIN-004` | 2 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `privileged_user_count` equals 0; `inspected_user_count` equals 0) |  |
| `OKTA-ADMIN-004` | 3 | warn | any of (`complete` does not equal true; `weak_factor_count` is greater than 0) |  |
| `OKTA-ADMIN-004` | 4 | pass | always |  |
| `OKTA-ADMIN-004` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-ADMIN-005` | 1 | fail | any of (`stale_active_count` is greater than 0; `never_activated_count` is greater than 0) | A proven violation retains precedence over incomplete companion evidence. |
| `OKTA-ADMIN-005` | 2 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `user_count` equals 0) |  |
| `OKTA-ADMIN-005` | 3 | warn | any of (`complete` does not equal true; `unknown_activity_count` is greater than 0; `attention_status_count` is greater than 0) |  |
| `OKTA-ADMIN-005` | 4 | pass | always |  |
| `OKTA-ADMIN-005` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-ADMIN-006` | 1 | manual | any of (`support_readable` equals false; `support_present` equals false) |  |
| `OKTA-ADMIN-006` | 2 | warn | any of (`third_party_readable` equals false; `support_disabled` equals false; `third_party_admin` does not equal false) |  |
| `OKTA-ADMIN-006` | 3 | pass | all of (`support_disabled` equals true; `third_party_admin` equals false) |  |
| `OKTA-ADMIN-006` | 4 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-INTEG-001` | 1 | fail | `insecure_active_count` is greater than 0 | A proven violation retains precedence over incomplete companion evidence. |
| `OKTA-INTEG-001` | 2 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `active_origin_count` equals 0) |  |
| `OKTA-INTEG-001` | 3 | warn | `complete` does not equal true |  |
| `OKTA-INTEG-001` | 4 | pass | always |  |
| `OKTA-INTEG-001` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-INTEG-002` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `zone_count` equals 0) |  |
| `OKTA-INTEG-002` | 2 | warn | any of (`complete` does not equal true; `custom_zone_count` equals 0) |  |
| `OKTA-INTEG-002` | 3 | pass | `custom_zone_count` is greater than 0 |  |
| `OKTA-INTEG-002` | 4 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-INTEG-003` | 1 | fail | `risky_active_count` is greater than 0 | A proven violation retains precedence over incomplete companion evidence. |
| `OKTA-INTEG-003` | 2 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `app_count` equals 0) |  |
| `OKTA-INTEG-003` | 3 | warn | any of (`complete` does not equal true; `risky_inactive_count` is greater than 0) |  |
| `OKTA-INTEG-003` | 4 | pass | always |  |
| `OKTA-INTEG-003` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-INTEG-004` | 1 | manual | `policy_readable` equals false |  |
| `OKTA-INTEG-004` | 2 | fail | all of (`risk_aware_rule_count` equals 0; `custom_zone_count` equals 0) |  |
| `OKTA-INTEG-004` | 3 | warn | any of (`complete` does not equal true; `risk_aware_rule_count` equals 0) |  |
| `OKTA-INTEG-004` | 4 | pass | `risk_aware_rule_count` is greater than 0 |  |
| `OKTA-INTEG-004` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-INTEG-005` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `app_count` equals 0) |  |
| `OKTA-INTEG-005` | 2 | warn | any of (`complete` does not equal true; `inactive_app_count` is greater than 0) |  |
| `OKTA-INTEG-005` | 3 | pass | `inactive_app_count` equals 0 |  |
| `OKTA-INTEG-005` | 4 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-INTEG-006` | 1 | fail | all of (`provisioning_app_count` is greater than 0; `deactivation_app_count` equals 0) | A proven violation retains precedence over incomplete companion evidence. |
| `OKTA-INTEG-006` | 2 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `app_count` equals 0) |  |
| `OKTA-INTEG-006` | 3 | warn | any of (`complete` does not equal true; `provisioning_app_count` equals 0) |  |
| `OKTA-INTEG-006` | 4 | pass | `deactivation_app_count` is greater than 0 |  |
| `OKTA-INTEG-006` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-MON-001` | 1 | manual | any of (all of (`streams_readable` equals false; `hooks_readable` equals false); all of (`streams_readable` equals false; `active_hook_count` equals 0)) |  |
| `OKTA-MON-001` | 2 | fail | all of (`active_stream_count` equals 0; `active_hook_count` equals 0) |  |
| `OKTA-MON-001` | 3 | warn | any of (`complete` does not equal true; `active_stream_count` equals 0) |  |
| `OKTA-MON-001` | 4 | pass | `active_stream_count` is greater than 0 |  |
| `OKTA-MON-001` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-MON-002` | 1 | manual | any of (`readable` does not equal true; not (`readable` is present and non-null)) |  |
| `OKTA-MON-002` | 2 | warn | any of (`complete` does not equal true; `event_count` equals 0) |  |
| `OKTA-MON-002` | 3 | pass | `event_count` is greater than 0 |  |
| `OKTA-MON-002` | 4 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-MON-003` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `configuration_present` equals false) |  |
| `OKTA-MON-003` | 2 | fail | all of (`mode` does not equal "block"; `mode` does not equal "audit"; `mode` does not equal "log_only") |  |
| `OKTA-MON-003` | 3 | warn | any of (`mode` equals "audit"; `mode` equals "log_only") |  |
| `OKTA-MON-003` | 4 | pass | `mode` equals "block" |  |
| `OKTA-MON-003` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-MON-004` | 1 | manual | any of (`readable` does not equal true; not (`readable` is present and non-null)) |  |
| `OKTA-MON-004` | 2 | warn | any of (`complete` does not equal true; `active_behavior_count` equals 0) |  |
| `OKTA-MON-004` | 3 | pass | `active_behavior_count` is greater than 0 |  |
| `OKTA-MON-004` | 4 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-MON-005` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); all of (`token_count` equals 0; `ssws_auth` equals true)) |  |
| `OKTA-MON-005` | 2 | warn | any of (`complete` does not equal true; `stale_count` is greater than 0; `undated_count` is greater than 0) |  |
| `OKTA-MON-005` | 3 | pass | always |  |
| `OKTA-MON-005` | 4 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-MON-006` | 1 | manual | any of (`readable` does not equal true; not (`readable` is present and non-null)) |  |
| `OKTA-MON-006` | 2 | warn | any of (`complete` does not equal true; `policy_count` equals 0) |  |
| `OKTA-MON-006` | 3 | pass | `policy_count` is greater than 0 |  |
| `OKTA-MON-006` | 4 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-MON-007` | 1 | fail | `expired_count` is greater than 0 | A proven violation retains precedence over incomplete companion evidence. |
| `OKTA-MON-007` | 2 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); all of (`token_count` equals 0; `ssws_auth` equals true)) |  |
| `OKTA-MON-007` | 3 | warn | any of (`complete` does not equal true; `unrestricted_count` is greater than 0; `missing_expiry_count` is greater than 0; `long_window_count` is greater than 0) |  |
| `OKTA-MON-007` | 4 | pass | always |  |
| `OKTA-MON-007` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-MON-008` | 1 | manual | any of (any of (`readable` does not equal true; not (`readable` is present and non-null)); `contact_count` equals 0) |  |
| `OKTA-MON-008` | 2 | fail | any of (all of (`technical_lookup_failed` equals false; `technical_contact_present` equals false); all of (`technical_lookup_failed` equals false; `technical_user_assigned` equals false); all of (`technical_status_known` equals true; `technical_user_active` equals false)) |  |
| `OKTA-MON-008` | 3 | warn | any of (`complete` does not equal true; `technical_lookup_failed` equals true; `technical_status_known` equals false) |  |
| `OKTA-MON-008` | 4 | pass | `technical_user_active` equals true |  |
| `OKTA-MON-008` | 5 | manual | always | Unknown or contradictory evidence requires manual review. |
| `OKTA-MON-009` | 1 | manual | always |  |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| None |  |  |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `OKTA-AUTH-001` | `requiredEvidenceReadable` | true |
| `OKTA-AUTH-001` | `requiredEvidenceComplete` | true |
| `OKTA-AUTH-002` | `requiredEvidenceReadable` | true |
| `OKTA-AUTH-002` | `requiredEvidenceComplete` | true |
| `OKTA-AUTH-003` | `requiredEvidenceReadable` | true |
| `OKTA-AUTH-003` | `requiredEvidenceComplete` | true |
| `OKTA-AUTH-004` | `requiredEvidenceReadable` | true |
| `OKTA-AUTH-004` | `requiredEvidenceComplete` | true |
| `OKTA-AUTH-005` | `requiredEvidenceReadable` | true |
| `OKTA-AUTH-005` | `requiredEvidenceComplete` | true |
| `OKTA-AUTH-006` | `max_idle_minutes` | 15 |
| `OKTA-AUTH-007` | `max_lifetime_minutes` | 1080 |
| `OKTA-AUTH-008` | `requiredEvidenceReadable` | true |
| `OKTA-AUTH-008` | `requiredEvidenceComplete` | true |
| `OKTA-AUTH-009` | `requiredEvidenceReadable` | true |
| `OKTA-AUTH-009` | `requiredEvidenceComplete` | true |
| `OKTA-ADMIN-001` | `pass_maximum` | 2 |
| `OKTA-ADMIN-001` | `warn_maximum` | 5 |
| `OKTA-ADMIN-002` | `inactive_days` | 90 |
| `OKTA-ADMIN-003` | `maximum_members` | 25 |
| `OKTA-ADMIN-004` | `requiredEvidenceReadable` | true |
| `OKTA-ADMIN-004` | `requiredEvidenceComplete` | true |
| `OKTA-ADMIN-005` | `inactive_days` | 90 |
| `OKTA-ADMIN-005` | `activation_days` | 30 |
| `OKTA-ADMIN-006` | `requiredEvidenceReadable` | true |
| `OKTA-ADMIN-006` | `requiredEvidenceComplete` | true |
| `OKTA-INTEG-001` | `requiredEvidenceReadable` | true |
| `OKTA-INTEG-001` | `requiredEvidenceComplete` | true |
| `OKTA-INTEG-002` | `requiredEvidenceReadable` | true |
| `OKTA-INTEG-002` | `requiredEvidenceComplete` | true |
| `OKTA-INTEG-003` | `requiredEvidenceReadable` | true |
| `OKTA-INTEG-003` | `requiredEvidenceComplete` | true |
| `OKTA-INTEG-004` | `requiredEvidenceReadable` | true |
| `OKTA-INTEG-004` | `requiredEvidenceComplete` | true |
| `OKTA-INTEG-005` | `requiredEvidenceReadable` | true |
| `OKTA-INTEG-005` | `requiredEvidenceComplete` | true |
| `OKTA-INTEG-006` | `requiredEvidenceReadable` | true |
| `OKTA-INTEG-006` | `requiredEvidenceComplete` | true |
| `OKTA-MON-001` | `requiredEvidenceReadable` | true |
| `OKTA-MON-001` | `requiredEvidenceComplete` | true |
| `OKTA-MON-002` | `requiredEvidenceReadable` | true |
| `OKTA-MON-002` | `requiredEvidenceComplete` | true |
| `OKTA-MON-003` | `requiredEvidenceReadable` | true |
| `OKTA-MON-003` | `requiredEvidenceComplete` | true |
| `OKTA-MON-004` | `requiredEvidenceReadable` | true |
| `OKTA-MON-004` | `requiredEvidenceComplete` | true |
| `OKTA-MON-005` | `maximum_age_days` | 90 |
| `OKTA-MON-006` | `requiredEvidenceReadable` | true |
| `OKTA-MON-006` | `requiredEvidenceComplete` | true |
| `OKTA-MON-007` | `maximum_window_days` | 30 |
| `OKTA-MON-008` | `requiredEvidenceReadable` | true |
| `OKTA-MON-008` | `requiredEvidenceComplete` | true |
| `OKTA-MON-009` | `requiredEvidenceReadable` | true |
| `OKTA-MON-009` | `requiredEvidenceComplete` | true |

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
| 1 | Phishing-resistant authenticators | IA-2(11) | - | CC6.1 | - | 8.2.1 | V-273190, V-273191 | ISM-0974 | A.9.4.2 |
| 2 | Administrator MFA enforcement | IA-2, IA-2(1) | - | CC6.1 | - | 8.3.1 | V-273193, V-273194 | ISM-0974 | A.9.4.2 |
| 3 | Password complexity | IA-5 | - | - | - | 8.3.6 | V-273195, V-273196, V-273197, V-273198, V-273199 | ISM-0421 | A.9.2.4 |
| 4 | Password aging and history | IA-5 | - | - | - | 8.3.9 | V-273200, V-273201, V-273209 | ISM-0421 | A.9.4.3 |
| 5 | Password lockout threshold | AC-7 | - | - | - | 8.2.6 | V-273189 | ISM-1173 | A.9.4.3 |
| 6 | Session idle timeout | AC-11 | - | CC6.6 | - | 8.2.8 | V-273186, V-273187 | ISM-1546 | A.9.4.2 |
| 7 | Session lifetime and persistent cookie controls | AC-12 | - | CC6.6 | - | - | V-273203, V-273206 | ISM-1546 | A.9.4.2 |
| 8 | Certificate or PIV/CAC authentication | IA-5(2) | - | - | - | - | V-273204, V-273207 | ISM-0974 | A.9.4.2 |
| 9 | FIPS and restricted authenticator posture | IA-2(11), SC-13 | - | CC6.1 | - | 8.4.2 | V-273190 | ISM-1682 | A.10.1.1 |
| 10 | Super admin assignments are constrained | AC-6 | - | CC6.3 | - | 7.2.1 | - | ISM-1175 | A.9.2.2 |
| 11 | Inactive privileged accounts | AC-2, AC-2(3) | - | CC6.2 | - | - | V-273188 | ISM-1175 | A.9.2.1 |
| 12 | Privileged group assignments are bounded | AC-6 | - | CC6.3 | - | 7.2.1 | - | ISM-1175 | A.9.2.2 |
| 13 | Privileged user MFA enrollment | IA-2(1) | - | CC6.1 | - | 8.4.2 | V-273193 | ISM-1173 | A.9.4.2 |
| 14 | Workforce account lifecycle hygiene | AC-2(3), AC-2(4) | - | CC6.2, CC6.3 | - | 8.2.6 | V-273188 | ISM-1175 | A.9.2.1, A.9.2.6 |
| 15 | Okta Support access and third-party admin governance | AC-2, AC-6(5), PS-7 | - | CC6.3 | - | 8.2.2 | - | ISM-1175 | A.9.2.3 |
| 16 | Trusted origins hygiene | AC-3, SC-7 | - | CC6.6 | - | - | - | - | A.13.1.1 |
| 17 | Network zones are configured | AC-17, AC-19 | - | CC6.6 | - | - | - | - | A.13.1.1 |
| 18 | OIDC application grant hygiene | AC-3 | - | CC6.1 | - | 7.2.1 | - | - | A.9.1.2 |
| 19 | Risk-based and contextual access controls | AC-2(12) | - | CC6.8 | - | - | - | ISM-0974 | A.9.2.2 |
| 20 | Application inventory hygiene | CM-8 | - | CC2.1 | - | - | - | - | A.8.1.1 |
| 21 | Provisioning and deprovisioning automation | AC-2(1), AC-2(3) | - | CC6.2, CC6.3 | - | 8.2.5 | - | ISM-1175 | A.9.2.1, A.9.2.6 |
| 22 | Log offloading and external monitoring | AU-4, AU-6 | - | - | - | - | V-273202 | ISM-0407 | A.12.4.1 |
| 23 | System log visibility | AU-2, AU-3 | - | - | - | - | - | ISM-0407 | A.12.4.1 |
| 24 | ThreatInsight posture | SI-4 | - | CC7.2 | - | - | - | ISM-0974 | A.12.6.1 |
| 25 | Behavior detection coverage | SI-4 | - | CC7.2 | - | - | - | ISM-0974 | A.12.6.1 |
| 26 | API token hygiene | IA-5, AU-6 | - | CC6.2 | - | 8.2.7 | - | - | A.9.2.4 |
| 27 | Device assurance policy coverage | CM-7 | - | CC6.7 | - | - | - | - | A.12.6.2 |
| 28 | API token expiry and network restrictions | IA-5(1), AC-17 | - | CC6.1 | - | 8.6.3 | - | - | A.9.4.3 |
| 29 | Security contact routing | IR-6, SI-5 | - | CC2.3 | - | 12.10.1 | - | ISM-0123 | A.16.1.2 |
| 30 | Administrator security notification emails | AU-6, SI-5 | - | CC7.2 | - | - | - | ISM-0123 | A.16.1.2 |

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
| `sign-on-policies` | `id`, `name`, `type`, `status`, `conditions`, `settings` |
| `sign-on-policy-rules` | `id`, `name`, `status`, `conditions`, `actions` |
| `password-policies` | `id`, `name`, `status`, `settings.password` |
| `mfa-policies` | `id`, `name`, `status`, `settings`, `conditions` |
| `access-policies` | `id`, `name`, `status`, `conditions`, `settings` |
| `access-policy-rules` | `id`, `name`, `status`, `conditions`, `actions` |
| `authenticators` | `id`, `key`, `name`, `type`, `status`, `settings` |
| `idps` | `id`, `name`, `type`, `status`, `protocol` |
| `authorization-servers` | `id`, `name`, `issuer`, `status`, `audiences` |
| `default-authorization-server` | `id`, `issuer`, `audiences` |
| `org-factors` | `id`, `factorType`, `provider`, `status` |
| `users` | `id`, `status`, `created`, `lastLogin`, `profile.login`, `profile.email` |
| `role-assignees` | `id`, `status`, `profile.login`, `lastLogin` |
| `user-roles` | `id`, `type`, `label`, `status` |
| `user-factors` | `id`, `factorType`, `provider`, `status` |
| `groups` | `id`, `type`, `profile.name` |
| `group-roles` | `id`, `type`, `label` |
| `group-members` | `id`, `status`, `profile.login` |
| `okta-support` | `support`, `expiration` |
| `third-party-admin` | `thirdPartyAdmin` |
| `apps` | `id`, `name`, `label`, `status`, `settings`, `credentials`, `features` |
| `trusted-origins` | `id`, `name`, `origin`, `status`, `scopes` |
| `network-zones` | `id`, `name`, `type`, `status`, `system` |
| `group-rules` | `id`, `name`, `status`, `conditions`, `actions` |
| `event-hooks` | `id`, `name`, `status`, `events` |
| `log-streams` | `id`, `name`, `type`, `status` |
| `system-log` | `uuid`, `published`, `eventType`, `severity`, `outcome` |
| `behaviors` | `id`, `name`, `type`, `status`, `settings` |
| `threat-insight` | `action`, `mode`, `settings`, `excludeZones` |
| `api-tokens` | `id`, `name`, `created`, `lastUpdated`, `expiresAt`, `network`, `userId` |
| `device-assurance` | `id`, `name`, `platform`, `status` |
| `org-contacts` | `contactType`, `userId` |

## Export layout

Required paths:

- `core_data/sign_on_policies.json`
- `core_data/sign_on_policy_rules.json`
- `core_data/password_policies.json`
- `core_data/password_policy_rules.json`
- `core_data/mfa_enrollment_policies.json`
- `core_data/access_policies.json`
- `core_data/access_policy_rules.json`
- `core_data/authenticators.json`
- `core_data/idps.json`
- `core_data/authorization_servers.json`
- `core_data/default_authorization_server.json`
- `core_data/org_factors.json`
- `core_data/users_with_role_assignments.json`
- `core_data/user_roles.json`
- `core_data/groups.json`
- `core_data/privileged_group_roles.json`
- `core_data/privileged_group_members.json`
- `core_data/users.json`
- `core_data/privileged_user_factors.json`
- `core_data/okta_support_access.json`
- `core_data/third_party_admin_setting.json`
- `core_data/apps.json`
- `core_data/trusted_origins.json`
- `core_data/network_zones.json`
- `core_data/group_rules.json`
- `core_data/event_hooks.json`
- `core_data/log_streams.json`
- `core_data/system_logs_recent.json`
- `core_data/behaviors.json`
- `core_data/threat_insight.json`
- `core_data/api_tokens.json`
- `core_data/device_assurance.json`
- `core_data/org_contacts.json`
- `core_data/collection_status.json`
- `analysis/authentication.json`
- `analysis/admin_access.json`
- `analysis/integrations.json`
- `analysis/monitoring.json`
- `analysis/findings.json`
- `compliance/executive_summary.md`
- `compliance/unified_compliance_matrix.md`
- `compliance/fedramp/fedramp_compliance_report.md`
- `compliance/fedramp/oscal_assessment_results.json`
- `compliance/disa_stig/stig_compliance_checklist.md`
- `compliance/irap/irap_compliance_report.md`
- `compliance/irap/essential_eight_assessment.md`
- `compliance/ismap/ismap_compliance_report.md`
- `compliance/soc2/soc2_compliance_report.md`
- `compliance/pci_dss/pci_dss_compliance_report.md`
- `QUICK_REFERENCE.md`

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `core_data/sign_on_policies.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/sign_on_policy_rules.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/password_policies.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/password_policy_rules.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/mfa_enrollment_policies.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/access_policies.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/access_policy_rules.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/authenticators.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/idps.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/authorization_servers.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/default_authorization_server.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/org_factors.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/users_with_role_assignments.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/user_roles.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/groups.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/privileged_group_roles.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/privileged_group_members.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/users.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/privileged_user_factors.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/okta_support_access.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/third_party_admin_setting.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/apps.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/trusted_origins.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/network_zones.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/group_rules.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/event_hooks.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/log_streams.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/system_logs_recent.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/behaviors.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/threat_insight.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/api_tokens.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/device_assurance.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/org_contacts.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/collection_status.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/authentication.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/admin_access.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/integrations.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/monitoring.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/findings.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `compliance/executive_summary.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/unified_compliance_matrix.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/fedramp/fedramp_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/fedramp/oscal_assessment_results.json` | json | Always. | The runtime-generated human-readable compliance report. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `compliance/disa_stig/stig_compliance_checklist.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/irap/irap_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/irap/essential_eight_assessment.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/ismap/ismap_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/soc2/soc2_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/pci_dss/pci_dss_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `QUICK_REFERENCE.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `_errors.log` | text | Only under the runtime condition stated for this conditional file. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |

### Record schemas

#### finding

- `id`
- `title`
- `severity`
- `status`
- `summary`
- `evidence`
- `framework mappings`

#### collection_marker

- `collected`
- `status`
- `endpoint`
- `error`

#### bundle_result

- `outputDir`
- `zipPath`
- `fileCount`
- `findingCount`
- `errorCount`

#### assessment

- `title or category`
- `summary`
- `findings`
- `errors when collection was partial`

#### pagination_state

- `items or rows seen`
- `reported total when available`
- `pages`
- `truncated`
- `stop reason`

JSON formatting: UTF-8 JSON with two-space indentation and a trailing newline.

Overwrite policy: Allocate a new <organization-host>-audit-bundle directory with a numeric suffix when either the directory or paired archive exists.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Create <allocated-directory>.zip beside the allocated organization-host audit directory.
