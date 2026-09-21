---
title: Box
description: Read-only Box Enterprise security inspection covering identity, sharing, data governance, and Shield monitoring, mapped to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP.
---

The Box integration inspects a Box Enterprise tenant through the Box Content API and reports posture findings for the 25 controls defined in `specs/box-sec-inspector.spec.md`. Every tool is read-only: nothing is created, changed, or deleted in the tenant.

## What it inspects

- **Identity and access**: SSO enforcement, 2-step verification for admins and all users, admin and co-admin sprawl, password policy, session duration, IP allowlisting, and inactive users derived from the enterprise event stream.
- **Sharing and collaboration**: external collaboration mode, collaboration allowlist hygiene, shared link defaults and expiration, shared link passwords, watermarking, app authorization activity, and custom terms of service.
- **Data governance**: device pins, classification labels, retention policies and assignments, legal hold policies and assignments.
- **Shield and monitoring**: Shield rules, information barriers and segments, the `admin_logs` enterprise event stream, and content access anomaly signals.

Findings are normalized as `{ id, control, title, severity, status, summary, evidence, mappings, manualEvidence }` where `severity` is `critical | high | medium | low | info` and `status` is `pass | warn | fail | manual`. A `manual` finding always includes the exact Admin Console evidence a human must collect.

## Setup and authentication

Create a Box Platform app in the Developer Console, enable the scopes below, and authorize it in the Admin Console (Apps > Custom Apps Manager). The inspector supports the three server-side auth flows Box documents.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `BOX_AUTH_METHOD` | `jwt`, `ccg`, or `oauth`. Optional; inferred from the credentials present. |
| `BOX_JWT_CONFIG_PATH` | Path to the JWT app config JSON downloaded from the Developer Console. |
| `BOX_JWT_PASSPHRASE` | Private key passphrase when it is not stored in the config file. |
| `BOX_JWT_ALGORITHM` | `RS256`, `RS384`, or `RS512` (default `RS512`). |
| `BOX_CLIENT_ID`, `BOX_CLIENT_SECRET` | App credentials for Client Credentials Grant, or for refreshing an OAuth token. |
| `BOX_ENTERPRISE_ID` | Enterprise ID for JWT and CCG service-account tokens and for enterprise-scoped endpoints. |
| `BOX_SUBJECT_TYPE`, `BOX_SUBJECT_ID` | Act as a specific managed user instead of the service account (`user` plus a user ID). |
| `BOX_ACCESS_TOKEN` (also `BOX_TOKEN`, `BOX_DEVELOPER_TOKEN`) | Pre-issued OAuth 2.0 access token. |
| `BOX_REFRESH_TOKEN` | OAuth 2.0 refresh token, used with the client ID and secret when a 401 is returned. |
| `BOX_CONFIG_PATH` | YAML config file path (default `~/.box-sec-inspector/config.yaml`). |
| `BOX_API_BASE_URL`, `BOX_TOKEN_URL` | Override `https://api.box.com/2.0` and `https://api.box.com/oauth2/token`. |
| `BOX_TIMEOUT`, `BOX_MAX_RETRIES` | Request timeout in seconds (default 30) and retries for 429 and 5xx responses (default 3). |

Precedence is explicit tool arguments, then environment variables, then the config file. The YAML file accepts the same keys in snake_case, optionally nested under a `box:` section:

```yaml
box:
  auth_method: ccg
  client_id: "abc123"
  client_secret: "..."
  enterprise_id: "123456"
  timeout_seconds: 30
```

### JWT (server authentication)

Point `BOX_JWT_CONFIG_PATH` at the config JSON (`boxAppSettings.clientID`, `clientSecret`, `appAuth.publicKeyID`, `appAuth.privateKey`, `appAuth.passphrase`, and `enterpriseID`). grclanker signs the assertion with `node:crypto` (`alg` RS512 by default, `kid` set to the public key ID, `aud` `https://api.box.com/oauth2/token`, `box_sub_type` `enterprise` or `user`, 45 second expiry) and posts it to the token endpoint with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`. No SDK is required.

### Client Credentials Grant

Set `BOX_CLIENT_ID`, `BOX_CLIENT_SECRET`, and `BOX_ENTERPRISE_ID`. grclanker posts `grant_type=client_credentials` with `box_subject_type=enterprise` and `box_subject_id=<enterprise_id>` (or `box_subject_type=user` when `BOX_SUBJECT_TYPE=user`). Tokens are cached until shortly before `expires_in` elapses and re-requested on 401.

### OAuth 2.0

Set `BOX_ACCESS_TOKEN` for a pre-issued token (for example a Developer Console developer token, or a token minted by your own OAuth flow for an admin or co-admin). When `BOX_REFRESH_TOKEN`, `BOX_CLIENT_ID`, and `BOX_CLIENT_SECRET` are present the client refreshes automatically after a 401. When no enterprise ID is configured it is discovered from `GET /users/me?fields=enterprise`.

### Required Box app scopes

| Application scope | Used for |
| --- | --- |
| Read all files and folders stored in Box | Metadata templates, classification template, terms of service |
| Manage users | `GET /users`, `GET /users/me` |
| Manage groups | `GET /groups` |
| Manage enterprise properties | Enterprise configuration, `admin_logs` events, collaboration allowlist, device pins, Shield lists and rules |
| Manage retention policies | Retention policies and assignments (Box Governance) |
| Manage legal holds | Legal hold policies and assignments (Box Governance) |
| Manage Shield (information barriers) | Shield information barriers and segments (Box Shield) |

Re-authorize the app in the Admin Console after changing scopes. `box_check_access` reports each surface separately so partial grants are visible before you run an assessment.

## Tools

| Tool | Purpose |
| --- | --- |
| `box_check_access` | Resolves credentials, exchanges a token, and probes 15 read surfaces (current user, enterprise configuration, users, groups, enterprise events, device pins, retention, legal holds, Shield barriers and lists, allowlist entries and exemptions, metadata and classification templates, terms of service). Reports `healthy` or `limited` with the next step. |
| `box_assess_identity_access` | Controls 1, 2, 3, 17, 18, 21, 22, 23, 24. Options: `user_limit`, `event_limit`, `lookback_days`, `max_admins`, `min_password_length`, `max_session_hours`. |
| `box_assess_sharing_collaboration` | Controls 4, 5, 6, 7, 8, 9, 19, 20. Options: `event_limit`, `lookback_days`, `stale_allowlist_days`. |
| `box_assess_data_governance` | Controls 10, 11, 12, 13. Option: `list_limit`. |
| `box_assess_shield_monitoring` | Controls 14, 15, 16, 25. Options: `event_limit`, `lookback_days`. |
| `box_export_audit_bundle` | Runs the access check plus all four assessments and writes an evidence bundle (default `./export/box`). |

Every tool accepts the auth arguments (`auth_method`, `jwt_config_path`, `jwt_passphrase`, `client_id`, `client_secret`, `enterprise_id`, `subject_type`, `subject_id`, `access_token`, `refresh_token`, `config_path`, `base_url`, `token_url`, `timeout_seconds`, `max_retries`).

### Audit bundle layout

```text
<enterprise_id>-audit-bundle/
  QUICK_REFERENCE.md
  metadata.json
  _errors.log                     (only when some reads failed)
  core_data/                      raw API snapshots (users, groups, events, policies, templates, ...)
  analysis/
    findings.json                 all 25 findings with evidence and mappings
    summary.json
    identity_access.json, sharing_collaboration.json, data_governance.json, shield_monitoring.json
  compliance/
    executive_summary.md
    unified_compliance_matrix.md
    fedramp/, cmmc/, soc2/, cis/, pci_dss/, disa_stig/, irap/, ismap/   one report each
<enterprise_id>-audit-bundle.zip
```

Output paths are resolved inside the output root with traversal and symlinked-parent protection, and files are written with `0600` permissions. Credentials are never written into the bundle.

## Control coverage

Status semantics: `pass` means the API evidence satisfies the control, `warn` means partial or threshold-adjacent evidence, `fail` means the API evidence contradicts the control, and `manual` means the API cannot prove the control and the finding lists the Admin Console evidence to collect. Absent data never produces `fail`: a configuration category that Box returns as `null` (the `2025.0` schema allows `security`, `content_and_sharing`, `user_settings`, and `shield` to be null) or an unreadable user list yields `manual` or `warn` with the reason, and a setting that is missing from a readable category yields `warn`. Every configuration item carries an `is_used` flag ("indicates whether a configuration is used for a given enterprise"); an item with `is_used: false` is treated as not enforced, so the finding is `warn` with the reported value under `evidence.unused_settings` and the per-item flags under `evidence.is_used`, and it never supports `pass`.

| # | Control | Tool | Finding | Status semantics |
| --- | --- | --- | --- | --- |
| 1 | SSO enforcement | identity_access | BOX-01 | pass when `is_enterprise_sso_required` is true and not in testing; warn in testing mode or when the flag is not exposed; fail when it is false; manual when `user_settings` is unreadable or null |
| 2 | 2FA for admins | identity_access | BOX-02 | pass when MFA is required and no admin or co-admin is `is_exempt_from_login_verification`; fail on exempt admins or MFA explicitly not required; warn when only SSO enforces MFA or the flag is not exposed; manual when users or `security` are unreadable |
| 3 | 2FA for all users | identity_access | BOX-03 | pass when MFA is required with no exempt users; warn on exemptions, SSO-only MFA, or an unexposed flag; fail when MFA is explicitly not required without required SSO; manual when users or `security` are unreadable |
| 4 | External collaboration restrictions | sharing_collaboration | BOX-04 | pass for `limit_collaboration_to_users_within_enterprise` or allowlisted domains; fail for `enable_external_collaboration` |
| 5 | Collaboration allowlist audit | sharing_collaboration | BOX-05 | fail on public email domains; warn on entries older than `stale_allowlist_days` or exempt users; pass otherwise |
| 6 | Sharing link policies | sharing_collaboration | BOX-06 | fail when `shared_link_default_access` is open; warn when open links remain selectable; pass for company or collaborator defaults |
| 7 | Shared link expiration | sharing_collaboration | BOX-07 | pass when `is_shared_links_expiration_enabled`; warn when only public links expire or the flag is not exposed; fail when it is false |
| 8 | Shared link password policy | sharing_collaboration | BOX-08 | manual: the API does not expose the open shared link password requirement |
| 9 | Watermarking enabled | sharing_collaboration | BOX-09 | pass or fail on `is_watermarking_enterprise_feature_enabled`; warn when the flag is absent |
| 10 | Device trust and pins | data_governance | BOX-10 | warn when no device pins exist; manual otherwise because the device trust policy is not exposed |
| 11 | Classification labels | data_governance | BOX-11 | pass when the security classification template defines labels; fail when none exist |
| 12 | Retention policies | data_governance | BOX-12 | pass when active policies have assignments; warn when unassigned; fail when none exist; manual without Governance access |
| 13 | Legal hold policies | data_governance | BOX-13 | pass when active holds have assignments; warn when unassigned or none exist; manual without Governance access |
| 14 | Shield smart access policies | shield_monitoring | BOX-14 | pass when Shield rules exist in the `shield` configuration category; fail when the category is readable but empty; manual without Shield access or when the category is null |
| 15 | Shield information barriers | shield_monitoring | BOX-15 | pass when enabled barriers have segments; warn when disabled, unsegmented, or absent |
| 16 | Enterprise event streaming | shield_monitoring | BOX-16 | pass when `admin_logs` returns events in the window; warn when empty; manual when unreadable |
| 17 | Admin role minimization | identity_access | BOX-17 | pass when admin plus co-admin count is at or below `max_admins`; warn above |
| 18 | Co-admin permission scoping | identity_access | BOX-18 | pass when no co-admins exist; manual otherwise because co-admin permission sets are not exposed |
| 19 | App approval process | sharing_collaboration | BOX-19 | manual: reports app authorization events and integration Shield lists, approval policy must be confirmed in the Admin Console |
| 20 | Custom terms of service | sharing_collaboration | BOX-20 | pass when a managed terms of service is enabled; fail when disabled or missing |
| 21 | Password policy strength | identity_access | BOX-21 | pass at or above `min_password_length` with weak password prevention and two character classes; warn between 8 and the target; fail below 8 |
| 22 | Session duration limits | identity_access | BOX-22 | pass when `session_duration` (and any custom duration) is at or below `max_session_hours`; fail above or when unlimited |
| 23 | IP allowlisting | identity_access | BOX-23 | manual: reports Shield IP lists, enterprise IP restrictions are not exposed |
| 24 | Inactive user detection | identity_access | BOX-24 | pass when every active managed user has activity events in `lookback_days`; warn or fail on inactive users; warn when the event sample is truncated |
| 25 | Content access monitoring | shield_monitoring | BOX-25 | pass when anomaly rules or Shield alerts exist; warn when only raw download events exist or when Shield rules or the event stream are unreadable; fail when both are readable and neither signal is present |

## Framework mappings

Each finding carries the eight mappings from the spec's compliance table, rendered as `<framework> <identifier>` (for example `FedRAMP IA-2`, `CMMC AC.L2-3.1.1`, `SOC 2 CC6.1`, `CIS 1.1`, `PCI-DSS 8.3.1`, `STIG SRG-APP-000148`, `IRAP ISM-1557`, `ISMAP CPS-04` for control 1). The export bundle renders them in `compliance/unified_compliance_matrix.md` and in one report per framework.

## Live smoke test

```bash
npm --prefix cli run test:box:live
```

The script exits 0 with a skip message when no Box credentials are present. With credentials it runs `box_check_access` and the identity and access assessment against the real enterprise.

## Limitations and manual controls

- Controls 8, 19, and 23 are always `manual`: the Box API does not expose the open shared link password requirement, the app approval policy, or enterprise IP allowlisting. Controls 10 and 18 are `manual` whenever device pins or co-admins exist because the device trust policy and co-admin permission sets are not exposed.
- Inactive user detection correlates `admin_logs` activity events (`LOGIN`, `ADMIN_LOGIN`, `DOWNLOAD`, `UPLOAD`, and similar) because the user object has no last login field. Raise `event_limit` for large enterprises; a truncated sample is reported as `warn`.
- Enterprise configuration, Shield lists, and Shield rules come from the versioned `2025.0` endpoints and require Manage enterprise properties. Retention and legal hold endpoints require Box Governance, Shield endpoints require Box Shield; missing licenses surface as `manual` findings with the reason.
- Box's published rate limit is 1000 API requests per minute per user; the client honors `retry-after` on 429 and applies exponential backoff on 5xx.
- Watermarking, classification application, and SIEM consumption of the event stream are verified at the enterprise level; sampled folder reviews remain a human step and are listed in `manualEvidence`.

## Official documentation

- [JWT auth without an SDK](https://developer.box.com/guides/authentication/jwt/without-sdk/) and [JWT setup](https://developer.box.com/guides/authentication/jwt/jwt-setup/)
- [Client Credentials Grant setup](https://developer.box.com/guides/authentication/client-credentials/client-credentials-setup/)
- [Refresh an access token](https://developer.box.com/guides/authentication/tokens/refresh/)
- [App authorization](https://developer.box.com/guides/authorization/) and [application scopes](https://developer.box.com/guides/api-calls/permissions-and-errors/scopes/)
- [Rate limits](https://developer.box.com/guides/api-calls/permissions-and-errors/rate-limits/)
- [Marker-based pagination](https://developer.box.com/guides/api-calls/pagination/marker-based/) and [offset-based pagination](https://developer.box.com/guides/api-calls/pagination/offset-based/)
- [Enterprise events](https://developer.box.com/guides/events/enterprise-events/for-enterprise/), [event triggers](https://developer.box.com/guides/events/event-triggers/), and [`GET /events`](https://developer.box.com/reference/get-events/)
- [`GET /users/me`](https://developer.box.com/reference/get-users-me/), [`GET /users`](https://developer.box.com/reference/get-users/), [`GET /groups`](https://developer.box.com/reference/get-groups/)
- [`GET /enterprise_configurations/{id}` (2025.0)](https://developer.box.com/reference/v2025.0/get-enterprise-configurations-id/) and [`GET /shield_lists` (2025.0)](https://developer.box.com/reference/v2025.0/get-shield-lists/)
- [`GET /enterprises/{id}/device_pinners`](https://developer.box.com/reference/get-enterprises-id-device-pinners/)
- [`GET /retention_policies`](https://developer.box.com/reference/get-retention-policies/) and [assignments](https://developer.box.com/reference/get-retention-policies-id-assignments/)
- [`GET /legal_hold_policies`](https://developer.box.com/reference/get-legal-hold-policies/) and [`GET /legal_hold_policy_assignments`](https://developer.box.com/reference/get-legal-hold-policy-assignments/)
- [`GET /shield_information_barriers`](https://developer.box.com/reference/get-shield-information-barriers/) and [segments](https://developer.box.com/reference/get-shield-information-barrier-segments/)
- [`GET /collaboration_whitelist_entries`](https://developer.box.com/reference/get-collaboration-whitelist-entries/) and [exempt targets](https://developer.box.com/reference/get-collaboration-whitelist-exempt-targets/)
- [`GET /metadata_templates/enterprise`](https://developer.box.com/reference/get-metadata-templates-enterprise/), [template schema](https://developer.box.com/reference/get-metadata-templates-id-id-schema/), and [classifications](https://developer.box.com/guides/metadata/classifications/)
- [`GET /terms_of_services`](https://developer.box.com/reference/get-terms-of-services/)
- [Box OpenAPI specification](https://github.com/box/box-openapi)
