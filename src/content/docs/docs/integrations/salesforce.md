---
title: Salesforce
description: Read-only Salesforce security inspector covering Health Check, session and password policy, MFA, permissions, sharing, connected apps, login forensics, audit trail, encryption, and certificates with FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP mappings.
---

The Salesforce inspector audits one org through the REST API (SOQL), the Tooling API, and the Metadata API `listMetadata` and `readMetadata` calls. Every tool is read-only: nothing is created, updated, or deleted in the org.

## What it inspects

- Security Health Check score and per-setting risks (`SecurityHealthCheck`, `SecurityHealthCheckRisks`)
- `SecuritySettings` metadata: session timeout, forced logout, IP locking, password policies, trusted IP ranges, clickjack and CSRF flags, MFA for direct UI logins
- `MyDomainSettings` metadata: login policy for `login.salesforce.com` and API logins
- `Profile` metadata for sensitive profiles (System Administrator plus every profile with Modify All Data, View All Data, Manage Users, Author Apex, Customize Application, Manage Profiles and Permission Sets, or Password Never Expires): `loginHours` and `loginIpRanges`, resolved from SOQL profile IDs through `listMetadata(Profile)` and read with `readMetadata(Profile)` in batches of 10 (at most 50 profiles)
- Users, profiles, permission sets, permission set assignments, and `TwoFactorMethodsInfo` enrollment. `Permissions*` fields on `Profile` and `PermissionSet` are probed through `describeSObject` first, so fields that do not exist in the org's edition (for example `PermissionsApiUserOnly`) are omitted instead of failing the query
- The caller's own permission flags from `UserPermissionAccess` (`Customize Application`, `View All Users`, and the other permissions the inspector depends on)
- `FieldPermissions` on fields whose names look sensitive, organization-wide defaults from `Organization`
- `TenantSecret` (Shield Platform Encryption) and the Tooling API `Certificate` object (expiration, key size, CA-signed, exportable private key)
- `ConnectedApplication`, `OauthToken`, `LoginHistory`, `SetupAuditTrail`, `EventLogFile`

Every SOQL statement selects only fields listed in the Object Reference for that object. `OauthToken` is read without `CreatedDate`, `ConnectedApplication` without `CreatedDate` and `LastModifiedDate`, and `TwoFactorMethodsInfo` without `Id`, because those fields are not documented on those objects and an `INVALID_FIELD` error would take down the whole dataset.

## Setup and authentication

1. Create a connected app with OAuth enabled and the `api` scope (add `refresh_token` if you plan to use a refresh token). For the JWT bearer flow, upload the certificate whose private key the inspector will sign with and pre-authorize the auditing user's profile or permission set.
2. Give the auditing user these permissions: `API Enabled`, `View Setup and Configuration`, `View Health Check`, `View All Users`, `Modify Metadata Through Metadata API Functions` (required by `listMetadata` and `readMetadata`), `Manage MFA in API` (required to query `TwoFactorMethodsInfo`), `Customize Application` (without it `OauthToken` returns only the caller's own tokens), and, when licensed, `View Event Log Files` and `Manage Encryption Keys`. `salesforce_check_access` reads the caller's flags from `UserPermissionAccess` and lists any that are false.
3. Export credentials for one of the supported flows.

JWT bearer flow (recommended):

```bash
export SF_CONSUMER_KEY=3MVG9...
export SF_USERNAME=auditor@example.com
export SF_PRIVATE_KEY_FILE=/secure/server.key
export SF_INSTANCE_URL=https://acme.my.salesforce.com
```

Username-password flow (legacy, must be enabled under Setup > OAuth and OpenID Connect Settings):

```bash
export SF_USERNAME=auditor@example.com
export SF_PASSWORD=...
export SF_SECURITY_TOKEN=...
export SF_CONSUMER_KEY=3MVG9...
export SF_CONSUMER_SECRET=...
```

Other inputs:

- `SF_CREDENTIALS_FILE`: JSON file with `grant_type` (`jwt-bearer`, `password`, or `authorization_code` with a `refresh_token`) plus the matching fields (`instance_url`, `login_url`, `username`, `password`, `security_token`, `consumer_key`, `consumer_secret`, `private_key_file`, `refresh_token`, `access_token`, `api_version`)
- `SF_ACCESS_TOKEN` with `SF_INSTANCE_URL`: reuse a token from `sf org display`
- `SF_LOGIN_URL`: explicit login host; otherwise `https://test.salesforce.com` is used when `SF_SANDBOX=true` or the instance URL is a sandbox host, and `https://login.salesforce.com` otherwise
- `SF_API_VERSION`: defaults to `64.0`

Precedence is explicit tool arguments, then environment variables, then the credentials file.

## Tools

| Tool | Purpose |
|---|---|
| `salesforce_check_access` | Probes the OAuth session, Organization, limits, Health Check, SecuritySettings, users, profiles, Profile metadata (`listMetadata`), permission sets, `TwoFactorMethodsInfo`, login history, audit trail, connected apps, `OauthToken`, event log files, and the caller's `UserPermissionAccess` flags; lists likely missing permissions, including any caller flag that is false |
| `salesforce_assess_platform_security` | Controls 1, 2, 3, 5, 18, 19, 20 |
| `salesforce_assess_identity_access` | Controls 4, 6, 7, 9, 10, 13 |
| `salesforce_assess_data_protection` | Controls 8, 12, 16, 17 |
| `salesforce_assess_monitoring_integrations` | Controls 11, 14, 15 |
| `salesforce_export_audit_bundle` | Writes `core_data/`, `analysis/`, `compliance/` (executive summary, unified matrix, eight framework reports), `QUICK_REFERENCE.md`, `_errors.log` when collection partially failed, and a zip named after the allocated output directory |

## Control coverage

| # | Control | Tool | Finding | Status semantics |
|---|---|---|---|---|
| 1 | Health Check score | platform_security | SF-01 | pass when score >= 90 with zero high risks; warn >= 70; fail below; manual when unreadable |
| 2 | Session timeout | platform_security | SF-02 | pass when `sessionTimeout` <= 2 hours, `forceLogoutOnSessionTimeout` true, and `lockSessionsToIp` true; warn without IP lock; fail otherwise; manual when flags absent |
| 3 | Password policy | platform_security | SF-03 | pass when length >= 12, complexity includes upper, lower, numeric, expiration <= 90 days, history >= 12, lockout enabled |
| 4 | MFA enforcement | identity_access | SF-04 | pass when `enableMFADirectUILoginOptIn` (or the Health Check MFA setting) is enforced, the administrator population is visible, and every active standard user has a registered method; warn when `TwoFactorMethodsInfo` returns exactly 2500 rows (the documented cap, which has no `done=false` signal); manual when the object is forbidden (`Manage MFA in API`) |
| 5 | IP range restrictions | platform_security | SF-05 | pass when every sensitive profile defines `loginIpRanges` and `enforceIpRangesEveryRequest` is true; warn when some sensitive profiles lack ranges, a profile could not be resolved, or the flag is off; fail when no profile ranges and no org-wide trusted ranges exist; manual when `readMetadata(Profile)` is forbidden |
| 6 | Login hour restrictions | identity_access | SF-06 | pass when every sensitive profile bounds `loginHours` on all seven days (each `{weekday}Start`/`{weekday}End` pair is independent; a day with no start or end, or a 0 to 1440 window, is unrestricted); warn when a profile bounds only some days (the unbounded days are named), some profiles restrict nothing, or a profile could not be resolved; fail when no profile bounds any day; manual when `readMetadata(Profile)` is forbidden |
| 7 | API access controls | identity_access | SF-07 | pass when <= 25 percent of profiles grant API Enabled and the administrator population is visible; the summary states when `PermissionsApiUserOnly` does not exist in the org |
| 8 | Field-level security | data_protection | SF-08 | pass when no sensitive field has more than 5 grants; manual when no matching fields |
| 9 | Permission set review | identity_access | SF-09 | pass when the administrator population is visible and no permission set grants elevated permissions, or elevated assignees are zero |
| 10 | Profile permissions | identity_access | SF-10 | pass when active admins <= threshold, none stale, none undated; manual when no administrator-class profile is visible or zero active administrators appear in a non-empty user list (a real org always has one) |
| 11 | Connected app OAuth | monitoring_integrations | SF-11 | warn at best: scopes are not exposed by SOQL; fail when most apps allow self-authorization; the finding flags `OauthToken` as a partial view when the caller lacks `Customize Application` |
| 12 | Sharing settings | data_protection | SF-12 | warn at best: custom object defaults are not read; fail when 3+ standard objects are public |
| 13 | Guest user access | identity_access | SF-13 | pass when a complete user list with at least one visible active administrator contains zero active guest users; manual when the population is not visible; fail when guests have API or elevated permissions |
| 14 | Login forensics | monitoring_integrations | SF-14 | pass when failures <= 10 percent, no source with 10+ failures, no legacy TLS |
| 15 | Setup change tracking | monitoring_integrations | SF-15 | pass when the trail is complete and no high-risk security changes; warn when changes need review |
| 16 | Data encryption | data_protection | SF-16 | manual not-applicable when `TenantSecret` is unavailable or forbidden; fail when no active secrets |
| 17 | Certificate management | data_protection | SF-17 | fail when expired or key < 2048; warn when expiring within 30 days, undated, `KeySize` absent (never assumed to be 2048), `OptionsIsCaSigned` absent, private key exportable, or awaiting a signed chain; self-signed versus CA-signed counts are reported |
| 18 | My Domain enforcement | platform_security | SF-18 | pass when `canOnlyLoginWithMyDomainUrl` and `doesApiLoginRequireOrgDomain` are true |
| 19 | Clickjack protection | platform_security | SF-19 | pass when all four `enableClickjack*` flags are true |
| 20 | CSRF protection | platform_security | SF-20 | pass when `enableCSRFOnGet` and `enableCSRFOnPost` are true |

Verdict rules that apply to every finding: unreadable, forbidden, or errored data yields `manual` with the cause and the Setup evidence to collect; empty inventories never pass unless emptiness is compliant (only control 13, and only when the user list itself is non-empty); partial or truncated inventories downgrade `pass` to `warn` with seen and total counts; items missing a date are reported separately and never counted as current.

Population sanity gate: every org has a System Administrator profile with Modify All Data and at least one active user on it. Controls 4, 7, 9, 10, and 13 therefore render `manual` when the visible profile list has no administrator-class profile, or when a non-empty user list shows zero active administrators, because that view can only come from a credential without `View All Users` or setup visibility. The `population_view_issue` field in the identity summary states the reason.

## Framework mappings

Every finding carries the spec mapping for its control across FedRAMP, CMMC 2.0, SOC 2, CIS Salesforce, PCI-DSS 4.0, DISA STIG, IRAP, and ISMAP, for example `FedRAMP AC-12`, `CMMC 2.0 L2 AC.L2-3.1.10`, `SOC 2 CC6.1`, `CIS Salesforce 2.1`, `PCI-DSS 4.0 8.2.8`, `DISA STIG SRG-APP-000295`, `IRAP ISM-1164`, `ISMAP 8.2.8` for session timeout.

## Live smoke test

```bash
npm --prefix cli run test:salesforce:live
```

The script skips with exit code 0 when no credentials are present; otherwise it runs `salesforce_check_access` and the platform security assessment.

## Limitations and manual controls

- Profile `loginHours` and `loginIpRanges` are read only for sensitive profiles (System Administrator plus profiles with elevated permissions), capped at 50 profiles; profiles that `listMetadata(Profile)` cannot map to a metadata `fullName` are listed as unresolved and keep controls 5 and 6 at `warn` or below.
- `TwoFactorMethodsInfo` returns at most 2500 rows with `done=true`; an exactly 2500-row result is treated as possibly truncated and control 4 stops at `warn`.
- `OauthToken` returns only the caller's own tokens when the caller lacks `Customize Application`, and the API gives no truncation signal; the inspector reads the caller's flag from `UserPermissionAccess` and marks control 11 as a partial view when it is false or unknown.
- `OauthToken` also has the same documented 2500-row hard cap as `TwoFactorMethodsInfo` (500 rows per query, `queryMore` up to 2500, then no more records, with `done=true`); an exactly 2500-row result is reported as possibly truncated in the control 11 evidence (`oauth_tokens_possibly_capped`) and summary, so a capped token count is never presented as complete.
- Connected app OAuth scopes, IP relaxation, and per-app policies beyond `OptionsAllowAdminApprovedUsersOnly` and refresh token validity are not exposed by SOQL.
- Custom object organization-wide defaults and sharing rules are not read; only the standard object defaults on `Organization` are evaluated.
- `Certificate` is a Tooling API object; self-signed certificates are reported but not failed on their own, since Salesforce issues self-signed certificates for JWT connected apps and SAML signing by design. Certificates without a `KeySize` value are reported as unknown and never counted as compliant.
- `listMetadata` and `readMetadata` require `Modify Metadata Through Metadata API Functions` or `Modify All Data`; without it, controls 2, 3, 5, 6, 18, 19, and 20 render as manual.
- Shield Event Monitoring and Platform Encryption are add-on licenses; unavailable objects render as manual not-applicable, never pass.
- The username-password flow is disabled by default in newer orgs and is kept only for legacy compatibility.

## Official documentation

- [REST API: Execute a SOQL Query](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_query.htm) (`nextRecordsUrl`, `done`, `totalSize`)
- [Tooling API: SecurityHealthCheckRisks](https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/tooling_api_objects_securityhealthcheckrisks.htm) (includes the `SecurityHealthCheck` Score query) and [Tooling API: Certificate](https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/tooling_api_objects_certificate.htm)
- [Metadata API: SecuritySettings](https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_securitysettings.htm)
- [Metadata API: MyDomainSettings](https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_mydomainsettings.htm)
- [Metadata API: readMetadata()](https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_readMetadata.htm) (limit of 10 fullNames per call), [listMetadata()](https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_listmetadata.htm), and [Profile](https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_profile.htm) (`loginHours`, `loginIpRanges`)
- [Object Reference: UserPermissionAccess](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_userpermissionaccess.htm) (the caller's `Permissions<Name>` flags)
- [Object Reference: LoginHistory](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_loginhistory.htm), [SetupAuditTrail](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_setupaudittrail.htm), [ConnectedApplication](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_connectedapplication.htm), [OauthToken](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_oauthtoken.htm), [TwoFactorMethodsInfo](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_twofactormethodsinfo.htm), [PermissionSet](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_permissionset.htm), [PermissionSetAssignment](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_permissionsetassignment.htm), [Organization](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_organization.htm), [TenantSecret](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_tenantsecret.htm), [FieldPermissions](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_fieldpermissions.htm), [EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile.htm)
- [OAuth 2.0 JWT Bearer Flow](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_jwt_flow.htm&type=5) and [OAuth 2.0 Username-Password Flow](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_username_password_flow.htm&type=5)
