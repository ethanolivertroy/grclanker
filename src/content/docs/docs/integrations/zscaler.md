---
title: Zscaler
description: Read-only ZIA and ZPA security inspector covering the 25 controls in the Zscaler spec with verdict-safe findings and audit bundles.
---

The Zscaler integration inspects Zscaler Internet Access (ZIA) and Zscaler Private Access (ZPA) tenants through their documented read APIs and evaluates the 25 controls in `specs/zscaler-sec-inspector.spec.md`. Every tool is read-only: the only non-GET calls are the ZIA session login and logout and the ZPA OAuth sign-in.

## What it inspects

- ZIA administration: administrator accounts and roles, password login bypasses, password expiry, the admin audit log report interface, and NSS feeds that export admin audit logs.
- ZIA policy: URL filtering, cloud firewall, DNS control, DLP engines, dictionaries and web DLP rules, SSL inspection rules and exemptions, sandbox rules, bandwidth control, browser isolation profiles, locations and sub-locations with GRE tunnels and VPN credentials, cloud app control, and the ATP and malware protection baseline.
- ZPA: application segments and segment groups, access, timeout, client forwarding and isolation policy rules, posture profiles, trusted networks, app connectors and groups, private service edges and groups, IdP controllers, SAML attributes, SCIM groups, enrollment and browser access certificates, emergency access users, and ZPA administrators.

## Setup and authentication

Credentials resolve with the precedence explicit tool arguments, then environment variables, then a YAML config file (`ZSCALER_CONFIG_FILE` or `~/.zscaler/zscaler.yaml` with `zia.client` and `zpa.client` blocks using `cloud`, `apiKey`, `username`, `password`, `clientId`, `clientSecret`, and `customerId` keys). Configure either product or both; controls for a product without credentials render as `manual` findings that name the missing variables.

### ZIA (legacy API key plus session)

| Variable | Purpose |
| --- | --- |
| `ZIA_CLOUD` | Cloud name: `zscaler`, `zscalerone`, `zscalertwo`, `zscalerthree`, `zscloud`, `zscalerbeta`, `zscalergov`, `zscalerten` (maps to `https://zsapi.<cloud>.net/api/v1`; `zspreview` maps to `https://admin.zspreview.net/api/v1`) |
| `ZIA_BASE_URL` | Optional explicit base URL instead of the cloud mapping |
| `ZIA_API_KEY` | Cloud Service API key (Administration > Cloud Service API Security) |
| `ZIA_USERNAME`, `ZIA_PASSWORD` | Administrator login used for `POST /api/v1/authenticatedSession` |

The API key is obfuscated exactly as documented in the ZIA API Getting Started guide: the last six digits of the millisecond timestamp select characters from the key, then the same six digits shifted right by one bit (zero padded) select characters offset by two. The session is a `JSESSIONID` cookie and is closed with `DELETE /api/v1/authenticatedSession` when a tool finishes. The admin needs a role that can view the policy areas above; unreadable areas produce manual findings, never passes.

### ZPA (client credentials)

| Variable | Purpose |
| --- | --- |
| `ZPA_CLIENT_ID`, `ZPA_CLIENT_SECRET` | API client from Administration > API Keys (a read-only role is enough) |
| `ZPA_CUSTOMER_ID` | Customer ID shown with the API client |
| `ZPA_CLOUD` | `PRODUCTION` (`https://config.private.zscaler.com`, default), `ZPATWO` (`https://config.zpatwo.net`), `BETA` (`https://config.zpabeta.net`), `GOV` (`https://config.zpagov.net`), `GOVUS` (`https://config.zpagov.us`), `PREVIEW` (`https://config.zpapreview.net`) |
| `ZPA_BASE_URL` | Optional explicit base URL |

The client posts `client_id` and `client_secret` as a form body to `POST /signin`, sends the returned bearer token, and pages every list with `page` and `pagesize` until the response `totalPages` is reached. Lists that stop early are recorded as partial and cap the verdict at `warn`.

`ZSCALER_CLIENT_ID`, `ZSCALER_CLIENT_SECRET` (OneAPI) and `ZDX_CLIENT_ID`, `ZDX_CLIENT_SECRET` are detected and reported by `zscaler_check_access`, but OneAPI OAuth mode and ZDX enrichment are not implemented in this release. Optional tuning: `ZSCALER_TIMEOUT` (seconds, default 30) and `ZSCALER_MAX_RETRIES` (default 3, honoring `Retry-After` on 429 and 5xx responses).

## Tools

| Tool | Purpose |
| --- | --- |
| `zscaler_check_access` | Probes ten ZIA and seven ZPA read surfaces and reports healthy, limited, or unavailable plus which products are configured |
| `zscaler_assess_zia_access_control` | Controls 6, 7, 14 (admin MFA evidence, RBAC, audit log export) |
| `zscaler_assess_zia_policy` | Controls 1, 2, 3, 4, 5, 16, 17, 18, 19, 20, 25 |
| `zscaler_assess_zpa` | Controls 8, 9, 10, 11, 12, 13, 15, 21, 22, 23, 24 |
| `zscaler_export_audit_bundle` | Runs everything and writes `core_data/`, `analysis/`, `compliance/` (executive summary, unified matrix, one report per framework), `QUICK_REFERENCE.md`, `_errors.log` when collection partially failed, and a zip named after the allocated directory (reruns allocate a new directory) |

Findings are normalized as `{id, control, title, severity, status, summary, evidence, mappings, manualEvidence}` with `status` in `pass`, `warn`, `fail`, `manual`. Verdict rules: a 401, 403, or errored endpoint is `manual` and names the cause; an empty inventory fails or is `manual` per the control's intent (the summary says which); products that are not configured or not licensed render `manual`; undated items (no last connect time, no certificate validity) never count as healthy and cap at `warn`; partial inventories cap at `warn` with seen and total counts.

## Control coverage

| # | Control | Tool | Finding | Status semantics |
| --- | --- | --- | --- | --- |
| 1 | URL Filtering Policy Audit | `zscaler_assess_zia_policy` | ZS-01 | pass when enabled BLOCK rules cover ANONYMIZER, OTHER_SECURITY, ADULT_THEMES, PORNOGRAPHY, GAMBLING; fail on zero, all-disabled, or no BLOCK rules; warn on missing categories |
| 2 | Firewall Rule Audit | `zscaler_assess_zia_policy` | ZS-02 | fail when the default rule allows or an enabled ALLOW rule has no scope; zero rules fail; warn when only the default rule exists or block rules skip full logging |
| 3 | DLP Engine Configuration | `zscaler_assess_zia_policy` | ZS-03 | pass with engines plus enabled BLOCK or ICAP_RESPONSE web DLP rules referencing engines; zero rules or engines fail; monitor-only rules warn |
| 4 | SSL Inspection Coverage | `zscaler_assess_zia_policy` | ZS-04 | pass with enabled DECRYPT rules, no blanket DO_NOT_DECRYPT rule, exemptions under the threshold, SSL scanning on every location; zero rules fail |
| 5 | Cloud Sandbox Analysis | `zscaler_assess_zia_policy` | ZS-05 | pass with enabled BLOCK sandbox rules; zero rules is manual (unlicensed or unconfigured); allow-only warns |
| 6 | Admin MFA Enforcement | `zscaler_assess_zia_access_control` | ZS-06 | always manual or warn: the ZIA API exposes `isPasswordLoginAllowed` but not per-admin MFA, so password-login admins warn and portal evidence is required |
| 7 | RBAC & Admin Role Audit | `zscaler_assess_zia_access_control` | ZS-07 | pass when Super Admin count is within `max_super_admins` and least-privilege roles exist; fail above the threshold |
| 8 | Application Segmentation | `zscaler_assess_zpa` | ZS-08 | fail for wildcard domain plus full port range or zero segments; warn for wildcard, full range, or bypassType ALWAYS |
| 9 | Zero Trust Access Policies | `zscaler_assess_zpa` | ZS-09 | fail for unconditional ALLOW rules or zero rules; warn when ALLOW rules lack identity, posture, or network criteria |
| 10 | Posture Profile Enforcement | `zscaler_assess_zpa` | ZS-10 | pass when every enabled ALLOW rule has a POSTURE condition; fail with zero profiles or no posture conditions |
| 11 | App Connector Health & Coverage | `zscaler_assess_zpa` | ZS-11 | pass when all enabled connectors report ZPN_STATUS_AUTHENTICATED and each group has two or more connected; undated connectors warn |
| 12 | IdP Integration & SAML Config | `zscaler_assess_zpa` | ZS-12 | pass with enabled USER IdP, SCIM, signed SAML requests, admin SSO, and no ZPA admin with local login and no 2FA |
| 13 | Session Timeout Configuration | `zscaler_assess_zpa` | ZS-13 | pass when enabled TIMEOUT_POLICY rules reauthenticate within `max_timeout_hours`; never-expire fails; ZIA admin session timeout is not exposed by the API |
| 14 | Audit Logging Enabled | `zscaler_assess_zia_access_control` | ZS-14 | pass when the audit report interface is readable and an enabled NSS feed exports ADMIN_AUDIT logs; zero feeds warn |
| 15 | Trusted Network Detection | `zscaler_assess_zpa` | ZS-15 | pass when trusted networks are referenced by enabled policy rules; zero networks manual; unreferenced networks warn |
| 16 | Bandwidth Control Policies | `zscaler_assess_zia_policy` | ZS-16 | pass with enabled rules; zero rules manual (license or need must be confirmed) |
| 17 | Browser Isolation Policies | `zscaler_assess_zia_policy` | ZS-17 | pass when isolation profiles are applied by enabled ISOLATE URL rules; zero profiles manual |
| 18 | Location & GRE/VPN Configuration | `zscaler_assess_zia_policy` | ZS-18 | pass when every location and sub-location has authRequired, sslScanEnabled, ofwEnabled; zero locations manual |
| 19 | Cloud Application Control | `zscaler_assess_zia_policy` | ZS-19 | pass with enabled rules whose actions block, isolate, or caution; zero rules fail; unread rule types manual |
| 20 | DNS Security Configuration | `zscaler_assess_zia_policy` | ZS-20 | pass with enabled BLOCK or REDIR DNS rules and dgaDomainsBlocked; zero rules fail |
| 21 | Service Edge Deployment | `zscaler_assess_zpa` | ZS-21 | pass when all private service edges are connected; zero edges manual (public service edges in use) |
| 22 | Forwarding Policy Audit | `zscaler_assess_zpa` | ZS-22 | fail for unconditional BYPASS rules; conditional bypasses warn; zero rules manual |
| 23 | Emergency Access Configuration | `zscaler_assess_zpa` | ZS-23 | pass when break-glass users exist and none is active; active users warn; zero users manual |
| 24 | Certificate Management | `zscaler_assess_zpa` | ZS-24 | fail on expired enrollment or browser access certificates; expiring or undated warn; the ZIA CA chain is manual evidence |
| 25 | Security Policy Baseline | `zscaler_assess_zia_policy` | ZS-25 | pass when the required ATP and malware flags are true and unscannable files are blocked; any false or absent flag fails |

## Framework mappings

Every finding carries the eight mappings from the spec table for its control: FedRAMP (NIST 800-53), CMMC 2.0, SOC 2, CIS Controls, PCI-DSS 4.0, DISA STIG, IRAP (ISM), and ISMAP. The bundle writes one report per framework under `compliance/`.

## Live smoke

```bash
npm --prefix cli run test:zscaler:live
```

The script skips with exit code 0 when no ZIA or ZPA credentials are present; otherwise it runs `zscaler_check_access` and one assessment against the real tenant.

## Endpoints and official documentation

All endpoints and fields below come from the ZIA API reference (https://help.zscaler.com/zia/api) and the ZPA API reference (https://help.zscaler.com/zpa/api-reference), with field shapes cross-checked against the public zscaler-sdk-go repository (https://github.com/zscaler/zscaler-sdk-go).

| Product | Endpoint | Fields read | Reference |
| --- | --- | --- | --- |
| ZIA | `POST`/`DELETE /api/v1/authenticatedSession` | `JSESSIONID` cookie | https://help.zscaler.com/zia/getting-started-zia-api and https://help.zscaler.com/zia/api-reference (Authentication) |
| ZIA | `GET /adminUsers` (`page`, `pageSize`, `includeAuditorUsers`, `includeAdminUsers`) | `loginName`, `disabled`, `isPasswordLoginAllowed`, `adminScopeType`, `role.id`, `role.name` | Admin & Role Management |
| ZIA | `GET /adminRoles/lite` | `id`, `name`, `roleType` | Admin & Role Management |
| ZIA | `GET /passwordExpiry/settings` | `passwordExpirationEnabled`, `passwordExpiryDays` | Admin & Role Management |
| ZIA | `GET /authSettings` | `samlEnabled` | User Authentication Settings |
| ZIA | `GET /auditlogEntryReport` | `status` | Audit Log Report |
| ZIA | `GET /nssFeeds` | `name`, `feedStatus`, `nssLogType` | Cloud NSS Feeds |
| ZIA | `GET /urlFilteringRules` | `name`, `state`, `action`, `urlCategories` | URL Filtering Policy |
| ZIA | `GET /firewallFilteringRules` | `name`, `state`, `action`, `defaultRule`, `enableFullLogging`, scope arrays | Cloud Firewall Policy |
| ZIA | `GET /firewallDnsRules` | `name`, `state`, `action`, `defaultRule` | DNS Control Policy |
| ZIA | `GET /dlpEngines`, `GET /dlpDictionaries`, `GET /webDlpRules` | `name`, `state`, `action`, `dlpEngines`, `withoutContentInspection` | Data Loss Prevention |
| ZIA | `GET /sslInspectionRules`, `GET /sslSettings/exemptedUrls` | `state`, `action.type`, scope arrays, `urls` | SSL Inspection Policy and Settings |
| ZIA | `GET /sandboxRules`, `GET /behavioralAnalysisAdvancedSettings` | `state`, `baRuleAction`, `firstTimeEnable`, `firstTimeOperation`, `fileHashesToBeBlocked` | Sandbox Policy and Settings |
| ZIA | `GET /cyberThreatProtection/advancedThreatSettings`, `/malwarePolicy`, `/malwareSettings` | protection flags listed in the control table, `riskTolerance`, `blockUnscannableFiles` | Advanced Threat Protection and Malware Protection Policy |
| ZIA | `GET /security`, `GET /security/advanced` | `whitelistUrls`, `blacklistUrls` | Security Policy Settings |
| ZIA | `GET /locations` (`page`, `pageSize`), `GET /locations/{locationId}/sublocations` | `authRequired`, `sslScanEnabled`, `ofwEnabled` | Location Management |
| ZIA | `GET /greTunnels`, `GET /vpnCredentials` | counts only | Traffic Forwarding |
| ZIA | `GET /bandwidthControlRules` | `name`, `state`, `minBandwidth`, `maxBandwidth` | Bandwidth Control |
| ZIA | `GET /browserIsolation/profiles` | `id`, `name` | Cloud Browser Isolation |
| ZIA | `GET /webApplicationRules/ruleTypeMapping`, `GET /webApplicationRules/{ruleType}` | `name`, `state`, `actions` | Cloud App Control Policy |
| ZPA | `POST /signin` | `access_token`, `expires_in` | https://help.zscaler.com/zpa/getting-started-zpa-api (Authentication) |
| ZPA | `GET /mgmtconfig/v1/admin/customers/{customerId}/application` | `enabled`, `domainNames`, `tcpPortRange`, `tcpPortRanges`, `udpPortRange`, `udpPortRanges`, `bypassType`, `segmentGroupId` | Application Segment Controller |
| ZPA | `GET .../segmentGroup` | `enabled` | Segment Group Controller |
| ZPA | `GET .../policySet/rules/policyType/{policyType}` (ACCESS_POLICY, TIMEOUT_POLICY, CLIENT_FORWARDING_POLICY, ISOLATION_POLICY) | `action`, `disabled`, `conditions[].operands[].objectType`, `reauthTimeout`, `reauthIdleTimeout` | Policy Set Controller |
| ZPA | `GET .../appConnectorGroup`, `GET .../connector` | `enabled`, `controlChannelStatus`, `appConnectorGroupName`, `lastBrokerConnectTime` | App Connector Group and App Connector Controller |
| ZPA | `GET .../serviceEdgeGroup`, `GET .../serviceEdge` | `enabled`, `controlChannelStatus`, `lastBrokerConnectTime` | Service Edge Group and Service Edge Controller |
| ZPA | `GET /mgmtconfig/v2/admin/customers/{customerId}/posture`, `.../trustedNetwork` | `name`, `postureType`, `networkId` | Posture Profile and Trusted Network Controller |
| ZPA | `GET /mgmtconfig/v2/.../idp`, `.../samlAttribute`, `GET /userconfig/v1/customers/{customerId}/scimgroup/idpId/{idpId}` | `enabled`, `ssoType`, `scimEnabled`, `signSamlRequest` | IdP Controller, SAML Attribute Controller, SCIM Group Controller |
| ZPA | `GET /mgmtconfig/v2/.../enrollmentCert`, `.../clientlessCertificate/issued` | `name`, `validToInEpochSec` | Enrollment Certificate and Browser Access Certificate Controller |
| ZPA | `GET .../emergencyAccess/users` | `emailId`, `userStatus`, `lastLoginTime` | Emergency Access Controller |
| ZPA | `GET .../administrators` | `username`, `isEnabled`, `localLoginDisabled`, `twoFactorAuthEnabled` | Administrator Controller |

## Limitations and manual controls

- Control 6 cannot reach `pass`: the ZIA API does not expose per-administrator MFA state, so the finding reports password-login bypasses and asks for portal evidence.
- Control 13 covers ZPA timeout policy only; the ZIA administrator session timeout is not exposed by the API and is listed as manual evidence in the finding.
- Control 14 verifies the audit report interface and NSS export feeds; retention is enforced by the receiving SIEM and must be documented separately.
- Control 24 covers ZPA enrollment and browser access certificates; the ZIA intermediate CA chain is manual evidence.
- Cloud Service API key inventory, ZDX metrics, and OneAPI OAuth mode are not implemented in this release.
- Empty inventories that are plausibly intentional (no sandbox rules, no bandwidth rules, no isolation profiles, no locations, no trusted networks, no private service edges, no forwarding rules, no emergency access users) render `manual` and say what to confirm; inventories that must never be empty (URL, firewall, DNS, DLP, SSL, cloud app rules, segments, access rules, posture profiles, connectors, IdPs, timeout rules) fail.
