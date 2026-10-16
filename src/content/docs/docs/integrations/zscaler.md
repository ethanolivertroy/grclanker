---
title: Zscaler
description: Read-only ZIA and ZPA security inspector covering the 25 controls in the Zscaler spec with verdict-safe findings and audit bundles.
---

The Zscaler integration inspects Zscaler Internet Access (ZIA) and Zscaler Private Access (ZPA) tenants through their documented read APIs. It evaluates the 25 controls in `specs/zscaler-sec-inspector.spec.md`.

Every tool is read-only. The only non-GET calls are the ZIA session login and logout and the ZPA OAuth sign-in.

## What it inspects

- **ZIA administration:** administrator accounts and roles, password login bypasses, password expiry, the admin audit log report interface, and NSS feeds that export admin audit logs.
- **ZIA policy:** URL filtering, cloud firewall, DNS control, DLP engines, dictionaries and web DLP rules, SSL inspection rules and exemptions, sandbox rules, bandwidth control, browser isolation profiles, locations and sub-locations with GRE tunnels and VPN credentials, cloud app control, and the ATP and malware protection baseline.
- **ZPA:** application segments and segment groups, access, timeout, client forwarding and isolation policy rules, posture profiles, trusted networks, app connectors and groups, private service edges and groups, IdP controllers, SAML attributes, SCIM groups, enrollment and browser access certificates, emergency access users, and ZPA administrators.

## Setup and authentication

Configure either product or both. Controls for a product without credentials render as `manual` findings that name the missing variables.

Credentials resolve with this precedence: explicit tool arguments, then environment variables, then a YAML config file.

The config file is `ZSCALER_CONFIG_FILE` or `~/.zscaler/zscaler.yaml`. A config file path that does not exist is skipped. The file holds:

- `zia.client` and `zpa.client` blocks using `cloud`, `baseUrl`, `apiKey`, `username`, `password`, `clientId`, `clientSecret`, and `customerId` keys
- An optional `zscaler.client` block whose OneAPI `clientId` and `clientSecret` are only detected

### ZIA (legacy API key plus session)

- `ZIA_CLOUD`: Cloud name.
  - `zscaler`, `zscalerone`, `zscalertwo`, `zscalerthree`, `zscloud`, `zscalerbeta`, `zscalergov`, and `zscalerten` map to `https://zsapi.<cloud>.net/api/v1`.
  - `zspreview` maps to `https://admin.zspreview.net/api/v1`.
  - The cloud list and both host forms are documented in the legacy ZIA sections of the [zscaler-sdk-go README](https://github.com/zscaler/zscaler-sdk-go#readme) (`zscaler/zia/v2_config.go`) and the [zscaler-sdk-python README](https://github.com/zscaler/zscaler-sdk-python#readme) (`zscaler/zia/legacy.py`).
- `ZIA_BASE_URL`: Optional explicit base URL instead of the cloud mapping.
- `ZIA_API_KEY`: Cloud Service API key (Administration > Cloud Service API Security).
- `ZIA_USERNAME`, `ZIA_PASSWORD`: Administrator login used for `POST /api/v1/authenticatedSession`.

The API key is obfuscated exactly as documented in the ZIA API Getting Started guide. The last six digits of the millisecond timestamp select characters from the key. Then the same six digits, shifted right by one bit (zero padded), select characters offset by two.

The session is a `JSESSIONID` cookie. It is closed with `DELETE /api/v1/authenticatedSession` when a tool finishes.

The admin needs a role that can view the policy areas above. Unreadable areas produce manual findings, never passes.

ZIA list endpoints that document `page` and `pageSize` are paged to completion:

- `/adminUsers`, `/locations`, `/greTunnels`, and `/vpnCredentials` at the documented maximum of 1000 per page
- `/urlFilteringRules` at the documented default of 100 (no maximum is published)
- `/firewallFilteringRules` at the documented default of 5000

A read that reaches the internal ceiling of 50 pages is recorded as partial and caps the dependent verdicts at `warn`. Endpoints without documented paging parameters return the whole array in one call.

Sub-locations are fetched for at most 100 parent locations. Beyond that, control 18 reports how many parents were read versus the total and caps at `warn`.

### ZPA (client credentials)

- `ZPA_CLIENT_ID`, `ZPA_CLIENT_SECRET`: API client from Administration > API Keys. A read-only role is enough.
- `ZPA_CUSTOMER_ID`: Customer ID shown with the API client.
- `ZPA_CLOUD` values and their base URLs:
  - `PRODUCTION` (default): `https://config.private.zscaler.com`
  - `ZPATWO`: `https://config.zpatwo.net`
  - `BETA`: `https://config.zpabeta.net`
  - `GOV`: `https://config.zpagov.net`
  - `GOVUS`: `https://config.zpagov.us`
  - `PREVIEW`: `https://config.zpapreview.net`
- `ZPA_BASE_URL`: Optional explicit base URL.

The client posts `client_id` and `client_secret` as a form body to `POST /signin` and sends the returned bearer token. It pages every list with `page` and `pagesize` (documented maximum 500) until the response `totalPages` is reached.

A response that omits `totalPages` (or returns a bare array) leaves the total unknown. In that case, the client:

- Keeps paging while pages are full.
- Stops on a short page.
- Treats a page identical to the previous one as a server that stopped advancing.

`GET /emergencyAccess/users` is the one surface documented with a `pageId` cursor and an `items`/`nextPage` wrapper. For that surface, the client:

- Follows `nextPage`.
- Deduplicates users by `userId` or `emailId`.
- Treats a cursor that repeats or cycles as the end of what can be read.

Every one of these exits, plus the 200-page ceiling, is recorded as partial with the pages read versus the total (or "total unknown") and caps the dependent verdicts at `warn`.

`zscaler_check_access` detects and reports `ZSCALER_CLIENT_ID`, `ZSCALER_CLIENT_SECRET` (OneAPI) and `ZDX_CLIENT_ID`, `ZDX_CLIENT_SECRET`. OneAPI OAuth mode and ZDX enrichment are not implemented in this release.

Optional tuning:

- `ZSCALER_TIMEOUT` (seconds, default 30)
- `ZSCALER_MAX_RETRIES` (default 3, honoring `Retry-After` on 429 and 5xx responses)

## Tools

- `zscaler_check_access`: Probes ten ZIA and seven ZPA read surfaces. Reports healthy, limited, or unavailable, plus which products are configured.
- `zscaler_assess_zia_access_control`: Controls 6, 7, 14 (admin MFA evidence, RBAC, audit log export).
- `zscaler_assess_zia_policy`: Controls 1, 2, 3, 4, 5, 16, 17, 18, 19, 20, 25.
- `zscaler_assess_zpa`: Controls 8, 9, 10, 11, 12, 13, 15, 21, 22, 23, 24.
- `zscaler_export_audit_bundle`: Runs everything into `zscaler-audit-<ZIA cloud or ZPA customer ID>-<YYYY-MM-DD>` under `output_dir` (default `./export/zscaler`). It writes:
  - `core_data/`
  - `analysis/`
  - `compliance/` (executive summary, unified matrix, one report per framework)
  - `QUICK_REFERENCE.md`
  - `_errors.log` when collection partially failed
  - A zip named after the allocated directory (reruns allocate a new directory)

### Findings and verdict rules

Findings are normalized as `{id, control, title, severity, status, summary, evidence, mappings, manualEvidence}` with `status` in `pass`, `warn`, `fail`, `manual`.

Verdict rules:

- A 401, 403, or errored endpoint never yields `pass`.
  - When it is the finding's primary inventory, the finding is `manual` and names the cause.
  - When it is a secondary inventory the finding also reads, the finding caps at `warn`. It names the inventory and endpoint with the HTTP status in its summary, and lists it under `evidence.unreadable_inventories`.
  - Examples of secondary inventories are ZPA `GET /serviceEdgeGroup` for control 21 and `GET /dlpDictionaries` for control 3.
- An empty inventory fails or is `manual` per the control's intent. The summary says which.
- Products that are not configured or not licensed render `manual`.
- Undated items (no last connect time, no certificate validity) never count as healthy and cap at `warn`.
- Every inventory a finding reads, primary or secondary, that came back partial caps that finding at `warn`. The finding also:
  - Sets `evidence.partial_inventory`.
  - Names the partial inventory with the records read over the pages read versus the total pages, or "total unknown" when the API published no total.
  - For sub-locations, names parents read versus total.

### Bundle secret hygiene

Every object written to the bundle, including `core_data/access_check.json` and `analysis/findings.json`, passes through export redaction.

Redaction replaces the value with `[REDACTED]` for:

- The credential fields the published schemas document: `kerberosPwd` on `GET /authSettings`, `scimSharedSecret` on `GET .../idp`, `preSharedKey`, `authenticationToken`, `password`, `tmpPassword`, `privateKey`, `zrsaencryptedprivatekey`, `zrsaencryptedsessionkey`.
- The free-text `comment` and `comments` fields on GRE tunnels and VPN credentials, where operators record pre-shared keys.
- Any other key whose normalized name contains `password`, `passwd`, `pwd`, `secret`, `token`, `passphrase`, `credential`, `private`, `community`, `preshared`, `apikey`, or ends in `key`.
  - This rule has a short exception list for benign schema fields: `isPasswordLoginAllowed`, `passwordExpirationEnabled`, `passwordExpiryDays`, `passwordStrength`, `publicKey`, `privateIp`, `tokenType`, and the module's own `passwordExpiry` and `vpnCredentials` datasets.

Booleans are never redacted.

API error text is scrubbed at the client:

- Raw non-JSON bodies are never echoed (only their byte count).
- The documented `message`, `code`, `reason`, and `error` fields are capped at 160 characters.
- Secret-named `key=value` pairs lose their value.
- Any token of 16 or more characters that is not an uppercase error code is dropped.

The regression suite seeds 32 canaries across the configured secrets, every documented credential field, credential-shaped undocumented fields, comment fields, and echoed error bodies. It then walks every bundle file and every zip entry.

## Control coverage

Each entry names the control number and name, then the tool and finding, then the status semantics.

- **1 URL Filtering Policy Audit** (`zscaler_assess_zia_policy`, ZS-01)
  - Pass when enabled BLOCK rules cover ANONYMIZER, OTHER_SECURITY, ADULT_THEMES, PORNOGRAPHY, GAMBLING.
  - Fail on zero, all-disabled, or no BLOCK rules.
  - Warn on missing categories.
- **2 Firewall Rule Audit** (`zscaler_assess_zia_policy`, ZS-02)
  - Fail when the default rule allows or an enabled ALLOW rule has no scope.
  - Zero rules fail.
  - Warn when only the default rule exists or block rules skip full logging. `enableFullLogging` is SDK-documented only, so a missing field never supports pass.
  - Partial rule reads cap at warn.
- **3 DLP Engine Configuration** (`zscaler_assess_zia_policy`, ZS-03)
  - Pass with engines plus enabled BLOCK or ICAP_RESPONSE web DLP rules referencing engines.
  - Zero rules or engines fail.
  - Monitor-only rules warn.
- **4 SSL Inspection Coverage** (`zscaler_assess_zia_policy`, ZS-04)
  - Pass with enabled DECRYPT rules, no blanket DO_NOT_DECRYPT rule, exemptions under the threshold, and SSL scanning on every location that was read.
  - Zero rules fail.
  - A partial location inventory caps at warn.
- **5 Cloud Sandbox Analysis** (`zscaler_assess_zia_policy`, ZS-05)
  - Pass with enabled BLOCK sandbox rules.
  - Zero rules is manual (unlicensed or unconfigured).
  - Allow-only warns.
  - Blocked hashes are counted from the documented `md5HashValueList`, with the legacy `fileHashesToBeBlocked` recorded only as evidence.
- **6 Admin MFA Enforcement** (`zscaler_assess_zia_access_control`, ZS-06)
  - Always manual or warn.
  - The ZIA API exposes `isPasswordLoginAllowed` but not per-admin MFA, so password-login admins warn and portal evidence is required.
- **7 RBAC & Admin Role Audit** (`zscaler_assess_zia_access_control`, ZS-07)
  - Pass when Super Admin count is within `max_super_admins` and least-privilege roles exist.
  - Fail above the threshold.
  - Admin scope is read from the documented `adminScope.Type`. The SDK-only `adminScopeType` is legacy evidence.
  - A partial admin inventory caps at warn.
- **8 Application Segmentation** (`zscaler_assess_zpa`, ZS-08)
  - Fail for wildcard domain plus full port range or zero segments.
  - Warn for wildcard, full range, or bypassType ALWAYS.
  - Partial segment or segment group inventories cap at warn.
- **9 Zero Trust Access Policies** (`zscaler_assess_zpa`, ZS-09)
  - Fail for unconditional ALLOW rules or zero rules.
  - Warn when ALLOW rules lack identity, posture, or network criteria. SCIM, SAML, IdP, user, and user group operands all count as identity.
  - A partial rule inventory caps at warn.
- **10 Posture Profile Enforcement** (`zscaler_assess_zpa`, ZS-10)
  - Pass when every enabled ALLOW rule has a POSTURE condition.
  - Fail with zero profiles or no posture conditions.
  - Partial profile or rule inventories cap at warn.
- **11 App Connector Health & Coverage** (`zscaler_assess_zpa`, ZS-11)
  - Pass when every enabled connector reports ZPN_STATUS_AUTHENTICATED with a `lastBrokerConnectTime` within `stale_connector_days` (default 30) and each group has two or more connected.
  - Authenticated connectors with a stale or missing timestamp warn.
  - None authenticated fails.
  - A partial connector inventory caps at warn.
- **12 IdP Integration & SAML Config** (`zscaler_assess_zpa`, ZS-12)
  - Pass with enabled USER IdP, SCIM, signed SAML requests, admin SSO, and no ZPA admin with local login and no 2FA.
  - The finding states that `GET /administrators` is documented only by zscaler-sdk-go.
  - The finding caps at warn when that surface or any IdP inventory is unreadable or partial.
- **13 Session Timeout Configuration** (`zscaler_assess_zpa`, ZS-13)
  - Pass when enabled TIMEOUT_POLICY rules reauthenticate within `max_timeout_hours`.
  - Never-expire fails.
  - ZIA admin session timeout is not exposed by the API.
- **14 Audit Logging Enabled** (`zscaler_assess_zia_access_control`, ZS-14)
  - Pass when the audit report interface is readable and an enabled NSS feed exports ADMIN_AUDIT logs.
  - Zero feeds warn.
  - A `400` from the bare `GET /auditlogEntryReport` renders manual naming that cause. The reference marks `statusId` required, and the SDKs send no parameter.
- **15 Trusted Network Detection** (`zscaler_assess_zpa`, ZS-15)
  - Pass when trusted networks read from `GET /mgmtconfig/v2/.../network` are referenced by enabled policy rules.
  - Zero networks manual.
  - Unreferenced networks warn.
  - A partial network inventory caps at warn.
- **16 Bandwidth Control Policies** (`zscaler_assess_zia_policy`, ZS-16)
  - Pass with enabled rules.
  - Zero rules manual (license or need must be confirmed).
- **17 Browser Isolation Policies** (`zscaler_assess_zia_policy`, ZS-17)
  - Pass when isolation profiles are applied by enabled ISOLATE URL rules.
  - Zero profiles manual.
- **18 Location & GRE/VPN Configuration** (`zscaler_assess_zia_policy`, ZS-18)
  - Pass when every location and sub-location that was read has authRequired, sslScanEnabled, ofwEnabled.
  - Zero locations manual.
  - When sub-locations were read for fewer parents than exist (100-parent cap) or the location list is partial, the finding reports parents read versus total and caps at warn.
- **19 Cloud Application Control** (`zscaler_assess_zia_policy`, ZS-19)
  - Pass with enabled rules whose actions block, isolate, or caution.
  - Zero rules fail.
  - Unread rule types manual.
- **20 DNS Security Configuration** (`zscaler_assess_zia_policy`, ZS-20)
  - Pass with enabled BLOCK or REDIR DNS rules and dgaDomainsBlocked.
  - Zero rules fail.
- **21 Service Edge Deployment** (`zscaler_assess_zpa`, ZS-21)
  - Pass when every enabled private service edge is authenticated with a `lastBrokerConnectTime` within `stale_connector_days`.
  - Stale or missing timestamps warn.
  - None authenticated fails.
  - Zero edges manual (public service edges in use).
- **22 Forwarding Policy Audit** (`zscaler_assess_zpa`, ZS-22)
  - Fail for unconditional BYPASS rules.
  - Conditional bypasses warn.
  - Zero rules manual.
- **23 Emergency Access Configuration** (`zscaler_assess_zpa`, ZS-23)
  - Pass when break-glass users exist and none is active.
  - Active users warn.
  - Zero users manual.
  - Users are read through the documented `pageId` cursor and deduplicated. An unfinished cursor caps at warn.
- **24 Certificate Management** (`zscaler_assess_zpa`, ZS-24)
  - Fail on expired enrollment or browser access certificates. Validity is read from `validToInEpochSec` or the `validTo` date-time.
  - Expiring or undated warn.
  - Partial or unreadable browser access certificate inventories cap at warn.
  - The ZIA CA chain is manual evidence.
- **25 Security Policy Baseline** (`zscaler_assess_zia_policy`, ZS-25)
  - Pass when the required ATP and malware flags are true and unscannable files are blocked.
  - Any false or absent flag fails.

## Framework mappings

Every finding carries the eight mappings from the spec table for its control: FedRAMP (NIST 800-53), CMMC 2.0, SOC 2, CIS Controls, PCI-DSS 4.0, DISA STIG, IRAP (ISM), and ISMAP.

The bundle writes one report per framework under `compliance/`.

## Live smoke

```bash
npm --prefix cli run test:zscaler:live
```

The script skips with exit code 0 when no ZIA or ZPA credentials are present. Otherwise it runs `zscaler_check_access` and one assessment against the real tenant.

## Endpoints and official documentation

Every endpoint, query parameter, and field below was verified against the OpenAPI documents published on the [Zscaler Automation Hub](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia) (ZIA and ZPA API reference).

The Hub serves the OneAPI base URL `https://api.zsapi.net/zia/api/v1`. The resource paths, parameters, and schemas are shared with the legacy `/api/v1` and `config.private.zscaler.com` surfaces this integration calls.

The legacy authentication flows are documented on help.zscaler.com ([ZIA API getting started](https://help.zscaler.com/zia/getting-started-zia-api), [ZPA API getting started](https://help.zscaler.com/zpa/getting-started-zpa-api)). They are implemented identically in [zscaler-sdk-go](https://github.com/zscaler/zscaler-sdk-go) (`zscaler/zia/v2_client.go`, `zscaler/zpa/v2_client.go`).

Entries marked "SDK only" name surfaces or fields that the published reference does not document. The dependent findings state that and never rest a `pass` on them.

Reference links below are relative to `https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/`.

Each entry names the product and the endpoint with its paging, then the fields read and the reference.

- **ZIA** `POST /api/v1/authenticatedSession` (`apiKey`, `username`, `password`, `timestamp`)
  - Fields read: `JSESSIONID` cookie
  - Reference: [zia/api-authentication/post-authenticated-session-info](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/api-authentication/post-authenticated-session-info). Obfuscation per the getting started guide and `zscaler/zia/v2_client.go`.
- **ZIA** `DELETE /api/v1/authenticatedSession`
  - Fields read: None
  - Reference: [zia/api-authentication/set-authenticated-session-info](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/api-authentication/set-authenticated-session-info)
- **ZIA** `GET /adminUsers` (`includeAuditorUsers`, `includeAdminUsers`, `page`, `pageSize` 1000, documented max 1000)
  - Fields read: `loginName`, `disabled`, `isPasswordLoginAllowed`, `adminScope.Type`, `role.id`, `role.name`. `adminScopeType` is SDK only and legacy evidence.
  - Reference: [zia/admin-role-management/get-admin-users](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/admin-role-management/get-admin-users)
- **ZIA** `GET /adminRoles/lite` (`includeAuditorRole`, `includePartnerRole`, `includeApiRole`; no paging documented)
  - Fields read: `id`, `name`, `roleType`
  - Reference: [zia/admin-role-management/get-role-summary](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/admin-role-management/get-role-summary)
- **ZIA** `GET /passwordExpiry/settings`
  - Fields read: `passwordExpirationEnabled`, `passwordExpiryDays`
  - Reference: [zia/admin-role-management/password-expiry-resource-get-password-expiry-settings](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/admin-role-management/password-expiry-resource-get-password-expiry-settings)
- **ZIA** `GET /authSettings`
  - Fields read: `samlEnabled`
  - Reference: [zia/authentication-settings/auth-settings-resource-get-auth-settings](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/authentication-settings/auth-settings-resource-get-auth-settings)
- **ZIA** `GET /auditlogEntryReport` (bare, as both SDKs send it)
  - The reference marks `statusId` required, so a `400` renders control 14 manual.
  - Fields read: `status`
  - Reference: [zia/admin-audit-logs/get-audit-report-entry-csv-export-status](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/admin-audit-logs/get-audit-report-entry-csv-export-status)
- **ZIA** `GET /nssFeeds` (no paging documented)
  - Fields read: `name`, `feedStatus`, `nssLogType`
  - Reference: [zia/cloud-nanolog-streaming-service-nss/nss-feeds-resource-get-all-nss-feeds](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/cloud-nanolog-streaming-service-nss/nss-feeds-resource-get-all-nss-feeds)
- **ZIA** `GET /urlFilteringRules` (`page`, `pageSize` 100, the documented default; no max published)
  - Fields read: `name`, `state`, `action`, `urlCategories`
  - Reference: [zia/url-filtering-policy/get-rules](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/url-filtering-policy/get-rules)
- **ZIA** `GET /firewallFilteringRules` (`page`, `pageSize` 5000, the documented default)
  - Fields read: `name`, `state`, `action`, `defaultRule`, scope arrays. `enableFullLogging` is SDK only (`filteringrules.go`), and its absence never supports pass.
  - Reference: [zia/firewall-policies/firewall-filtering-rules-resource-get-firewall-filtering-rules](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/firewall-policies/firewall-filtering-rules-resource-get-firewall-filtering-rules)
- **ZIA** `GET /firewallDnsRules` (no paging documented)
  - Fields read: `name`, `state`, `action`, `defaultRule`
  - Reference: [zia/dns-control-policy/firewall-dns-rules-resource-get-firewall-dns-rules](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/dns-control-policy/firewall-dns-rules-resource-get-firewall-dns-rules)
- **ZIA** `GET /dlpEngines` (no paging documented)
  - Fields read: `id`, `name`
  - Reference: [zia/data-loss-prevention/dlp-engine-resource-get-dlp-engines](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/data-loss-prevention/dlp-engine-resource-get-dlp-engines)
- **ZIA** `GET /dlpDictionaries` (`search`; no paging documented)
  - Fields read: `id`, `name`
  - Reference: [zia/data-loss-prevention/dlp-dictionary-resource-get-dlp-dictionaries](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/data-loss-prevention/dlp-dictionary-resource-get-dlp-dictionaries)
- **ZIA** `GET /webDlpRules` (no paging documented)
  - Fields read: `name`, `state`, `action`, `dlpEngines`, `withoutContentInspection`
  - Reference: [zia/data-loss-prevention/web-dlp-rule-resource-get-rules](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/data-loss-prevention/web-dlp-rule-resource-get-rules)
- **ZIA** `GET /sslInspectionRules` (no paging documented)
  - Fields read: `name`, `state`, `action.type`, scope arrays
  - Reference: [zia/ssl-inspection-policy/ssl-inspection-rule-resource-get-ssl-inspection-rules](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/ssl-inspection-policy/ssl-inspection-rule-resource-get-ssl-inspection-rules)
- **ZIA** `GET /sslSettings/exemptedUrls`
  - Fields read: `urls`
  - Reference: [zia/intermediate-ca-certificates/get-ssl-exempted-urls](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/intermediate-ca-certificates/get-ssl-exempted-urls)
- **ZIA** `GET /sandboxRules` (no paging documented)
  - Fields read: `name`, `state`, `baRuleAction`, `firstTimeEnable`, `firstTimeOperation`
  - Reference: [zia/sandbox-policy-settings/ba-rule-resource-get-rules](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/sandbox-policy-settings/ba-rule-resource-get-rules)
- **ZIA** `GET /behavioralAnalysisAdvancedSettings`
  - Fields read: `md5HashValueList`. The legacy `fileHashesToBeBlocked` (SDK only, `sandbox_settings.go`) is recorded as evidence when present.
  - Reference: [zia/sandbox-policy-settings/ba-advanced-settings-resource-get-custom-file-hash](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/sandbox-policy-settings/ba-advanced-settings-resource-get-custom-file-hash)
- **ZIA** `GET /cyberThreatProtection/advancedThreatSettings`
  - Fields read: ATP flags listed in the control table, `riskTolerance`, `dgaDomainsBlocked`
  - Reference: [zia/advanced-threat-protection-policy/cyber-threat-protection-resource-get-config](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/advanced-threat-protection-policy/cyber-threat-protection-resource-get-config)
- **ZIA** `GET /cyberThreatProtection/malwarePolicy`, `GET /cyberThreatProtection/malwareSettings`
  - Fields read: Malware flags listed in the control table, `blockUnscannableFiles`, `blockPasswordProtectedArchiveFiles`
  - References: [zia/malware-protection-policy/cyber-threat-protection-resource-get-malware-policy-config](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/malware-protection-policy/cyber-threat-protection-resource-get-malware-policy-config), [.../cyber-threat-protection-resource-get-malware-settings-config](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/malware-protection-policy/cyber-threat-protection-resource-get-malware-settings-config)
- **ZIA** `GET /security`, `GET /security/advanced`
  - Fields read: `whitelistUrls`, `blacklistUrls`
  - References: [zia/security-policy-settings/get-config](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/security-policy-settings/get-config), [zia/security-policy-settings/get-advanced-policy](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/security-policy-settings/get-advanced-policy)
- **ZIA** `GET /locations` (`page`, `pageSize` 1000, documented max 1000)
  - Fields read: `id`, `name`, `authRequired`, `sslScanEnabled`, `ofwEnabled`
  - Reference: [zia/location-management/get-top-locations](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/location-management/get-top-locations)
- **ZIA** `GET /locations/{locationId}/sublocations` (no paging documented; fetched for at most 100 parents)
  - Fields read: `id`, `name`, `parentId`, `authRequired`, `sslScanEnabled`, `ofwEnabled`
  - Reference: [zia/location-management/get-sub-locations](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/location-management/get-sub-locations)
- **ZIA** `GET /greTunnels` (`page`, `pageSize` 1000, documented max 1000)
  - Fields read: Counts only
  - Reference: [zia/traffic-forwarding/gre-tunnel-resource-get-all-gre-tunnels](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/traffic-forwarding/gre-tunnel-resource-get-all-gre-tunnels)
- **ZIA** `GET /vpnCredentials` (`includeOnlyWithoutLocation=false`, `page`, `pageSize` 1000, documented max 1000)
  - Fields read: Counts only
  - Reference: [zia/traffic-forwarding/get-vpn-credentials](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/traffic-forwarding/get-vpn-credentials)
- **ZIA** `GET /bandwidthControlRules` (no paging documented)
  - Fields read: `name`, `state`, `minBandwidth`, `maxBandwidth`
  - Reference: [zia/bandwidth-control-classes/bandwidth-control-rule-resource-get-rules](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/bandwidth-control-classes/bandwidth-control-rule-resource-get-rules)
- **ZIA** `GET /browserIsolation/profiles` (no paging documented)
  - Fields read: `id`, `name`
  - Reference: [zia/browser-isolation/browser-isolation-resource-get-cloud-browser-isolation-profiles](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/browser-isolation/browser-isolation-resource-get-cloud-browser-isolation-profiles)
- **ZIA** `GET /webApplicationRules/ruleTypeMapping`, `GET /webApplicationRules/{ruleType}`
  - Fields read: Rule type keys; `name`, `state`, `actions`
  - References: [zia/cloud-app-control-policy/web-application-rule-resource-get-rule-type-mapping](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/cloud-app-control-policy/web-application-rule-resource-get-rule-type-mapping), [.../web-application-rule-resource-get-rules-by-type](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/cloud-app-control-policy/web-application-rule-resource-get-rules-by-type)
- **ZPA** `POST /signin` (form `client_id`, `client_secret`)
  - Fields read: `access_token`, `expires_in`
  - Reference (legacy ZPA authentication): [ZPA API getting started](https://help.zscaler.com/zpa/getting-started-zpa-api) and `zscaler/zpa/v2_client.go`. The Automation Hub documents only the OneAPI OAuth flow.
- **ZPA** `GET /mgmtconfig/v1/admin/customers/{customerId}/application` (`page`, `pagesize` 500, documented max 500, to `totalPages`)
  - Fields read: `enabled`, `domainNames`, `tcpPortRange`, `tcpPortRanges`, `udpPortRange`, `udpPortRanges`, `bypassType`, `segmentGroupId`
  - Reference: [zpa/application-segment-management/gets-all-configured-application-segments-for-the-specified-customer](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/application-segment-management/gets-all-configured-application-segments-for-the-specified-customer)
- **ZPA** `GET .../v1/.../segmentGroup` (`page`, `pagesize` 500)
  - Fields read: Count only
  - Reference: [zpa/segment-group-management/gets-all-configured-segment-groups-for-the-specified-customer](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/segment-group-management/gets-all-configured-segment-groups-for-the-specified-customer)
- **ZPA** `GET .../v1/.../policySet/rules/policyType/{policyType}` (`page`, `pagesize` 500)
  - Policy types: ACCESS_POLICY, TIMEOUT_POLICY, CLIENT_FORWARDING_POLICY, ISOLATION_POLICY
  - Fields read: `name`, `action`, `disabled`, `conditions[].operands[].objectType`, `reauthTimeout`, `reauthIdleTimeout`
  - Reference: [zpa/policy-management/gets-paginated-policy-rules-for-the-specified-policy-type](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/policy-management/gets-paginated-policy-rules-for-the-specified-policy-type)
- **ZPA** `GET .../v1/.../appConnectorGroup` (`page`, `pagesize` 500)
  - Fields read: `id`, `name`, `enabled`
  - Reference: [zpa/app-connector-group/gets-all-configured-app-connector-groups-for-the-specified-customer](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/app-connector-group/gets-all-configured-app-connector-groups-for-the-specified-customer)
- **ZPA** `GET .../v1/.../connector` (`page`, `pagesize` 500)
  - Fields read: `name`, `enabled`, `controlChannelStatus`, `lastBrokerConnectTime`, `appConnectorGroupName`, `appConnectorGroupId`
  - Reference: [zpa/app-connector-management/gets-all-configured-app-connector-details-for-the-specified-customer](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/app-connector-management/gets-all-configured-app-connector-details-for-the-specified-customer)
- **ZPA** `GET .../v1/.../serviceEdgeGroup` (`page`, `pagesize` 500)
  - Fields read: Count only
  - Reference: [zpa/service-edge-group/get-private-broker-groups](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/service-edge-group/get-private-broker-groups)
- **ZPA** `GET .../v1/.../serviceEdge` (`page`, `pagesize` 500)
  - Fields read: `name`, `enabled`, `controlChannelStatus`, `lastBrokerConnectTime`
  - Reference: [zpa/private-service-edge-management/gets-all-the-configured-service-edge-details-for-the-specified-customer](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/private-service-edge-management/gets-all-the-configured-service-edge-details-for-the-specified-customer)
- **ZPA** `GET /mgmtconfig/v2/admin/customers/{customerId}/posture` (`page`, `pagesize` 500)
  - Fields read: `name`, `postureType`
  - Reference: [zpa/posture-profiles/get-all-attributes](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/posture-profiles/get-all-attributes)
- **ZPA** `GET /mgmtconfig/v2/admin/customers/{customerId}/network` (`page`, `pagesize` 500)
  - Fields read: `id`, `name`
  - Reference: [zpa/trusted-networks/get-all-trusted-networks](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/trusted-networks/get-all-trusted-networks)
- **ZPA** `GET .../v2/.../idp` (`page`, `pagesize` 500)
  - Fields read: `name`, `enabled`, `ssoType`, `scimEnabled`, `signSamlRequest`
  - Reference: [zpa/idp-management/get-all-idp](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/idp-management/get-all-idp)
- **ZPA** `GET .../v2/.../samlAttribute` (`page`, `pagesize` 500)
  - Fields read: Count only
  - Reference: [zpa/saml-attributes/get-all-attributes-by-page](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/saml-attributes/get-all-attributes-by-page)
- **ZPA** `GET /userconfig/v1/customers/{customerId}/scimgroup/idpId/{idpId}` (`page`, `pagesize` 500, documented max 500)
  - Fields read: Count only
  - Reference: [zpa/scim-groups/get-all-scim-groups](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/scim-groups/get-all-scim-groups)
- **ZPA** `GET .../v2/.../enrollmentCert` (`page`, `pagesize` 500)
  - Fields read: `name`, `validToInEpochSec`, `validTo` (date-time)
  - Reference for field shapes: [zpa/enrollment-certificates/gets-the-enrollment-certificate-details-for-the-specified-id](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/enrollment-certificates/gets-the-enrollment-certificate-details-for-the-specified-id)
  - Reference for the list operation: [zpa/signing-certificate/get-all-signing-cert](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/signing-certificate/get-all-signing-cert) (`search`, `page`, `pagesize` max 500). It is published under the signing-certificate category.
- **ZPA** `GET .../v2/.../clientlessCertificate/issued` (`page`, `pagesize` 500)
  - Fields read: `name`, `validToInEpochSec`, `validTo` (date-time)
  - Reference: [zpa/certificate-management/get-all-issued-certs](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/certificate-management/get-all-issued-certs)
- **ZPA** `GET .../v1/.../emergencyAccess/users` (`pageId` cursor from `nextPage`, `pageSize` 500, documented max 500; `items` wrapper)
  - Fields read: `userId`, `emailId`, `userStatus`, `lastLoginTime`
  - Reference: [zpa/emergency-access-management/get-all-emergency-access-group-users](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zpa/emergency-access-management/get-all-emergency-access-group-users)
- **ZPA** `GET .../v1/.../administrators` (`page`, `pagesize` 500)
  - Fields read: `username`, `isEnabled`, `localLoginDisabled`, `twoFactorAuthEnabled`
  - Reference (SDK only): `zscaler/zpa/services/administrator_controller/administrator_controller.go` and `tests/unit/zpa/services/administratorcontroller_test.go` in zscaler-sdk-go
  - The endpoint is absent from the published ZPA reference, so control 12 states this and never passes on it alone.

## Limitations and manual controls

- Control 6 cannot reach `pass`. The ZIA API does not expose per-administrator MFA state, so the finding reports password-login bypasses and asks for portal evidence.
- Control 13 covers ZPA timeout policy only. The ZIA administrator session timeout is not exposed by the API and is listed as manual evidence in the finding.
- Control 14 verifies the audit report interface and NSS export feeds. Retention is enforced by the receiving SIEM and must be documented separately.
  - The published reference marks `statusId` as a required query parameter on `GET /auditlogEntryReport` (it names an export task created by `POST`, which this read-only inspector never issues).
  - Both official SDKs send a bare `GET`. The inspector sends the bare `GET` as well.
  - If a tenant enforces the documented shape and returns `400`, control 14 renders `manual` naming that cause rather than passing.
- Control 24 covers ZPA enrollment and browser access certificates. The ZIA intermediate CA chain is manual evidence.
- Surfaces documented only by the official SDKs are treated as supplementary evidence:
  - ZPA `GET /administrators`. Control 12 says so in its summary and caps at `warn` when it is unreadable.
  - `enableFullLogging` on firewall rules.
  - The legacy `adminScopeType` and `fileHashesToBeBlocked` keys.
- ZPA admin roles are not read because neither `/admin/roles` nor `/roles` appears in the published reference.
- Cloud Service API key inventory, ZDX metrics, and OneAPI OAuth mode are not implemented in this release.
- Empty inventories that are plausibly intentional render `manual` and say what to confirm. The cases are no sandbox rules, no bandwidth rules, no isolation profiles, no locations, no trusted networks, no private service edges, no forwarding rules, and no emergency access users.
- Inventories that must never be empty fail. They are URL, firewall, DNS, DLP, SSL, cloud app rules, segments, access rules, posture profiles, connectors, IdPs, and timeout rules.
