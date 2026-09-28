---
slug: "zscaler-sec-inspector"
name: "Zscaler Security Inspector"
vendor: "Zscaler"
category: "zero-trust-and-secure-web-gateway"
language: "language-neutral"
status: "generated"
version: "1.0.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# Zscaler Security Inspector

Portable contract for the shipped ZIA administrative and policy assessments and ZPA zero-trust access assessment.

## Purpose

Give security and compliance teams a read-only, repeatable view of ZIA administrative and policy controls and ZPA zero-trust access controls without treating missing product credentials or unreadable tenant surfaces as compliance.

## Design guidance

Use dedicated ZIA and ZPA API credentials and configure only the products in scope. Preserve cloud selection, product availability, pagination, retry exhaustion, and per-surface permission failures as evidence. ZDX and OneAPI detection does not imply shipped assessment coverage.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- ZIA and ZPA authenticate independently; absent credentials produce explicit not-configured manual findings for that product.
- The ZIA client logs out in a finally path, and ZIA API-key obfuscation plus session cookies are never written to findings or bundles.
- List pagination and configured retry exhaustion remain partial or unreadable; presentation samples never establish compliance.
- ZDX and OneAPI credentials are recognized by configuration but the shipped assessment tools cover ZIA and ZPA only.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `zscaler_check_access` | Validate read-only Zscaler access: ZIA (admin users, roles, auth settings, audit log report, URL filtering, firewall, DLP, SSL inspection, ATP, locations) and ZPA (application segments, segment groups, access policy, connectors, IdP, posture, administrators). Products without credentials are reported as not configured. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zscaler_assess_zia_access_control` | Assess ZIA administrator security (spec controls 6, 7, 14): password-login bypasses and MFA evidence, Super Admin concentration and role scoping, and admin audit log export via NSS feeds. Unreadable or empty surfaces render manual, never pass. | `ZS-06`, `ZS-07`, `ZS-14` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zscaler_assess_zia_policy` | Assess ZIA policy posture (spec controls 1-5, 16-20, 25): URL filtering, cloud firewall, DLP, SSL inspection and exemptions, sandbox, bandwidth control, browser isolation, locations and sub-locations with GRE/VPN, cloud app control, DNS control, and the ATP/malware baseline. Empty inventories fail or render manual per control intent; unreadable surfaces never pass. | `ZS-01`, `ZS-02`, `ZS-03`, `ZS-04`, `ZS-05`, `ZS-16`, `ZS-17`, `ZS-18`, `ZS-19`, `ZS-20`, `ZS-25` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zscaler_assess_zpa` | Assess ZPA posture (spec controls 8-13, 15, 21-24): application segmentation, access policy criteria, posture enforcement, app connector health and redundancy, IdP/SAML/SCIM and admin login hardening, timeout policy, trusted networks, private service edges, client forwarding bypasses, emergency access, and certificate expiry. Renders manual when ZPA credentials are absent. | `ZS-08`, `ZS-09`, `ZS-10`, `ZS-11`, `ZS-12`, `ZS-13`, `ZS-15`, `ZS-21`, `ZS-22`, `ZS-23`, `ZS-24` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `zscaler_export_audit_bundle` | Run every Zscaler assessment and write an evidence bundle: core_data/ raw snapshots (secrets redacted), analysis/ findings, compliance/ executive summary, unified matrix, and per-framework reports (FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, DISA STIG, IRAP, ISMAP), QUICK_REFERENCE.md, _errors.log on partial collection, and a zip named after the allocated directory. Reruns never overwrite a prior bundle. | `ZS-01`, `ZS-02`, `ZS-03`, `ZS-04`, `ZS-05`, `ZS-06`, `ZS-07`, `ZS-08`, `ZS-09`, `ZS-10`, `ZS-11`, `ZS-12`, `ZS-13`, `ZS-14`, `ZS-15`, `ZS-16`, `ZS-17`, `ZS-18`, `ZS-19`, `ZS-20`, `ZS-21`, `ZS-22`, `ZS-23`, `ZS-24`, `ZS-25` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `zscaler_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `zia_cloud` | string | no | ZIA cloud name (zscaler, zscalerone, zscalertwo, zscalerthree, zscloud, zscalerbeta, zscalergov, zscalerten). Defaults to ZIA_CLOUD. |
| `zia_base_url` | string | no | Explicit ZIA API base URL such as https://zsapi.zscalerthree.net/api/v1. Defaults to the cloud mapping. |
| `zia_api_key` | string | no | ZIA Cloud Service API key. Defaults to ZIA_API_KEY. |
| `zia_username` | string | no | ZIA administrator login name. Defaults to ZIA_USERNAME. |
| `zia_password` | string | no | ZIA administrator password. Defaults to ZIA_PASSWORD. |
| `zpa_cloud` | string | no | ZPA cloud (PRODUCTION, ZPATWO, BETA, GOV, GOVUS, PREVIEW). Defaults to ZPA_CLOUD or PRODUCTION. |
| `zpa_base_url` | string | no | Explicit ZPA base URL such as https://config.private.zscaler.com. Defaults to the cloud mapping. |
| `zpa_client_id` | string | no | ZPA API client ID. Defaults to ZPA_CLIENT_ID. |
| `zpa_client_secret` | string | no | ZPA API client secret. Defaults to ZPA_CLIENT_SECRET. |
| `zpa_customer_id` | string | no | ZPA customer ID. Defaults to ZPA_CUSTOMER_ID. |
| `config_file` | string | no | YAML config file. Defaults to ZSCALER_CONFIG_FILE or ~/.zscaler/zscaler.yaml. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429/5xx responses, honoring Retry-After. Defaults to 3. |

#### `zscaler_assess_zia_access_control`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `zia_cloud` | string | no | ZIA cloud name (zscaler, zscalerone, zscalertwo, zscalerthree, zscloud, zscalerbeta, zscalergov, zscalerten). Defaults to ZIA_CLOUD. |
| `zia_base_url` | string | no | Explicit ZIA API base URL such as https://zsapi.zscalerthree.net/api/v1. Defaults to the cloud mapping. |
| `zia_api_key` | string | no | ZIA Cloud Service API key. Defaults to ZIA_API_KEY. |
| `zia_username` | string | no | ZIA administrator login name. Defaults to ZIA_USERNAME. |
| `zia_password` | string | no | ZIA administrator password. Defaults to ZIA_PASSWORD. |
| `zpa_cloud` | string | no | ZPA cloud (PRODUCTION, ZPATWO, BETA, GOV, GOVUS, PREVIEW). Defaults to ZPA_CLOUD or PRODUCTION. |
| `zpa_base_url` | string | no | Explicit ZPA base URL such as https://config.private.zscaler.com. Defaults to the cloud mapping. |
| `zpa_client_id` | string | no | ZPA API client ID. Defaults to ZPA_CLIENT_ID. |
| `zpa_client_secret` | string | no | ZPA API client secret. Defaults to ZPA_CLIENT_SECRET. |
| `zpa_customer_id` | string | no | ZPA customer ID. Defaults to ZPA_CUSTOMER_ID. |
| `config_file` | string | no | YAML config file. Defaults to ZSCALER_CONFIG_FILE or ~/.zscaler/zscaler.yaml. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429/5xx responses, honoring Retry-After. Defaults to 3. |
| `max_super_admins` | number | no | Maximum acceptable Super Admin count before failing. Defaults to 5. |

#### `zscaler_assess_zia_policy`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `zia_cloud` | string | no | ZIA cloud name (zscaler, zscalerone, zscalertwo, zscalerthree, zscloud, zscalerbeta, zscalergov, zscalerten). Defaults to ZIA_CLOUD. |
| `zia_base_url` | string | no | Explicit ZIA API base URL such as https://zsapi.zscalerthree.net/api/v1. Defaults to the cloud mapping. |
| `zia_api_key` | string | no | ZIA Cloud Service API key. Defaults to ZIA_API_KEY. |
| `zia_username` | string | no | ZIA administrator login name. Defaults to ZIA_USERNAME. |
| `zia_password` | string | no | ZIA administrator password. Defaults to ZIA_PASSWORD. |
| `zpa_cloud` | string | no | ZPA cloud (PRODUCTION, ZPATWO, BETA, GOV, GOVUS, PREVIEW). Defaults to ZPA_CLOUD or PRODUCTION. |
| `zpa_base_url` | string | no | Explicit ZPA base URL such as https://config.private.zscaler.com. Defaults to the cloud mapping. |
| `zpa_client_id` | string | no | ZPA API client ID. Defaults to ZPA_CLIENT_ID. |
| `zpa_client_secret` | string | no | ZPA API client secret. Defaults to ZPA_CLIENT_SECRET. |
| `zpa_customer_id` | string | no | ZPA customer ID. Defaults to ZPA_CUSTOMER_ID. |
| `config_file` | string | no | YAML config file. Defaults to ZSCALER_CONFIG_FILE or ~/.zscaler/zscaler.yaml. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429/5xx responses, honoring Retry-After. Defaults to 3. |
| `max_ssl_exemptions` | number | no | Maximum acceptable SSL inspection exempted URLs before warning. Defaults to 50. |

#### `zscaler_assess_zpa`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `zia_cloud` | string | no | ZIA cloud name (zscaler, zscalerone, zscalertwo, zscalerthree, zscloud, zscalerbeta, zscalergov, zscalerten). Defaults to ZIA_CLOUD. |
| `zia_base_url` | string | no | Explicit ZIA API base URL such as https://zsapi.zscalerthree.net/api/v1. Defaults to the cloud mapping. |
| `zia_api_key` | string | no | ZIA Cloud Service API key. Defaults to ZIA_API_KEY. |
| `zia_username` | string | no | ZIA administrator login name. Defaults to ZIA_USERNAME. |
| `zia_password` | string | no | ZIA administrator password. Defaults to ZIA_PASSWORD. |
| `zpa_cloud` | string | no | ZPA cloud (PRODUCTION, ZPATWO, BETA, GOV, GOVUS, PREVIEW). Defaults to ZPA_CLOUD or PRODUCTION. |
| `zpa_base_url` | string | no | Explicit ZPA base URL such as https://config.private.zscaler.com. Defaults to the cloud mapping. |
| `zpa_client_id` | string | no | ZPA API client ID. Defaults to ZPA_CLIENT_ID. |
| `zpa_client_secret` | string | no | ZPA API client secret. Defaults to ZPA_CLIENT_SECRET. |
| `zpa_customer_id` | string | no | ZPA customer ID. Defaults to ZPA_CUSTOMER_ID. |
| `config_file` | string | no | YAML config file. Defaults to ZSCALER_CONFIG_FILE or ~/.zscaler/zscaler.yaml. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429/5xx responses, honoring Retry-After. Defaults to 3. |
| `cert_expiry_warn_days` | number | no | Warn when a certificate expires within this many days. Defaults to 30. |
| `stale_connector_days` | number | no | Days since last broker connect before a connector is reported stale. Defaults to 30. |
| `max_timeout_hours` | number | no | Maximum acceptable reauthentication timeout in hours. Defaults to 24. |

#### `zscaler_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `zia_cloud` | string | no | ZIA cloud name (zscaler, zscalerone, zscalertwo, zscalerthree, zscloud, zscalerbeta, zscalergov, zscalerten). Defaults to ZIA_CLOUD. |
| `zia_base_url` | string | no | Explicit ZIA API base URL such as https://zsapi.zscalerthree.net/api/v1. Defaults to the cloud mapping. |
| `zia_api_key` | string | no | ZIA Cloud Service API key. Defaults to ZIA_API_KEY. |
| `zia_username` | string | no | ZIA administrator login name. Defaults to ZIA_USERNAME. |
| `zia_password` | string | no | ZIA administrator password. Defaults to ZIA_PASSWORD. |
| `zpa_cloud` | string | no | ZPA cloud (PRODUCTION, ZPATWO, BETA, GOV, GOVUS, PREVIEW). Defaults to ZPA_CLOUD or PRODUCTION. |
| `zpa_base_url` | string | no | Explicit ZPA base URL such as https://config.private.zscaler.com. Defaults to the cloud mapping. |
| `zpa_client_id` | string | no | ZPA API client ID. Defaults to ZPA_CLIENT_ID. |
| `zpa_client_secret` | string | no | ZPA API client secret. Defaults to ZPA_CLIENT_SECRET. |
| `zpa_customer_id` | string | no | ZPA customer ID. Defaults to ZPA_CUSTOMER_ID. |
| `config_file` | string | no | YAML config file. Defaults to ZSCALER_CONFIG_FILE or ~/.zscaler/zscaler.yaml. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_retries` | number | no | Retries for 429/5xx responses, honoring Retry-After. Defaults to 3. |
| `output_dir` | string | no | Root directory for bundles. Defaults to ./export/zscaler. |
| `max_super_admins` | number | no | Maximum acceptable Super Admin count. Defaults to 5. |
| `max_ssl_exemptions` | number | no | Maximum acceptable SSL exempted URLs. Defaults to 50. |
| `cert_expiry_warn_days` | number | no | Certificate expiry warning window in days. Defaults to 30. |
| `stale_connector_days` | number | no | Stale connector threshold in days. Defaults to 30. |
| `max_timeout_hours` | number | no | Maximum acceptable reauthentication timeout in hours. Defaults to 24. |


## Authentication

Supported modes:

- ZIA legacy API-key obfuscation and session cookie
- ZPA OAuth client credentials

Credential precedence, highest first:

1. Explicit tool arguments
2. Zscaler environment variables
3. Zscaler YAML config file

Environment variables: `ZSCALER_CONFIG_FILE`, `ZIA_CLOUD`, `ZIA_BASE_URL`, `ZIA_API_KEY`, `ZIA_USERNAME`, `ZIA_PASSWORD`, `ZPA_CLOUD`, `ZPA_BASE_URL`, `ZPA_CLIENT_ID`, `ZPA_CLIENT_SECRET`, `ZPA_CUSTOMER_ID`, `ZSCALER_CLIENT_ID`, `ZSCALER_CLIENT_SECRET`, `ZDX_CLIENT_ID`, `ZDX_CLIENT_SECRET`, `ZSCALER_TIMEOUT`, `ZSCALER_MAX_RETRIES`

Configuration locations: ~/.zscaler/zscaler.yaml, Explicit path from config_file or ZSCALER_CONFIG_FILE

Credential and deployment variants: ZIA commercial, beta, government, and tenant clouds, ZPA production, beta, government, and government-US clouds

Configuration fields: `zia.client`, `zpa.client`, `zscaler.client`

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

Credential refresh: POST /authenticatedSession for ZIA; POST /signin for ZPA OAuth client credentials.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| role | `ZIA administrator API read access to the declared administrative and policy surfaces` | `zia-administration`, `zia-policy` |  |
| oauth-scope | `ZPA API client read access for the configured customer` | `zpa-policy` |  |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `zia-administration` | HTTP | `GET /api/v1/{adminUsers\|adminRoles\|authSettings\|auditLogFeeds}` | ZIA API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `loginName`, `role`, `adminScope`, `mfa`, `status` | [Official documentation](https://help.zscaler.com/zia/api) |
| `zia-policy` | HTTP | `GET /api/v1/{urlFilteringRules\|firewallFilteringRules\|dlpEngines\|sslInspectionRules\|sandboxRules\|locations}` | ZIA API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `state`, `action`, `rank`, `order`, `destinations`, `locations` | [Official documentation](https://help.zscaler.com/zia/api) |
| `zpa-policy` | HTTP | `GET /mgmtconfig/v1/admin/customers/{customerId}/{application\|policy\|posture\|connector\|idp\|admin\|certificate} resources` | ZPA API | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `enabled`, `operator`, `action`, `health`, `modifiedTime`, `expirationDate` | [Official documentation](https://help.zscaler.com/zpa/api-reference) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `zia-administration` | client | Use the configured ZIA API origin; never follow a server link to a different origin. | yes |
| `zia-administration` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `zia-administration` | response | A JSON object or list containing only the documented id, loginName, role, adminScope, mfa, status members consumed by verdicts. | yes |
| `zia-policy` | client | Use the configured ZIA API origin; never follow a server link to a different origin. | yes |
| `zia-policy` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `zia-policy` | response | A JSON object or list containing only the documented id, name, state, action, rank, order, destinations, locations members consumed by verdicts. | yes |
| `zpa-policy` | client | Use the configured ZPA API origin; never follow a server link to a different origin. | yes |
| `zpa-policy` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `zpa-policy` | response | A JSON object or list containing only the documented id, name, enabled, operator, action, health, modifiedTime, expirationDate members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `zia-administration`, `zia-policy`, `zpa-policy` | `page`, `pageSize`, `totalPages`, `totalElements`, `next` | service default | caller limit | none | Completion requires reaching the documented final page or total without a repeated cursor, empty advancing page, or configured item cap. | Reported final page; Reported total reached; Short or empty final page; Repeated cursor; Configured cap |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Zscaler Security Inspector | Cloud, product, and endpoint specific | `Retry-After` | 429, 500, 502, 503, 504 | Honor bounded Retry-After and retry transient responses up to the configured retry count; exhausted reads remain unreadable. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | URL Filtering Policy Audit | ZS-01 | Evaluate the ordered first-match rules for ZS-01 below. |
| 2 | Firewall Rule Audit | ZS-02 | Evaluate the ordered first-match rules for ZS-02 below. |
| 3 | DLP Engine Configuration | ZS-03 | Evaluate the ordered first-match rules for ZS-03 below. |
| 4 | SSL Inspection Coverage | ZS-04 | Evaluate the ordered first-match rules for ZS-04 below. |
| 5 | Cloud Sandbox Analysis | ZS-05 | Evaluate the ordered first-match rules for ZS-05 below. |
| 6 | Admin MFA Enforcement | ZS-06 | Evaluate the ordered first-match rules for ZS-06 below. |
| 7 | RBAC & Admin Role Audit | ZS-07 | Evaluate the ordered first-match rules for ZS-07 below. |
| 8 | Application Segmentation | ZS-08 | Evaluate the ordered first-match rules for ZS-08 below. |
| 9 | Zero Trust Access Policies | ZS-09 | Evaluate the ordered first-match rules for ZS-09 below. |
| 10 | Posture Profile Enforcement | ZS-10 | Evaluate the ordered first-match rules for ZS-10 below. |
| 11 | App Connector Health & Coverage | ZS-11 | Evaluate the ordered first-match rules for ZS-11 below. |
| 12 | IdP Integration & SAML Config | ZS-12 | Evaluate the ordered first-match rules for ZS-12 below. |
| 13 | Session Timeout Configuration | ZS-13 | Evaluate the ordered first-match rules for ZS-13 below. |
| 14 | Audit Logging Enabled | ZS-14 | Evaluate the ordered first-match rules for ZS-14 below. |
| 15 | Trusted Network Detection | ZS-15 | Evaluate the ordered first-match rules for ZS-15 below. |
| 16 | Bandwidth Control Policies | ZS-16 | Evaluate the ordered first-match rules for ZS-16 below. |
| 17 | Browser Isolation Policies | ZS-17 | Evaluate the ordered first-match rules for ZS-17 below. |
| 18 | Location & GRE/VPN Configuration | ZS-18 | Evaluate the ordered first-match rules for ZS-18 below. |
| 19 | Cloud Application Control | ZS-19 | Evaluate the ordered first-match rules for ZS-19 below. |
| 20 | DNS Security Configuration | ZS-20 | Evaluate the ordered first-match rules for ZS-20 below. |
| 21 | Service Edge Deployment | ZS-21 | Evaluate the ordered first-match rules for ZS-21 below. |
| 22 | Forwarding Policy Audit | ZS-22 | Evaluate the ordered first-match rules for ZS-22 below. |
| 23 | Emergency Access Configuration | ZS-23 | Evaluate the ordered first-match rules for ZS-23 below. |
| 24 | Certificate Management | ZS-24 | Evaluate the ordered first-match rules for ZS-24 below. |
| 25 | Security Policy Baseline | ZS-25 | Evaluate the ordered first-match rules for ZS-25 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `ZS-01` | high | `zscaler_assess_zia_policy` | `zia-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate URL Filtering Policy Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate URL Filtering Policy Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate URL Filtering Policy Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for URL Filtering Policy Audit is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-02` | high | `zscaler_assess_zia_policy` | `zia-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Firewall Rule Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Firewall Rule Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Firewall Rule Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Firewall Rule Audit is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-03` | high | `zscaler_assess_zia_policy` | `zia-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate DLP Engine Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate DLP Engine Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate DLP Engine Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for DLP Engine Configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-04` | high | `zscaler_assess_zia_policy` | `zia-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate SSL Inspection Coverage from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate SSL Inspection Coverage from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate SSL Inspection Coverage from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for SSL Inspection Coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-05` | medium | `zscaler_assess_zia_policy` | `zia-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Cloud Sandbox Analysis from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Cloud Sandbox Analysis from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Cloud Sandbox Analysis from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Cloud Sandbox Analysis is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-06` | critical | `zscaler_assess_zia_access_control` | `zia-administration` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Admin MFA Enforcement from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Admin MFA Enforcement from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Admin MFA Enforcement from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Admin MFA Enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-07` | high | `zscaler_assess_zia_access_control` | `zia-administration` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate RBAC & Admin Role Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate RBAC & Admin Role Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate RBAC & Admin Role Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for RBAC & Admin Role Audit is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-08` | high | `zscaler_assess_zpa` | `zpa-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Application Segmentation from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Application Segmentation from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Application Segmentation from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Application Segmentation is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-09` | critical | `zscaler_assess_zpa` | `zpa-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Zero Trust Access Policies from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Zero Trust Access Policies from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Zero Trust Access Policies from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Zero Trust Access Policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-10` | high | `zscaler_assess_zpa` | `zpa-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Posture Profile Enforcement from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Posture Profile Enforcement from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Posture Profile Enforcement from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Posture Profile Enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-11` | medium | `zscaler_assess_zpa` | `zpa-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate App Connector Health & Coverage from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate App Connector Health & Coverage from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate App Connector Health & Coverage from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for App Connector Health & Coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-12` | critical | `zscaler_assess_zpa` | `zpa-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate IdP Integration & SAML Config from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate IdP Integration & SAML Config from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate IdP Integration & SAML Config from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for IdP Integration & SAML Config is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-13` | medium | `zscaler_assess_zpa` | `zpa-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Session Timeout Configuration from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Session Timeout Configuration from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Session Timeout Configuration from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Session Timeout Configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-14` | high | `zscaler_assess_zia_access_control` | `zia-administration` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Audit Logging Enabled from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Audit Logging Enabled from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Audit Logging Enabled from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Audit Logging Enabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-15` | medium | `zscaler_assess_zpa` | `zpa-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Trusted Network Detection from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Trusted Network Detection from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Trusted Network Detection from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Trusted Network Detection is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-16` | low | `zscaler_assess_zia_policy` | `zia-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Bandwidth Control Policies from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Bandwidth Control Policies from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Bandwidth Control Policies from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Bandwidth Control Policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-17` | medium | `zscaler_assess_zia_policy` | `zia-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Browser Isolation Policies from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Browser Isolation Policies from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Browser Isolation Policies from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Browser Isolation Policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-18` | medium | `zscaler_assess_zia_policy` | `zia-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Location & GRE/VPN Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Location & GRE/VPN Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Location & GRE/VPN Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Location & GRE/VPN Configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-19` | medium | `zscaler_assess_zia_policy` | `zia-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Cloud Application Control from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Cloud Application Control from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Cloud Application Control from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Cloud Application Control is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-20` | high | `zscaler_assess_zia_policy` | `zia-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate DNS Security Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate DNS Security Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate DNS Security Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for DNS Security Configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-21` | low | `zscaler_assess_zpa` | `zpa-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Service Edge Deployment from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Service Edge Deployment from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Service Edge Deployment from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Service Edge Deployment is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-22` | medium | `zscaler_assess_zpa` | `zpa-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Forwarding Policy Audit from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Forwarding Policy Audit from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Forwarding Policy Audit from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Forwarding Policy Audit is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-23` | medium | `zscaler_assess_zpa` | `zpa-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Emergency Access Configuration from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Emergency Access Configuration from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Emergency Access Configuration from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Emergency Access Configuration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-24` | high | `zscaler_assess_zpa` | `zpa-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Certificate Management from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Certificate Management from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Certificate Management from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Certificate Management is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `ZS-25` | high | `zscaler_assess_zia_policy` | `zia-policy` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Security Policy Baseline from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Security Policy Baseline from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Security Policy Baseline from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | The required evidence for Security Policy Baseline is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `ZS-01` | 1 | manual | `zs_01_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-01` | 2 | fail | `zs_01_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-01` | 3 | manual | `zs_01_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-01` | 4 | warn | `zs_01_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-01` | 5 | pass | `zs_01_branch_05_matches` equals true |  |
| `ZS-01` | 6 | manual | `zs_01_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-02` | 1 | manual | `zs_02_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-02` | 2 | fail | `zs_02_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-02` | 3 | manual | `zs_02_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-02` | 4 | warn | `zs_02_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-02` | 5 | pass | `zs_02_branch_05_matches` equals true |  |
| `ZS-02` | 6 | manual | `zs_02_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-03` | 1 | manual | `zs_03_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-03` | 2 | fail | `zs_03_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-03` | 3 | manual | `zs_03_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-03` | 4 | warn | `zs_03_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-03` | 5 | pass | `zs_03_branch_05_matches` equals true |  |
| `ZS-03` | 6 | manual | `zs_03_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-04` | 1 | manual | `zs_04_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-04` | 2 | fail | `zs_04_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-04` | 3 | manual | `zs_04_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-04` | 4 | warn | `zs_04_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-04` | 5 | pass | `zs_04_branch_05_matches` equals true |  |
| `ZS-04` | 6 | manual | `zs_04_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-05` | 1 | manual | `zs_05_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-05` | 2 | fail | `zs_05_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-05` | 3 | manual | `zs_05_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-05` | 4 | warn | `zs_05_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-05` | 5 | pass | `zs_05_branch_05_matches` equals true |  |
| `ZS-05` | 6 | manual | `zs_05_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-06` | 1 | manual | `zs_06_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-06` | 2 | fail | `zs_06_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-06` | 3 | manual | `zs_06_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-06` | 4 | warn | `zs_06_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-06` | 5 | pass | `zs_06_branch_05_matches` equals true |  |
| `ZS-06` | 6 | manual | `zs_06_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-07` | 1 | manual | `zs_07_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-07` | 2 | fail | `zs_07_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-07` | 3 | manual | `zs_07_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-07` | 4 | warn | `zs_07_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-07` | 5 | pass | `zs_07_branch_05_matches` equals true |  |
| `ZS-07` | 6 | manual | `zs_07_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-08` | 1 | manual | `zs_08_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-08` | 2 | fail | `zs_08_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-08` | 3 | manual | `zs_08_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-08` | 4 | warn | `zs_08_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-08` | 5 | pass | `zs_08_branch_05_matches` equals true |  |
| `ZS-08` | 6 | manual | `zs_08_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-09` | 1 | manual | `zs_09_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-09` | 2 | fail | `zs_09_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-09` | 3 | manual | `zs_09_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-09` | 4 | warn | `zs_09_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-09` | 5 | pass | `zs_09_branch_05_matches` equals true |  |
| `ZS-09` | 6 | manual | `zs_09_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-10` | 1 | manual | `zs_10_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-10` | 2 | fail | `zs_10_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-10` | 3 | manual | `zs_10_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-10` | 4 | warn | `zs_10_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-10` | 5 | pass | `zs_10_branch_05_matches` equals true |  |
| `ZS-10` | 6 | manual | `zs_10_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-11` | 1 | manual | `zs_11_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-11` | 2 | fail | `zs_11_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-11` | 3 | manual | `zs_11_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-11` | 4 | warn | `zs_11_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-11` | 5 | pass | `zs_11_branch_05_matches` equals true |  |
| `ZS-11` | 6 | manual | `zs_11_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-12` | 1 | manual | `zs_12_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-12` | 2 | fail | `zs_12_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-12` | 3 | manual | `zs_12_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-12` | 4 | warn | `zs_12_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-12` | 5 | pass | `zs_12_branch_05_matches` equals true |  |
| `ZS-12` | 6 | manual | `zs_12_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-13` | 1 | manual | `zs_13_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-13` | 2 | fail | `zs_13_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-13` | 3 | manual | `zs_13_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-13` | 4 | warn | `zs_13_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-13` | 5 | pass | `zs_13_branch_05_matches` equals true |  |
| `ZS-13` | 6 | manual | `zs_13_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-14` | 1 | manual | `zs_14_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-14` | 2 | fail | `zs_14_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-14` | 3 | manual | `zs_14_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-14` | 4 | warn | `zs_14_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-14` | 5 | pass | `zs_14_branch_05_matches` equals true |  |
| `ZS-14` | 6 | manual | `zs_14_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-15` | 1 | manual | `zs_15_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-15` | 2 | fail | `zs_15_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-15` | 3 | manual | `zs_15_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-15` | 4 | warn | `zs_15_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-15` | 5 | pass | `zs_15_branch_05_matches` equals true |  |
| `ZS-15` | 6 | manual | `zs_15_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-16` | 1 | manual | `zs_16_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-16` | 2 | fail | `zs_16_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-16` | 3 | manual | `zs_16_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-16` | 4 | warn | `zs_16_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-16` | 5 | pass | `zs_16_branch_05_matches` equals true |  |
| `ZS-16` | 6 | manual | `zs_16_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-17` | 1 | manual | `zs_17_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-17` | 2 | fail | `zs_17_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-17` | 3 | manual | `zs_17_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-17` | 4 | warn | `zs_17_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-17` | 5 | pass | `zs_17_branch_05_matches` equals true |  |
| `ZS-17` | 6 | manual | `zs_17_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-18` | 1 | manual | `zs_18_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-18` | 2 | fail | `zs_18_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-18` | 3 | manual | `zs_18_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-18` | 4 | warn | `zs_18_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-18` | 5 | pass | `zs_18_branch_05_matches` equals true |  |
| `ZS-18` | 6 | manual | `zs_18_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-19` | 1 | manual | `zs_19_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-19` | 2 | fail | `zs_19_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-19` | 3 | manual | `zs_19_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-19` | 4 | warn | `zs_19_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-19` | 5 | pass | `zs_19_branch_05_matches` equals true |  |
| `ZS-19` | 6 | manual | `zs_19_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-20` | 1 | manual | `zs_20_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-20` | 2 | fail | `zs_20_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-20` | 3 | manual | `zs_20_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-20` | 4 | warn | `zs_20_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-20` | 5 | pass | `zs_20_branch_05_matches` equals true |  |
| `ZS-20` | 6 | manual | `zs_20_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-21` | 1 | manual | `zs_21_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-21` | 2 | fail | `zs_21_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-21` | 3 | manual | `zs_21_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-21` | 4 | warn | `zs_21_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-21` | 5 | pass | `zs_21_branch_05_matches` equals true |  |
| `ZS-21` | 6 | manual | `zs_21_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-22` | 1 | manual | `zs_22_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-22` | 2 | fail | `zs_22_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-22` | 3 | manual | `zs_22_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-22` | 4 | warn | `zs_22_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-22` | 5 | pass | `zs_22_branch_05_matches` equals true |  |
| `ZS-22` | 6 | manual | `zs_22_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-23` | 1 | manual | `zs_23_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-23` | 2 | fail | `zs_23_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-23` | 3 | manual | `zs_23_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-23` | 4 | warn | `zs_23_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-23` | 5 | pass | `zs_23_branch_05_matches` equals true |  |
| `ZS-23` | 6 | manual | `zs_23_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-24` | 1 | manual | `zs_24_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-24` | 2 | fail | `zs_24_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-24` | 3 | manual | `zs_24_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-24` | 4 | warn | `zs_24_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-24` | 5 | pass | `zs_24_branch_05_matches` equals true |  |
| `ZS-24` | 6 | manual | `zs_24_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `ZS-25` | 1 | manual | `zs_25_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `ZS-25` | 2 | fail | `zs_25_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `ZS-25` | 3 | manual | `zs_25_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `ZS-25` | 4 | warn | `zs_25_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `ZS-25` | 5 | pass | `zs_25_branch_05_matches` equals true |  |
| `ZS-25` | 6 | manual | `zs_25_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `ZS-01` | `zs_01_branch_01_matches` | ZS-01 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-01` | `zs_01_branch_02_matches` | ZS-01 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-01` | `zs_01_branch_03_matches` | ZS-01 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-01` | `zs_01_branch_04_matches` | ZS-01 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-01` | `zs_01_branch_05_matches` | ZS-01 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-01` | `zs_01_branch_06_matches` | ZS-01 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-02` | `zs_02_branch_01_matches` | ZS-02 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-02` | `zs_02_branch_02_matches` | ZS-02 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-02` | `zs_02_branch_03_matches` | ZS-02 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-02` | `zs_02_branch_04_matches` | ZS-02 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-02` | `zs_02_branch_05_matches` | ZS-02 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-02` | `zs_02_branch_06_matches` | ZS-02 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-03` | `zs_03_branch_01_matches` | ZS-03 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-03` | `zs_03_branch_02_matches` | ZS-03 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-03` | `zs_03_branch_03_matches` | ZS-03 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-03` | `zs_03_branch_04_matches` | ZS-03 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-03` | `zs_03_branch_05_matches` | ZS-03 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-03` | `zs_03_branch_06_matches` | ZS-03 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-04` | `zs_04_branch_01_matches` | ZS-04 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-04` | `zs_04_branch_02_matches` | ZS-04 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-04` | `zs_04_branch_03_matches` | ZS-04 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-04` | `zs_04_branch_04_matches` | ZS-04 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-04` | `zs_04_branch_05_matches` | ZS-04 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-04` | `zs_04_branch_06_matches` | ZS-04 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-05` | `zs_05_branch_01_matches` | ZS-05 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-05` | `zs_05_branch_02_matches` | ZS-05 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-05` | `zs_05_branch_03_matches` | ZS-05 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-05` | `zs_05_branch_04_matches` | ZS-05 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-05` | `zs_05_branch_05_matches` | ZS-05 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-05` | `zs_05_branch_06_matches` | ZS-05 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-06` | `zs_06_branch_01_matches` | ZS-06 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-06` | `zs_06_branch_02_matches` | ZS-06 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-06` | `zs_06_branch_03_matches` | ZS-06 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-06` | `zs_06_branch_04_matches` | ZS-06 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-06` | `zs_06_branch_05_matches` | ZS-06 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-06` | `zs_06_branch_06_matches` | ZS-06 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-07` | `zs_07_branch_01_matches` | ZS-07 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-07` | `zs_07_branch_02_matches` | ZS-07 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-07` | `zs_07_branch_03_matches` | ZS-07 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-07` | `zs_07_branch_04_matches` | ZS-07 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-07` | `zs_07_branch_05_matches` | ZS-07 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-07` | `zs_07_branch_06_matches` | ZS-07 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-08` | `zs_08_branch_01_matches` | ZS-08 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-08` | `zs_08_branch_02_matches` | ZS-08 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-08` | `zs_08_branch_03_matches` | ZS-08 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-08` | `zs_08_branch_04_matches` | ZS-08 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-08` | `zs_08_branch_05_matches` | ZS-08 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-08` | `zs_08_branch_06_matches` | ZS-08 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-09` | `zs_09_branch_01_matches` | ZS-09 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-09` | `zs_09_branch_02_matches` | ZS-09 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-09` | `zs_09_branch_03_matches` | ZS-09 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-09` | `zs_09_branch_04_matches` | ZS-09 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-09` | `zs_09_branch_05_matches` | ZS-09 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-09` | `zs_09_branch_06_matches` | ZS-09 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-10` | `zs_10_branch_01_matches` | ZS-10 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-10` | `zs_10_branch_02_matches` | ZS-10 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-10` | `zs_10_branch_03_matches` | ZS-10 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-10` | `zs_10_branch_04_matches` | ZS-10 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-10` | `zs_10_branch_05_matches` | ZS-10 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-10` | `zs_10_branch_06_matches` | ZS-10 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-11` | `zs_11_branch_01_matches` | ZS-11 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-11` | `zs_11_branch_02_matches` | ZS-11 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-11` | `zs_11_branch_03_matches` | ZS-11 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-11` | `zs_11_branch_04_matches` | ZS-11 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-11` | `zs_11_branch_05_matches` | ZS-11 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-11` | `zs_11_branch_06_matches` | ZS-11 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-12` | `zs_12_branch_01_matches` | ZS-12 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-12` | `zs_12_branch_02_matches` | ZS-12 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-12` | `zs_12_branch_03_matches` | ZS-12 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-12` | `zs_12_branch_04_matches` | ZS-12 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-12` | `zs_12_branch_05_matches` | ZS-12 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-12` | `zs_12_branch_06_matches` | ZS-12 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-13` | `zs_13_branch_01_matches` | ZS-13 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-13` | `zs_13_branch_02_matches` | ZS-13 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-13` | `zs_13_branch_03_matches` | ZS-13 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-13` | `zs_13_branch_04_matches` | ZS-13 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-13` | `zs_13_branch_05_matches` | ZS-13 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-13` | `zs_13_branch_06_matches` | ZS-13 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-14` | `zs_14_branch_01_matches` | ZS-14 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-14` | `zs_14_branch_02_matches` | ZS-14 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-14` | `zs_14_branch_03_matches` | ZS-14 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-14` | `zs_14_branch_04_matches` | ZS-14 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-14` | `zs_14_branch_05_matches` | ZS-14 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-14` | `zs_14_branch_06_matches` | ZS-14 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-15` | `zs_15_branch_01_matches` | ZS-15 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-15` | `zs_15_branch_02_matches` | ZS-15 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-15` | `zs_15_branch_03_matches` | ZS-15 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-15` | `zs_15_branch_04_matches` | ZS-15 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-15` | `zs_15_branch_05_matches` | ZS-15 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-15` | `zs_15_branch_06_matches` | ZS-15 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-16` | `zs_16_branch_01_matches` | ZS-16 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-16` | `zs_16_branch_02_matches` | ZS-16 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-16` | `zs_16_branch_03_matches` | ZS-16 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-16` | `zs_16_branch_04_matches` | ZS-16 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-16` | `zs_16_branch_05_matches` | ZS-16 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-16` | `zs_16_branch_06_matches` | ZS-16 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-17` | `zs_17_branch_01_matches` | ZS-17 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-17` | `zs_17_branch_02_matches` | ZS-17 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-17` | `zs_17_branch_03_matches` | ZS-17 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-17` | `zs_17_branch_04_matches` | ZS-17 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-17` | `zs_17_branch_05_matches` | ZS-17 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-17` | `zs_17_branch_06_matches` | ZS-17 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-18` | `zs_18_branch_01_matches` | ZS-18 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-18` | `zs_18_branch_02_matches` | ZS-18 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-18` | `zs_18_branch_03_matches` | ZS-18 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-18` | `zs_18_branch_04_matches` | ZS-18 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-18` | `zs_18_branch_05_matches` | ZS-18 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-18` | `zs_18_branch_06_matches` | ZS-18 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-19` | `zs_19_branch_01_matches` | ZS-19 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-19` | `zs_19_branch_02_matches` | ZS-19 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-19` | `zs_19_branch_03_matches` | ZS-19 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-19` | `zs_19_branch_04_matches` | ZS-19 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-19` | `zs_19_branch_05_matches` | ZS-19 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-19` | `zs_19_branch_06_matches` | ZS-19 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-20` | `zs_20_branch_01_matches` | ZS-20 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-20` | `zs_20_branch_02_matches` | ZS-20 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-20` | `zs_20_branch_03_matches` | ZS-20 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-20` | `zs_20_branch_04_matches` | ZS-20 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-20` | `zs_20_branch_05_matches` | ZS-20 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-20` | `zs_20_branch_06_matches` | ZS-20 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-21` | `zs_21_branch_01_matches` | ZS-21 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-21` | `zs_21_branch_02_matches` | ZS-21 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-21` | `zs_21_branch_03_matches` | ZS-21 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-21` | `zs_21_branch_04_matches` | ZS-21 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-21` | `zs_21_branch_05_matches` | ZS-21 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-21` | `zs_21_branch_06_matches` | ZS-21 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-22` | `zs_22_branch_01_matches` | ZS-22 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-22` | `zs_22_branch_02_matches` | ZS-22 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-22` | `zs_22_branch_03_matches` | ZS-22 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-22` | `zs_22_branch_04_matches` | ZS-22 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-22` | `zs_22_branch_05_matches` | ZS-22 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-22` | `zs_22_branch_06_matches` | ZS-22 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-23` | `zs_23_branch_01_matches` | ZS-23 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-23` | `zs_23_branch_02_matches` | ZS-23 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-23` | `zs_23_branch_03_matches` | ZS-23 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-23` | `zs_23_branch_04_matches` | ZS-23 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-23` | `zs_23_branch_05_matches` | ZS-23 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-23` | `zs_23_branch_06_matches` | ZS-23 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-24` | `zs_24_branch_01_matches` | ZS-24 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-24` | `zs_24_branch_02_matches` | ZS-24 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-24` | `zs_24_branch_03_matches` | ZS-24 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-24` | `zs_24_branch_04_matches` | ZS-24 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-24` | `zs_24_branch_05_matches` | ZS-24 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-24` | `zs_24_branch_06_matches` | ZS-24 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `ZS-25` | `zs_25_branch_01_matches` | ZS-25 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `ZS-25` | `zs_25_branch_02_matches` | ZS-25 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `ZS-25` | `zs_25_branch_03_matches` | ZS-25 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `ZS-25` | `zs_25_branch_04_matches` | ZS-25 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `ZS-25` | `zs_25_branch_05_matches` | ZS-25 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `ZS-25` | `zs_25_branch_06_matches` | ZS-25 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `ZS-01` | `requiredEvidenceReadable` | true |
| `ZS-01` | `requiredEvidenceComplete` | true |
| `ZS-02` | `requiredEvidenceReadable` | true |
| `ZS-02` | `requiredEvidenceComplete` | true |
| `ZS-03` | `requiredEvidenceReadable` | true |
| `ZS-03` | `requiredEvidenceComplete` | true |
| `ZS-04` | `requiredEvidenceReadable` | true |
| `ZS-04` | `requiredEvidenceComplete` | true |
| `ZS-05` | `requiredEvidenceReadable` | true |
| `ZS-05` | `requiredEvidenceComplete` | true |
| `ZS-06` | `requiredEvidenceReadable` | true |
| `ZS-06` | `requiredEvidenceComplete` | true |
| `ZS-07` | `requiredEvidenceReadable` | true |
| `ZS-07` | `requiredEvidenceComplete` | true |
| `ZS-08` | `requiredEvidenceReadable` | true |
| `ZS-08` | `requiredEvidenceComplete` | true |
| `ZS-09` | `requiredEvidenceReadable` | true |
| `ZS-09` | `requiredEvidenceComplete` | true |
| `ZS-10` | `requiredEvidenceReadable` | true |
| `ZS-10` | `requiredEvidenceComplete` | true |
| `ZS-11` | `requiredEvidenceReadable` | true |
| `ZS-11` | `requiredEvidenceComplete` | true |
| `ZS-12` | `requiredEvidenceReadable` | true |
| `ZS-12` | `requiredEvidenceComplete` | true |
| `ZS-13` | `requiredEvidenceReadable` | true |
| `ZS-13` | `requiredEvidenceComplete` | true |
| `ZS-14` | `requiredEvidenceReadable` | true |
| `ZS-14` | `requiredEvidenceComplete` | true |
| `ZS-15` | `requiredEvidenceReadable` | true |
| `ZS-15` | `requiredEvidenceComplete` | true |
| `ZS-16` | `requiredEvidenceReadable` | true |
| `ZS-16` | `requiredEvidenceComplete` | true |
| `ZS-17` | `requiredEvidenceReadable` | true |
| `ZS-17` | `requiredEvidenceComplete` | true |
| `ZS-18` | `requiredEvidenceReadable` | true |
| `ZS-18` | `requiredEvidenceComplete` | true |
| `ZS-19` | `requiredEvidenceReadable` | true |
| `ZS-19` | `requiredEvidenceComplete` | true |
| `ZS-20` | `requiredEvidenceReadable` | true |
| `ZS-20` | `requiredEvidenceComplete` | true |
| `ZS-21` | `requiredEvidenceReadable` | true |
| `ZS-21` | `requiredEvidenceComplete` | true |
| `ZS-22` | `requiredEvidenceReadable` | true |
| `ZS-22` | `requiredEvidenceComplete` | true |
| `ZS-23` | `requiredEvidenceReadable` | true |
| `ZS-23` | `requiredEvidenceComplete` | true |
| `ZS-24` | `requiredEvidenceReadable` | true |
| `ZS-24` | `requiredEvidenceComplete` | true |
| `ZS-25` | `requiredEvidenceReadable` | true |
| `ZS-25` | `requiredEvidenceComplete` | true |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `ZS-01` | compliant | All required source reads are complete and this derivation returns pass: Evaluate URL Filtering Policy Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate URL Filtering Policy Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-02` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Firewall Rule Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Firewall Rule Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-03` | compliant | All required source reads are complete and this derivation returns pass: Evaluate DLP Engine Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate DLP Engine Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-04` | compliant | All required source reads are complete and this derivation returns pass: Evaluate SSL Inspection Coverage from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate SSL Inspection Coverage from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-05` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Cloud Sandbox Analysis from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Cloud Sandbox Analysis from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-06` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Admin MFA Enforcement from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Admin MFA Enforcement from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-07` | compliant | All required source reads are complete and this derivation returns pass: Evaluate RBAC & Admin Role Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate RBAC & Admin Role Audit from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-08` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Application Segmentation from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-08` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Application Segmentation from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-09` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Zero Trust Access Policies from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-09` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Zero Trust Access Policies from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-09` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-09` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-10` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Posture Profile Enforcement from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-10` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Posture Profile Enforcement from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-10` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-10` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-11` | compliant | All required source reads are complete and this derivation returns pass: Evaluate App Connector Health & Coverage from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-11` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate App Connector Health & Coverage from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-11` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-11` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-12` | compliant | All required source reads are complete and this derivation returns pass: Evaluate IdP Integration & SAML Config from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-12` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate IdP Integration & SAML Config from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-12` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-12` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-13` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Session Timeout Configuration from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-13` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Session Timeout Configuration from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-13` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-13` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-14` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Audit Logging Enabled from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-14` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Audit Logging Enabled from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-14` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-14` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-15` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Trusted Network Detection from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-15` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Trusted Network Detection from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-15` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-15` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-16` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Bandwidth Control Policies from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-16` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Bandwidth Control Policies from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-16` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-16` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-17` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Browser Isolation Policies from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-17` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Browser Isolation Policies from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-17` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-17` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-18` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Location & GRE/VPN Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-18` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Location & GRE/VPN Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-18` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-18` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-19` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Cloud Application Control from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-19` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Cloud Application Control from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-19` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-19` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-20` | compliant | All required source reads are complete and this derivation returns pass: Evaluate DNS Security Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-20` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate DNS Security Configuration from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-20` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-20` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-21` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Service Edge Deployment from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-21` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Service Edge Deployment from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-21` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-21` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-22` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Forwarding Policy Audit from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-22` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Forwarding Policy Audit from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-22` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-22` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-23` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Emergency Access Configuration from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-23` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Emergency Access Configuration from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-23` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-23` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-24` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Certificate Management from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-24` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Certificate Management from the complete ZPA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-24` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-24` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `ZS-25` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Security Policy Baseline from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `ZS-25` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Security Policy Baseline from the complete ZIA inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `ZS-25` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `ZS-25` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | URL Filtering Policy Audit | SC-7, SI-4 | C.3.13, C.5.3 | CC6.1, CC6.8 | CIS CSC 9 | 1.2, 6.2 | V-XXXXX | ISM-0261 | 7.3.1 |
| 2 | Firewall Rule Audit | AC-4, SC-7 | C.3.13, C.4.6 | CC6.1, CC6.6 | CIS CSC 9, 12 | 1.2, 1.3 | V-XXXXX | ISM-1416 | 7.1.1 |
| 3 | DLP Engine Configuration | SC-28, SI-4 | C.3.8, C.5.3 | CC6.1, CC6.7 | CIS CSC 3 | 3.4, 3.5 | V-XXXXX | ISM-0457 | 7.2.1 |
| 4 | SSL Inspection Coverage | SC-8, SI-4 | C.3.8, C.5.3 | CC6.1, CC6.7 | CIS CSC 9 | 4.1, 4.2 | V-XXXXX | ISM-0490 | 7.2.2 |
| 5 | Cloud Sandbox Analysis | SI-3, SI-4 | C.5.2, C.5.3 | CC6.8, CC7.1 | CIS CSC 8, 10 | 5.2 | V-XXXXX | ISM-1288 | 8.2.1 |
| 6 | Admin MFA Enforcement | IA-2, IA-5 | C.1.1, C.3.7 | CC6.1, CC6.2 | CIS CSC 5, 6 | 8.3, 8.4 | V-XXXXX | ISM-1504 | 6.2.1 |
| 7 | RBAC & Admin Role Audit | AC-2, AC-6 | C.1.1, C.1.4 | CC6.1, CC6.3 | CIS CSC 5, 6 | 7.1, 7.2 | V-XXXXX | ISM-1506 | 6.1.1 |
| 8 | Application Segmentation | SC-7, AC-4 | C.3.12, C.3.13 | CC6.1, CC6.6 | CIS CSC 12 | 1.2, 1.4 | V-XXXXX | ISM-1181 | 7.1.2 |
| 9 | Zero Trust Access Policies | AC-3, AC-4 | C.1.1, C.3.13 | CC6.1, CC6.3 | CIS CSC 6, 14 | 7.1, 7.2 | V-XXXXX | ISM-1416 | 6.1.2 |
| 10 | Posture Profile Enforcement | CM-6, SI-4 | C.2.3, C.5.3 | CC6.1, CC6.8 | CIS CSC 4, 10 | 5.2, 5.3 | V-XXXXX | ISM-1407 | 5.1.1 |
| 11 | App Connector Health & Coverage | SI-4, CM-8 | C.2.4, C.5.1 | CC6.1, CC7.1 | CIS CSC 1, 2 | 11.4 | V-XXXXX | ISM-1034 | 8.1.1 |
| 12 | IdP Integration & SAML Config | IA-2, IA-8 | C.1.1, C.3.7 | CC6.1, CC6.2 | CIS CSC 5, 16 | 8.3 | V-XXXXX | ISM-1504 | 6.2.2 |
| 13 | Session Timeout Configuration | AC-11, AC-12 | C.1.10, C.3.7 | CC6.1 | CIS CSC 4, 16 | 8.6 | V-XXXXX | ISM-0853 | 6.3.1 |
| 14 | Audit Logging Enabled | AU-2, AU-6 | C.3.1, C.3.3 | CC7.2, CC7.3 | CIS CSC 6, 8 | 10.1, 10.2 | V-XXXXX | ISM-0580 | 8.4.1 |
| 15 | Trusted Network Detection | AC-17, SC-7 | C.3.7, C.3.13 | CC6.1, CC6.6 | CIS CSC 12 | 1.2 | V-XXXXX | ISM-1416 | 7.1.3 |
| 16 | Bandwidth Control Policies | SC-7, SC-5 | C.3.13, C.4.6 | CC6.1 | CIS CSC 9 | 1.2 | V-XXXXX | ISM-1416 | 7.4.1 |
| 17 | Browser Isolation Policies | SC-7, SI-3 | C.5.2, C.5.3 | CC6.1, CC6.8 | CIS CSC 9 | 5.2, 6.2 | V-XXXXX | ISM-1288 | 8.2.2 |
| 18 | Location & GRE/VPN Configuration | SC-8, AC-17 | C.3.7, C.3.8 | CC6.1, CC6.6 | CIS CSC 12 | 4.1 | V-XXXXX | ISM-0490 | 7.1.4 |
| 19 | Cloud Application Control | SC-7, SI-4 | C.3.13, C.5.3 | CC6.1, CC6.8 | CIS CSC 2, 9 | 1.2, 6.2 | V-XXXXX | ISM-0261 | 7.3.2 |
| 20 | DNS Security Configuration | SC-7, SI-4 | C.3.13, C.5.3 | CC6.1, CC6.8 | CIS CSC 9 | 1.2 | V-XXXXX | ISM-1416 | 7.1.5 |
| 21 | Service Edge Deployment | SI-4, CM-8 | C.2.4, C.5.1 | CC6.1, CC7.1 | CIS CSC 1, 2 | 11.4 | V-XXXXX | ISM-1034 | 8.1.2 |
| 22 | Forwarding Policy Audit | AC-4, SC-7 | C.3.13, C.4.6 | CC6.1, CC6.6 | CIS CSC 9, 12 | 1.2, 1.3 | V-XXXXX | ISM-1416 | 7.1.6 |
| 23 | Emergency Access Configuration | AC-2, CP-2 | C.1.1, C.3.6 | CC6.1, A1.2 | CIS CSC 5, 16 | 8.6 | V-XXXXX | ISM-1610 | 6.4.1 |
| 24 | Certificate Management | SC-12, SC-17 | C.3.8, C.3.10 | CC6.1, CC6.7 | CIS CSC 3 | 4.1 | V-XXXXX | ISM-0490 | 7.2.3 |
| 25 | Security Policy Baseline | SI-3, SI-4 | C.5.2, C.5.3 | CC6.8, CC7.1 | CIS CSC 8, 10 | 5.2, 5.3 | V-XXXXX | ISM-1288 | 8.2.3 |

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

Sensitive fields and values: apiKey, password, clientSecret, authorization, cookie, token

Credential formats: ZIA API keys, ZIA administrator passwords, ZIA session cookies, ZPA OAuth client secrets and bearer tokens

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `zia-administration` | `id`, `loginName`, `role`, `adminScope`, `mfa`, `status` |
| `zia-policy` | `id`, `name`, `state`, `action`, `rank`, `order`, `destinations`, `locations` |
| `zpa-policy` | `id`, `name`, `enabled`, `operator`, `action`, `health`, `modifiedTime`, `expirationDate` |

## Export layout

Required paths:

- `QUICK_REFERENCE.md`
- `core_data/access_check.json`
- `core_data/zia_access_control.json`
- `core_data/zia_policy.json`
- `core_data/zpa.json`
- `analysis/findings.json`
- `analysis/summary.json`
- `analysis/zia_access_control.json`
- `analysis/zia_policy.json`
- `analysis/zpa.json`
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

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `QUICK_REFERENCE.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `core_data/access_check.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/zia_access_control.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/zia_policy.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/zpa.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/findings.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/summary.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/zia_access_control.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/zia_policy.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/zpa.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `compliance/executive_summary.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/unified_compliance_matrix.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/fedramp/fedramp_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cmmc/cmmc_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/soc2/soc2_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cis/cis_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/pci_dss/pci_dss_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/disa_stig/stig_compliance_checklist.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/irap/irap_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/ismap/ismap_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
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

Overwrite policy: Allocate a new Zscaler audit directory and numeric suffix without overwriting an existing directory or paired archive.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Create <allocated-directory>.zip beside the allocated Zscaler audit directory.
