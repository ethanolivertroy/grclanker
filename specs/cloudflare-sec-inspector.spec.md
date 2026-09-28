---
slug: "cloudflare-sec-inspector"
name: "Cloudflare Security Inspector"
vendor: "Cloudflare"
category: "edge-security"
language: "language-neutral"
status: "generated"
version: "1.0.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# Cloudflare Security Inspector

Portable contract for the shipped Cloudflare identity, zone-security, and traffic-control assessments.

## Purpose

Give security and compliance teams a read-only, repeatable view of Cloudflare identity, zone, edge, and Zero Trust controls without treating an unlicensed, denied, or unreadable feature as compliant.

## Design guidance

Prefer a scoped API token over a Global API Key. Select an account explicitly when more than one is visible. Preserve plan limitations, per-zone read failures, pagination state, and configured sampling caps as evidence.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Known runtime gaps

- Account context is explicit or discovered only when exactly one readable account is visible; ambiguous or unreadable account context keeps account checks manual.
- Zone findings aggregate per-zone judgments, and a proved failing zone has precedence over warnings while any unreadable sampled zone prevents pass.
- Every paged result retains seen, reported total, page count, and truncation; finding evidence arrays are presentation samples only.
- Feature and plan ambiguity is preserved as manual evidence where the API cannot distinguish an unlicensed feature from an empty configuration.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `cloudflare_check_access` | Validate read-only Cloudflare access across token verification, accounts, zones, zone settings, DNSSEC, rulesets, members, Zero Trust apps, and audit logs. | None | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `cloudflare_assess_identity` | Assess Cloudflare authentication method, token verification and scoping, API token expiration, member privilege concentration, Zero Trust Access coverage, and identity provider posture. | `CF-IAM-01`, `CF-IAM-02`, `CF-IAM-03`, `CF-IAM-04`, `CF-IAM-05`, `CF-IAM-06` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `cloudflare_assess_zone_security` | Assess Cloudflare zone security across WAF managed and custom rulesets, HTTP DDoS sensitivity, strict SSL, minimum TLS, HSTS, HTTPS enforcement, DNSSEC, Universal SSL certificates, Authenticated Origin Pulls, Browser Integrity Check, email obfuscation, security header transform rules, and DNS origin exposure. | `CF-ZONE-01`, `CF-ZONE-02`, `CF-ZONE-03`, `CF-ZONE-04`, `CF-ZONE-05`, `CF-ZONE-06`, `CF-ZONE-07`, `CF-ZONE-08`, `CF-ZONE-09`, `CF-ZONE-10`, `CF-ZONE-11`, `CF-ZONE-12`, `CF-ZONE-13`, `CF-ZONE-14`, `CF-ZONE-15` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `cloudflare_assess_traffic_controls` | Assess Cloudflare traffic and edge control posture across rate limiting rulesets, page rules, bot management, account audit logs, IP access rules, and Gateway policies. | `CF-TRF-01`, `CF-TRF-02`, `CF-TRF-03`, `CF-TRF-04`, `CF-TRF-05`, `CF-TRF-06` | A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte. |
| `cloudflare_export_audit_bundle` | Export a Cloudflare audit package with access checks, identity, zone security, and traffic-control findings, per-framework compliance reports, JSON analysis, raw core data, an errors log on partial failure, and a zip archive. | `CF-IAM-01`, `CF-IAM-02`, `CF-IAM-03`, `CF-IAM-04`, `CF-IAM-05`, `CF-IAM-06`, `CF-ZONE-01`, `CF-ZONE-02`, `CF-ZONE-03`, `CF-ZONE-04`, `CF-ZONE-05`, `CF-ZONE-06`, `CF-ZONE-07`, `CF-ZONE-08`, `CF-ZONE-09`, `CF-ZONE-10`, `CF-ZONE-11`, `CF-ZONE-12`, `CF-ZONE-13`, `CF-ZONE-14`, `CF-ZONE-15`, `CF-TRF-01`, `CF-TRF-02`, `CF-TRF-03`, `CF-TRF-04`, `CF-TRF-05`, `CF-TRF-06` | A text result plus output directory, paired archive path, file count, finding count, and collection-error count. |

### Parameters

#### `cloudflare_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `api_token` | string | no | Cloudflare API token. Defaults to CLOUDFLARE_API_TOKEN. |
| `api_key` | string | no | Legacy Cloudflare Global API Key. Defaults to CLOUDFLARE_API_KEY. |
| `email` | string | no | Cloudflare account email for Global API Key auth. Defaults to CLOUDFLARE_EMAIL. |
| `account_id` | string | no | Cloudflare account ID for account-scoped checks. Defaults to CLOUDFLARE_ACCOUNT_ID. |
| `base_url` | string | no | Cloudflare API base URL. Defaults to https://api.cloudflare.com/client/v4. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |

#### `cloudflare_assess_identity`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `api_token` | string | no | Cloudflare API token. Defaults to CLOUDFLARE_API_TOKEN. |
| `api_key` | string | no | Legacy Cloudflare Global API Key. Defaults to CLOUDFLARE_API_KEY. |
| `email` | string | no | Cloudflare account email for Global API Key auth. Defaults to CLOUDFLARE_EMAIL. |
| `account_id` | string | no | Cloudflare account ID for account-scoped checks. Defaults to CLOUDFLARE_ACCOUNT_ID. |
| `base_url` | string | no | Cloudflare API base URL. Defaults to https://api.cloudflare.com/client/v4. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `max_super_admins` | number | no | Maximum acceptable Super Administrator assignments before failing. Defaults to 2. |
| `member_limit` | number | no | Maximum account members to inspect. Defaults to 200. |
| `token_limit` | number | no | Maximum API tokens to inspect. Defaults to 200. |
| `zone_limit` | number | no | Maximum zones to sample. Defaults to 20. |

#### `cloudflare_assess_zone_security`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `api_token` | string | no | Cloudflare API token. Defaults to CLOUDFLARE_API_TOKEN. |
| `api_key` | string | no | Legacy Cloudflare Global API Key. Defaults to CLOUDFLARE_API_KEY. |
| `email` | string | no | Cloudflare account email for Global API Key auth. Defaults to CLOUDFLARE_EMAIL. |
| `account_id` | string | no | Cloudflare account ID for account-scoped checks. Defaults to CLOUDFLARE_ACCOUNT_ID. |
| `base_url` | string | no | Cloudflare API base URL. Defaults to https://api.cloudflare.com/client/v4. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `zone_limit` | number | no | Maximum zones to sample. Defaults to 20. |

#### `cloudflare_assess_traffic_controls`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `api_token` | string | no | Cloudflare API token. Defaults to CLOUDFLARE_API_TOKEN. |
| `api_key` | string | no | Legacy Cloudflare Global API Key. Defaults to CLOUDFLARE_API_KEY. |
| `email` | string | no | Cloudflare account email for Global API Key auth. Defaults to CLOUDFLARE_EMAIL. |
| `account_id` | string | no | Cloudflare account ID for account-scoped checks. Defaults to CLOUDFLARE_ACCOUNT_ID. |
| `base_url` | string | no | Cloudflare API base URL. Defaults to https://api.cloudflare.com/client/v4. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `zone_limit` | number | no | Maximum zones to sample. Defaults to 20. |
| `audit_limit` | number | no | Maximum audit log entries to inspect. Defaults to 200. |

#### `cloudflare_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `api_token` | string | no | Cloudflare API token. Defaults to CLOUDFLARE_API_TOKEN. |
| `api_key` | string | no | Legacy Cloudflare Global API Key. Defaults to CLOUDFLARE_API_KEY. |
| `email` | string | no | Cloudflare account email for Global API Key auth. Defaults to CLOUDFLARE_EMAIL. |
| `account_id` | string | no | Cloudflare account ID for account-scoped checks. Defaults to CLOUDFLARE_ACCOUNT_ID. |
| `base_url` | string | no | Cloudflare API base URL. Defaults to https://api.cloudflare.com/client/v4. |
| `timeout_seconds` | number | no | HTTP timeout in seconds. Defaults to 30. |
| `output_dir` | string | no | Output root. Defaults to ./export/cloudflare. |
| `max_super_admins` | number | no | Maximum acceptable Super Administrator assignments before failing. Defaults to 2. |
| `member_limit` | number | no | Maximum account members to inspect. Defaults to 200. |
| `token_limit` | number | no | Maximum API tokens to inspect. Defaults to 200. |
| `zone_limit` | number | no | Maximum zones to sample. Defaults to 20. |
| `audit_limit` | number | no | Maximum audit log entries to inspect. Defaults to 200. |


## Authentication

Supported modes:

- Cloudflare API token
- Global API key with account email

Credential precedence, highest first:

1. Explicit tool arguments
2. CLOUDFLARE_* environment variables

Environment variables: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_API_KEY`, `CLOUDFLARE_EMAIL`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_BASE_URL`, `CLOUDFLARE_TIMEOUT`

Configuration locations: (none)

Credential and deployment variants: Explicit account ID, Single visible account discovery, Custom same-origin API base URL

Configuration fields: None

Malformed configuration: Reject malformed or ambiguous configuration before any request; never echo credential values.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| oauth-scope | `Token, Account, Zone, DNS, SSL, WAF, Zero Trust, audit-log, and firewall read permissions required by each declared surface` | `token-and-account`, `members-and-tokens`, `zero-trust-identity`, `zones-and-settings`, `zone-rules-and-certificates`, `traffic-and-account-controls` |  |
| plan | `The account or zone plan must expose the assessed WAF, bot, Access, Gateway, audit-log, and certificate features` | `zero-trust-identity`, `zones-and-settings`, `zone-rules-and-certificates`, `traffic-and-account-controls` |  |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `token-and-account` | HTTP | `GET /user/tokens/verify and /accounts/{account_id}` | Cloudflare API v4 | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `status`, `expires_on`, `id`, `name`, `settings` | [Official documentation](https://developers.cloudflare.com/api/resources/) |
| `members-and-tokens` | HTTP | `GET /accounts/{account_id}/{members\|tokens}` | Cloudflare API v4 | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `status`, `roles`, `policies`, `expires_on`, `modified_on` | [Official documentation](https://developers.cloudflare.com/api/resources/) |
| `zero-trust-identity` | HTTP | `GET /accounts/{account_id}/access/{apps\|policies\|identity_providers}` | Cloudflare API v4 | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `type`, `decision`, `include`, `exclude`, `require` | [Official documentation](https://developers.cloudflare.com/api/resources/) |
| `zones-and-settings` | HTTP | `GET /zones and /zones/{zone_id}/settings` | Cloudflare API v4 | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `id`, `name`, `status`, `plan`, `value` | [Official documentation](https://developers.cloudflare.com/api/resources/) |
| `zone-rules-and-certificates` | HTTP | `GET /zones/{zone_id}/{rulesets\|dnssec\|ssl\|origin_tls_client_auth\|dns_records}` | Cloudflare API v4 | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `phase`, `kind`, `rules`, `status`, `enabled`, `expires_on`, `content`, `proxied` | [Official documentation](https://developers.cloudflare.com/api/resources/) |
| `traffic-and-account-controls` | HTTP | `GET /accounts/{account_id}/{audit_logs\|firewall/access_rules/rules\|gateway/rules}` | Cloudflare API v4 | N/A | read | The collector projects the response to the listed verdict fields before evidence export. | `action`, `when`, `mode`, `notes`, `modified_on`, `enabled`, `filters` | [Official documentation](https://developers.cloudflare.com/api/resources/) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `token-and-account` | client | Use the configured Cloudflare API v4 origin; never follow a server link to a different origin. | yes |
| `token-and-account` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `token-and-account` | response | A JSON object or list containing only the documented status, expires_on, id, name, settings members consumed by verdicts. | yes |
| `members-and-tokens` | client | Use the configured Cloudflare API v4 origin; never follow a server link to a different origin. | yes |
| `members-and-tokens` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `members-and-tokens` | response | A JSON object or list containing only the documented id, status, roles, policies, expires_on, modified_on members consumed by verdicts. | yes |
| `zero-trust-identity` | client | Use the configured Cloudflare API v4 origin; never follow a server link to a different origin. | yes |
| `zero-trust-identity` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `zero-trust-identity` | response | A JSON object or list containing only the documented id, name, type, decision, include, exclude, require members consumed by verdicts. | yes |
| `zones-and-settings` | client | Use the configured Cloudflare API v4 origin; never follow a server link to a different origin. | yes |
| `zones-and-settings` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `zones-and-settings` | response | A JSON object or list containing only the documented id, name, status, plan, value members consumed by verdicts. | yes |
| `zone-rules-and-certificates` | client | Use the configured Cloudflare API v4 origin; never follow a server link to a different origin. | yes |
| `zone-rules-and-certificates` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `zone-rules-and-certificates` | response | A JSON object or list containing only the documented phase, kind, rules, status, enabled, expires_on, content, proxied members consumed by verdicts. | yes |
| `traffic-and-account-controls` | client | Use the configured Cloudflare API v4 origin; never follow a server link to a different origin. | yes |
| `traffic-and-account-controls` | headers | Authorization appropriate to the selected authentication mode; Accept: application/json | yes |
| `traffic-and-account-controls` | response | A JSON object or list containing only the documented action, when, mode, notes, modified_on, enabled, filters members consumed by verdicts. | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `token-and-account`, `members-and-tokens`, `zero-trust-identity`, `zones-and-settings`, `zone-rules-and-certificates`, `traffic-and-account-controls` | `result_info.page`, `result_info.total_pages`, `result_info.total_count` | service default | caller limit | none | Completion requires reaching result_info.total_pages or total_count without a repeated or empty advancing page and remaining below every configured zone, member, token, or audit cap. | Reported final page; Reported total reached; Repeated page; Empty advancing page; Configured item cap |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| Cloudflare Security Inspector | Endpoint and account-plan specific | `Retry-After`, `Ratelimit`, `Ratelimit-Policy` | 429, 500, 502, 503, 504 | Honor bounded Retry-After and use bounded retries for transient responses; exhausted reads remain unreadable. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | WAF managed rulesets deployed | CF-ZONE-01 | Evaluate the ordered first-match rules for CF-ZONE-01 below. |
| 2 | WAF custom rules with blocking actions | CF-ZONE-06 | Evaluate the ordered first-match rules for CF-ZONE-06 below. |
| 3 | HTTP DDoS protection sensitivity | CF-ZONE-07 | Evaluate the ordered first-match rules for CF-ZONE-07 below. |
| 4 | Bot and automated traffic controls | CF-TRF-03 | Evaluate the ordered first-match rules for CF-TRF-03 below. |
| 5 | SSL mode Full (Strict) | CF-ZONE-02 | Evaluate the ordered first-match rules for CF-ZONE-02 below. |
| 6 | Minimum TLS version | CF-ZONE-03 | Evaluate the ordered first-match rules for CF-ZONE-03 below. |
| 7 | HSTS enforcement | CF-ZONE-04 | Evaluate the ordered first-match rules for CF-ZONE-04 below. |
| 8 | DNSSEC enabled | CF-ZONE-05 | Evaluate the ordered first-match rules for CF-ZONE-05 below. |
| 9 | Zero Trust Access app and policy coverage | CF-IAM-04 | Evaluate the ordered first-match rules for CF-IAM-04 below. |
| 10 | Zero Trust identity provider coverage | CF-IAM-05 | Evaluate the ordered first-match rules for CF-IAM-05 below. |
| 11 | Account audit log visibility | CF-TRF-04 | Evaluate the ordered first-match rules for CF-TRF-04 below. |
| 12 | Authentication method hygiene | CF-IAM-01 | Evaluate the ordered first-match rules for CF-IAM-01 below. |
| 13 | API token expiration | CF-IAM-02, CF-IAM-06 | Evaluate the ordered first-match rules for CF-IAM-02, CF-IAM-06 below. |
| 14 | Account member privilege concentration | CF-IAM-03 | Evaluate the ordered first-match rules for CF-IAM-03 below. |
| 15 | Page rule security regressions | CF-TRF-02 | Evaluate the ordered first-match rules for CF-TRF-02 below. |
| 16 | Rate limiting coverage | CF-TRF-01 | Evaluate the ordered first-match rules for CF-TRF-01 below. |
| 17 | IP access rules | CF-TRF-05 | Evaluate the ordered first-match rules for CF-TRF-05 below. |
| 18 | Authenticated Origin Pulls | CF-ZONE-11 | Evaluate the ordered first-match rules for CF-ZONE-11 below. |
| 19 | Browser Integrity Check | CF-ZONE-12 | Evaluate the ordered first-match rules for CF-ZONE-12 below. |
| 20 | Email Address Obfuscation | CF-ZONE-13 | Evaluate the ordered first-match rules for CF-ZONE-13 below. |
| 21 | Always Use HTTPS | CF-ZONE-08 | Evaluate the ordered first-match rules for CF-ZONE-08 below. |
| 22 | Automatic HTTPS Rewrites | CF-ZONE-09 | Evaluate the ordered first-match rules for CF-ZONE-09 below. |
| 23 | Security headers via transform rules | CF-ZONE-14 | Evaluate the ordered first-match rules for CF-ZONE-14 below. |
| 24 | Gateway SWG policies | CF-TRF-06 | Evaluate the ordered first-match rules for CF-TRF-06 below. |
| 25 | Universal SSL and certificate validity | CF-ZONE-10 | Evaluate the ordered first-match rules for CF-ZONE-10 below. |
| 27 | DNS record origin exposure | CF-ZONE-15 | Evaluate the ordered first-match rules for CF-ZONE-15 below. |

### Finding notes

These notes explain intent only. The ordered rule table is normative.

| Finding | Severity | Owning tool | Sources | Evidence fields | Pass note | Warn note | Fail note | Manual note |
|---|---|---|---|---|---|---|---|---|
| `CF-IAM-01` | high | `cloudflare_assess_identity` | `token-and-account` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Authentication method hygiene from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Authentication method hygiene from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Authentication method hygiene from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Authentication method hygiene is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-IAM-02` | high | `cloudflare_assess_identity` | `token-and-account` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Current token verification and scoping from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Current token verification and scoping from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Current token verification and scoping from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Current token verification and scoping is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-IAM-03` | medium | `cloudflare_assess_identity` | `members-and-tokens` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Account member privilege concentration from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Account member privilege concentration from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Account member privilege concentration from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Account member privilege concentration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-IAM-04` | high | `cloudflare_assess_identity` | `zero-trust-identity` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Zero Trust Access app and policy coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Zero Trust Access app and policy coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Zero Trust Access app and policy coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Zero Trust Access app and policy coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-IAM-05` | medium | `cloudflare_assess_identity` | `zero-trust-identity` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Zero Trust identity provider coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Zero Trust identity provider coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Zero Trust identity provider coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Zero Trust identity provider coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-IAM-06` | medium | `cloudflare_assess_identity` | `members-and-tokens` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate API token expiration from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate API token expiration from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate API token expiration from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for API token expiration is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-01` | high | `cloudflare_assess_zone_security` | `zones-and-settings`, `zone-rules-and-certificates` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate WAF managed rulesets deployed from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate WAF managed rulesets deployed from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate WAF managed rulesets deployed from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for WAF managed rulesets deployed is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-02` | high | `cloudflare_assess_zone_security` | `zones-and-settings` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate SSL mode Full (Strict) from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate SSL mode Full (Strict) from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate SSL mode Full (Strict) from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for SSL mode Full (Strict) is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-03` | medium | `cloudflare_assess_zone_security` | `zones-and-settings` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Minimum TLS version from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Minimum TLS version from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Minimum TLS version from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Minimum TLS version is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-04` | medium | `cloudflare_assess_zone_security` | `zones-and-settings` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate HSTS enforcement from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate HSTS enforcement from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate HSTS enforcement from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for HSTS enforcement is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-05` | medium | `cloudflare_assess_zone_security` | `zone-rules-and-certificates` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate DNSSEC enabled from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate DNSSEC enabled from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate DNSSEC enabled from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for DNSSEC enabled is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-06` | medium | `cloudflare_assess_zone_security` | `zone-rules-and-certificates` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate WAF custom rules with blocking actions from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate WAF custom rules with blocking actions from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate WAF custom rules with blocking actions from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for WAF custom rules with blocking actions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-07` | high | `cloudflare_assess_zone_security` | `zone-rules-and-certificates` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate HTTP DDoS protection sensitivity from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate HTTP DDoS protection sensitivity from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate HTTP DDoS protection sensitivity from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for HTTP DDoS protection sensitivity is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-08` | medium | `cloudflare_assess_zone_security` | `zones-and-settings` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Always Use HTTPS from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Always Use HTTPS from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Always Use HTTPS from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Always Use HTTPS is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-09` | low | `cloudflare_assess_zone_security` | `zones-and-settings` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Automatic HTTPS Rewrites from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Automatic HTTPS Rewrites from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Automatic HTTPS Rewrites from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Automatic HTTPS Rewrites is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-10` | medium | `cloudflare_assess_zone_security` | `zone-rules-and-certificates` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Universal SSL and certificate validity from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Universal SSL and certificate validity from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Universal SSL and certificate validity from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Universal SSL and certificate validity is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-11` | medium | `cloudflare_assess_zone_security` | `zone-rules-and-certificates` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Authenticated Origin Pulls from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Authenticated Origin Pulls from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Authenticated Origin Pulls from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Authenticated Origin Pulls is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-12` | low | `cloudflare_assess_zone_security` | `zones-and-settings` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Browser Integrity Check from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Browser Integrity Check from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Browser Integrity Check from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Browser Integrity Check is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-13` | low | `cloudflare_assess_zone_security` | `zones-and-settings` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Email Address Obfuscation from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Email Address Obfuscation from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Email Address Obfuscation from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Email Address Obfuscation is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-14` | medium | `cloudflare_assess_zone_security` | `zone-rules-and-certificates` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Security headers via transform rules from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Security headers via transform rules from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Security headers via transform rules from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Security headers via transform rules is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-ZONE-15` | low | `cloudflare_assess_zone_security` | `zone-rules-and-certificates` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate DNS record origin exposure from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate DNS record origin exposure from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate DNS record origin exposure from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for DNS record origin exposure is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-TRF-01` | medium | `cloudflare_assess_traffic_controls` | `zone-rules-and-certificates` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Rate limiting coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Rate limiting coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Rate limiting coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Rate limiting coverage is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-TRF-02` | medium | `cloudflare_assess_traffic_controls` | `zone-rules-and-certificates` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Page rule security regressions from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Page rule security regressions from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Page rule security regressions from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Page rule security regressions is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-TRF-03` | medium | `cloudflare_assess_traffic_controls` | `zones-and-settings` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Bot and automated traffic controls from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Bot and automated traffic controls from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Bot and automated traffic controls from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Bot and automated traffic controls is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-TRF-04` | high | `cloudflare_assess_traffic_controls` | `traffic-and-account-controls` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Account audit log visibility from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Account audit log visibility from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Account audit log visibility from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Account audit log visibility is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-TRF-05` | medium | `cloudflare_assess_traffic_controls` | `traffic-and-account-controls` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate IP access rules from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate IP access rules from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate IP access rules from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for IP access rules is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |
| `CF-TRF-06` | medium | `cloudflare_assess_traffic_controls` | `traffic-and-account-controls` | `evidence_readable`, `evidence_complete`, `inventory_count`, `violation_count`, `review_count` | Complete readable evidence satisfies the compliant branch of this derivation: Evaluate Gateway SWG policies from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Readable evidence satisfies a review branch, or an otherwise-compliant required source is partial: Evaluate Gateway SWG policies from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | Complete readable evidence satisfies the violation branch, which has first-match precedence: Evaluate Gateway SWG policies from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | The required evidence for Gateway SWG policies is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict. |

### Ordered decision rules

Rules are evaluated from lowest order number to highest. The first matching condition determines the finding status; later rules are not evaluated.

| Finding | Order | Outcome | First-match condition | Explanatory note |
|---|---|---|---|---|
| `CF-IAM-01` | 1 | manual | `cf_iam_01_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-IAM-01` | 2 | fail | `cf_iam_01_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-IAM-01` | 3 | manual | `cf_iam_01_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-IAM-01` | 4 | warn | `cf_iam_01_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-IAM-01` | 5 | pass | `cf_iam_01_branch_05_matches` equals true |  |
| `CF-IAM-01` | 6 | manual | `cf_iam_01_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-IAM-02` | 1 | manual | `cf_iam_02_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-IAM-02` | 2 | fail | `cf_iam_02_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-IAM-02` | 3 | manual | `cf_iam_02_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-IAM-02` | 4 | warn | `cf_iam_02_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-IAM-02` | 5 | pass | `cf_iam_02_branch_05_matches` equals true |  |
| `CF-IAM-02` | 6 | manual | `cf_iam_02_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-IAM-03` | 1 | manual | `cf_iam_03_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-IAM-03` | 2 | fail | `cf_iam_03_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-IAM-03` | 3 | manual | `cf_iam_03_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-IAM-03` | 4 | warn | `cf_iam_03_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-IAM-03` | 5 | pass | `cf_iam_03_branch_05_matches` equals true |  |
| `CF-IAM-03` | 6 | manual | `cf_iam_03_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-IAM-04` | 1 | manual | `cf_iam_04_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-IAM-04` | 2 | fail | `cf_iam_04_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-IAM-04` | 3 | manual | `cf_iam_04_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-IAM-04` | 4 | warn | `cf_iam_04_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-IAM-04` | 5 | pass | `cf_iam_04_branch_05_matches` equals true |  |
| `CF-IAM-04` | 6 | manual | `cf_iam_04_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-IAM-05` | 1 | manual | `cf_iam_05_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-IAM-05` | 2 | fail | `cf_iam_05_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-IAM-05` | 3 | fail | `cf_iam_05_branch_03_matches` equals true |  |
| `CF-IAM-05` | 4 | warn | `cf_iam_05_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-IAM-05` | 5 | pass | `cf_iam_05_branch_05_matches` equals true |  |
| `CF-IAM-05` | 6 | manual | `cf_iam_05_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-IAM-06` | 1 | manual | `cf_iam_06_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-IAM-06` | 2 | fail | `cf_iam_06_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-IAM-06` | 3 | manual | `cf_iam_06_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-IAM-06` | 4 | warn | `cf_iam_06_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-IAM-06` | 5 | pass | `cf_iam_06_branch_05_matches` equals true |  |
| `CF-IAM-06` | 6 | manual | `cf_iam_06_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-01` | 1 | manual | `cf_zone_01_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-01` | 2 | fail | `cf_zone_01_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-01` | 3 | manual | `cf_zone_01_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-01` | 4 | warn | `cf_zone_01_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-01` | 5 | pass | `cf_zone_01_branch_05_matches` equals true |  |
| `CF-ZONE-01` | 6 | manual | `cf_zone_01_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-02` | 1 | manual | `cf_zone_02_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-02` | 2 | fail | `cf_zone_02_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-02` | 3 | manual | `cf_zone_02_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-02` | 4 | warn | `cf_zone_02_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-02` | 5 | pass | `cf_zone_02_branch_05_matches` equals true |  |
| `CF-ZONE-02` | 6 | manual | `cf_zone_02_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-03` | 1 | manual | `cf_zone_03_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-03` | 2 | fail | `cf_zone_03_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-03` | 3 | manual | `cf_zone_03_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-03` | 4 | warn | `cf_zone_03_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-03` | 5 | pass | `cf_zone_03_branch_05_matches` equals true |  |
| `CF-ZONE-03` | 6 | manual | `cf_zone_03_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-04` | 1 | manual | `cf_zone_04_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-04` | 2 | fail | `cf_zone_04_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-04` | 3 | manual | `cf_zone_04_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-04` | 4 | warn | `cf_zone_04_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-04` | 5 | pass | `cf_zone_04_branch_05_matches` equals true |  |
| `CF-ZONE-04` | 6 | manual | `cf_zone_04_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-05` | 1 | manual | `cf_zone_05_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-05` | 2 | fail | `cf_zone_05_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-05` | 3 | manual | `cf_zone_05_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-05` | 4 | warn | `cf_zone_05_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-05` | 5 | pass | `cf_zone_05_branch_05_matches` equals true |  |
| `CF-ZONE-05` | 6 | manual | `cf_zone_05_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-06` | 1 | manual | `cf_zone_06_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-06` | 2 | fail | `cf_zone_06_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-06` | 3 | manual | `cf_zone_06_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-06` | 4 | warn | `cf_zone_06_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-06` | 5 | pass | `cf_zone_06_branch_05_matches` equals true |  |
| `CF-ZONE-06` | 6 | manual | `cf_zone_06_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-07` | 1 | manual | `cf_zone_07_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-07` | 2 | fail | `cf_zone_07_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-07` | 3 | manual | `cf_zone_07_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-07` | 4 | warn | `cf_zone_07_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-07` | 5 | pass | `cf_zone_07_branch_05_matches` equals true |  |
| `CF-ZONE-07` | 6 | manual | `cf_zone_07_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-08` | 1 | manual | `cf_zone_08_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-08` | 2 | fail | `cf_zone_08_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-08` | 3 | manual | `cf_zone_08_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-08` | 4 | warn | `cf_zone_08_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-08` | 5 | pass | `cf_zone_08_branch_05_matches` equals true |  |
| `CF-ZONE-08` | 6 | manual | `cf_zone_08_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-09` | 1 | manual | `cf_zone_09_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-09` | 2 | fail | `cf_zone_09_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-09` | 3 | manual | `cf_zone_09_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-09` | 4 | warn | `cf_zone_09_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-09` | 5 | pass | `cf_zone_09_branch_05_matches` equals true |  |
| `CF-ZONE-09` | 6 | manual | `cf_zone_09_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-10` | 1 | manual | `cf_zone_10_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-10` | 2 | fail | `cf_zone_10_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-10` | 3 | manual | `cf_zone_10_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-10` | 4 | warn | `cf_zone_10_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-10` | 5 | pass | `cf_zone_10_branch_05_matches` equals true |  |
| `CF-ZONE-10` | 6 | manual | `cf_zone_10_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-11` | 1 | manual | `cf_zone_11_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-11` | 2 | fail | `cf_zone_11_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-11` | 3 | manual | `cf_zone_11_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-11` | 4 | warn | `cf_zone_11_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-11` | 5 | pass | `cf_zone_11_branch_05_matches` equals true |  |
| `CF-ZONE-11` | 6 | manual | `cf_zone_11_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-12` | 1 | manual | `cf_zone_12_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-12` | 2 | fail | `cf_zone_12_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-12` | 3 | manual | `cf_zone_12_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-12` | 4 | warn | `cf_zone_12_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-12` | 5 | pass | `cf_zone_12_branch_05_matches` equals true |  |
| `CF-ZONE-12` | 6 | manual | `cf_zone_12_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-13` | 1 | manual | `cf_zone_13_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-13` | 2 | fail | `cf_zone_13_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-13` | 3 | manual | `cf_zone_13_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-13` | 4 | warn | `cf_zone_13_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-13` | 5 | pass | `cf_zone_13_branch_05_matches` equals true |  |
| `CF-ZONE-13` | 6 | manual | `cf_zone_13_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-14` | 1 | manual | `cf_zone_14_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-14` | 2 | fail | `cf_zone_14_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-14` | 3 | manual | `cf_zone_14_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-14` | 4 | warn | `cf_zone_14_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-14` | 5 | pass | `cf_zone_14_branch_05_matches` equals true |  |
| `CF-ZONE-14` | 6 | manual | `cf_zone_14_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-ZONE-15` | 1 | manual | `cf_zone_15_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-ZONE-15` | 2 | fail | `cf_zone_15_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-ZONE-15` | 3 | manual | `cf_zone_15_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-ZONE-15` | 4 | warn | `cf_zone_15_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-ZONE-15` | 5 | pass | `cf_zone_15_branch_05_matches` equals true |  |
| `CF-ZONE-15` | 6 | manual | `cf_zone_15_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-TRF-01` | 1 | manual | `cf_trf_01_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-TRF-01` | 2 | fail | `cf_trf_01_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-TRF-01` | 3 | manual | `cf_trf_01_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-TRF-01` | 4 | warn | `cf_trf_01_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-TRF-01` | 5 | pass | `cf_trf_01_branch_05_matches` equals true |  |
| `CF-TRF-01` | 6 | manual | `cf_trf_01_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-TRF-02` | 1 | manual | `cf_trf_02_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-TRF-02` | 2 | fail | `cf_trf_02_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-TRF-02` | 3 | manual | `cf_trf_02_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-TRF-02` | 4 | warn | `cf_trf_02_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-TRF-02` | 5 | pass | `cf_trf_02_branch_05_matches` equals true |  |
| `CF-TRF-02` | 6 | manual | `cf_trf_02_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-TRF-03` | 1 | manual | `cf_trf_03_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-TRF-03` | 2 | fail | `cf_trf_03_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-TRF-03` | 3 | manual | `cf_trf_03_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-TRF-03` | 4 | warn | `cf_trf_03_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-TRF-03` | 5 | pass | `cf_trf_03_branch_05_matches` equals true |  |
| `CF-TRF-03` | 6 | manual | `cf_trf_03_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-TRF-04` | 1 | manual | `cf_trf_04_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-TRF-04` | 2 | fail | `cf_trf_04_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-TRF-04` | 3 | manual | `cf_trf_04_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-TRF-04` | 4 | warn | `cf_trf_04_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-TRF-04` | 5 | pass | `cf_trf_04_branch_05_matches` equals true |  |
| `CF-TRF-04` | 6 | manual | `cf_trf_04_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-TRF-05` | 1 | manual | `cf_trf_05_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-TRF-05` | 2 | fail | `cf_trf_05_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-TRF-05` | 3 | pass | `cf_trf_05_branch_03_matches` equals true |  |
| `CF-TRF-05` | 4 | warn | `cf_trf_05_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-TRF-05` | 5 | pass | `cf_trf_05_branch_05_matches` equals true |  |
| `CF-TRF-05` | 6 | manual | `cf_trf_05_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |
| `CF-TRF-06` | 1 | manual | `cf_trf_06_branch_01_matches` equals true | Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass. |
| `CF-TRF-06` | 2 | fail | `cf_trf_06_branch_02_matches` equals true | A violation proved by readable evidence has precedence over partial companion inventories. |
| `CF-TRF-06` | 3 | manual | `cf_trf_06_branch_03_matches` equals true | This check's documented empty-inventory behavior requires manual confirmation. |
| `CF-TRF-06` | 4 | warn | `cf_trf_06_branch_04_matches` equals true | Incomplete source cardinality or an explicit review condition prevents pass. |
| `CF-TRF-06` | 5 | pass | `cf_trf_06_branch_05_matches` equals true |  |
| `CF-TRF-06` | 6 | manual | `cf_trf_06_branch_06_matches` equals true | Unknown or contradictory evidence requires manual review. |

### Derived decision facts

| Finding | Input | Portable derivation |
|---|---|---|
| `CF-IAM-01` | `cf_iam_01_branch_01_matches` | CF-IAM-01 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-IAM-01` | `cf_iam_01_branch_02_matches` | CF-IAM-01 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-IAM-01` | `cf_iam_01_branch_03_matches` | CF-IAM-01 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-IAM-01` | `cf_iam_01_branch_04_matches` | CF-IAM-01 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-IAM-01` | `cf_iam_01_branch_05_matches` | CF-IAM-01 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-IAM-01` | `cf_iam_01_branch_06_matches` | CF-IAM-01 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-IAM-02` | `cf_iam_02_branch_01_matches` | CF-IAM-02 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-IAM-02` | `cf_iam_02_branch_02_matches` | CF-IAM-02 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-IAM-02` | `cf_iam_02_branch_03_matches` | CF-IAM-02 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-IAM-02` | `cf_iam_02_branch_04_matches` | CF-IAM-02 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-IAM-02` | `cf_iam_02_branch_05_matches` | CF-IAM-02 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-IAM-02` | `cf_iam_02_branch_06_matches` | CF-IAM-02 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-IAM-03` | `cf_iam_03_branch_01_matches` | CF-IAM-03 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-IAM-03` | `cf_iam_03_branch_02_matches` | CF-IAM-03 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-IAM-03` | `cf_iam_03_branch_03_matches` | CF-IAM-03 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-IAM-03` | `cf_iam_03_branch_04_matches` | CF-IAM-03 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-IAM-03` | `cf_iam_03_branch_05_matches` | CF-IAM-03 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-IAM-03` | `cf_iam_03_branch_06_matches` | CF-IAM-03 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-IAM-04` | `cf_iam_04_branch_01_matches` | CF-IAM-04 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-IAM-04` | `cf_iam_04_branch_02_matches` | CF-IAM-04 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-IAM-04` | `cf_iam_04_branch_03_matches` | CF-IAM-04 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-IAM-04` | `cf_iam_04_branch_04_matches` | CF-IAM-04 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-IAM-04` | `cf_iam_04_branch_05_matches` | CF-IAM-04 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-IAM-04` | `cf_iam_04_branch_06_matches` | CF-IAM-04 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-IAM-05` | `cf_iam_05_branch_01_matches` | CF-IAM-05 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-IAM-05` | `cf_iam_05_branch_02_matches` | CF-IAM-05 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-IAM-05` | `cf_iam_05_branch_03_matches` | CF-IAM-05 ordered branch 3 (fail) is true exactly when its portable evidence condition matches. Computed as: all of (`inventory_count` equals 0; `evidence_complete` equals true). |
| `CF-IAM-05` | `cf_iam_05_branch_04_matches` | CF-IAM-05 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-IAM-05` | `cf_iam_05_branch_05_matches` | CF-IAM-05 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-IAM-05` | `cf_iam_05_branch_06_matches` | CF-IAM-05 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-IAM-06` | `cf_iam_06_branch_01_matches` | CF-IAM-06 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-IAM-06` | `cf_iam_06_branch_02_matches` | CF-IAM-06 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-IAM-06` | `cf_iam_06_branch_03_matches` | CF-IAM-06 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-IAM-06` | `cf_iam_06_branch_04_matches` | CF-IAM-06 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-IAM-06` | `cf_iam_06_branch_05_matches` | CF-IAM-06 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-IAM-06` | `cf_iam_06_branch_06_matches` | CF-IAM-06 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-01` | `cf_zone_01_branch_01_matches` | CF-ZONE-01 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-01` | `cf_zone_01_branch_02_matches` | CF-ZONE-01 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-01` | `cf_zone_01_branch_03_matches` | CF-ZONE-01 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-01` | `cf_zone_01_branch_04_matches` | CF-ZONE-01 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-01` | `cf_zone_01_branch_05_matches` | CF-ZONE-01 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-01` | `cf_zone_01_branch_06_matches` | CF-ZONE-01 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-02` | `cf_zone_02_branch_01_matches` | CF-ZONE-02 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-02` | `cf_zone_02_branch_02_matches` | CF-ZONE-02 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-02` | `cf_zone_02_branch_03_matches` | CF-ZONE-02 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-02` | `cf_zone_02_branch_04_matches` | CF-ZONE-02 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-02` | `cf_zone_02_branch_05_matches` | CF-ZONE-02 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-02` | `cf_zone_02_branch_06_matches` | CF-ZONE-02 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-03` | `cf_zone_03_branch_01_matches` | CF-ZONE-03 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-03` | `cf_zone_03_branch_02_matches` | CF-ZONE-03 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-03` | `cf_zone_03_branch_03_matches` | CF-ZONE-03 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-03` | `cf_zone_03_branch_04_matches` | CF-ZONE-03 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-03` | `cf_zone_03_branch_05_matches` | CF-ZONE-03 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-03` | `cf_zone_03_branch_06_matches` | CF-ZONE-03 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-04` | `cf_zone_04_branch_01_matches` | CF-ZONE-04 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-04` | `cf_zone_04_branch_02_matches` | CF-ZONE-04 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-04` | `cf_zone_04_branch_03_matches` | CF-ZONE-04 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-04` | `cf_zone_04_branch_04_matches` | CF-ZONE-04 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-04` | `cf_zone_04_branch_05_matches` | CF-ZONE-04 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-04` | `cf_zone_04_branch_06_matches` | CF-ZONE-04 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-05` | `cf_zone_05_branch_01_matches` | CF-ZONE-05 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-05` | `cf_zone_05_branch_02_matches` | CF-ZONE-05 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-05` | `cf_zone_05_branch_03_matches` | CF-ZONE-05 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-05` | `cf_zone_05_branch_04_matches` | CF-ZONE-05 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-05` | `cf_zone_05_branch_05_matches` | CF-ZONE-05 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-05` | `cf_zone_05_branch_06_matches` | CF-ZONE-05 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-06` | `cf_zone_06_branch_01_matches` | CF-ZONE-06 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-06` | `cf_zone_06_branch_02_matches` | CF-ZONE-06 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-06` | `cf_zone_06_branch_03_matches` | CF-ZONE-06 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-06` | `cf_zone_06_branch_04_matches` | CF-ZONE-06 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-06` | `cf_zone_06_branch_05_matches` | CF-ZONE-06 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-06` | `cf_zone_06_branch_06_matches` | CF-ZONE-06 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-07` | `cf_zone_07_branch_01_matches` | CF-ZONE-07 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-07` | `cf_zone_07_branch_02_matches` | CF-ZONE-07 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-07` | `cf_zone_07_branch_03_matches` | CF-ZONE-07 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-07` | `cf_zone_07_branch_04_matches` | CF-ZONE-07 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-07` | `cf_zone_07_branch_05_matches` | CF-ZONE-07 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-07` | `cf_zone_07_branch_06_matches` | CF-ZONE-07 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-08` | `cf_zone_08_branch_01_matches` | CF-ZONE-08 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-08` | `cf_zone_08_branch_02_matches` | CF-ZONE-08 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-08` | `cf_zone_08_branch_03_matches` | CF-ZONE-08 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-08` | `cf_zone_08_branch_04_matches` | CF-ZONE-08 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-08` | `cf_zone_08_branch_05_matches` | CF-ZONE-08 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-08` | `cf_zone_08_branch_06_matches` | CF-ZONE-08 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-09` | `cf_zone_09_branch_01_matches` | CF-ZONE-09 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-09` | `cf_zone_09_branch_02_matches` | CF-ZONE-09 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-09` | `cf_zone_09_branch_03_matches` | CF-ZONE-09 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-09` | `cf_zone_09_branch_04_matches` | CF-ZONE-09 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-09` | `cf_zone_09_branch_05_matches` | CF-ZONE-09 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-09` | `cf_zone_09_branch_06_matches` | CF-ZONE-09 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-10` | `cf_zone_10_branch_01_matches` | CF-ZONE-10 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-10` | `cf_zone_10_branch_02_matches` | CF-ZONE-10 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-10` | `cf_zone_10_branch_03_matches` | CF-ZONE-10 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-10` | `cf_zone_10_branch_04_matches` | CF-ZONE-10 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-10` | `cf_zone_10_branch_05_matches` | CF-ZONE-10 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-10` | `cf_zone_10_branch_06_matches` | CF-ZONE-10 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-11` | `cf_zone_11_branch_01_matches` | CF-ZONE-11 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-11` | `cf_zone_11_branch_02_matches` | CF-ZONE-11 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-11` | `cf_zone_11_branch_03_matches` | CF-ZONE-11 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-11` | `cf_zone_11_branch_04_matches` | CF-ZONE-11 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-11` | `cf_zone_11_branch_05_matches` | CF-ZONE-11 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-11` | `cf_zone_11_branch_06_matches` | CF-ZONE-11 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-12` | `cf_zone_12_branch_01_matches` | CF-ZONE-12 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-12` | `cf_zone_12_branch_02_matches` | CF-ZONE-12 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-12` | `cf_zone_12_branch_03_matches` | CF-ZONE-12 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-12` | `cf_zone_12_branch_04_matches` | CF-ZONE-12 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-12` | `cf_zone_12_branch_05_matches` | CF-ZONE-12 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-12` | `cf_zone_12_branch_06_matches` | CF-ZONE-12 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-13` | `cf_zone_13_branch_01_matches` | CF-ZONE-13 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-13` | `cf_zone_13_branch_02_matches` | CF-ZONE-13 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-13` | `cf_zone_13_branch_03_matches` | CF-ZONE-13 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-13` | `cf_zone_13_branch_04_matches` | CF-ZONE-13 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-13` | `cf_zone_13_branch_05_matches` | CF-ZONE-13 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-13` | `cf_zone_13_branch_06_matches` | CF-ZONE-13 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-14` | `cf_zone_14_branch_01_matches` | CF-ZONE-14 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-14` | `cf_zone_14_branch_02_matches` | CF-ZONE-14 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-14` | `cf_zone_14_branch_03_matches` | CF-ZONE-14 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-14` | `cf_zone_14_branch_04_matches` | CF-ZONE-14 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-14` | `cf_zone_14_branch_05_matches` | CF-ZONE-14 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-14` | `cf_zone_14_branch_06_matches` | CF-ZONE-14 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-ZONE-15` | `cf_zone_15_branch_01_matches` | CF-ZONE-15 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-ZONE-15` | `cf_zone_15_branch_02_matches` | CF-ZONE-15 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-ZONE-15` | `cf_zone_15_branch_03_matches` | CF-ZONE-15 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-ZONE-15` | `cf_zone_15_branch_04_matches` | CF-ZONE-15 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-ZONE-15` | `cf_zone_15_branch_05_matches` | CF-ZONE-15 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-ZONE-15` | `cf_zone_15_branch_06_matches` | CF-ZONE-15 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-TRF-01` | `cf_trf_01_branch_01_matches` | CF-TRF-01 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-TRF-01` | `cf_trf_01_branch_02_matches` | CF-TRF-01 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-TRF-01` | `cf_trf_01_branch_03_matches` | CF-TRF-01 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-TRF-01` | `cf_trf_01_branch_04_matches` | CF-TRF-01 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-TRF-01` | `cf_trf_01_branch_05_matches` | CF-TRF-01 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-TRF-01` | `cf_trf_01_branch_06_matches` | CF-TRF-01 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-TRF-02` | `cf_trf_02_branch_01_matches` | CF-TRF-02 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-TRF-02` | `cf_trf_02_branch_02_matches` | CF-TRF-02 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-TRF-02` | `cf_trf_02_branch_03_matches` | CF-TRF-02 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-TRF-02` | `cf_trf_02_branch_04_matches` | CF-TRF-02 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-TRF-02` | `cf_trf_02_branch_05_matches` | CF-TRF-02 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-TRF-02` | `cf_trf_02_branch_06_matches` | CF-TRF-02 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-TRF-03` | `cf_trf_03_branch_01_matches` | CF-TRF-03 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-TRF-03` | `cf_trf_03_branch_02_matches` | CF-TRF-03 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-TRF-03` | `cf_trf_03_branch_03_matches` | CF-TRF-03 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-TRF-03` | `cf_trf_03_branch_04_matches` | CF-TRF-03 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-TRF-03` | `cf_trf_03_branch_05_matches` | CF-TRF-03 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-TRF-03` | `cf_trf_03_branch_06_matches` | CF-TRF-03 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-TRF-04` | `cf_trf_04_branch_01_matches` | CF-TRF-04 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-TRF-04` | `cf_trf_04_branch_02_matches` | CF-TRF-04 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-TRF-04` | `cf_trf_04_branch_03_matches` | CF-TRF-04 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-TRF-04` | `cf_trf_04_branch_04_matches` | CF-TRF-04 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-TRF-04` | `cf_trf_04_branch_05_matches` | CF-TRF-04 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-TRF-04` | `cf_trf_04_branch_06_matches` | CF-TRF-04 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-TRF-05` | `cf_trf_05_branch_01_matches` | CF-TRF-05 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-TRF-05` | `cf_trf_05_branch_02_matches` | CF-TRF-05 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-TRF-05` | `cf_trf_05_branch_03_matches` | CF-TRF-05 ordered branch 3 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`inventory_count` equals 0; `evidence_complete` equals true). |
| `CF-TRF-05` | `cf_trf_05_branch_04_matches` | CF-TRF-05 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-TRF-05` | `cf_trf_05_branch_05_matches` | CF-TRF-05 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-TRF-05` | `cf_trf_05_branch_06_matches` | CF-TRF-05 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |
| `CF-TRF-06` | `cf_trf_06_branch_01_matches` | CF-TRF-06 ordered branch 1 (manual) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_readable` does not equal true; not (`evidence_readable` is present and non-null)). |
| `CF-TRF-06` | `cf_trf_06_branch_02_matches` | CF-TRF-06 ordered branch 2 (fail) is true exactly when its portable evidence condition matches. Computed as: `violation_count` is greater than 0. |
| `CF-TRF-06` | `cf_trf_06_branch_03_matches` | CF-TRF-06 ordered branch 3 (manual) is true exactly when its portable evidence condition matches. Computed as: `inventory_count` equals 0. |
| `CF-TRF-06` | `cf_trf_06_branch_04_matches` | CF-TRF-06 ordered branch 4 (warn) is true exactly when its portable evidence condition matches. Computed as: any of (`evidence_complete` does not equal true; `review_count` is greater than 0). |
| `CF-TRF-06` | `cf_trf_06_branch_05_matches` | CF-TRF-06 ordered branch 5 (pass) is true exactly when its portable evidence condition matches. Computed as: all of (`evidence_readable` equals true; `evidence_complete` equals true; `violation_count` equals 0; `review_count` equals 0). |
| `CF-TRF-06` | `cf_trf_06_branch_06_matches` | CF-TRF-06 ordered branch 6 (manual) is true exactly when its portable evidence condition matches. Computed as: always. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `CF-IAM-01` | `requiredEvidenceReadable` | true |
| `CF-IAM-01` | `requiredEvidenceComplete` | true |
| `CF-IAM-02` | `requiredEvidenceReadable` | true |
| `CF-IAM-02` | `requiredEvidenceComplete` | true |
| `CF-IAM-03` | `requiredEvidenceReadable` | true |
| `CF-IAM-03` | `requiredEvidenceComplete` | true |
| `CF-IAM-04` | `requiredEvidenceReadable` | true |
| `CF-IAM-04` | `requiredEvidenceComplete` | true |
| `CF-IAM-05` | `requiredEvidenceReadable` | true |
| `CF-IAM-05` | `requiredEvidenceComplete` | true |
| `CF-IAM-06` | `requiredEvidenceReadable` | true |
| `CF-IAM-06` | `requiredEvidenceComplete` | true |
| `CF-ZONE-01` | `requiredEvidenceReadable` | true |
| `CF-ZONE-01` | `requiredEvidenceComplete` | true |
| `CF-ZONE-02` | `requiredEvidenceReadable` | true |
| `CF-ZONE-02` | `requiredEvidenceComplete` | true |
| `CF-ZONE-03` | `requiredEvidenceReadable` | true |
| `CF-ZONE-03` | `requiredEvidenceComplete` | true |
| `CF-ZONE-04` | `requiredEvidenceReadable` | true |
| `CF-ZONE-04` | `requiredEvidenceComplete` | true |
| `CF-ZONE-05` | `requiredEvidenceReadable` | true |
| `CF-ZONE-05` | `requiredEvidenceComplete` | true |
| `CF-ZONE-06` | `requiredEvidenceReadable` | true |
| `CF-ZONE-06` | `requiredEvidenceComplete` | true |
| `CF-ZONE-07` | `requiredEvidenceReadable` | true |
| `CF-ZONE-07` | `requiredEvidenceComplete` | true |
| `CF-ZONE-08` | `requiredEvidenceReadable` | true |
| `CF-ZONE-08` | `requiredEvidenceComplete` | true |
| `CF-ZONE-09` | `requiredEvidenceReadable` | true |
| `CF-ZONE-09` | `requiredEvidenceComplete` | true |
| `CF-ZONE-10` | `requiredEvidenceReadable` | true |
| `CF-ZONE-10` | `requiredEvidenceComplete` | true |
| `CF-ZONE-11` | `requiredEvidenceReadable` | true |
| `CF-ZONE-11` | `requiredEvidenceComplete` | true |
| `CF-ZONE-12` | `requiredEvidenceReadable` | true |
| `CF-ZONE-12` | `requiredEvidenceComplete` | true |
| `CF-ZONE-13` | `requiredEvidenceReadable` | true |
| `CF-ZONE-13` | `requiredEvidenceComplete` | true |
| `CF-ZONE-14` | `requiredEvidenceReadable` | true |
| `CF-ZONE-14` | `requiredEvidenceComplete` | true |
| `CF-ZONE-15` | `requiredEvidenceReadable` | true |
| `CF-ZONE-15` | `requiredEvidenceComplete` | true |
| `CF-TRF-01` | `requiredEvidenceReadable` | true |
| `CF-TRF-01` | `requiredEvidenceComplete` | true |
| `CF-TRF-02` | `requiredEvidenceReadable` | true |
| `CF-TRF-02` | `requiredEvidenceComplete` | true |
| `CF-TRF-03` | `requiredEvidenceReadable` | true |
| `CF-TRF-03` | `requiredEvidenceComplete` | true |
| `CF-TRF-04` | `requiredEvidenceReadable` | true |
| `CF-TRF-04` | `requiredEvidenceComplete` | true |
| `CF-TRF-05` | `requiredEvidenceReadable` | true |
| `CF-TRF-05` | `requiredEvidenceComplete` | true |
| `CF-TRF-06` | `requiredEvidenceReadable` | true |
| `CF-TRF-06` | `requiredEvidenceComplete` | true |

### Illustrative criterion notes

Examples are explanatory, not normative. The ordered first-match conditions above are the executable contract.

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `CF-IAM-01` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Authentication method hygiene from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-IAM-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Authentication method hygiene from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-IAM-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-IAM-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-IAM-02` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Current token verification and scoping from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-IAM-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Current token verification and scoping from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-IAM-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-IAM-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-IAM-03` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Account member privilege concentration from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-IAM-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Account member privilege concentration from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-IAM-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-IAM-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-IAM-04` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Zero Trust Access app and policy coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-IAM-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Zero Trust Access app and policy coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-IAM-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-IAM-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-IAM-05` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Zero Trust identity provider coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-IAM-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Zero Trust identity provider coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-IAM-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-IAM-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-IAM-06` | compliant | All required source reads are complete and this derivation returns pass: Evaluate API token expiration from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-IAM-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate API token expiration from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-IAM-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-IAM-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-01` | compliant | All required source reads are complete and this derivation returns pass: Evaluate WAF managed rulesets deployed from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate WAF managed rulesets deployed from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-02` | compliant | All required source reads are complete and this derivation returns pass: Evaluate SSL mode Full (Strict) from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate SSL mode Full (Strict) from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-03` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Minimum TLS version from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Minimum TLS version from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-04` | compliant | All required source reads are complete and this derivation returns pass: Evaluate HSTS enforcement from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate HSTS enforcement from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-05` | compliant | All required source reads are complete and this derivation returns pass: Evaluate DNSSEC enabled from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate DNSSEC enabled from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-06` | compliant | All required source reads are complete and this derivation returns pass: Evaluate WAF custom rules with blocking actions from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate WAF custom rules with blocking actions from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-07` | compliant | All required source reads are complete and this derivation returns pass: Evaluate HTTP DDoS protection sensitivity from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-07` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate HTTP DDoS protection sensitivity from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-07` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-07` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-08` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Always Use HTTPS from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-08` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Always Use HTTPS from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-08` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-08` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-09` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Automatic HTTPS Rewrites from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-09` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Automatic HTTPS Rewrites from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-09` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-09` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-10` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Universal SSL and certificate validity from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-10` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Universal SSL and certificate validity from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-10` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-10` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-11` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Authenticated Origin Pulls from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-11` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Authenticated Origin Pulls from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-11` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-11` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-12` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Browser Integrity Check from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-12` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Browser Integrity Check from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-12` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-12` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-13` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Email Address Obfuscation from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-13` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Email Address Obfuscation from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-13` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-13` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-14` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Security headers via transform rules from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-14` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Security headers via transform rules from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-14` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-14` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-ZONE-15` | compliant | All required source reads are complete and this derivation returns pass: Evaluate DNS record origin exposure from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-ZONE-15` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate DNS record origin exposure from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-ZONE-15` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-ZONE-15` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-TRF-01` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Rate limiting coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-TRF-01` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Rate limiting coverage from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-TRF-01` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-TRF-01` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-TRF-02` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Page rule security regressions from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-TRF-02` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Page rule security regressions from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-TRF-02` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-TRF-02` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-TRF-03` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Bot and automated traffic controls from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-TRF-03` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Bot and automated traffic controls from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-TRF-03` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-TRF-03` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-TRF-04` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Account audit log visibility from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-TRF-04` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Account audit log visibility from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-TRF-04` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-TRF-04` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-TRF-05` | compliant | All required source reads are complete and this derivation returns pass: Evaluate IP access rules from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-TRF-05` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate IP access rules from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-TRF-05` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-TRF-05` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |
| `CF-TRF-06` | compliant | All required source reads are complete and this derivation returns pass: Evaluate Gateway SWG policies from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | pass | A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence. |
| `CF-TRF-06` | noncompliant | A complete source read satisfies the fail branch of this derivation: Evaluate Gateway SWG policies from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account. | fail | A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence. |
| `CF-TRF-06` | partial | At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists. | warn | Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime. |
| `CF-TRF-06` | unreadable | A required value is null, missing, denied, never requested, malformed, or unreadable. | manual | Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | WAF managed rulesets deployed | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.1 | 6.6 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 2 | WAF custom rules with blocking actions | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.2 | 6.6 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 3 | HTTP DDoS protection sensitivity | SC-5 | SC.L2-3.13.6 | CC6.6 | 9.3 | 6.5.10 | SRG-APP-000246 | ISM-1020 | CPS-11 |
| 4 | Bot and automated traffic controls | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.4 | 6.6 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 5 | SSL mode Full (Strict) | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.1 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 6 | Minimum TLS version | SC-8(1) | SC.L2-3.13.8 | CC6.7 | 3.2 | 4.1 | SRG-APP-000219 | ISM-1369 | CPS-09 |
| 7 | HSTS enforcement | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.3 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 8 | DNSSEC enabled | SC-20 | SC.L2-3.13.15 | CC6.7 | 3.4 | - | SRG-APP-000516 | ISM-1183 | CPS-09 |
| 9 | Zero Trust Access app and policy coverage | AC-3 | AC.L2-3.1.2 | CC6.1 | 1.1 | 7.2.1 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 10 | Zero Trust identity provider coverage | IA-2 | AC.L2-3.1.1 | CC6.1 | 1.2 | 8.3.1 | SRG-APP-000148 | ISM-1557 | CPS-04 |
| 11 | Account audit log visibility | AU-2 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.2.1 | SRG-APP-000089 | ISM-0580 | CPS-10 |
| 12 | Authentication method hygiene | AC-6 | AC.L2-3.1.5 | CC6.3 | 5.1 | 7.2.1 | SRG-APP-000340 | ISM-0432 | CPS-07 |
| 13 | API token expiration | IA-5(1) | IA.L2-3.5.8 | CC6.1 | 5.2 | 8.6.3 | SRG-APP-000175 | ISM-1590 | CPS-05 |
| 14 | Account member privilege concentration | AC-2 | AC.L2-3.1.1 | CC6.3 | 6.1 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 15 | Page rule security regressions | CM-6 | CM.L2-3.4.2 | CC8.1 | 10.1 | 2.2 | SRG-APP-000386 | ISM-0380 | CPS-12 |
| 16 | Rate limiting coverage | SC-5 | SC.L2-3.13.6 | CC6.6 | 9.5 | 6.5.10 | SRG-APP-000246 | ISM-1020 | CPS-11 |
| 17 | IP access rules | SC-7(5) | SC.L2-3.13.1 | CC6.6 | 9.6 | 1.3.2 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 18 | Authenticated Origin Pulls | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.5 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 19 | Browser Integrity Check | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.7 | 6.6 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 20 | Email Address Obfuscation | SC-7 | SC.L2-3.13.1 | CC6.7 | 3.6 | - | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 21 | Always Use HTTPS | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.7 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 22 | Automatic HTTPS Rewrites | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.8 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 23 | Security headers via transform rules | SC-7 | SC.L2-3.13.1 | CC6.7 | 9.8 | 6.5.10 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 24 | Gateway SWG policies | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.9 | 1.3.1 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 25 | Universal SSL and certificate validity | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.9 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 27 | DNS record origin exposure | - | - | - | - | - | - | - | - |

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

Sensitive fields and values: api_token, api_key, authorization, x-auth-key, x-auth-email, cookie

Credential formats: Cloudflare API tokens, Cloudflare Global API keys, session cookies

Reviewed benign exceptions: Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field.

Integration-specific rules:

- Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.
- Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.
- Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `token-and-account` | `status`, `expires_on`, `id`, `name`, `settings` |
| `members-and-tokens` | `id`, `status`, `roles`, `policies`, `expires_on`, `modified_on` |
| `zero-trust-identity` | `id`, `name`, `type`, `decision`, `include`, `exclude`, `require` |
| `zones-and-settings` | `id`, `name`, `status`, `plan`, `value` |
| `zone-rules-and-certificates` | `phase`, `kind`, `rules`, `status`, `enabled`, `expires_on`, `content`, `proxied` |
| `traffic-and-account-controls` | `action`, `when`, `mode`, `notes`, `modified_on`, `enabled`, `filters` |

## Export layout

Required paths:

- `README.md`
- `QUICK_REFERENCE.md`
- `metadata.json`
- `core_data/access.json`
- `core_data/accounts.json`
- `core_data/zones.json`
- `analysis/identity.json`
- `analysis/zone-security.json`
- `analysis/traffic-controls.json`
- `analysis/findings.json`
- `compliance/executive_summary.md`
- `compliance/unified_compliance_matrix.md`
- `compliance/fedramp/fedramp_compliance_report.md`
- `compliance/cmmc/cmmc_compliance_report.md`
- `compliance/soc2/soc2_compliance_report.md`
- `compliance/cis/cis_compliance_report.md`
- `compliance/pci_dss/pci_dss_compliance_report.md`
- `compliance/disa_stig/disa_stig_compliance_report.md`
- `compliance/irap/irap_compliance_report.md`
- `compliance/ismap/ismap_compliance_report.md`

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `README.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `QUICK_REFERENCE.md` | markdown | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 text. |
| `metadata.json` | json | Always. | The runtime-generated bundle metadata or operator guidance. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/access.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/accounts.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `core_data/zones.json` | json | Always. | The projected runtime dataset or its explicit unavailable marker. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/identity.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/zone-security.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/traffic-controls.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `analysis/findings.json` | json | Always. | Runtime assessment or finding records. | UTF-8 JSON with two-space indentation and a trailing newline. |
| `compliance/executive_summary.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/unified_compliance_matrix.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/fedramp/fedramp_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cmmc/cmmc_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/soc2/soc2_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/cis/cis_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/pci_dss/pci_dss_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
| `compliance/disa_stig/disa_stig_compliance_report.md` | markdown | Always. | The runtime-generated human-readable compliance report. | UTF-8 text. |
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

Overwrite policy: Allocate a new Cloudflare audit directory and numeric suffix without overwriting an existing directory or paired archive.

Path safety: Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.

Archive pairing: Create <allocated-directory>.zip beside the allocated Cloudflare audit directory.
