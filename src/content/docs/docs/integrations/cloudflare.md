---
title: Cloudflare
description: Read-only Cloudflare security inspector covering WAF and DDoS rulesets, TLS, DNS, Zero Trust, API tokens, and traffic controls with evidence bundles.
---

The Cloudflare integration inspects accounts and zones through the Cloudflare v4 API and renders findings mapped to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP. Every request path, ruleset phase, zone setting id, and response field the tools read is traceable to a page on [developers.cloudflare.com/api](https://developers.cloudflare.com/api/).

## What it inspects

- Identity: credential type, current token verification and scoping, API token expiration, member privilege concentration, Zero Trust Access applications and policies, identity providers
- Zone security: WAF managed and custom rulesets, HTTP DDoS sensitivity overrides, SSL mode, minimum TLS, HSTS, Always Use HTTPS, Automatic HTTPS Rewrites, DNSSEC, Universal SSL and certificate packs, Authenticated Origin Pulls, Browser Integrity Check, Email Address Obfuscation, security header transform rules, unproxied DNS records
- Traffic controls: rate limiting rulesets, page rules, bot management, account audit logs, IP access rules, Gateway policies

## Setup and authentication

Use a scoped API token (`CLOUDFLARE_API_TOKEN`). The legacy Global API Key pair (`CLOUDFLARE_EMAIL` + `CLOUDFLARE_API_KEY`) is accepted but fails finding CF-IAM-01. Set `CLOUDFLARE_ACCOUNT_ID` (or pass `account_id`) when the token can see more than one account; account-scoped findings stay manual until the account is unambiguous. Zone checks sample up to `zone_limit` zones (default 20) from `GET /zones`, filtered by `account.id` when an account is configured.

| Surface | Token permission (read) |
|---------|-------------------------|
| Accounts, members, audit logs | Account Settings: Read |
| Zones and zone settings | Zone: Read, Zone Settings: Read |
| Rulesets (WAF, DDoS, rate limiting, transform rules) | Zone WAF: Read, Transform Rules: Read |
| DNS records and DNSSEC | DNS: Read |
| Certificate packs, Universal SSL, Authenticated Origin Pulls (zone-level and per-hostname) | SSL and Certificates: Read |
| Zone subscription (names the plan on manual bot findings) | Billing: Read |
| Bot management | Bot Management: Read |
| Page rules | Page Rules: Read |
| IP access rules | Account Firewall Access Rules: Read |
| Access apps, policies, identity providers | Access: Apps and Policies: Read, Access: Organizations, Identity Providers, and Groups: Read |
| Gateway rules and Zero Trust account (`gateway_tag`) | Zero Trust: Read |
| API tokens | User API Tokens: Read, Account API Tokens: Read |

## Tools

| Tool | Purpose |
|------|---------|
| `cloudflare_check_access` | Probe token verification, accounts, zones, zone settings, DNSSEC, rulesets, members, Access apps, and audit logs. A failed probe carries `count: null`, the observed `http_status`, and the scrubbed error. The zone-scoped probes (zone settings, DNSSEC, rulesets) are `not_attempted` when `/zones` itself could not be read, carrying the `/zones` status and error (`Not attempted: /zones could not be read (...)`), counted outside the readable tally, and turning the check `limited`; they are `not_configured` only when `/zones` was read and returned no zone |
| `cloudflare_assess_identity` | CF-IAM-01 through CF-IAM-06 |
| `cloudflare_assess_zone_security` | CF-ZONE-01 through CF-ZONE-15 |
| `cloudflare_assess_traffic_controls` | CF-TRF-01 through CF-TRF-06 |
| `cloudflare_export_audit_bundle` | Run everything and write `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log` on partial failure, and a zip named after the allocated directory |

The bundle never carries credentials or contact details. `core_data/accounts.json` and `core_data/zones.json` are projected before they are written: accounts keep `id`, `name`, `type`, `created_on`, and the governance settings (`enforce_twofactor`, `api_access_enabled`, `access_approval_expiry`, `use_account_custom_ns_by_default`, plus an `abuse_contact_email_configured` boolean in place of the address); zones keep identity, status, name server, `plan`, `owner` (`id`, `type`), and `account` (`id`, `name`) fields. Token lists are never written; finding evidence records token names or ids, counts, and per-source seen and total figures only. Error text keeps the structured Cloudflare error messages and describes any non-JSON error body by content type and length instead of echoing it; a `SyntaxError` reaching the error sink from any path is recorded by name only (`SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body`), because V8's parse message quotes a snippet of the rejected text. The scrub follows one boundary. A value inside any carrier (an `Authorization`, `Cookie`, `Set-Cookie`, `X-Auth-Key`, `X-Auth-Email`, or `x-api-key` header, a `Bearer`, `Basic`, `Token`, or `ApiKey` scheme, a session or cookie assignment, a URL's userinfo or a query pair, a key-value pair whose key names a credential) is removed whatever its shape. A key names a credential when it is a credential word (`password`, `token`, `skey`), sets one off with `_`, `-`, or `.` (`DB_PASSWORD`, `AZURE_CLIENT_SECRET`, `x-api-key`), or is a lowerCamelCase or lowercase compound ending in one (`accessToken`), so `password=letmein`, `DB_PASSWORD=Sunshine`, and `AZURE_CLIENT_SECRET: abc12` lose their values unquoted as well as quoted, whatever the value's length or shape; a PascalCase error code that merely ends in the word (`InvalidAuthenticationToken: Access token has expired`) is prose and stays, and an identifier-named key (`AWS_ACCESS_KEY_ID`, `AZURE_TENANT_ID`, `CLOUDFLARE_EMAIL`, `AAP_USERNAME`) keeps its value unless the value's own shape removes it (an `AKIA` access key id goes, a tenant UUID stays). A quoted header or pair value (`Authorization: Bearer "value"`, `X-Auth-Key: "value"`, `Cookie: sid='value'`, `X-Api-Key: "value"`, with or without spaces, single or double quotes, plain or JSON-escaped) is removed whole between its quotes, so a short or name-shaped value never survives inside quotes as prose; a `Cookie`, `Set-Cookie`, `X-Auth-Key`, or `X-Auth-Email` value is free form and follows the compound-line rule: a value that is itself quoted ends at its closing quote (a closed value holding `; Name:` is one value and the quotes stay around the marker), and an unquoted value, or a quoted one that is never closed, ends at the `;` or `,` that introduces the next `Name:` header token on the line or at the end of the line, so a following header (`Content-Type: "application/json"`, `Date: Mon, 22 Sep 2026 12:30:00 GMT`) keeps its name and value and a following credential header gets its own carrier treatment (`Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"`). A quoted value that names no credential (`Content-Type: "application/json"`) stays. The configured API token or API key is removed whatever their shape and in their JSON-escaped, URL-encoded, base64, and base64url forms. A bare run of 16 or more characters shaped like a token (base64 symbols, digits scattered through letters, camelCase pieces of one or two letters, hex digests, AWS key ids, JWTs, PEM blocks) is removed. A bare value shaped like a name (hyphen- or underscore-joined words with at most one digit group each, such as `prod-us-east-2026`, uppercase codes, UUIDs, camelCase identifiers such as `GetAccessKeyLastUsed`) stays, because in prose it is indistinguishable from a resource name; opaque identifiers whose shape is a token's are therefore removed from error text and travel in structured fields (`endpoint`, `status`, `http_status`). The tools read no configuration file: every setting comes from tool arguments and environment variables. Every fixed-text message the integration emits (the parse and non-JSON notes, the `not attempted` and `Not attempted` wordings, the manual-review, partial-inventory, and zone-plan prose) is held to the scrub by a test and survives it unchanged.

## Status semantics

- `pass`: every sampled item met the control using documented fields
- `warn`: partially met, or the inventory was partial (the summary reports seen and total counts)
- `fail`: at least one sampled item violates the control
- `manual`: the API could not prove the control (401/403, plan not present, empty inventory that cannot be judged, or no automatable signal); the summary names the endpoint, the missing permission, and the evidence to collect

A 401, 403, or errored read never produces `pass`. That holds for every inventory a finding reads, not only its primary one: CF-IAM-04 is manual when `/accounts/{account_id}/access/policies` cannot be read even though the application list was (a bypass decision can live in a reusable policy), CF-IAM-06 is warn when only one of `/user/tokens` and `/accounts/{account_id}/tokens` is readable, with its counts scoped to "the N readable tokens (<source>)" and the denied source named as the reason for the cap rather than folded into the tally as zero (its `sources` entry carries `seen`, `total`, and `truncated` as `null` beside the `http_status` and error), and CF-TRF-06 is manual when zero Gateway rules exist and `/accounts/{account_id}/gateway` cannot be read; each summary names the endpoint and the permission to grant. Items without dates (`expires_on`, `last_used_on`, certificate `expires_on`, `modified_on`) are never counted valid or fresh.

A truncated listing never produces `pass` either. Page-numbered listings stop at their item cap or when `result_info.total_count` exceeds the collected items, cursor listings (`/zones/{zone_id}/rulesets`) stop at their cap, at a 100-page budget, at a cursor that repeats, or at an empty page that still carries a cursor, and a 404 that arrives after items were collected keeps them; every one of those exits reports `truncated` with the total when the API supplied one, and the dependent finding is capped at warn with `Partial <inventory> inventory: <seen> seen of <total>` in its summary. CF-IAM-04 applies that to both the application list and the reusable policy list.

## Control coverage

| Spec | Control | Tool | Finding | Automated signal |
|------|---------|------|---------|------------------|
| 1 | WAF managed rules | zone_security | CF-ZONE-01 | enabled `execute` rule in `http_request_firewall_managed`, `overrides.enabled` not false |
| 2 | WAF custom rules | zone_security | CF-ZONE-06 | enabled block/challenge rules in `http_request_firewall_custom` |
| 3 | DDoS protection | zone_security | CF-ZONE-07 | `ddos_l7` override `sensitivity_level`; `eoff` fails, `low` warns; with no override, a `kind: managed` `phase: ddos_l7` ruleset in the zone ruleset list passes at default sensitivity, otherwise manual |
| 4 | Bot management | traffic_controls | CF-TRF-03 | `fight_mode`, `sbfm_definitely_automated`; Enterprise Bot Management is manual and names the plan from `/subscription` `rate_plan.public_name` |
| 5 | SSL Full (Strict) | zone_security | CF-ZONE-02 | setting `ssl` = `strict` |
| 6 | Minimum TLS | zone_security | CF-ZONE-03 | setting `min_tls_version` in 1.2 or 1.3 |
| 7 | HSTS | zone_security | CF-ZONE-04 | `security_header.strict_transport_security` enabled, `max_age` >= 15552000, `include_subdomains`, `preload` |
| 8 | DNSSEC | zone_security | CF-ZONE-05 | `/dnssec` `status` = `active` |
| 9 | Access policies | identity | CF-IAM-04 | apps carry policies, no `decision: bypass` |
| 10 | Identity providers | identity | CF-IAM-05 | at least one non `onetimepin` provider |
| 11 | Audit logging | traffic_controls | CF-TRF-04 | events in the last 30 days from `/audit_logs`; retention is manual |
| 12 | Token scoping | identity | CF-IAM-01, CF-IAM-02 | auth method; `/user/tokens/verify` `status`, token `policies[].permission_groups` |
| 13 | Token expiration | identity | CF-IAM-06 | active tokens without `expires_on` fail; manual when no token source is readable, with every token count `null`; warn with counts scoped to the readable source when `/user/tokens` or `/accounts/{account_id}/tokens` is denied or truncated |
| 14 | Member roles | identity | CF-IAM-03 | Super Administrator role count, `two_factor_authentication_enabled` |
| 15 | Page rules | traffic_controls | CF-TRF-02 | rules requested with `status=active`; `disable_security`, `security_level` essentially_off, `ssl` off/flexible, cache_everything on sensitive paths fail |
| 16 | Rate limiting | traffic_controls | CF-TRF-01 | enabled rules with `ratelimit` in `http_ratelimit`; none fails; legacy `/rate_limits` is read only when the entry point is unreadable and caps at warn |
| 17 | IP access rules | traffic_controls | CF-TRF-05 | `mode`, `notes`, `modified_on` staleness over 365 days |
| 18 | Authenticated Origin Pulls | zone_security | CF-ZONE-11 | zone-level `/origin_tls_client_auth/settings` `enabled` or setting `tls_client_auth`, plus per-hostname associations (`enabled`, `status`, `created_at`, `updated_at`); disabled, non-active, undated, or truncated associations cap at warn |
| 19 | Browser Integrity Check | zone_security | CF-ZONE-12 | setting `browser_check` = `on` |
| 20 | Email obfuscation | zone_security | CF-ZONE-13 | setting `email_obfuscation` = `on` |
| 21 | Always Use HTTPS | zone_security | CF-ZONE-08 | setting `always_use_https` = `on` |
| 22 | Automatic HTTPS Rewrites | zone_security | CF-ZONE-09 | setting `automatic_https_rewrites` = `on` |
| 23 | Security headers | zone_security | CF-ZONE-14 | `rewrite` rules in `http_response_headers_transform` setting CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| 24 | Gateway policies | traffic_controls | CF-TRF-06 | enabled block/isolate rules with `dns` or `http` filters; no rules fails when `/accounts/{account_id}/gateway` returns a `gateway_tag`, otherwise manual (plan) |
| 25 | Universal SSL | zone_security | CF-ZONE-10 | `/ssl/universal/settings` `enabled`, certificate pack `status` active, certificate `expires_on` |
| extra | DNS origin exposure | zone_security | CF-ZONE-15 | unproxied A/AAAA/CNAME records from `/dns_records` |

## Endpoints

| Endpoint | Reference |
|----------|-----------|
| `GET /accounts` | [List Accounts](https://developers.cloudflare.com/api/resources/accounts/methods/list/) |
| `GET /zones` | [List Zones](https://developers.cloudflare.com/api/resources/zones/methods/list/) |
| `GET /zones/{zone_id}/settings/{setting_id}` | [Get zone setting](https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/get/) (the get-all form is deprecated and not used) |
| `GET /zones/{zone_id}/rulesets` | [List zone rulesets](https://developers.cloudflare.com/api/resources/rulesets/methods/list/) (cursor pagination) |
| `GET /zones/{zone_id}/rulesets/phases/{phase}/entrypoint` | [Get a zone entry point ruleset](https://developers.cloudflare.com/api/resources/rulesets/subresources/phases/methods/get/) |
| `GET /zones/{zone_id}/dns_records` | [List DNS Records](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/) |
| `GET /zones/{zone_id}/dnssec` | [DNSSEC Details](https://developers.cloudflare.com/api/resources/dns/subresources/dnssec/methods/get/) |
| `GET /zones/{zone_id}/ssl/certificate_packs?status=all` | [List Certificate Packs](https://developers.cloudflare.com/api/resources/ssl/subresources/certificate_packs/methods/list/) |
| `GET /zones/{zone_id}/ssl/universal/settings` | [Universal SSL Settings Details](https://developers.cloudflare.com/api/resources/ssl/subresources/universal/subresources/settings/methods/get/) |
| `GET /zones/{zone_id}/origin_tls_client_auth/settings` | [Get Enablement Setting for Zone](https://developers.cloudflare.com/api/resources/origin_tls_client_auth/subresources/settings/methods/get/) |
| `GET /zones/{zone_id}/origin_tls_client_auth/hostnames?status=all&per_page=1000` | List Hostname Associations, OpenAPI operation `per-hostname-authenticated-origin-pull-list-hostname-associations` in [cloudflare/api-schemas openapi.json](https://github.com/cloudflare/api-schemas/blob/main/openapi.json); the rendered site only publishes the [per-hostname get page](https://developers.cloudflare.com/api/resources/origin_tls_client_auth/subresources/hostnames/methods/get/) |
| `GET /zones/{zone_id}/subscription` | [Zone Subscription Details](https://developers.cloudflare.com/api/resources/zones/subresources/subscriptions/methods/get/) (only when the bot finding is manual) |
| `GET /zones/{zone_id}/bot_management` | [Get Zone Bot Management Config](https://developers.cloudflare.com/api/resources/bot_management/methods/get/) |
| `GET /zones/{zone_id}/rate_limits` | [List rate limits](https://developers.cloudflare.com/api/resources/rate_limits/methods/list/) (deprecated; read only when the `http_ratelimit` entry point is unreadable, evidence only, capped at warn) |
| `GET /zones/{zone_id}/pagerules?status=active` | [List Page Rules](https://developers.cloudflare.com/api/resources/page_rules/methods/list/) (no pagination; `status` defaults to `disabled`, so active is requested explicitly) |
| `GET /zones/{zone_id}/firewall/rules` | [List firewall rules](https://developers.cloudflare.com/api/resources/firewall/subresources/rules/methods/list/) (deprecated, fallback evidence only) |
| `GET /accounts/{account_id}/access/apps` | [List Access applications](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/) |
| `GET /accounts/{account_id}/access/policies` | [List Access reusable policies](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/policies/methods/list/) |
| `GET /accounts/{account_id}/access/identity_providers` | [List Access identity providers](https://developers.cloudflare.com/api/resources/zero_trust/subresources/identity_providers/methods/list/) |
| `GET /accounts/{account_id}/gateway/rules` | [List Zero Trust Gateway rules](https://developers.cloudflare.com/api/resources/zero_trust/subresources/gateway/subresources/rules/methods/list/) (no pagination) |
| `GET /accounts/{account_id}/gateway` | [Get Zero Trust account information](https://developers.cloudflare.com/api/resources/zero_trust/subresources/gateway/methods/list/) (`gateway_tag` proves Gateway is provisioned) |
| `GET /accounts/{account_id}/audit_logs` | [Get account audit logs](https://developers.cloudflare.com/api/resources/audit_logs/methods/list/) |
| `GET /accounts/{account_id}/members` | [List Members](https://developers.cloudflare.com/api/resources/accounts/subresources/members/methods/list/) |
| `GET /accounts/{account_id}/firewall/access_rules/rules` | [List IP Access rules](https://developers.cloudflare.com/api/resources/firewall/subresources/access_rules/methods/list/) |
| `GET /accounts/{account_id}/tokens` | [List Tokens](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/list/) |
| `GET /user/tokens` | [List Tokens](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/list/) |
| `GET /user/tokens/{token_id}` | [Token Details](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/get/) |
| `GET /user/tokens/verify` | [Verify Token](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/) |

## Framework mappings

Each finding carries the spec mapping row for its control across FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP. The export writes `compliance/unified_compliance_matrix.md` plus one report per framework under `compliance/<framework>/`.

## Live smoke

```bash
CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=... npm --prefix cli run test:cloudflare:live
```

The script exits 0 with a skip message when neither `CLOUDFLARE_API_TOKEN` nor the `CLOUDFLARE_EMAIL` + `CLOUDFLARE_API_KEY` pair is set. Otherwise it runs the access check and one zone security assessment on up to three zones.

## Limitations and manual controls

- DDoS (3): when no `ddos_l7` override ruleset exists, the finding passes only if the zone ruleset list shows the managed `ddos_l7` ruleset (default sensitivity); if the list cannot be read or lacks it, the finding is manual. Per-rule overrides require Enterprise with Advanced DDoS Protection.
- Bot management (4): Enterprise Bot Management enforcement lives in WAF custom rules using bot scores, so it is reported manual and names the current plan from `/zones/{zone_id}/subscription` `rate_plan.public_name`; `zones[].plan` is deprecated and is not read. Bot Fight Mode and Super Bot Fight Mode are judged automatically.
- Authenticated Origin Pulls (18): zone-level enablement and every per-hostname certificate association are automated. Associations are paginated to completion (`per_page=1000`, `status=all`); `deleted` associations are ignored, and disabled, non-active, undated, or truncated associations cap the finding at warn.
- Audit logging (11): the API proves recent events exist; retention configuration is manual.
- Gateway (24): zero Gateway rules fails when `/accounts/{account_id}/gateway` returns a `gateway_tag` (Gateway is provisioned) and is otherwise manual because the product may not be licensed.
- Zone checks sample `zone_limit` zones; the summary reports seen and total counts whenever the inventory is partial and caps the verdict at warn.
- Legacy `firewall/rules`, `firewall/waf/packages`, and `rate_limits` endpoints are deprecated; the rulesets API is authoritative. Legacy reads happen only when the corresponding rulesets read fails, are evidence only, and never produce a pass.
