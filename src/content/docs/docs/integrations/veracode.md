---
title: Veracode
description: Read-only Veracode security inspector covering scan coverage, policy compliance, finding hygiene, SCA posture, and identity hygiene with framework mappings.
---

The Veracode tools inspect a Veracode Application Security Platform account through the HMAC-signed REST APIs. They never mutate the platform: every call is a GET, and results are normalized into findings with FedRAMP, CMMC, SOC 2, CIS Controls v8, PCI-DSS, STIG, IRAP, and ISMAP mappings from `specs/veracode-sec-inspector.spec.md`.

## What it inspects

- Application inventory: last completed scan dates, scan statuses, business criticality, team assignment, and policy assignment from the Applications API
- Policy compliance: `policy_compliance_status` per application, custom policy adoption, finding rules, scan frequency rules, and grace periods from the Policy API
- Finding hygiene: open flaw aging against severity SLAs, mitigation proposal and approval state, potential false positive rate, and Very High/High flaw density from the Findings API and Summary Report API
- SCA posture: open high-CVSS vulnerability issues and HIGH risk license issues per workspace, plus application coverage through upload-and-scan SCA or linked agent projects (SCA Agent API)
- Dynamic Analysis configuration: authentication and crawl settings per scan (Dynamic Analysis API)
- Identity hygiene: team-unrestricted roles, Administrator counts, inactive users, SAML usage, API accounts without teams, and API credential age and expiration (Identity API)

## Setup and authentication

1. In the Veracode Platform, create an API service account (or use your user) and generate API credentials (API ID and API key secret). The secret is a hex string; store it outside the repository.
2. Grant the roles the inspector needs:
   - Security Insights or Reviewer for applications, policies, findings, and summary reports
   - Administrator for users, teams, roles, and other users' API credentials
   - Workspace Administrator or Workspace Editor when agent-based SCA is licensed
   - Dynamic Analysis visibility (Security Insights covers the analyses list) when Dynamic Analysis is licensed
3. Provide credentials with one of these mechanisms (explicit tool arguments win, then environment variables, then the credentials file):
   - Tool arguments `api_key_id` and `api_key_secret`
   - Environment variables `VERACODE_API_KEY_ID` and `VERACODE_API_KEY_SECRET`
   - `~/.veracode/credentials` INI file with `veracode_api_key_id` and `veracode_api_key_secret` under a profile; `VERACODE_API_PROFILE` or the `profile` argument selects the profile (default `default`), and `credentials_file` or `VERACODE_API_CREDENTIALS_FILE` overrides the path
4. Pick the region with `region` or `VERACODE_REGION`: `us` (api.veracode.com, default), `eu` (api.veracode.eu), or `us-fed` (api.veracode.us). `base_url` or `VERACODE_API_BASE_URL` overrides the host explicitly.

Requests are signed per the documented `VERACODE-HMAC-SHA-256` scheme: the data string `id=...&host=...&url=<path and query>&method=GET`, a 16-byte random nonce, a millisecond timestamp, the key chain `HMAC(key, nonce) -> HMAC(., timestamp) -> HMAC(., "vcode_request_version_1")`, and a final HMAC over the data string. The secret is redacted from error messages and never written into bundles.

## Tools

| Tool | Purpose |
| --- | --- |
| `veracode_check_access` | Probes every read surface and reports readable counts, HTTP status, and the role each surface requires (Security Insights, Reviewer, Administrator, Workspace roles) |
| `veracode_assess_scan_coverage` | Controls 1, 4, 10, 11, 13, 14, 19 |
| `veracode_assess_policy_compliance` | Controls 2, 15, 20 |
| `veracode_assess_findings_hygiene` | Controls 3, 12, 16, 17 |
| `veracode_assess_sca_posture` | Controls 5, 6, 18 |
| `veracode_assess_access_controls` | Controls 7, 8, 9 |
| `veracode_export_audit_bundle` | Runs everything and writes `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log` on partial failure, and a paired zip |

Every finding is `{ id, title, severity, status, summary, evidence, mappings }` where `status` is `pass`, `warn`, `fail`, or `manual`.

## Control coverage

| # | Control | Tool | Finding | Status semantics |
| --- | --- | --- | --- | --- |
| 1 | Application scan coverage | scan_coverage | VERACODE-01 | fail when any application's `last_completed_scan_date` is older than `max_scan_age_days` (90); warn when applications expose no date; pass only for a complete inventory with every application fresh |
| 2 | Policy compliance status | policy_compliance | VERACODE-02 | fail on `DID_NOT_PASS` or no assigned policy; warn on `CONDITIONAL_PASS`, `NOT_ASSESSED`, `DETERMINING`, `VENDOR_REVIEW`; pass only when every assigned policy is `PASSED` |
| 3 | Flaw aging | findings_hygiene | VERACODE-03 | open `UNRESOLVED` findings aged from `first_found_date` against 30/60/90/180 days for severity 5/4/3/2; missing dates warn; zero findings is manual |
| 4 | Scan frequency compliance | scan_coverage | VERACODE-04 | required interval from the assigned policy's `scan_frequency_rules`; overdue fails; no requirement or missing date warns |
| 5 | SCA library currency | sca_posture | VERACODE-05 | open workspace vulnerability issues at or above `sca_cvss_threshold` (7) fail; unlicensed or empty SCA is manual |
| 6 | SCA license risk | sca_posture | VERACODE-06 | open license issues with `risk` HIGH fail; UNKNOWN risk warns |
| 7 | Team access controls | access_controls | VERACODE-07 | no teams fails; more than `max_unrestricted_users` active users on roles with `ignore_team_restrictions` fails; applications without a team warn |
| 8 | User role audit | access_controls | VERACODE-08 | Administrator count above `max_admins`, humans without login in `inactive_days`, or API accounts without a team fail; missing `last_login` warns |
| 9 | API credential management | access_controls | VERACODE-09 | unrevoked credentials with `created_ts` older than `max_credential_age_days` (365) fail; missing `created_ts` or `expiration_ts` warns |
| 10 | Sandbox usage | scan_coverage | VERACODE-10 | applications with zero development sandboxes warn |
| 11 | Prescan module coverage | scan_coverage | VERACODE-11 | manual: prescan results only exist in the XML `getprescanresults.do` API |
| 12 | Mitigation approval workflow | findings_hygiene | VERACODE-12 | `resolution_status` PROPOSED or mitigation annotations without a comment fail (findings fetched with `include_annot=TRUE`) |
| 13 | Dynamic scan configuration | scan_coverage | VERACODE-13 | scans without `auth_configuration.authentications` or with `crawl_configuration.disabled` fail; unlicensed or empty Dynamic Analysis is manual |
| 14 | Pipeline integration status | scan_coverage | VERACODE-14 | manual: Pipeline Scan results are not persisted on application profiles |
| 15 | Custom policy profiles | policy_compliance | VERACODE-15 | no `CUSTOMER` type policy fails; applications on built-in policies or custom policies without finding rules warn |
| 16 | Finding false positive rate | findings_hygiene | VERACODE-16 | applications above `max_fp_rate_percent` (20) of `POTENTIAL_FALSE_POSITIVE` findings warn |
| 17 | Very High/High flaw density | findings_hygiene | VERACODE-17 | summary report module `loc` and `numflawssev4` plus `numflawssev5`; above `max_flaw_density_per_kloc` (1) fails; missing LOC warns |
| 18 | SCA workspace coverage | sca_posture | VERACODE-18 | applications with neither `upload_and_scan_sca_enabled` nor a linked SCA agent project warn |
| 19 | Scan completion rate | scan_coverage | VERACODE-19 | latest scans in `ANALYSIS_ERRORS`, `SCAN_CANCELED`, `PRE_SCAN_FAILED`, `INCOMPLETE`, or similar statuses fail; applications without scan records warn |
| 20 | Collections compliance posture | policy_compliance | VERACODE-20 | manual: the Collections API is not in the published REST reference; business-unit grouping is provided as evidence |

Verdict safety rules apply to every control: forbidden or errored endpoints yield `manual` with the cause, empty inventories never pass, items missing dates never count as fresh, pagination runs to `page.total_pages` or the verdict is downgraded, and any sampled or team-scoped partial view downgrades `pass` to `warn` with seen and total counts.

## Framework mappings

Each finding carries the spec's mapping row, for example control 1: FedRAMP SA-11, CMMC L2 3.14.1, SOC 2 CC7.1, CIS Controls v8 16.12, PCI-DSS 6.5, STIG SRG-APP-000456, IRAP ISM-1143, ISMAP VM-01. The export bundle writes `compliance/unified_compliance_matrix.md` plus one report per framework (`fedramp.md`, `cmmc.md`, `soc2.md`, `cis-controls-v8.md`, `pci-dss.md`, `stig.md`, `irap.md`, `ismap.md`).

## Live smoke

```bash
npm --prefix cli run test:veracode:live
```

The script skips with exit code 0 when no credentials are configured. Otherwise it runs `veracode_check_access` and the policy compliance assessment against the real tenant.

## Limitations and manual controls

- Controls 11 (prescan module coverage), 14 (pipeline integration), and 20 (collections posture) always render as `manual` with the evidence a human must collect.
- SCA (controls 5, 6, 18) and Dynamic Analysis (control 13) render as `manual` with an unlicensed or not applicable summary when the APIs return 401, 403, or 404 or return empty inventories.
- Per-application calls (sandboxes, findings, summary reports, SCA projects) are capped by `max_applications` (100); when the cap is below the inventory the verdict flags the partial view.
- The Reporting API is not called because report generation requires a POST.

## Official documentation

- [Region domains for Veracode services](https://docs.veracode.com/r/Region_Domains_for_Veracode_APIs)
- [API authentication](https://docs.veracode.com/r/API_authentication)
- [HMAC signing example for Java](https://docs.veracode.com/r/t_configure_java_library)
- [Get a list of application profiles](https://docs.veracode.com/r/r_applications_list) and [Applications API specification](https://app.swaggerhub.com/apis/Veracode/veracode-applications-api-specification/1.0)
- [Findings REST API](https://docs.veracode.com/r/c_findings_v2_intro), [Findings REST API examples](https://docs.veracode.com/r/c_findings_v2_examples), and [Findings API specification](https://app.swaggerhub.com/apis/Veracode/veracode-findings_api_specification/2.1)
- [Summary Report API specification](https://app.swaggerhub.com/apis/Veracode/veracode-summary_report_api/v2)
- [Policy API specification](https://app.swaggerhub.com/apis/Veracode/veracode-policy_api_specification/1.0)
- [Identity API specification](https://app.swaggerhub.com/apis/Veracode/veracode-identity_api/1.5)
- [SCA Agent API specification](https://app.swaggerhub.com/apis/Veracode/veracode-sca_agent_api_specification/3.0)
- [Dynamic Analysis Configuration Service API specification](https://app.swaggerhub.com/apis/Veracode/veracode-dynamic_analysis_configuration_service_api/1.0)
- [Reporting API specification](https://app.swaggerhub.com/apis/Veracode/veracode-reporting_api_specification/1.12.0)
