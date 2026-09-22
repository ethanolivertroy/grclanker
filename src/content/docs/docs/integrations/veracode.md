---
title: Veracode
description: Read-only Veracode security inspector covering scan coverage, policy compliance, finding hygiene, SCA posture, and identity hygiene with framework mappings.
---

The Veracode tools inspect a Veracode Application Security Platform account through the HMAC-signed REST APIs. They never mutate the platform: every call is a GET, and results are normalized into findings with FedRAMP, CMMC, SOC 2, CIS Controls v8, PCI-DSS, STIG, IRAP, and ISMAP mappings from `specs/veracode-sec-inspector.spec.md`.

## What it inspects

- Application inventory: latest static scan status and publish date, business criticality, team assignment, and policy assignment from the Applications API
- Policy compliance: `policy_compliance_status` per application, custom policy adoption, finding rules, scan frequency rules, and grace periods from the Policy API
- Finding hygiene: open flaw aging against severity SLAs, mitigation proposal and approval state, potential false positive rate, and Very High/High flaw density from the Findings API and Summary Report API
- SCA posture: open high-CVSS vulnerability issues and HIGH risk license issues per workspace, plus application coverage through upload-and-scan SCA or linked agent projects (SCA Agent API)
- Dynamic Analysis configuration: authentication and crawl settings per scan (Dynamic Analysis API)
- Identity hygiene: team-unrestricted roles, Administrator counts, inactive users, SAML usage, API accounts without teams, and API credential age and expiration (Identity API, users listed with `include_roles=true` and `include_teams=true`, teams with `all_for_org=true`)

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
| `veracode_check_access` | Probes every read surface with a one-page request and reports the role each surface requires (Security Insights, Reviewer, Administrator, Workspace roles). A readable list reports the vendor `total_elements` when the page carried it, otherwise the items on that page with the note `first page only, total unknown` when the walk did not finish; a surface that could not be read reports `count: null`, the HTTP status the request observed, the path that failed, and the scrubbed error |
| `veracode_assess_scan_coverage` | Controls 1, 4, 10, 11, 13, 14, 19 |
| `veracode_assess_policy_compliance` | Controls 2, 15, 20 |
| `veracode_assess_findings_hygiene` | Controls 3, 12, 16, 17 |
| `veracode_assess_sca_posture` | Controls 5, 6, 18 |
| `veracode_assess_access_controls` | Controls 7, 8, 9 |
| `veracode_export_audit_bundle` | Runs everything and writes `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log` on partial failure, and a paired zip |

Every finding is `{ id, title, severity, status, summary, evidence, mappings }` where `status` is `pass`, `warn`, `fail`, or `manual`.

### Pagination and truncation reporting

Every HAL list (`/appsec/v1/applications`, `/appsec/v1/policies`, `/appsec/v2/applications/{guid}/findings`, `/api/authn/v2/users`, `/api/authn/v2/teams`, `/api/authn/v2/roles`, `/srcclr/v3/workspaces`, workspace issues and libraries, `/was/configservice/v1/analyses`, per-analysis scans, per-application sandboxes) is walked with `page` and `size` until the last page. The walk finishes when the payload's `page.total_pages` is reached or, without page metadata, when a page comes back shorter than the page size. Every other exit reports `complete: false`: the page cap (50 pages by default; 10 for sandboxes, 20 for workspace issues, 5 for workspace libraries and per-analysis scans) reached with more pages promised or with no page metadata at all, a page whose items repeat the previous page (the server ignored `page`, recorded as `<path> returned the same page twice, so pagination stopped after N items`), and a `total_elements` larger than the items read. A capped walk without metadata leaves `totalElements` undefined, so the finding states `Only N of an unknown total of <items> were read (P/? pages), so the verdict reflects a partial inventory`; with metadata it states seen versus total and pages fetched versus `total_pages`. A finding that reads an incomplete list never passes: `pass` drops to `warn` and the note is appended to the summary. Per-item sampling caps (`max_applications`, `max_workspaces`, `max_analyses`, ten scans per analysis, 200 API accounts) are stated the same way (`Only S of T <items> were sampled, so the verdict reflects a partial view`) and demote `pass` to `warn`.

### Export bundle

`core_data/<assessment>.json` (`scan-coverage`, `policy-compliance`, `findings-hygiene`, `sca-posture`, `access-controls`) holds the raw snapshot each assess tool also returns as `rawData`; `analysis/<assessment>.json` holds the title, `summary`, findings, and errors; `analysis/findings.json` merges every finding; `analysis/summary.md` renders the access check and every assessment as text; `core_data/access.json` is the access check result. Every JSON document passes through the same redaction before it is written: the value of every credential-named key is replaced by `[REDACTED]` (the key is normalized to lowercase with dots, underscores, and hyphens removed and matched on the suffixes `password`, `passwd`, `passphrase`, `secret`, `token`, `apikey`, `privatekey`, `scriptdata`, `scriptbody`, and `certificate`, so `api_token`, `client_secret`, and `login_script_data` are caught while `credentials_readable` and `api_id` stay legible), `{name, value}` and `{key, value}` pairs whose name is credential-shaped (application profile `custom_fields`) have their value replaced, JWT-shaped strings are replaced, and every URL keeps only scheme, host, and path with userinfo and query string replaced (`git_repo_url` with `user:token@`, target URLs with session parameters). Dynamic scan configurations are not stored verbatim: each is projected to `analysis_id`, `scan_id`, a scrubbed `target_url`, `authentication_types` (the keys of `auth_configuration.authentications`), `authentication_details: "[REDACTED]"` when any authentication exists, `crawl_disabled`, `crawl_script_present`, and `allowed_host_count`. Per-user API credential records keep only `api_id`, `created_ts`, `expiration_ts`, `revocation_ts`, and `last_used_ts`; per-analysis scan lists keep `scan_id` and a scrubbed `target_url`.

A surface that was denied, errored, or timed out is written as the marker `{ collected: false, status, endpoint, error }`, where `status` and `endpoint` are the HTTP status and path of the request that actually failed (both `null` when the failure carried none), never as `[]` or `{}`; a per-parent dataset whose requests were never issued because the inventory it depends on was unreadable or empty (sandboxes, findings, summary reports, SCA projects, workspace issues and libraries, dynamic scans and configurations, API credentials) is written as `{ collected: false, status: null, endpoint: null, error: "Not requested: ..." }` naming that cause. A readable but empty list stays `[]`. Assessment summaries render `null`, never `0`, for every count derived from a surface that was not read (`applications_seen`, `applications_total`, `applications_sampled`, `policies_seen`, `workspaces_seen`, `workspaces_sampled`, `users_seen`, `teams_seen`, `roles_seen`), and evidence such as `libraries_seen` is `null` when no library list was readable. Every HTTP status, path, and error string in a finding, a summary, the access check, or `_errors.log` comes from a request the run made: `manual` verdicts name the failed surface's own status (`was forbidden (<401 or 403>)`, `returned an error (<status>)`, or `could not be read` when no status was observed) and the API key secret is replaced by `[REDACTED]` in every error string.

## Control coverage

| # | Control | Tool | Finding | Status semantics |
| --- | --- | --- | --- | --- |
| 1 | Application scan coverage | scan_coverage | VERACODE-01 | judged on the latest STATIC entry in `scans[]` (`scan_type`, published `status`, `modified_date`): fail when that scan is older than `max_scan_age_days` (90) or an application exposes no static scan at all (dynamic, manual, or SCA scans do not count); warn when the latest static scan is unpublished or undated; pass only for a complete inventory with every application fresh. The scan-type agnostic `last_completed_scan_date` is evidence only |
| 2 | Policy compliance status | policy_compliance | VERACODE-02 | fail on `DID_NOT_PASS` or no assigned policy; warn on `CONDITIONAL_PASS`, `NOT_ASSESSED`, `DETERMINING`, `VENDOR_REVIEW`; pass only when every assigned policy is `PASSED` |
| 3 | Flaw aging | findings_hygiene | VERACODE-03 | open `UNRESOLVED` findings aged from `first_found_date` against 30/60/90/180 days for severity 5/4/3/2; missing dates warn; zero findings is manual |
| 4 | Scan frequency compliance | scan_coverage | VERACODE-04 | required interval is the strictest of every assigned policy's `scan_frequency_rules` per scan type (checked against the matching published `scans[]` entry; `ONCE` requires one published scan, `NOT_REQUIRED` is skipped) and the business criticality tier (`critical_scan_interval_days` 7 for VERY_HIGH, `standard_scan_interval_days` 31 for other tiers, checked against `last_completed_scan_date`); overdue fails; no requirement, unpublished or undated scans, or assigned policies missing from the policy inventory warn |
| 5 | SCA library currency | sca_posture | VERACODE-05 | manual when `/srcclr/v3/workspaces` is unavailable (401, 403, or 404, named as unlicensed or missing Workspace role), errored, or empty, or when no sampled workspace's open vulnerability issue list was readable; fail on open issues at or above `sca_cvss_threshold` (7); manual when no issues were returned but no library was readable in any sampled workspace (it is unknown whether a scan populated them); pass only when every sampled workspace's issue list and library list were read to completion: a page-capped workspace, issue, or library list (`Only N of ... were read`, `N issue lists were truncated`, `N library lists were truncated, so libraries_seen is a lower bound`), a sampled subset of workspaces (`max_workspaces`, 25), or an unreadable issue or library list (`N workspace library lists were unreadable, so libraries_seen undercounts the scanned libraries`) drops pass to warn; `libraries_seen` is `null` when no library list was readable |
| 6 | SCA license risk | sca_posture | VERACODE-06 | open license issues with `risk` HIGH fail; UNKNOWN risk warns |
| 7 | Team access controls | access_controls | VERACODE-07 | manual when the users, roles, or teams endpoint could not be read (the summary names which and its observed status) or returned zero users or zero roles; teams are listed with `all_for_org=true`; zero teams fails; more than `max_unrestricted_users` active users on roles with `ignore_team_restrictions` fails; applications without a team warn; pass only when the user, role, team, and application lists were all read to completion: a page-capped user, role, team, or application list drops pass to warn with seen versus total (or an unknown total), an unreadable application inventory drops it to warn (`The application inventory was unreadable, so application team assignment was not verified`), and a refused `all_for_org=true` makes the member-only team list a partial view, so pass downgrades to warn (manual when the API user is a member of no teams); evidence records `roles_seen`, `roles_complete`, and `teams_scope` |
| 8 | User role audit | access_controls | VERACODE-08 | users are listed with `detailed=true`, `include_roles=true`, and `include_teams=true`; Administrator count above `max_admins`, humans without login in `inactive_days`, or API accounts without a team fail; missing `last_login` warns |
| 9 | API credential management | access_controls | VERACODE-09 | unrevoked credentials with `created_ts` older than `max_credential_age_days` (365) fail; missing `created_ts` or `expiration_ts` warns |
| 10 | Sandbox usage | scan_coverage | VERACODE-10 | applications with zero development sandboxes warn |
| 11 | Prescan module coverage | scan_coverage | VERACODE-11 | manual: prescan results only exist in the XML `getprescanresults.do` API |
| 12 | Mitigation approval workflow | findings_hygiene | VERACODE-12 | `resolution_status` PROPOSED or mitigation annotations without a comment fail (findings fetched with `include_annot=TRUE`) |
| 13 | Dynamic scan configuration | scan_coverage | VERACODE-13 | manual when `/was/configservice/v1/analyses` is unavailable (401, 403, or 404, named as unlicensed or missing role), errored, or empty, or when no scan configuration could be read; scans without `auth_configuration.authentications` or with `crawl_configuration.disabled` fail; pass only when every inspected configuration was read from complete lists: the analyses walk, each per-analysis scan list (5-page cap, recorded per analysis in `evidence.scan_coverage` as `scans_seen`, `scans_total`, and `scan_list_complete`), the `max_analyses` (25) sample, the ten-scans-per-analysis sample (`Only 10 of N scans of <analysis> were sampled`), and any unreadable scan list or configuration each drop pass to warn and are named in the summary |
| 14 | Pipeline integration status | scan_coverage | VERACODE-14 | manual: Pipeline Scan results are not persisted on application profiles |
| 15 | Custom policy profiles | policy_compliance | VERACODE-15 | no `CUSTOMER` type policy fails; applications on built-in policies or custom policies without finding rules warn |
| 16 | Finding false positive rate | findings_hygiene | VERACODE-16 | manual when the application inventory is unreadable or empty, when no sampled finding list was readable (the first failure's status is named), or when no sampled application returned findings; applications where more than `max_fp_rate_percent` (20) of findings carry an `annotations[].action` FP mitigation (read with `include_annot=TRUE`) warn; pass only when every sampled finding list was read to its last page: a finding list that hit the 50-page cap or repeated a page is computed over the findings seen and drops pass to warn (`N finding lists were truncated, so the rate was computed over the findings seen (total unknown or larger)`), as do a page-capped application inventory, the `max_applications` sample, and unreadable finding lists; `evidence.per_application` records `findings_seen`, `findings_total` (`null` when the API reported none), and `list_complete`; `finding_status.resolution` is recorded as evidence only because it is not enumerated in the published reference |
| 17 | Very High/High flaw density | findings_hygiene | VERACODE-17 | summary report module `loc` and `numflawssev4` plus `numflawssev5`; above `max_flaw_density_per_kloc` (1) fails; missing LOC warns |
| 18 | SCA workspace coverage | sca_posture | VERACODE-18 | manual when the application inventory is unreadable or empty, or when the SCA Agent API is unavailable and no sampled application has `upload_and_scan_sca_enabled`; applications with neither `upload_and_scan_sca_enabled` nor an entry in `linked_projects` from `GET /srcclr/v3/applications/{guid}/projects` (the documented `LinkedProjects` shape) warn; pass only when every sampled application is covered and the application list was complete: a page-capped inventory, the `max_applications` sample, or unreadable linked project lists drop pass to warn; when `/srcclr/v3/workspaces` was unavailable no linked project list is requested (`evidence.sca_agent_api_available: false`) and a pass earned by upload-and-scan SCA alone says so, naming the observed status of the workspaces request, or `no workspaces` when that list was empty (`The SCA Agent API was unavailable (<status>), so linked agent projects were not checked; every sampled application is covered by upload-and-scan SCA alone`) |
| 19 | Scan completion rate | scan_coverage | VERACODE-19 | latest scans in `ANALYSIS_ERRORS`, `SCAN_CANCELED`, `PRE_SCAN_FAILED`, `INCOMPLETE`, or similar statuses fail; applications without scan records warn |
| 20 | Collections compliance posture | policy_compliance | VERACODE-20 | manual: the Collections API is not in the published REST reference; business-unit grouping is provided as evidence |

Verdict safety rules apply to every control: forbidden or errored endpoints yield `manual` naming the surface and the HTTP status the failed request observed, empty inventories never pass, items missing dates never count as fresh, and every list a finding reads must have been walked to its last page or the verdict is downgraded: a page-cap exit (with or without page metadata), a repeated page, or a `total_elements` that outruns the items reports `complete: false`, the summary states seen versus total or `an unknown total`, and `pass` drops to `warn` for the application list (controls 1, 2, 3, 4, 7, 10, 12, 15, 16, 17, 18, 19), the policy list (4, 15), the user, role, and team lists (7, 8, 9), the workspace, issue, and library lists (5, 6), the analyses and per-analysis scan lists (13), and the per-application finding lists (3, 12, 16). Any sampled or team-scoped partial view downgrades `pass` to `warn` with seen and total counts. Bundle JSON has credential-named fields, JWT-shaped values, and URL userinfo or query strings replaced by `[REDACTED]`, dynamic scan configurations are projected to their non-secret settings, and every surface that was not collected is written as a marker object rather than an empty list (see Export bundle).

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
- The business criticality cadence for control 4 (VERY_HIGH weekly, every other tier monthly) is the spec's organizational default; adjust `critical_scan_interval_days` and `standard_scan_interval_days` to match the organization's scanning standard.
- The `scans[]` array on an application profile exposes only the latest scan per type, so an application whose latest static scan is still in progress is reported as unconfirmed (warn) rather than stale.
- The Reporting API is not called because report generation requires a POST.

## Official documentation

- [Region domains for Veracode services](https://docs.veracode.com/r/Region_Domains_for_Veracode_APIs)
- [API authentication](https://docs.veracode.com/r/API_authentication)
- [HMAC signing example for Java](https://docs.veracode.com/r/t_configure_java_library)
- [Get a list of application profiles](https://docs.veracode.com/r/r_applications_list) and [Applications API specification](https://app.swaggerhub.com/apis/Veracode/veracode-applications-api-specification/1.0)
- [Findings REST API](https://docs.veracode.com/r/c_findings_v2_intro), [Findings REST API examples](https://docs.veracode.com/r/c_findings_v2_examples), and [Findings API specification](https://app.swaggerhub.com/apis/Veracode/veracode-findings_api_specification/2.1)
- [Summary Report API specification](https://app.swaggerhub.com/apis/Veracode/veracode-summary_report_api/v2)
- [Policy API specification](https://app.swaggerhub.com/apis/Veracode/veracode-policy_api_specification/1.0)
- [Identity REST API](https://docs.veracode.com/r/c_identity_intro) (`all_for_org=true` for the organization-wide team list) and [Identity API specification](https://app.swaggerhub.com/apis/Veracode/veracode-identity_api/1.5) (`detailed`, `include_roles`, `include_teams` query parameters)
- [SCA Agent API specification](https://app.swaggerhub.com/apis/Veracode/veracode-sca_agent_api_specification/3.0) (`LinkedProjects.linked_projects` for `GET /v3/applications/{appGuid}/projects`)
- [Dynamic Analysis Configuration Service API specification](https://app.swaggerhub.com/apis/Veracode/veracode-dynamic_analysis_configuration_service_api/1.0)
- [Reporting API specification](https://app.swaggerhub.com/apis/Veracode/veracode-reporting_api_specification/1.12.0)
