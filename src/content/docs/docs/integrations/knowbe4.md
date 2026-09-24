---
title: KnowBe4
description: Read-only inspection of KnowBe4 KMSAT phishing simulations, training campaigns, user risk, and account governance through the Reporting API, with optional PhishER GraphQL enrichment.
---

The KnowBe4 integration audits a KnowBe4 Security Awareness Training (KMSAT) account against the twenty controls in `specs/knowbe4-sec-inspector.spec.md`. It reads phishing security tests and recipients, training campaigns and enrollments, users, groups, and account settings through the KnowBe4 Reporting API, and optionally reads PhishER messages through the PhishER GraphQL API. Every tool is read-only; nothing in this integration creates, changes, or deletes KnowBe4 data.

## What it inspects

- Phishing program: test cadence, active-user coverage, phish-prone percentage, failure-rate trend, campaign targeting, Phish Alert Button report rate, and scheduling regularity.
- Training program: campaign completion, new-user enrollment timeliness, remedial training after phishing failures, content currency, and required compliance modules.
- User risk and hygiene: risk score distribution, group coverage across phishing and training, and inactive users still marked active.
- Account governance: console administrator count and domains, SSO enforcement, report review cadence, USB drop tests, and callback (voice) phishing tests.

## Setup and authentication

1. In the KnowBe4 console open **Account Settings** and, in the **API** section, create or copy a **Reporting API** key. Reporting API keys are read-only and account-scoped.
2. Optionally copy a **PhishER Product API** key from the same section if you want PhishER report-rate enrichment.
3. Note where your account is hosted. The console hostname selects the API region: `training.knowbe4.com` is `us`, and `eu.knowbe4.com`, `ca.knowbe4.com`, `uk.knowbe4.com`, and `de.knowbe4.com` map to `eu`, `ca`, `uk`, and `de`.

Configuration resolves in this order: explicit tool arguments, then environment variables, then the config file.

| Setting | Tool argument | Environment variable | Config file key | Default |
| --- | --- | --- | --- | --- |
| Reporting API key (required) | `api_token` | `KNOWBE4_API_TOKEN` | `api_token` | none |
| Region (`us`, `eu`, `ca`, `uk`, `de`) | `region` | `KNOWBE4_REGION` | `region` | `us` |
| Reporting API base URL override | `base_url` | `KNOWBE4_BASE_URL` | `base_url` | derived from region, for example `https://us.api.knowbe4.com` |
| PhishER Product API key (optional) | `phisher_api_token` | `KNOWBE4_PHISHER_API_TOKEN` | `phisher_api_token` | none |
| PhishER GraphQL URL override | `phisher_graphql_url` | `KNOWBE4_PHISHER_GRAPHQL_URL` | `phisher_graphql_url` | derived from region, for example `https://training.knowbe4.com/graphql` |
| Config file path | `config_file` | `KNOWBE4_CONFIG_FILE` | n/a | `~/.knowbe4-inspector/config.yaml` |
| HTTP timeout in seconds | `timeout_seconds` | `KNOWBE4_TIMEOUT` | `timeout_seconds` | `30` |
| Redact user PII in findings and exports | `redact_pii` | `KNOWBE4_REDACT_PII` | `redact_pii` | `false` |

Example config file:

```yaml
# ~/.knowbe4-inspector/config.yaml
api_token: "<reporting api key>"
region: eu
phisher_api_token: "<phisher product api key>"
redact_pii: true
```

Regional base URLs follow the official documentation: the Reporting API uses `https://<region>.api.knowbe4.com` and the PhishER GraphQL API uses `https://training.knowbe4.com/graphql` for US accounts or `https://<region>.knowbe4.com/graphql` for EU, CA, UK, and DE accounts. Both APIs use an `Authorization: Bearer <token>` header. Tokens are never written to findings, bundles, or error messages.

## Rate limits and pagination

The Reporting API allows four requests per second, a burst of 50 requests per minute, and 2,000 requests per day plus the number of licensed users. The client spaces requests at least 250 ms apart, retries `429` and `503` responses with exponential backoff (honoring `Retry-After` when present), and pages every list endpoint with `page` and `per_page` (500 per page, or 10 for training campaigns as documented). Recipient results are only loaded for the most recent security tests (`security_test_sample_limit`, default 12) to stay within the daily quota on large accounts. PhishER messages are paged with the GraphQL `per`, `page`, and `nextPageKey` arguments of `phisherMessages`, filtered with a Lucene `reported_at` range for the lookback window.

The PhishER argument names come from the public schema that the developer portal's schema browser loads: an unauthenticated introspection query posted to `https://training.knowbe4.com/graphql?scope=phisher` returns `phisherMessages(per: Int, page: Int, all: Boolean, query: String!, sortField: PhisherMessageSortFields, sortDirection: SortDirections, nextPageKey: String)` and `phisherRules(per: Int, page: Int, all: Boolean, query: String!, active: Boolean)`, both returning `nodes` plus a `pagination { page pages per totalCount nextPageKey }` object. The PhishER pagination prose page describes `page` and `per_page` with REST wording; GraphQL validation rejects arguments that are not in the schema, so the client follows the schema. You can reproduce the check with:

```bash
curl -s -X POST 'https://training.knowbe4.com/graphql?scope=phisher' \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { fields { name args { name } } } } }"}'
```

## Tools

| Tool | Purpose | Notable parameters |
| --- | --- | --- |
| `knowbe4_check_access` | Probes `/v1/account`, users, groups, phishing campaigns, security tests, training campaigns, enrollments, store purchases, and policies, plus PhishER when a key is configured. Reports `healthy` or `limited`. | auth parameters only |
| `knowbe4_assess_phishing_program` | Controls 1, 2, 6, 7, 9, 19, 20. | `lookback_days` (90), `max_campaign_gap_days` (30), `min_coverage_pct` (90), `max_phish_prone_pct` (15), `min_report_rate_pct` (50), `max_schedule_gap_days` (45), `require_full_targeting` (true), `security_test_sample_limit` (12), `phisher_message_limit` (1000) |
| `knowbe4_assess_training_program` | Controls 3, 4, 10, 11, 17. | `training_lookback_days` (365), `min_completion_pct` (90), `fail_completion_pct` (80), `enrollment_grace_days` (30), `remedial_window_days` (14), `max_content_age_days` (365), `required_compliance_topics`, `enrollment_limit` (20000) |
| `knowbe4_assess_user_risk` | Controls 5, 8, 18. | `max_mean_risk_score` (50), `max_risk_score_stddev` (25), `inactive_days` (180), `lookback_days` (90), `user_limit` (5000) |
| `knowbe4_assess_account_governance` | Controls 12, 13, 14, 15, 16. | `max_admin_count` (3), `require_usb_tests` (true), `require_vishing_tests` (true), `lookback_days` (90) |
| `knowbe4_export_audit_bundle` | Runs every assessment and writes an evidence bundle plus a `.zip`. | all of the above plus `output_dir` (default `./export/knowbe4`) |

Every assessment returns findings shaped as `{ id, control, title, severity, status, summary, evidence, mappings, manualEvidence }` with severity `critical`, `high`, `medium`, `low`, or `info` and status `pass`, `warn`, `fail`, or `manual`. Finding ids are `KNOWBE4-01` through `KNOWBE4-20` and match the spec control numbers.

### Finding status semantics

- `pass`: the Reporting API evidence satisfies the control.
- `warn`: the control is partially satisfied, the data was too thin to conclude (unsampled tests, a capped list, an empty user population, or a context inventory that was unreadable), or a low severity hygiene issue was found.
- `fail`: the API evidence shows the control is not met.
- `manual`: the API cannot verify the control; the summary and `manualEvidence` state exactly which console export a human must collect.

An unreadable inventory never produces a `pass`. It is recorded in the assessment `errors` list, in `core_data/collection_status.json`, and in the bundle `_errors.log`, and the affected finding carries `Unreadable inventory: <inventory> (<endpoint>: <error>), so <what was not checked>. Collect manually: <console evidence>.` in its summary plus the same entries under `evidence.unreadable_inventories`. That holds for every inventory a finding reads, not only its primary one: a finding that combines several inventories (users plus security tests plus recipient results, groups plus phishing and training campaigns, training campaigns plus enrollments plus policies) never `pass`es while any of them is unreadable (403, 401, 5xx, or a transport error), even when the readable inventories alone would satisfy the control. The verdict is `manual` when the missing inventory is essential (security tests for 1, 2, 6, 7, 10, 19, and 20; users for 2, 4, 5, and 18; training campaigns for 3, 8, 11, and 17; enrollments for 4 and 10; groups and phishing campaigns for 8; phishing campaigns for 9, plus users or groups for 9 when no campaign targets All Users; the account for 12; callback tests for 16) and `warn` when the readable inventories still support a judgement and the summary says what was not checked (recipient results for 2, 10, and 18; users and the account for 6; the risk score history for 5 and 7; the account for 5; security tests, users, and groups for 9 while an All Users campaign exists; PhishER messages for 19; enrollments for 3 and 17; training campaigns for 10; store purchases for 11; policies for 17; security tests and enrollments for 18). Failing verdicts on the readable inventories stay `fail`.

A truncated listing never produces a `pass` either. Every list read is capped (`user_limit`, `enrollment_limit`, `phisher_message_limit`, and an internal cap for the other inventories), and the client reports the listing as truncated when the cap stopped it while the last page was still full or dropped items from it (the Reporting API returns bare arrays with no total, so a short page is the only completion signal), and for PhishER when the cap stopped short of `totalCount`, when the server repeats the same `nextPageKey`, or when an empty page arrives while `totalCount` says more exist. When a finding's verdict depends on a truncated inventory, a clean verdict becomes `warn`, the summary ends with `Truncated listing: <inventory> (<seen> of <total> loaded, truncated at <argument> (<limit>))` plus the argument to raise, and the evidence carries `truncated_inventories` with the seen versus total counts. A count that would read as "none exist" renders `null` rather than `0` when the inventory it is derived from was truncated or unreadable (`KNOWBE4-10` renders `remediated_users` as `null` when the enrollments read stopped before any remediation was seen, and as the count observed, a lower bound, when some were), while a positive count and the figures named for the read's own size (`enrollments_loaded`, `users_read`, `security_tests_read`) always render. A listing the server stopped rather than the cap (an empty page or an ended pagination while `totalCount` says more exist, a repeated `nextPageKey`) states its own stop reason in that clause instead of the cap (`<seen> of <total> loaded; the server returned an empty page while reporting <total> records`), the remedy to raise the argument is offered only for a cap exit, and the reason is written per inventory under `truncation_reason` in `core_data/collection_status.json` and in `truncated_inventories`. Context inventories (the per-user phish-prone average, the account risk score, PhishER enrichment, uploaded policies) only annotate the evidence when truncated; the PhishER inbox clause on KNOWBE4-19 carries the same stop reason. Failing verdicts stay `fail`.

### Audit bundle layout

```text
<account>-knowbe4-audit-bundle/
  QUICK_REFERENCE.md
  metadata.json
  core_data/          Reporting API (and PhishER) snapshots with credential values replaced by [REDACTED] and free-form user fields dropped
  core_data/collection_status.json
                      one row per inventory: readable, error, truncated, truncation_reason, seen, total, limit, limit_argument
  analysis/           findings.json, control_coverage.json, per-area json and md, access_check.md
  compliance/         executive_summary.md, unified_compliance_matrix.md,
                      fedramp/, cmmc/, soc2/, cis_controls/, pci_dss/, disa_stig/, irap/, ismap/
  _errors.log         only when some reads failed
<account>-knowbe4-audit-bundle.zip
```

Output paths are resolved inside `output_dir`; traversal outside the root and symlinked parent directories are rejected. Directories are created with mode `0700` and files with `0600`. Set `redact_pii` to pseudonymize emails and mask names, phone numbers, and IP addresses in `core_data/` and findings.

Credentials never reach the bundle regardless of `redact_pii`. User records drop their free-form fields (`comment`, `custom_field_1` through `custom_field_4`, `custom_date_1`, `custom_date_2`) at collection time, including the user embedded in each security test recipient, because nothing downstream reads them and an admin can type anything into them. Every `core_data/` file then passes through a redaction step that replaces the value under any credential-shaped key (`token`, `secret`, `password`, `passphrase`, `authorization`, `credential`, `bearer`, `api_key`/`apiKey`, `private_key`, `access_key`, `client_secret`, and their plural and camelCase forms, plus `{name, value}` pairs whose name is credential-shaped) with `[REDACTED]` whether the value is a string, a list, or a nested object, keeping the key so an auditor can see the field existed. URL-shaped keys (`url`, `uri`, `endpoint`, `link`, `href`) keep only scheme and host so signed policy and content links cannot carry a token into the bundle. Non-JSON error bodies are described by content type and length in error text, never echoed, and JSON error messages are capped in length. The assessment tools return findings, summaries, and errors without the raw snapshots.

Recorded error text follows one rule at one place: every collection error, access surface `error`, assessment `errors` entry, `_errors.log` line, and tool failure message is produced by a single function that passes the thrown message through the module scrubber, and a `SyntaxError` raised by the transport is recorded as its class name plus a fixed note because the parser's message quotes the body. The scrubber removes the configured Reporting API and PhishER tokens at full length in plain, base64, base64url, URL-encoded, form-encoded, and JSON-escaped form, and the value of every credential carrier whatever the value's shape: a `key=value`, `key: value`, or `"key": "value"` pair whose key carries a credential word (`api_token`, `KNOWBE4_API_TOKEN`, `phisher_api_token`, and the bearer ids `secret_id`, `session_id`, and `token_id`), also when the key follows a JSON escape (`\"api_token\": \"v\"`) or a command-line flag (`--api-token v`, `--api-token=v`, `-Dapi_token=v`); an authorization scheme word in any casing (`Bearer`, `bearer`, `Basic`, `Token`) loses the value after it, a bare token or a whole auth-param list (`Snowflake Token="v"`, `Digest username="v", nonce="v", response="v"`) alike, and the word itself stays only under `Authorization`, `Proxy-Authorization`, and `WWW-Authenticate`, where a challenge's `realm="api"` stays as well, while an API-key or token header (`X-Api-Key: splunk rejected`, `X-Phisher-Token: token rejected`) and a credential-named assignment (`token=Bearer v`) lose their whole value; a cookie header loses its value whole, its `;` separating pairs and attributes; the query of any URL becomes one marker, and a credential-named parameter of a relative path or bare query string loses its value whole, a `;` inside the value included (`?token=v;rest` renders `?token=[REDACTED]`, as URLSearchParams reads it); and a webhook or callback URL keeps its origin alone. A `webhook`-prefixed key is a URL carrier only when its last segment is `url` or `uri` or the key is the bare `webhook`; `webhook_secret`, `webhook_token`, and `webhookSecret` are credential keys and lose their value whatever its shape. A configured secret that is itself a carrier word (`password`, `Authorization`, `Bearer`) is removed after the carriers rather than before them, so the pair or header it names still loses its value. A name after a path slash (`GET /v1/account: 403`) is a path segment, not a key, and a key whose last segment names a setting (`KNOWBE4_BASE_URL`, `KNOWBE4_PHISHER_GRAPHQL_URL`, `phisher_message_limit`, `inactive_days`) keeps a word value and loses only a token-shaped or registered one, so every fixed message and every finding summary, manual-evidence instruction, and bundle document survives the pass unchanged; the test suite sweeps the strings recorded by healthy and partially denied runs for alterations.

## Control coverage

| Spec control | Tool | Finding | Status semantics |
| --- | --- | --- | --- |
| 1. Phishing simulation frequency | `knowbe4_assess_phishing_program` | `KNOWBE4-01` | pass when the latest security test started within `max_campaign_gap_days`; fail otherwise or when no test has ever run; manual when security tests are unreadable |
| 2. Phishing simulation coverage | `knowbe4_assess_phishing_program` | `KNOWBE4-02` | pass when at least `min_coverage_pct` of active users appear as recipients of tests in `lookback_days`; warn when unsampled tests could hide coverage, some recipient results were unreadable, the user list hit `user_limit`, or the API returned no active users; fail otherwise; manual when security tests or users are unreadable |
| 3. Training completion rates | `knowbe4_assess_training_program` | `KNOWBE4-03` | pass when every completed campaign in `training_lookback_days` is at or above `min_completion_pct`; warn between `fail_completion_pct` and the target; fail below `fail_completion_pct`. A campaign reporting the `-1` completion sentinel is measured from its enrollments; when the enrollment list hit `enrollment_limit` it is listed as unmeasurable (`campaigns_with_truncated_enrollments`) and caps the verdict at warn, and when the enrollment list is unreadable it lands in `campaigns_without_measurable_completion` and the verdict is capped at warn with the unreadable inventory named; manual when training campaigns are unreadable |
| 4. Training enrollment timeliness | `knowbe4_assess_training_program` | `KNOWBE4-04` | pass when users who joined in the window were enrolled within `enrollment_grace_days`; warn when the late share is 5% or less, enrollment or user collection was capped, or the API returned no active users; fail otherwise; manual when users or enrollments are unreadable |
| 5. User risk score distribution | `knowbe4_assess_user_risk` | `KNOWBE4-05` | fail when the mean `current_risk_score` exceeds `max_mean_risk_score`; warn when the standard deviation exceeds `max_risk_score_stddev`, no scores exist, the API returned no active users, the user list hit `user_limit`, or the account or its risk score history (comparison context) is unreadable; pass otherwise; manual when users are unreadable |
| 6. Phish-prone percentage tracking | `knowbe4_assess_phishing_program` | `KNOWBE4-06` | evaluated only from the delivered-weighted phish-prone percentage of security tests in `lookback_days`; fail above `max_phish_prone_pct`; warn when above the program baseline, when no test ran in the window, when tests report no rate (the per-user average is shown as context only, because never-tested users report 0%), or when users or the account (the context figures) are unreadable; pass otherwise; manual when security tests are unreadable |
| 7. Phishing failure rate trending | `knowbe4_assess_phishing_program` | `KNOWBE4-07` | compares the older and newer halves of tests in twice `lookback_days`; fail when the newer half is more than 2 points worse, warn above 0.5 points, with fewer than four tests, or when the account risk score history is unreadable, pass otherwise; manual when security tests are unreadable |
| 8. Group coverage analysis | `knowbe4_assess_user_risk` | `KNOWBE4-08` | pass when every active group with members was targeted by a phishing and a training campaign in `lookback_days` (All Users counts); fail otherwise; manual when groups, phishing campaigns, or training campaigns are unreadable |
| 9. Campaign targeting completeness | `knowbe4_assess_phishing_program` | `KNOWBE4-09` | pass when an active campaign targets All Users or targeted groups cover `min_coverage_pct` of active users; warn when the user list hit `user_limit`, or when security tests, users, or groups are unreadable while a campaign still targets All Users; fail when `require_full_targeting` is true and coverage is short; manual when phishing campaigns are unreadable, or when users or groups are unreadable and no campaign targets All Users (the coverage estimate needs both) |
| 10. Remedial training triggers | `knowbe4_assess_training_program` | `KNOWBE4-10` | pass when at least 90% of users who failed a sampled test more than `remedial_window_days` ago were enrolled afterwards and every test in the window was sampled (auto-enroll campaigns listed); warn from 50%, whenever unsampled tests remain in the window (sampled and unsampled counts are in the evidence), or when recipient results or training campaigns are unreadable; fail below 50%; manual when security tests or enrollments are unreadable |
| 11. Training content currency | `knowbe4_assess_training_program` | `KNOWBE4-11` | fail when assigned ModStore modules are retired; warn when modules were published more than `max_content_age_days` ago, when a module has no publish date in either the campaign content or the store catalog (listed as `undated_modules`), when none are assigned, or when store purchases are unreadable; pass otherwise; manual when training campaigns are unreadable |
| 12. Admin role audit | `knowbe4_assess_account_governance` | `KNOWBE4-12` | fail when console admins exceed `max_admin_count`; warn when an admin uses a domain outside the account's allowed domains; pass otherwise; manual when the account is unreadable |
| 13. SSO integration status | `knowbe4_assess_account_governance` | `KNOWBE4-13` | manual: the Reporting API does not expose SAML or admin MFA settings |
| 14. Reporting frequency | `knowbe4_assess_account_governance` | `KNOWBE4-14` | manual: no API record of generated or reviewed reports; latest test and campaign dates are included as context |
| 15. USB test campaign execution | `knowbe4_assess_account_governance` | `KNOWBE4-15` | always manual: USB Drive Tests are not in the Reporting API. With `require_usb_tests` true the finding asks for the console campaign export; with it false the finding states that the control was scoped out by configuration and asks for the policy or risk-acceptance record. It never passes |
| 16. Vishing campaign execution | `knowbe4_assess_account_governance` | `KNOWBE4-16` | pass when a callback phishing test (`campaign_type=callback`) started in `lookback_days`; fail when none did; manual when callback tests are unreadable, or when `require_vishing_tests` is false (scoped out by configuration, evidence is the policy or risk-acceptance record) |
| 17. Compliance training modules | `knowbe4_assess_training_program` | `KNOWBE4-17` | fail when a `required_compliance_topics` entry has no assigned module or is assigned but has zero training enrollments; warn when compliance modules are missing or unenrolled without a required list, when completion is below `min_completion_pct`, when zero enrollments coincide with truncated or unreadable enrollment data, when completion was computed over an enrollment list that hit `enrollment_limit` (`completion_data_partial`), or when enrollments or uploaded policies are unreadable; pass otherwise; manual when training campaigns are unreadable |
| 18. Inactive user cleanup | `knowbe4_assess_user_risk` | `KNOWBE4-18` | fail when active users show no delivered phishing test, training activity, or sign-in in `inactive_days`; warn when activity data was partial, the user list hit `user_limit`, the API returned no active users, the share is 5% or less, or security tests, recipient results, or enrollments (the activity signals) are unreadable; pass otherwise; manual when users are unreadable |
| 19. Phishing report rate | `knowbe4_assess_phishing_program` | `KNOWBE4-19` | pass when `reported_count / delivered_count` across recent tests meets `min_report_rate_pct`; warn above half the target or when the configured PhishER inbox is unreadable; fail below; PhishER message counts are attached when a PhishER key is configured, and a PhishER listing truncated at `phisher_message_limit` is stated in the summary and evidence (messages loaded versus `totalCount`) without changing the verdict, because the rate comes from the security test counters; manual when security tests are unreadable |
| 20. Campaign scheduling regularity | `knowbe4_assess_phishing_program` | `KNOWBE4-20` | measures gaps between consecutive tests in `lookback_days` (anchored on the last test before the window) plus the gap from the latest test to now; pass when no gap exceeds `max_schedule_gap_days`; fail otherwise, including when the program stopped running tests or never ran one; manual when security tests are unreadable |

## Framework mappings

Each finding carries eight mappings from the spec's compliance table: FedRAMP (NIST SP 800-53), CMMC Level 2, SOC 2, CIS Controls v8, PCI-DSS, DISA STIG SRG, IRAP (ISM), and ISMAP. For example `KNOWBE4-01` maps to `FedRAMP AT-2(1)`, `CMMC L2 3.2.1`, `SOC 2 CC1.4`, `CIS Controls v8 14.1`, `PCI-DSS 12.6.2`, `DISA STIG SRG-APP-000516`, `IRAP ISM-0252`, and `ISMAP HR-01`. The audit bundle writes one report per framework under `compliance/` and a unified matrix that lists all twenty controls with their statuses.

## Live smoke test

```bash
KNOWBE4_API_TOKEN=... KNOWBE4_REGION=us npm --prefix cli run test:knowbe4:live
```

The script skips with exit code 0 when no Reporting API key or config file is present. Otherwise it runs `knowbe4_check_access` and the account governance assessment with PII redaction enabled, printing the readable surfaces, the five governance findings, and the number of API requests consumed.

## Limitations and manual controls

- Controls 13 (SSO), 14 (report review cadence), and 15 (USB drop tests) are `manual`. Their findings state the console evidence to collect: the SAML settings under Account Settings, scheduled report configurations and review records, and the USB Drive Test campaign list. The KSAT GraphQL API exposes `samlEnabled`, `forceMfa`, and `usbCampaigns` for entitled accounts and is a candidate for automating these later.
- Vishing (control 16) is evaluated through KnowBe4 callback phishing tests, which are the voice-channel simulation the Reporting API exposes with `campaign_type=callback`.
- Scoping a control out with `require_usb_tests: false` or `require_vishing_tests: false` renders it as `manual`, not `pass`, so framework reports never show a configuration flag as satisfied evidence. The finding text states that the control was scoped out and names the policy or risk-acceptance record that would satisfy it.
- Coverage (2), remediation (10), and inactivity (18) use recipient results from the most recent `security_test_sample_limit` tests. Older tests inside the window are reported as unsampled (`sampled_security_tests` and `unsampled_security_tests` in the evidence) and cap those verdicts at `warn` rather than `pass`.
- Every list read is capped: users by `user_limit`, enrollments by `enrollment_limit`, PhishER messages by `phisher_message_limit`, and the remaining inventories by an internal cap. The client reports a listing as truncated whenever the cap stopped it while more pages could exist, `core_data/collection_status.json` records `truncated`, `seen`, `total`, and `limit` per inventory, the collection result still exposes `user_limit_reached` and `enrollment_limit_reached`, and the assessment summaries repeat them. A finding whose verdict was computed over a truncated inventory degrades from `pass` to `warn` with `Truncated listing:` in its summary and `truncated_inventories` in its evidence (controls 2, 4, 5, 9, and 18 for the user list; 4, 10, and 17 for enrollments; every control for its own primary listing). Controls 3, 4, and 17 additionally treat a hit `enrollment_limit` as partial data: control 3 lists campaigns that fall back to enrollments (the `-1` sentinel) as unmeasurable, control 17 never passes on completion figures computed over the truncated list, and control 4 stays at `warn` instead of failing on missing enrollments. Recipient results that hit the cap for a single test are flagged with `recipients_truncated` on that test.
- An empty active user list is not a clean population. The Reporting API introduction states that anonymized accounts cannot retrieve user data, so when `/v1/users` returns nothing controls 2, 4, 5, and 18 warn with `user_list_empty: true` instead of passing on zero users.
- KnowBe4 has announced that the `page` parameter will be deprecated in November 2026 in favor of `per_page` and `cursor`. The client uses `page` and `per_page` today because the cursor response contract is not yet documented; switching to cursor pagination is a follow-up.
- Risk scores, phish-prone percentages, and admin lists are only as fresh as the Reporting API. There is no PII-free mode for `core_data/` other than `redact_pii`.

## Official documentation

- Reporting API overview, authentication, pagination, and rate limits: https://developer.knowbe4.com/rest/reporting
- Reporting API OpenAPI definition (endpoint paths, parameters, response fields): https://developer.knowbe4.com/elvis-swagger.yml
- PhishER GraphQL API: https://developer.knowbe4.com/graphql/phisher
- PhishER authentication: https://developer.knowbe4.com/pages/phisher/Authentication.md
- PhishER regional base URLs: https://developer.knowbe4.com/pages/phisher/Base-URL.md
- PhishER pagination: https://developer.knowbe4.com/pages/phisher/Pagination.md
- KSAT GraphQL API (SSO, MFA, and USB campaign fields referenced by the manual controls): https://developer.knowbe4.com/graphql/ksat
