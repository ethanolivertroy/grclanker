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

## Tools

| Tool | Purpose | Notable parameters |
| --- | --- | --- |
| `knowbe4_check_access` | Probes `/v1/account`, users, groups, phishing campaigns, security tests, training campaigns, enrollments, store purchases, and policies, plus PhishER when a key is configured. Reports `healthy` or `limited`. | auth parameters only |
| `knowbe4_assess_phishing_program` | Controls 1, 2, 6, 7, 9, 19, 20. | `lookback_days` (90), `max_campaign_gap_days` (30), `min_coverage_pct` (90), `max_phish_prone_pct` (15), `min_report_rate_pct` (50), `max_schedule_gap_days` (45), `require_full_targeting` (true), `security_test_sample_limit` (12), `phisher_message_limit` (1000) |
| `knowbe4_assess_training_program` | Controls 3, 4, 10, 11, 17. | `training_lookback_days` (365), `min_completion_pct` (90), `fail_completion_pct` (80), `enrollment_grace_days` (30), `remedial_window_days` (14), `max_content_age_days` (365), `required_compliance_topics`, `enrollment_limit` (20000) |
| `knowbe4_assess_user_risk` | Controls 5, 8, 18. | `max_mean_risk_score` (50), `max_risk_score_stddev` (25), `inactive_days` (180), `lookback_days` (90), `user_limit` (5000) |
| `knowbe4_assess_account_governance` | Controls 12, 13, 14, 15, 16. | `max_admin_count` (3), `require_usb_tests` (true), `require_vishing_tests` (true), `lookback_days` (90) |
| `knowbe4_export_audit_bundle` | Runs every assessment and writes an evidence bundle plus a `.zip`. | all of the above plus `output_dir` (default `./export/knowbe4`) |

Every assessment returns findings shaped as `{ id, control, title, severity, status, summary, evidence, mappings, manualEvidence }` with severity `critical`, `high`, `medium`, `low`, or `info` and status `pass`, `warn`, `fail`, or `manual`. Finding ids are `KNOWBE4-01` through `KNOWBE4-20` and match the spec control numbers. When a required endpoint is unreadable the affected findings degrade to `warn` with a `collection_error` in the evidence instead of failing the whole run.

### Audit bundle layout

```text
<account>-knowbe4-audit-bundle/
  QUICK_REFERENCE.md
  metadata.json
  core_data/          raw Reporting API (and PhishER) snapshots
  analysis/           findings.json, control_coverage.json, per-area json and md, access_check.md
  compliance/         executive_summary.md, unified_compliance_matrix.md,
                      fedramp/, cmmc/, soc2/, cis_controls/, pci_dss/, disa_stig/, irap/, ismap/
  _errors.log         only when some reads failed
<account>-knowbe4-audit-bundle.zip
```

Output paths are resolved inside `output_dir`; traversal outside the root and symlinked parent directories are rejected. Directories are created with mode `0700` and files with `0600`. Set `redact_pii` to pseudonymize emails and mask names, phone numbers, and IP addresses in `core_data/` and findings.

## Control coverage

| Spec control | Tool | Finding | Status semantics |
| --- | --- | --- | --- |
| 1. Phishing simulation frequency | `knowbe4_assess_phishing_program` | `KNOWBE4-01` | pass when the latest security test started within `max_campaign_gap_days`; fail otherwise or when no test has ever run |
| 2. Phishing simulation coverage | `knowbe4_assess_phishing_program` | `KNOWBE4-02` | pass when at least `min_coverage_pct` of active users appear as recipients of tests in `lookback_days`; warn when unsampled tests could hide coverage; fail otherwise |
| 3. Training completion rates | `knowbe4_assess_training_program` | `KNOWBE4-03` | pass when every completed campaign in `training_lookback_days` is at or above `min_completion_pct`; warn between `fail_completion_pct` and the target; fail below `fail_completion_pct` |
| 4. Training enrollment timeliness | `knowbe4_assess_training_program` | `KNOWBE4-04` | pass when users who joined in the window were enrolled within `enrollment_grace_days`; warn when the late share is 5% or less or enrollment collection was capped; fail otherwise |
| 5. User risk score distribution | `knowbe4_assess_user_risk` | `KNOWBE4-05` | fail when the mean `current_risk_score` exceeds `max_mean_risk_score`; warn when the standard deviation exceeds `max_risk_score_stddev` or no scores exist; pass otherwise |
| 6. Phish-prone percentage tracking | `knowbe4_assess_phishing_program` | `KNOWBE4-06` | fail when the delivered-weighted phish-prone percentage of recent tests exceeds `max_phish_prone_pct`; warn when above the program baseline; pass otherwise |
| 7. Phishing failure rate trending | `knowbe4_assess_phishing_program` | `KNOWBE4-07` | compares the older and newer halves of tests in twice `lookback_days`; fail when the newer half is more than 2 points worse, warn above 0.5 points or with fewer than four tests, pass otherwise |
| 8. Group coverage analysis | `knowbe4_assess_user_risk` | `KNOWBE4-08` | pass when every active group with members was targeted by a phishing and a training campaign in `lookback_days` (All Users counts); fail otherwise |
| 9. Campaign targeting completeness | `knowbe4_assess_phishing_program` | `KNOWBE4-09` | pass when an active campaign targets All Users or targeted groups cover `min_coverage_pct` of active users; fail when `require_full_targeting` is true and coverage is short |
| 10. Remedial training triggers | `knowbe4_assess_training_program` | `KNOWBE4-10` | pass when at least 90% of users who failed a sampled test more than `remedial_window_days` ago were enrolled afterwards (auto-enroll campaigns listed); warn from 50%; fail below |
| 11. Training content currency | `knowbe4_assess_training_program` | `KNOWBE4-11` | fail when assigned ModStore modules are retired; warn when modules were published more than `max_content_age_days` ago or none are assigned; pass otherwise |
| 12. Admin role audit | `knowbe4_assess_account_governance` | `KNOWBE4-12` | fail when console admins exceed `max_admin_count`; warn when an admin uses a domain outside the account's allowed domains; pass otherwise |
| 13. SSO integration status | `knowbe4_assess_account_governance` | `KNOWBE4-13` | manual: the Reporting API does not expose SAML or admin MFA settings |
| 14. Reporting frequency | `knowbe4_assess_account_governance` | `KNOWBE4-14` | manual: no API record of generated or reviewed reports; latest test and campaign dates are included as context |
| 15. USB test campaign execution | `knowbe4_assess_account_governance` | `KNOWBE4-15` | manual when `require_usb_tests` is true (USB Drive Tests are not in the Reporting API); pass when the policy does not require them |
| 16. Vishing campaign execution | `knowbe4_assess_account_governance` | `KNOWBE4-16` | pass when a callback phishing test (`campaign_type=callback`) started in `lookback_days`; fail when none did; manual when callback tests are unreadable; pass when not required |
| 17. Compliance training modules | `knowbe4_assess_training_program` | `KNOWBE4-17` | fail when a `required_compliance_topics` entry has no assigned module; warn when compliance modules are missing without a required list or completion is below `min_completion_pct`; pass otherwise |
| 18. Inactive user cleanup | `knowbe4_assess_user_risk` | `KNOWBE4-18` | fail when active users show no delivered phishing test, training activity, or sign-in in `inactive_days`; warn when activity data was partial or the share is 5% or less; pass otherwise |
| 19. Phishing report rate | `knowbe4_assess_phishing_program` | `KNOWBE4-19` | pass when `reported_count / delivered_count` across recent tests meets `min_report_rate_pct`; warn above half the target; fail below; PhishER message counts are attached when a PhishER key is configured |
| 20. Campaign scheduling regularity | `knowbe4_assess_phishing_program` | `KNOWBE4-20` | pass when no gap between consecutive tests in the last year exceeds `max_schedule_gap_days`; fail otherwise; warn with fewer than two tests |

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
- Coverage, remediation, and inactivity use recipient results from the most recent `security_test_sample_limit` tests. Older tests inside the window are reported as unsampled and turn coverage into `warn` rather than `fail`.
- User and enrollment reads are capped by `user_limit` and `enrollment_limit`; when a cap is reached the affected findings say so.
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
