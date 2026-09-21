---
slug: "pagerduty-sec-inspector"
name: "PagerDuty Security Inspector"
vendor: "PagerDuty"
category: "devops-developer-platforms"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
legacy_repo: "https://github.com/hackIDLE/pagerduty-sec-inspector"
reference_docs: "https://developer.pagerduty.com/api-reference/"
---

# PagerDuty Security Inspector

## 1. Overview

A security compliance inspection tool for **PagerDuty** incident management platforms. Audits authentication settings, user roles and access controls, service configurations, escalation policy coverage, audit logging, API key management, and integration security against enterprise security baselines and compliance frameworks.

PagerDuty is a critical incident response platform; misconfigurations can lead to missed alerts, unauthorized access to incident data, or gaps in on-call coverage. This tool uses the PagerDuty REST API v2 to evaluate security posture.

## 2. APIs & SDKs

### PagerDuty REST API v2

Base URL: `https://api.pagerduty.com`

| Endpoint | Purpose |
|----------|---------|
| `GET /users` | List all users with contact info, roles |
| `GET /users/{id}` | User detail including role, teams |
| `GET /users/{id}/contact_methods` | User contact methods (phone, email, push) |
| `GET /users/{id}/notification_rules` | User notification preferences |
| `GET /users/{id}/sessions` | Active user sessions |
| `GET /teams` | List all teams |
| `GET /teams/{id}/members` | Team membership |
| `GET /services` | List all services with config |
| `GET /services/{id}` | Service detail (urgency, acknowledgement timeout) |
| `GET /services/{id}/integrations` | Service integrations (inbound) |
| `GET /escalation_policies` | List all escalation policies |
| `GET /escalation_policies/{id}` | Policy detail with escalation rules |
| `GET /schedules` | List all on-call schedules |
| `GET /schedules/{id}` | Schedule detail with layers, overrides |
| `GET /oncalls` | Current on-call entries |
| `GET /response_plays` | Automated response configurations |
| `GET /audit/records` | Audit trail of admin actions |
| `GET /analytics/incidents` | Incident analytics and metrics |
| `GET /analytics/services` | Service-level analytics |
| `GET /addons` | Installed add-ons/extensions |
| `GET /abilities` | Account feature abilities (SSO, etc.) |
| `GET /tags` | Tags for resource organization |
| `GET /vendors` | Integration vendor catalog |
| `GET /extensions` | Outbound extensions (webhooks) |
| `GET /webhooks/subscriptions` | V3 webhook subscriptions |
| `GET /business_services` | Business service definitions |

### Rate Limits

- Account-level: 960 requests/minute (16 req/s)
- Per-user API key: 960 requests/minute
- Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- Pagination: cursor-based (`offset` + `limit`, max 100 per page)

### SDKs & Tools

| Tool | Type | Notes |
|------|------|-------|
| `pdpyras` | Official Python SDK | REST API wrapper with session management |
| `go-pagerduty` | Community Go SDK | Full API coverage, actively maintained |
| `pd` CLI | Official CLI | Interactive + scripted PagerDuty management |
| `terraform-provider-pagerduty` | Official Terraform | Infrastructure-as-code for PD config |

## 3. Authentication

### API Key Authentication

#### Account-Level API Key (Recommended for Inspection)
- Generated in PagerDuty web UI: Settings → API Access → Create New API Key
- Full read access to all account resources
- Header: `Authorization: Token token=<API_KEY>`
- Read-only key is sufficient for inspection

#### User-Level API Key
- Scoped to individual user's permissions
- May not have visibility into all resources
- Same header format

### OAuth 2.0

- App registration in PagerDuty Developer portal
- Authorization Code flow with PKCE
- Scopes: granular per-resource (e.g., `users.read`, `services.read`)
- Token endpoint: `https://identity.pagerduty.com/oauth/token`

### Configuration

```
PAGERDUTY_API_KEY=<account_api_key>
PAGERDUTY_BASE_URL=https://api.pagerduty.com  # default
PAGERDUTY_USER_EMAIL=<requester_email>          # required for some endpoints
```

## 4. Security Controls

| # | Control | API Source | Severity |
|---|---------|-----------|----------|
| 1 | SSO enforcement enabled for account | `GET /abilities` → check for `sso` | Critical |
| 2 | User roles follow least privilege (minimal admins) | `GET /users` → `role` field analysis | Critical |
| 3 | No users with `owner` role beyond account owner | `GET /users` → `role = 'owner'` | High |
| 4 | Team-based access configured (users assigned to teams) | `GET /users` + `GET /teams/{id}/members` | High |
| 5 | All services have escalation policies assigned | `GET /services` → `escalation_policy` | Critical |
| 6 | Escalation policies have multiple escalation levels | `GET /escalation_policies` → `escalation_rules` count | High |
| 7 | Escalation policies do not terminate without notification | `GET /escalation_policies` → final rule analysis | High |
| 8 | On-call schedules provide 24/7 coverage (no gaps) | `GET /schedules` → `final_schedule` gap analysis | High |
| 9 | On-call schedule has multiple participants (no single point) | `GET /schedules` → `schedule_layers` user count | Medium |
| 10 | Incident response plays configured for critical services | `GET /response_plays` | Medium |
| 11 | Audit logging is active and accessible | `GET /audit/records` → verify records exist | High |
| 12 | Audit log retention meets compliance requirements | `GET /audit/records` → oldest record date check | Medium |
| 13 | API keys are rotated (no keys older than 90 days) | `GET /audit/records` → key creation events | High |
| 14 | Webhook endpoints use HTTPS | `GET /extensions` + `GET /webhooks/subscriptions` → URL scheme | High |
| 15 | Webhook signatures verified (HMAC) | `GET /webhooks/subscriptions` → `delivery_method` config | Medium |
| 16 | Integration permissions are scoped appropriately | `GET /services/{id}/integrations` → integration type review | Medium |
| 17 | Notification rules configured for all users | `GET /users/{id}/notification_rules` for each user | Medium |
| 18 | Contact methods verified for all on-call users | `GET /users/{id}/contact_methods` for on-call users | High |
| 19 | Service urgency rules configured (not all high) | `GET /services` → `incident_urgency_rule` | Low |
| 20 | Custom incident priorities defined and used | `GET /priorities` | Low |
| 21 | Service dependencies mapped for impact analysis | `GET /business_services` + `GET /service_dependencies` | Medium |
| 22 | Acknowledgement timeouts configured on services | `GET /services` → `acknowledgement_timeout` | Medium |
| 23 | Auto-resolve timeouts configured on services | `GET /services` → `auto_resolve_timeout` | Low |
| 24 | Analytics access restricted to appropriate roles | `GET /abilities` → analytics capability check | Medium |
| 25 | Change events tracking enabled for services | `GET /services/{id}` → change event integration | Low |

## 5. Compliance Framework Mappings

| Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---------|---------|------|-------|-----|---------|------|------|-------|
| 1. SSO enforcement | IA-2 | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 2. Least privilege roles | AC-6(1) | AC.L2-3.1.5 | CC6.3 | 6.1 | 7.1.1 | SRG-APP-000340 | ISM-1508 | 8.1.2 |
| 3. Owner role restricted | AC-6(5) | AC.L2-3.1.5 | CC6.3 | 6.2 | 7.1.2 | SRG-APP-000340 | ISM-1508 | 8.1.3 |
| 4. Team-based access | AC-3 | AC.L2-3.1.2 | CC6.1 | 6.1 | 7.1.1 | SRG-APP-000033 | ISM-1508 | 8.1.1 |
| 5. Services have escalation policies | IR-4 | IR.L2-3.6.1 | CC7.3 | 17.1 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 16.1.1 |
| 6. Multi-level escalation | IR-4(1) | IR.L2-3.6.2 | CC7.3 | 17.2 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 16.1.2 |
| 7. Escalation terminates with notification | IR-4 | IR.L2-3.6.1 | CC7.3 | 17.1 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 16.1.1 |
| 8. 24/7 on-call coverage | IR-7 | IR.L2-3.6.1 | CC7.3 | 17.3 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 16.1.3 |
| 9. Multiple on-call participants | IR-7(1) | IR.L2-3.6.2 | CC7.3 | 17.3 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 16.1.3 |
| 10. Response plays configured | IR-4(1) | IR.L2-3.6.2 | CC7.4 | 17.4 | 12.10.6 | SRG-APP-000516 | ISM-0043 | 16.1.4 |
| 11. Audit logging active | AU-2 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.1 | SRG-APP-000089 | ISM-0580 | 12.1.1 |
| 12. Audit log retention | AU-11 | AU.L2-3.3.1 | CC7.2 | 8.3 | 10.7 | SRG-APP-000515 | ISM-0859 | 12.1.2 |
| 13. API key rotation | IA-5(1) | IA.L2-3.5.10 | CC6.1 | 4.4 | 8.2.4 | SRG-APP-000174 | ISM-1557 | 8.2.4 |
| 14. HTTPS webhooks | SC-8(1) | SC.L2-3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0487 | 10.1.1 |
| 15. Webhook HMAC signatures | SC-8(1) | SC.L2-3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0487 | 10.1.1 |
| 16. Integration scoping | AC-6 | AC.L2-3.1.1 | CC6.3 | 6.1 | 7.1.1 | SRG-APP-000033 | ISM-1508 | 8.1.1 |
| 17. Notification rules configured | IR-6 | IR.L2-3.6.1 | CC7.3 | 17.5 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 16.1.5 |
| 18. Contact methods verified | IR-7 | IR.L2-3.6.1 | CC7.3 | 17.5 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 16.1.5 |
| 19. Service urgency configured | IR-4 | IR.L2-3.6.1 | CC7.3 | 17.6 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 16.1.1 |
| 20. Incident priorities defined | IR-4 | IR.L2-3.6.1 | CC7.4 | 17.6 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 16.1.1 |
| 21. Service dependencies mapped | CM-8 | CM.L2-3.4.1 | CC3.1 | 2.1 | 2.4 | SRG-APP-000141 | ISM-1284 | 6.1.1 |
| 22. Ack timeouts configured | IR-4 | IR.L2-3.6.1 | CC7.3 | 17.1 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 16.1.1 |
| 23. Auto-resolve timeouts | IR-4 | IR.L2-3.6.1 | CC7.3 | 17.1 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 16.1.1 |
| 24. Analytics access restricted | AC-6 | AC.L2-3.1.1 | CC6.3 | 6.1 | 7.1.1 | SRG-APP-000033 | ISM-1508 | 8.1.1 |
| 25. Change event tracking | CM-3 | CM.L2-3.4.3 | CC8.1 | 2.3 | 6.4.5 | SRG-APP-000128 | ISM-1211 | 6.2.1 |

## 6. Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| PagerDuty Admin Dashboard | Built-in | Manual review, no automation |
| PagerDuty Analytics | Built-in | Performance metrics, not security audit |
| PagerDuty Audit Records API | Built-in API | Raw audit data, no analysis |
| Terraform PagerDuty Provider | Open source IaC | Config-as-code but not audit-focused |
| Drata / Vanta | Commercial SaaS | PagerDuty integration for SOC 2 |
| **No open-source PagerDuty security inspector exists** | Gap | This tool fills the gap |

## 7. Architecture

```
pagerduty-sec-inspector/
├── cmd/
│   └── pagerduty-sec-inspector/
│       └── main.go                     # Entry point, CLI parsing
├── internal/
│   ├── auth/
│   │   ├── apikey.go                   # API key authentication
│   │   ├── oauth.go                    # OAuth 2.0 flow
│   │   └── config.go                   # Credential loading, validation
│   ├── client/
│   │   ├── pagerduty.go               # HTTP client with rate limiting, pagination
│   │   ├── users.go                    # User and contact method calls
│   │   ├── teams.go                    # Team membership calls
│   │   ├── services.go                # Service and integration calls
│   │   ├── escalation_policies.go     # Escalation policy calls
│   │   ├── schedules.go              # Schedule and on-call calls
│   │   ├── audit.go                   # Audit record calls
│   │   ├── analytics.go              # Analytics calls
│   │   ├── extensions.go             # Extensions and webhook calls
│   │   └── abilities.go              # Account abilities/features
│   ├── analyzers/
│   │   ├── analyzer.go                # Analyzer interface definition
│   │   ├── authentication.go          # Control 1
│   │   ├── access_control.go          # Controls 2, 3, 4, 24
│   │   ├── incident_response.go       # Controls 5, 6, 7, 10, 19, 20
│   │   ├── oncall_coverage.go         # Controls 8, 9, 17, 18
│   │   ├── audit_logging.go           # Controls 11, 12, 13
│   │   ├── integration_security.go    # Controls 14, 15, 16
│   │   └── service_config.go          # Controls 21, 22, 23, 25
│   ├── models/
│   │   ├── finding.go                 # Security finding with severity, mapping
│   │   ├── compliance.go              # Framework mapping definitions
│   │   ├── user.go                    # User, contact method, notification structs
│   │   ├── service.go                 # Service, integration structs
│   │   └── schedule.go               # Schedule, on-call structs
│   └── reporters/
│       ├── reporter.go                # Reporter interface
│       ├── json.go                    # JSON output
│       ├── csv.go                     # CSV output
│       ├── html.go                    # HTML dashboard report
│       └── sarif.go                   # SARIF for CI/CD integration
├── pkg/
│   └── version/
│       └── version.go                 # Build version info
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── spec.md
└── README.md
```

### grclanker implementation

The Go layout above is the original standalone design. The shipped implementation is a single TypeScript module in grclanker, `cli/extensions/grc-tools/pagerduty.ts`, registered through `registerPagerdutyTools`. It exposes seven read-only tools:

| Tool | Controls |
|------|----------|
| `pagerduty_check_access` | Probes 14 read surfaces (abilities, users, teams, services, escalation policies, schedules, on-calls, audit records, extensions, webhook subscriptions, business services, priorities, incident workflows, change events) and reports missing permissions |
| `pagerduty_assess_access_control` | 1, 2, 3, 4, 24 |
| `pagerduty_assess_incident_response` | 5, 6, 7, 10, 19, 20, 22, 23 |
| `pagerduty_assess_oncall_coverage` | 8, 9, 17, 18 |
| `pagerduty_assess_audit_logging` | 11, 12, 13 |
| `pagerduty_assess_integration_security` | 14, 15, 16, 21, 25 |
| `pagerduty_export_audit_bundle` | All 25, written as `core_data/`, `analysis/`, `compliance/` (executive summary, unified matrix, one report per framework in section 5), `QUICK_REFERENCE.md`, `_errors.log`, and a `.zip` |

Findings use ids `PD-01` through `PD-25`, one per control, with status `pass`, `warn`, `fail`, or `manual` and the eight framework mappings from section 5. Regression coverage lives in `cli/tests/pagerduty.test.mjs`; `npm --prefix cli run test:pagerduty:live` runs a credential-gated smoke test against a real account.

## 8. CLI Interface

```
pagerduty-sec-inspector [flags]

Flags:
  --api-key string          PagerDuty API key (or PAGERDUTY_API_KEY env)
  --email string            Requester email for API calls (or PAGERDUTY_USER_EMAIL env)
  --base-url string         API base URL (default: https://api.pagerduty.com)
  --controls string         Comma-separated control IDs to run (default: all)
  --skip-controls string    Comma-separated control IDs to skip
  --severity string         Minimum severity: critical,high,medium,low (default: low)
  --format string           Output format: json,csv,html,sarif (default: json)
  --output string           Output file path (default: stdout)
  --include-analytics       Include analytics data in assessment
  --api-key-max-age int     Max API key age in days (default: 90)
  --schedule-coverage-days int  Days ahead to check on-call coverage (default: 30)
  --concurrency int         Max concurrent API requests (default: 10)
  --timeout duration        HTTP request timeout (default: 30s)
  --verbose                 Enable verbose/debug logging
  --version                 Print version and exit
  --help                    Show help
```

### Example Usage

```bash
# Full inspection with JSON output
pagerduty-sec-inspector --api-key "$PD_API_KEY" --email admin@company.com \
  --format json --output report.json

# Critical controls only, HTML report
pagerduty-sec-inspector --severity critical --format html --output dashboard.html

# On-call coverage check for next 60 days
pagerduty-sec-inspector --controls 5,6,7,8,9 --schedule-coverage-days 60 --format json

# CI/CD integration with SARIF
pagerduty-sec-inspector --format sarif --output results.sarif
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/pagerduty-sec-inspector

# 2. Add dependencies
go get github.com/PagerDuty/go-pagerduty

# 3. Define models and interfaces
#    - internal/models/finding.go (Finding struct, Severity enum)
#    - internal/models/compliance.go (framework mapping tables)
#    - internal/analyzers/analyzer.go (Analyzer interface)
#    - internal/reporters/reporter.go (Reporter interface)

# 4. Implement authentication
#    - internal/auth/config.go (env/flag loading)
#    - internal/auth/apikey.go (API key header injection)

# 5. Build API client
#    - internal/client/pagerduty.go (base client, rate limiter, paginator)
#    - internal/client/users.go, services.go, etc.

# 6. Implement analyzers
#    - internal/analyzers/authentication.go
#    - internal/analyzers/access_control.go
#    - ... (all 7 analyzer files)

# 7. Implement reporters
#    - internal/reporters/json.go, csv.go, html.go, sarif.go

# 8. Wire CLI entry point
#    - cmd/pagerduty-sec-inspector/main.go

# 9. Test and build
go test ./...
go build -ldflags "-X pkg/version.Version=$(git describe --tags)" \
  -o bin/pagerduty-sec-inspector ./cmd/pagerduty-sec-inspector/
```

## 10. Status

Implemented in grclanker (TypeScript) on 2026-09-21. All 25 controls in section 4 produce a finding; 22 are evaluated automatically from the REST API and 3 (controls 1, 13, and 24) always return `manual` findings that state the exact web app evidence to collect, because the API does not expose the underlying setting. Every finding carries the section 5 framework mappings. The tool set, tests, live smoke script, and integration guide (`src/content/docs/docs/integrations/pagerduty.md`) shipped together.

### Shipped

- Configuration precedence explicit arguments, then environment variables, then `~/.config/grclanker/pagerduty.json` (override with `PAGERDUTY_CONFIG_FILE`).
- Auth modes: REST API key (`Authorization: Token token=<key>`, account or user key, `PAGERDUTY_API_TOKEN`, `PAGERDUTY_API_KEY`, `PAGERDUTY_TOKEN`, or `PD_API_KEY`), pre-issued OAuth bearer token (`PAGERDUTY_ACCESS_TOKEN`), and Scoped OAuth client credentials (`PAGERDUTY_CLIENT_ID`, `PAGERDUTY_CLIENT_SECRET`, `PAGERDUTY_SUBDOMAIN`) exchanged at `https://identity.pagerduty.com/oauth/token` with the `as_account-<region>.<subdomain>` scope plus the `*.read` scopes each endpoint documents.
- US (`https://api.pagerduty.com`) and EU (`https://api.eu.pagerduty.com`) service regions via `PAGERDUTY_REGION` or an explicit `PAGERDUTY_BASE_URL`.
- API client with `Accept: application/vnd.pagerduty+json;version=2`, optional `From` header, classic `limit`/`offset`/`more` pagination with `total=true` capped at the documented 10,000 record ceiling, cursor pagination for audit records and incident workflow triggers, 429 and 5xx retry honoring `ratelimit-reset` and `Retry-After`, timeouts, and token redaction in error messages. Every list returns a collection that records whether it is complete, the server-reported total, and the truncation reason.
- Credential scope probe through `GET /users/me` (400 identifies an account-level key; a user-level key or OAuth user token reports its role) so findings that depend on a complete inventory can be downgraded when the credential only sees its own teams.
- Audit bundle with raw API snapshots, per-category analysis JSON, executive summary, unified compliance matrix, eight framework reports, quick reference, error log, and zip archive written through a traversal and symlink safe path resolver. The bundle directory and zip share one allocated name (`-2`, `-3` suffixes) so re-runs never overwrite an earlier archive.

### Verdict safety

Verdicts never pass on missing or partial evidence:

- Unreadable, forbidden, or errored endpoints yield `manual` with the cause and the web app evidence to collect.
- Empty inventories never pass: zero users, teams, services, escalation policies, schedules, or on-call entries are `manual`; zero incident workflows, priorities, or business services from a readable endpoint are `fail`; zero webhooks make controls 14 and 15 `manual` (not applicable). Control 15 passes only when `/extensions` was readable, the extension count is stated, none is a legacy generic webhook, and at least one v3 subscription has `active: true`.
- Plan-gated features (HTTP 402 or a plan message) and controls the API cannot observe (1, 13, 24) yield `manual`.
- Audit records, change events, and schedule entries missing a date are reported in a separate bucket, never counted as recent or as coverage, and cap the verdict at `warn`.
- Truncated collections (`user_limit`, `service_limit`, `audit_limit`, or the 10,000 record ceiling) and non-admin user-level credentials downgrade every would-be `pass` to `warn` with seen and total counts in the summary and `evidence.partial_view`.
- Enabling flags (`is_enabled`, `active`, `enabled`, `blacklisted`, `num_loops`, rule `targets`, user `role`, `extension_schema`, ability names) must be present and true; an absent or false flag never supports `pass`.

### Deviations from this spec, following the official docs

- Rate limit headers are `ratelimit-limit`, `ratelimit-remaining`, and `ratelimit-reset` (no `X-` prefix), per https://developer.pagerduty.com/docs/72d3b724589e3-rest-api-rate-limits.
- Pagination is classic `limit`/`offset` with a `more` flag on most index endpoints (max 100 per page, `offset + limit` no more than 10,000), and cursor based (`cursor`, `next_cursor`) only on the endpoints the docs list, including `GET /audit/records` and `GET /incident_workflows/triggers`, per https://developer.pagerduty.com/docs/rest-api-v2/pagination/.
- Control 10: `GET /response_plays` is no longer in the published OpenAPI reference, so the implementation reads `GET /incident_workflows` and `GET /incident_workflows/triggers` and treats any `response_play` reference still present on a service as legacy automation.
- Control 13: there is no REST endpoint that lists API keys or their creation dates. The finding is `manual`, supported by the distinct `method.truncated_token` values seen in audit records so an auditor can compare observed keys against the Integrations > API Access Keys page.
- Control 14 and 15: v3 webhook subscriptions live at `GET /webhook_subscriptions` (not `/webhooks/subscriptions`), and signature verification cannot be observed from the API. v3 deliveries are always signed with an HMAC-SHA256 `X-PagerDuty-Signature` header, so the finding passes when `/extensions` was readable, no unsigned legacy generic webhook extensions remain, and at least one subscription is `active`, and it asks the auditor to confirm receivers verify the signature.
- Control 11: an HTTP 402 from `GET /audit/records` means the plan lacks the Audit Trail feature; the finding is `manual` with a plan summary rather than `fail`, because the API cannot show whether logging is achieved another way.
- Control 16: `GET /services/{id}/integrations` is not a list endpoint; integrations are read through `include[]=integrations` on `GET /services`.
- Controls 17 and 18: notification rules and contact methods are read through `include[]=notification_rules,contact_methods` on `GET /users` instead of per-user calls. The API does not expose phone or SMS verification status, so control 18 checks that on-call users have enabled, non-blocked phone, SMS, or push methods and flags email-only users as `warn`.
- Control 21: business service dependencies are read from `GET /service_dependencies/business_services/{id}`.
- Control 12: PagerDuty documents 12 months of audit record retention, so the assessment probes the 11-to-12 month window and returns `manual` when the required retention exceeds 365 days.
- Control 1 and 24: `GET /abilities` reveals whether `sso` and analytics features are enabled but not whether SSO login is required or which roles can open Analytics, so both findings are `manual` with the abilities and user role counts attached as supporting evidence.

### Remaining

- CSV, HTML, and SARIF reporters from section 8 are not implemented; grclanker emits JSON analysis files and markdown reports.
- Controls 1, 13, and 24 stay `manual` until PagerDuty exposes SSO enforcement, API key inventory, or per-role analytics permissions through the REST API.
- The live smoke test has not been run against a real account in this repository; it skips when credentials are absent.
