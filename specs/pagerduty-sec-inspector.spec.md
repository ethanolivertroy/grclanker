---
slug: "pagerduty-sec-inspector"
name: "PagerDuty Security Inspector"
vendor: "PagerDuty"
category: "devops-developer-platforms"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/pagerduty-sec-inspector"
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

Not yet implemented. Spec only.
