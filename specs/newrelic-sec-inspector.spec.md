---
slug: "newrelic-sec-inspector"
name: "New Relic Security Inspector"
vendor: "New Relic"
category: "monitoring-logging-observability"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/newrelic-sec-inspector"
---

# New Relic Security Inspector — Architecture Specification

## 1. Overview

**newrelic-sec-inspector** is a security compliance inspection tool for New Relic environments. It audits authentication configurations, user access controls, API key management, data governance settings, and operational security posture across a New Relic organization via the NerdGraph GraphQL API and REST API v2. The tool produces structured findings mapped to major compliance frameworks, enabling security teams to identify misconfigurations and maintain continuous compliance.

Written in Go with a hybrid CLI/TUI architecture, it supports both automated pipeline execution (JSON/SARIF output) and interactive exploration of findings.

## 2. APIs & SDKs

### NerdGraph API (GraphQL)

| Query/Mutation | Purpose |
|----------------|---------|
| `{ actor { accounts { id name } } }` | List all accounts in the organization |
| `{ actor { users { userSearch { users { id email name type } } } } }` | Enumerate users and user types |
| `{ actor { apiAccess { key { ... } keySearch { keys { ... } } } } }` | API key inventory and metadata |
| `{ actor { account(id:) { nrql(query:) { results } } } }` | Execute NRQL queries (audit events, config data) |
| `{ actor { entitySearch(query:) { results { entities { ... } } } } }` | Search monitored entities |
| `alertsPoliciesSearch` | Alert policy configurations |
| `dashboardSearch` | Dashboard inventory and permissions |
| `logConfigurationsSearch` | Log obfuscation rules and patterns |
| `syntheticMonitorSearch` | Synthetic monitor configurations |

**Endpoint:** `https://api.newrelic.com/graphql`
- EU datacenter: `https://api.eu.newrelic.com/graphql`

### REST API v2

| Endpoint | Purpose |
|----------|---------|
| `GET /v2/users.json` | User listing with roles |
| `GET /v2/alerts_policies.json` | Alert policies |
| `GET /v2/alerts_conditions.json` | Alert conditions |
| `GET /v2/notification_channels.json` | Notification channel destinations |

**Base URL:** `https://api.newrelic.com` (US), `https://api.eu.newrelic.com` (EU)

### Audit via NRQL

```sql
-- Authentication events
SELECT * FROM NrAuditEvent WHERE actionIdentifier LIKE 'authentication%' SINCE 30 days ago

-- User management changes
SELECT * FROM NrAuditEvent WHERE actionIdentifier LIKE 'user%' SINCE 30 days ago

-- API key events
SELECT * FROM NrAuditEvent WHERE actionIdentifier LIKE 'api_key%' SINCE 30 days ago

-- Data retention changes
SELECT * FROM NrdbQuery WHERE query LIKE '%retention%' SINCE 30 days ago
```

### SDKs and Libraries

| Name | Language | Notes |
|------|----------|-------|
| `newrelic-client-go` | Go | Official Go client for NerdGraph and REST |
| `newrelic-api` | Python | Community Python wrapper |
| New Relic CLI (`newrelic`) | Go | Official CLI tool |
| Terraform Provider (`newrelic`) | HCL | Official IaC provider |

## 3. Authentication

### User API Key

```
Api-Key: NRAK-XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

- User API keys are scoped to a specific user and inherit their permissions
- Created via NerdGraph or the UI under User menu > API Keys
- The inspector requires a key from a user with **Organization Manager** or **Authentication Domain Manager** role

### Account ID

Required for NRQL queries and account-scoped operations. Multiple account IDs can be specified for multi-account organizations.

### Required Permissions

| Permission | Purpose |
|------------|---------|
| `organization.read` | Organization-level settings |
| `authentication_domain.read` | SSO/SAML configuration |
| `user_management.read` | User and role enumeration |
| `api_key.read` | API key inventory |
| `insights_query.run` | Execute NRQL audit queries |
| `alert_policies.read` | Alert configuration review |
| `dashboards.read` | Dashboard permission audit |

### Configuration

```bash
export NEW_RELIC_API_KEY="NRAK-XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
export NEW_RELIC_ACCOUNT_ID="1234567"
export NEW_RELIC_REGION="US"  # or "EU"
```

Alternatively, configure via `~/.newrelic-sec-inspector/config.yaml` or CLI flags.

## 4. Security Controls

1. **SSO/SAML Enforcement** — Verify SAML identity provider is configured and SSO is enforced on the authentication domain.
2. **User Type Least Privilege** — Ensure users are assigned the minimum user type (basic, core, full platform) required for their role.
3. **Admin User Minimization** — Detect excessive number of users with admin or organization manager roles.
4. **API Key Inventory** — Enumerate all user keys, ingest keys, and browser keys; identify keys with excessive scope.
5. **API Key Age** — Detect user API keys older than 90 days without rotation.
6. **Unused API Keys** — Identify API keys with no recent activity (via NrAuditEvent queries).
7. **Account Access Controls** — Verify users have access only to accounts required for their role.
8. **Cross-Account Access Restrictions** — Detect users with access to production and non-production accounts simultaneously.
9. **Alert Policy Coverage** — Ensure critical infrastructure entities have associated alert policies.
10. **Alert Notification Channels** — Verify alert notifications route to approved destinations (not personal email).
11. **Data Retention Settings** — Confirm data retention periods meet compliance requirements per data type.
12. **Log Obfuscation Rules** — Verify obfuscation rules are configured to mask PII, credentials, and sensitive data in logs.
13. **Synthetic Monitor Security** — Check that synthetic monitor scripts do not contain hardcoded credentials; verify secure credential storage.
14. **Dashboard Permissions** — Detect dashboards with overly broad sharing (public or org-wide for sensitive data).
15. **Logs in Context Security** — Verify application logs forwarded to New Relic do not contain plaintext secrets or tokens.
16. **Infrastructure Agent Configuration** — Check infrastructure agent settings for secure communication (TLS, proxy config).
17. **Applied Intelligence Sensitivity** — Review incident intelligence settings to prevent sensitive data exposure in correlations.
18. **Authentication Domain Configuration** — Verify authentication domain settings (provisioning type, user type management).
19. **Inactive User Accounts** — Detect user accounts that have not logged in within 90 days.
20. **Custom Role Permissions** — Audit custom roles for overly permissive capability grants.

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 | SSO/SAML Enforcement | IA-2 | AC.L2-3.1.1 | CC6.1 | 1.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | CPS-04 |
| 2 | User Type Least Privilege | AC-6 | AC.L2-3.1.5 | CC6.3 | 6.1 | 7.2.1 | SRG-APP-000340 | ISM-0432 | CPS-07 |
| 3 | Admin User Minimization | AC-6(5) | AC.L2-3.1.5 | CC6.3 | 6.2 | 7.2.2 | SRG-APP-000340 | ISM-1507 | CPS-07 |
| 4 | API Key Inventory | IA-5 | IA.L2-3.5.2 | CC6.1 | 5.1 | 8.6.1 | SRG-APP-000175 | ISM-1590 | CPS-05 |
| 5 | API Key Age | IA-5(1) | IA.L2-3.5.8 | CC6.1 | 5.2 | 8.6.3 | SRG-APP-000175 | ISM-1590 | CPS-05 |
| 6 | Unused API Keys | AC-2(3) | AC.L2-3.1.1 | CC6.2 | 5.3 | 8.1.4 | SRG-APP-000025 | ISM-1404 | CPS-07 |
| 7 | Account Access Controls | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.3 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 8 | Cross-Account Restrictions | AC-4 | AC.L2-3.1.3 | CC6.6 | 6.4 | 7.2.3 | SRG-APP-000039 | ISM-1148 | CPS-11 |
| 9 | Alert Policy Coverage | SI-4 | SI.L2-3.14.6 | CC7.2 | 8.1 | 10.6.1 | SRG-APP-000089 | ISM-0580 | CPS-10 |
| 10 | Alert Notification Channels | AU-5 | AU.L2-3.3.4 | CC7.3 | 8.2 | 10.6.1 | SRG-APP-000108 | ISM-0580 | CPS-10 |
| 11 | Data Retention Settings | AU-11 | AU.L2-3.3.1 | CC7.4 | 8.3 | 3.1 | SRG-APP-000515 | ISM-0859 | CPS-10 |
| 12 | Log Obfuscation Rules | SC-28 | SC.L2-3.13.16 | CC6.7 | 3.1 | 3.4 | SRG-APP-000231 | ISM-0457 | CPS-09 |
| 13 | Synthetic Monitor Security | IA-5(7) | IA.L2-3.5.10 | CC6.1 | 5.4 | 8.2.1 | SRG-APP-000175 | ISM-1590 | CPS-05 |
| 14 | Dashboard Permissions | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.5 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 15 | Logs in Context Security | SC-28 | SC.L2-3.13.16 | CC6.7 | 3.2 | 3.4 | SRG-APP-000231 | ISM-0457 | CPS-09 |
| 16 | Infrastructure Agent Config | SC-8 | SC.L2-3.13.8 | CC6.7 | 9.1 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-11 |
| 17 | Applied Intelligence Settings | SC-28 | SC.L2-3.13.16 | CC6.7 | 3.3 | 3.4.1 | SRG-APP-000231 | ISM-0457 | CPS-09 |
| 18 | Auth Domain Configuration | IA-2 | AC.L2-3.1.1 | CC6.1 | 1.2 | 8.3.2 | SRG-APP-000148 | ISM-1557 | CPS-04 |
| 19 | Inactive User Accounts | AC-2(3) | AC.L2-3.1.1 | CC6.2 | 7.1 | 8.1.4 | SRG-APP-000025 | ISM-1404 | CPS-07 |
| 20 | Custom Role Permissions | AC-6 | AC.L2-3.1.5 | CC6.3 | 6.6 | 7.2.2 | SRG-APP-000340 | ISM-0432 | CPS-07 |

## 6. Existing Tools

| Tool | Type | Limitations |
|------|------|-------------|
| New Relic Vulnerability Management | Built-in | Focuses on application vulnerabilities, not org config security |
| New Relic Terraform Provider | IaC | Enforces desired state but no compliance reporting or drift detection |
| New Relic CLI | CLI | Management tool, no security assessment capability |
| NerdGraph API Explorer | Interactive | Manual query tool, no automated assessment |
| Custom NRQL Dashboards | Dashboard | Can query audit events but no structured compliance mapping |

**Gap:** No existing tool provides automated security posture assessment of New Relic organization-level configurations mapped to compliance frameworks. newrelic-sec-inspector fills this gap.

## 7. Architecture

```
newrelic-sec-inspector/
├── cmd/
│   └── newrelic-sec-inspector/
│       └── main.go                 # Entrypoint, CLI bootstrap
├── internal/
│   ├── analyzers/
│   │   ├── analyzer.go             # Analyzer interface and registry
│   │   ├── sso.go                  # SSO/SAML enforcement checks
│   │   ├── users.go                # User type, admin, inactive user checks
│   │   ├── apikeys.go              # API key inventory, age, and usage
│   │   ├── access.go               # Account access and cross-account checks
│   │   ├── alerts.go               # Alert policy coverage and routing
│   │   ├── retention.go            # Data retention settings checks
│   │   ├── obfuscation.go          # Log obfuscation rule checks
│   │   ├── synthetics.go           # Synthetic monitor credential checks
│   │   ├── dashboards.go           # Dashboard permission audit
│   │   ├── logs.go                 # Logs in Context security checks
│   │   ├── infrastructure.go       # Infrastructure agent config checks
│   │   ├── roles.go                # Custom role permission audit
│   │   └── authdomain.go           # Authentication domain config checks
│   ├── client/
│   │   ├── client.go               # Unified API client (GraphQL + REST)
│   │   ├── graphql.go              # NerdGraph GraphQL client
│   │   ├── rest.go                 # REST API v2 client
│   │   ├── auth.go                 # API key authentication
│   │   ├── ratelimit.go            # Rate limiter (configurable)
│   │   └── region.go               # US/EU region resolution
│   ├── config/
│   │   ├── config.go               # Configuration loading and validation
│   │   └── redact.go               # Credential redaction for logging
│   ├── models/
│   │   ├── user.go                 # User, account, role models
│   │   ├── apikey.go               # API key models
│   │   ├── alert.go                # Alert policy/condition models
│   │   ├── entity.go               # Entity search result models
│   │   └── finding.go              # Finding severity/status model
│   ├── reporters/
│   │   ├── reporter.go             # Reporter interface
│   │   ├── json.go                 # JSON output
│   │   ├── sarif.go                # SARIF 2.1.0 output
│   │   ├── csv.go                  # CSV output
│   │   ├── table.go                # Terminal table output
│   │   └── html.go                 # HTML report with charts
│   └── tui/
│       ├── app.go                  # Bubble Tea TUI application
│       ├── views.go                # Finding detail views
│       └── styles.go               # Lip Gloss styling
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── spec.md
└── README.md
```

### Key Design Decisions

- **Dual API strategy**: NerdGraph (GraphQL) for modern endpoints, REST v2 for legacy endpoints not yet migrated
- **NRQL-based auditing**: Leverages NRQL queries against NrAuditEvent for historical security event analysis
- **Multi-account support**: Iterates across all accounts in the organization for comprehensive coverage
- **Region-aware**: Supports both US and EU datacenters with automatic endpoint resolution

## 8. CLI Interface

```
newrelic-sec-inspector [command] [flags]

Commands:
  scan        Run all or selected security analyzers
  list        List available analyzers and their descriptions
  version     Print version information

Scan Flags:
  --api-key string         New Relic User API key (env: NEW_RELIC_API_KEY)
  --account-id strings     Account ID(s) to scan (env: NEW_RELIC_ACCOUNT_ID)
  --region string          Region: US or EU (env: NEW_RELIC_REGION, default "US")
  --analyzers strings      Run specific analyzers (comma-separated)
  --exclude strings        Exclude specific analyzers
  --severity string        Minimum severity to report: critical,high,medium,low,info
  --format string          Output format: table,json,sarif,csv,html (default "table")
  --output string          Output file path (default: stdout)
  --tui                    Launch interactive TUI
  --no-color               Disable colored output
  --config string          Path to config file (default "~/.newrelic-sec-inspector/config.yaml")
  --timeout duration       API request timeout (default 30s)
  --audit-window duration  NRQL audit event lookback window (default 30d)
  --verbose                Enable verbose logging
```

### Usage Examples

```bash
# Full scan of all accounts
newrelic-sec-inspector scan

# Scan specific account with JSON output
newrelic-sec-inspector scan --account-id 1234567 --format json

# Scan only authentication controls
newrelic-sec-inspector scan --analyzers sso,users,apikeys

# Generate SARIF for CI/CD
newrelic-sec-inspector scan --format sarif --output results.sarif

# EU region scan
newrelic-sec-inspector scan --region EU

# Interactive TUI
newrelic-sec-inspector scan --tui
```

## 9. Build Sequence

```bash
# Prerequisites
go 1.22+

# Clone and build
git clone https://github.com/hackIDLE/newrelic-sec-inspector.git
cd newrelic-sec-inspector
go mod download
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o bin/newrelic-sec-inspector ./cmd/newrelic-sec-inspector/

# Run tests
go test ./...

# Build Docker image
docker build -t newrelic-sec-inspector .

# Run via Docker
docker run --rm \
  -e NEW_RELIC_API_KEY \
  -e NEW_RELIC_ACCOUNT_ID \
  -e NEW_RELIC_REGION \
  newrelic-sec-inspector scan --format json
```

### Makefile Targets

```
make build       # Build binary
make test        # Run tests
make lint        # Run golangci-lint
make docker      # Build Docker image
make release     # Build for all platforms (linux/darwin/windows, amd64/arm64)
```

## 10. Status

Not yet implemented. Spec only.
