---
slug: "knowbe4-sec-inspector"
name: "KnowBe4 Security Inspector"
vendor: "KnowBe4"
category: "vulnerability-application-security"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/knowbe4-sec-inspector"
---

# KnowBe4 Security Inspector - Architecture Specification

## 1. Overview

KnowBe4 Security Inspector is a security compliance inspection tool for KnowBe4 Security Awareness Training and Simulated Phishing platforms. It audits phishing simulation coverage, training completion rates, user risk scores, campaign effectiveness, and organizational security awareness posture through the KnowBe4 Reporting API. The tool produces structured findings mapped to major compliance frameworks, enabling continuous monitoring of human-layer security controls.

Written in Go with a hybrid CLI/TUI architecture, it performs read-only inspection of KnowBe4 account configuration and metrics via the REST Reporting API and produces machine-readable JSON and human-readable reports.

## 2. APIs & SDKs

### KnowBe4 Reporting API v1

| Resource | Endpoint | Method | Purpose |
|----------|----------|--------|---------|
| Account | `/v1/account` | GET | Account-level settings, subscription, admin info |
| Users | `/v1/users` | GET | All users with risk scores, phish-prone %, status |
| Users (single) | `/v1/users/{userId}` | GET | Detailed user profile with training and phishing history |
| Groups | `/v1/groups` | GET | Group definitions and membership counts |
| Group Members | `/v1/groups/{groupId}/members` | GET | Users within a specific group |
| Phishing Campaigns | `/v1/phishing/campaigns` | GET | Phishing simulation campaign configurations |
| Phishing Campaign (single) | `/v1/phishing/campaigns/{campaignId}` | GET | Campaign details including template, schedule |
| Security Tests | `/v1/phishing/security_tests` | GET | Individual phishing test results per campaign |
| Security Test Results | `/v1/phishing/security_tests/{testId}/recipients` | GET | Per-recipient results (clicked, reported, opened) |
| Training Campaigns | `/v1/training/campaigns` | GET | Training campaign definitions and status |
| Training Enrollments | `/v1/training/enrollments` | GET | Per-user training enrollment and completion status |
| Training Campaign (single) | `/v1/training/campaigns/{campaignId}` | GET | Training campaign details including modules assigned |
| Store Purchases | `/v1/training/store_purchases` | GET | Content purchased from KnowBe4 ModStore |

### API Details

- **Base URLs**:
  - US: `https://us.api.knowbe4.com`
  - EU: `https://eu.api.knowbe4.com`
  - CA: `https://ca.api.knowbe4.com`
  - UK: `https://uk.api.knowbe4.com`
  - DE: `https://de.api.knowbe4.com`
- **Pagination**: Link header-based (`rel="next"`), default page size 500
- **Rate Limits**: Varies by subscription tier; typically 1000 requests per day for Reporting API
- **Response Format**: JSON
- **Filtering**: `?status=active`, `?group_id=`, `?campaign_id=`

### SDKs and Libraries

| Tool | Language | Package | Notes |
|------|----------|---------|-------|
| No official SDK | - | - | KnowBe4 provides REST API only; no official client libraries |
| `go-knowbe4` | Go | Custom HTTP client in this project | Thin wrapper over `net/http` with auth and pagination |
| `requests` | Python | `pip install requests` | Common choice for Python-based integrations |
| KnowBe4 CLI | - | - | No official CLI exists |

## 3. Authentication

### API Token Authentication

KnowBe4 uses a single API token (Bearer token) for authentication. The token is generated in the KnowBe4 admin console under **Account Settings > API**.

| Method | Header | Format |
|--------|--------|--------|
| Bearer Token | `Authorization` | `Bearer <api_token>` |

### Token Details

- Tokens are account-scoped (one token per KnowBe4 account)
- Tokens provide read-only access to the Reporting API
- Token does not expire but can be regenerated (invalidates previous token)
- No OAuth flow; token is static and manually provisioned
- Separate write-capable tokens exist for the User Events API (not used by this tool)

### Configuration Precedence

1. CLI flag (`--api-token`)
2. Environment variable (`KNOWBE4_API_TOKEN`)
3. Config file (`~/.knowbe4-inspector/config.yaml` with `api_token` field)

### Region Configuration

The API region must be specified to select the correct base URL:

1. CLI flag (`--region us|eu|ca|uk|de`)
2. Environment variable (`KNOWBE4_REGION`)
3. Config file (`~/.knowbe4-inspector/config.yaml` with `region` field)
4. Default: `us`

### Security Considerations

- The API token grants read access to all user PII (names, emails, department, risk scores)
- Token should be stored securely (environment variable or encrypted config)
- This tool never writes data or modifies KnowBe4 configuration
- Sensitive user fields (email, name) can be redacted in reports with `--redact-pii`

## 4. Security Controls

1. **Phishing simulation frequency** - Verify phishing campaigns run at least monthly; flag accounts with no campaign in the last 30 days
2. **Phishing simulation coverage** - Confirm phishing campaigns target all active users, not a subset; flag if <90% of active users were tested in the last 90 days
3. **Training completion rates** - Check that training campaign completion is above threshold (default 90%); flag campaigns with <80% completion
4. **Training enrollment timeliness** - Verify new users are enrolled in training within 30 days of account creation
5. **User risk score distribution** - Analyze organization-wide risk scores; flag accounts where mean risk score exceeds threshold or standard deviation is high
6. **Phish-prone percentage tracking** - Track organization phish-prone % over time; flag if current rate exceeds baseline or industry average (default threshold: 15%)
7. **Phishing failure rate trending** - Analyze click/fail rates across campaigns; flag upward trends (worsening security awareness)
8. **Group coverage analysis** - Verify all defined groups have been included in at least one phishing and one training campaign in the last 90 days
9. **Campaign targeting completeness** - Flag campaigns that target fewer than all active users when the policy requires full coverage
10. **Remedial training triggers** - Verify that users who fail phishing simulations are auto-enrolled in remedial training campaigns
11. **Training content currency** - Check that assigned training modules were published/updated within the last 12 months; flag stale content
12. **Admin role audit** - Enumerate users with admin access to the KnowBe4 console; flag accounts with excessive admin count (>3)
13. **SSO integration status** - Verify SSO/SAML is configured for admin console access (available via account settings check)
14. **Reporting frequency** - Check that phishing and training reports have been generated/reviewed at intervals meeting policy requirements
15. **USB test campaign execution** - Verify USB drop test campaigns have been conducted if policy requires physical security awareness testing
16. **Vishing campaign execution** - Verify voice phishing (vishing) campaigns are conducted per policy requirements
17. **Compliance training modules** - Confirm required compliance modules (HIPAA, PCI, GDPR, etc.) are assigned and completed by relevant user groups
18. **Inactive user cleanup** - Identify users in KnowBe4 marked as active who have not participated in any campaign for 180+ days
19. **Phishing report rate** - Analyze percentage of users who correctly report simulated phishing; flag if report rate is below threshold (default: 50%)
20. **Campaign scheduling regularity** - Verify phishing campaigns are scheduled with consistent intervals (no long gaps exceeding 45 days between campaigns)

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS Controls v8 | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----------------|---------|------|------|-------|
| 1 | Phishing simulation frequency | AT-2(1) | L2 3.2.1 | CC1.4 | 14.1 | 12.6.2 | SRG-APP-000516 | ISM-0252 | HR-01 |
| 2 | Phishing simulation coverage | AT-2(1) | L2 3.2.2 | CC1.4 | 14.2 | 12.6.2 | SRG-APP-000516 | ISM-0252 | HR-01 |
| 3 | Training completion rates | AT-2 | L2 3.2.1 | CC1.4 | 14.1 | 12.6.1 | SRG-APP-000516 | ISM-0252 | HR-02 |
| 4 | Training enrollment timeliness | AT-2 | L2 3.2.2 | CC1.4 | 14.2 | 12.6.1 | SRG-APP-000516 | ISM-0252 | HR-02 |
| 5 | User risk score distribution | RA-3 | L2 3.11.1 | CC3.2 | 14.4 | 12.6.2 | SRG-APP-000516 | ISM-0253 | RA-01 |
| 6 | Phish-prone % tracking | AT-2(1) | L2 3.2.3 | CC1.4 | 14.4 | 12.6.3.1 | SRG-APP-000516 | ISM-0252 | HR-03 |
| 7 | Failure rate trending | AT-2(1) | L2 3.2.3 | CC1.4 | 14.4 | 12.6.3.1 | SRG-APP-000516 | ISM-0252 | HR-03 |
| 8 | Group coverage | AT-2 | L2 3.2.2 | CC1.4 | 14.2 | 12.6.1 | SRG-APP-000516 | ISM-0252 | HR-01 |
| 9 | Campaign targeting | AT-2 | L2 3.2.2 | CC1.4 | 14.2 | 12.6.2 | SRG-APP-000516 | ISM-0252 | HR-01 |
| 10 | Remedial training triggers | AT-2(2) | L2 3.2.3 | CC1.4 | 14.3 | 12.6.3 | SRG-APP-000516 | ISM-0253 | HR-04 |
| 11 | Training content currency | AT-3 | L2 3.2.1 | CC1.4 | 14.1 | 12.6.1 | SRG-APP-000516 | ISM-0252 | HR-02 |
| 12 | Admin role audit | AC-6(5) | L2 3.1.5 | CC6.3 | 5.4 | 7.2.2 | SRG-APP-000340 | ISM-0432 | AC-01 |
| 13 | SSO integration | IA-2(1) | L2 3.5.3 | CC6.1 | 6.5 | 8.4.2 | SRG-APP-000149 | ISM-1401 | AM-01 |
| 14 | Reporting frequency | CA-7 | L2 3.12.3 | CC7.2 | 14.4 | 12.6.2 | SRG-APP-000516 | ISM-0253 | SO-01 |
| 15 | USB test campaigns | AT-2(1) | L2 3.2.1 | CC1.4 | 14.1 | 12.6.2 | SRG-APP-000516 | ISM-0252 | HR-05 |
| 16 | Vishing campaigns | AT-2(1) | L2 3.2.1 | CC1.4 | 14.1 | 12.6.2 | SRG-APP-000516 | ISM-0252 | HR-05 |
| 17 | Compliance training modules | AT-2 | L2 3.2.1 | CC1.4 | 14.1 | 12.6.1 | SRG-APP-000516 | ISM-0252 | HR-06 |
| 18 | Inactive user cleanup | AC-2(3) | L2 3.1.1 | CC6.2 | 5.3 | 8.1.4 | SRG-APP-000025 | ISM-1648 | AC-02 |
| 19 | Phishing report rate | AT-2(1) | L2 3.2.3 | CC1.4 | 14.4 | 12.6.3.1 | SRG-APP-000516 | ISM-0252 | HR-03 |
| 20 | Campaign scheduling regularity | AT-2 | L2 3.2.1 | CC1.4 | 14.1 | 12.6.2 | SRG-APP-000516 | ISM-0252 | HR-01 |

## 6. Existing Tools

| Tool | Type | Coverage | Limitations |
|------|------|----------|-------------|
| **KnowBe4 Console Reports** | Native (Web UI) | Full platform reporting, SAML, PhishER | Console-only; no CLI or API export of rendered reports; limited custom analysis |
| **KnowBe4 Executive Reports** | Native (PDF) | Phish-prone %, training completion summaries | PDF only; no machine-readable format; limited granularity |
| **PhishER** | Native add-on | Email triage, threat intelligence | Separate product; focused on incident response, not compliance auditing |
| **KnowBe4 Virtual Risk Officer (VRO)** | Native feature | Risk scoring, predictive risk | Requires Diamond/Platinum tier; scoring algorithm is opaque |
| **SCORM exports** | Standard | Training completion data | Requires LMS integration; not a real-time audit tool |
| **Custom API scripts** | Community | Ad-hoc querying of Reporting API | Fragmented; no compliance mapping; typically Python one-off scripts |

### Differentiation

KnowBe4 Security Inspector provides automated, continuous compliance auditing of security awareness program effectiveness. Unlike native console reports (which require manual export), this tool programmatically evaluates KnowBe4 metrics against configurable policy thresholds and maps findings to eight compliance frameworks. It bridges the gap between KnowBe4 platform data and GRC audit requirements.

## 7. Architecture

```
knowbe4-sec-inspector/
├── cmd/
│   └── knowbe4-sec-inspector/
│       └── main.go                    # Entry point, CLI parsing, TUI initialization
├── internal/
│   ├── analyzers/
│   │   ├── analyzer.go                # Analyzer interface and registry
│   │   ├── phishing.go                # Controls 1-2, 6-7, 9, 19-20: Phishing campaign analysis
│   │   ├── training.go                # Controls 3-4, 10-11, 17: Training completion and enrollment
│   │   ├── risk.go                    # Control 5: Risk score distribution analysis
│   │   ├── coverage.go                # Control 8: Group and user coverage across campaigns
│   │   ├── admin.go                   # Controls 12-13: Admin roles and SSO configuration
│   │   ├── reporting.go               # Control 14: Report generation frequency audit
│   │   ├── physical.go                # Controls 15-16: USB and vishing campaign checks
│   │   └── users.go                   # Control 18: Inactive user identification
│   ├── reporters/
│   │   ├── reporter.go                # Reporter interface
│   │   ├── json.go                    # JSON output (findings array)
│   │   ├── csv.go                     # CSV tabular output
│   │   ├── html.go                    # Styled HTML report with charts
│   │   ├── compliance.go              # Compliance matrix report (framework-mapped)
│   │   └── trend.go                   # Time-series trend report for phishing/training metrics
│   ├── client/
│   │   ├── knowbe4.go                 # KnowBe4 API client (auth, base URL, HTTP methods)
│   │   ├── pagination.go              # Link header pagination handler
│   │   └── ratelimit.go               # Rate limiter (daily quota tracking)
│   ├── config/
│   │   ├── config.go                  # Configuration struct and loader
│   │   ├── defaults.go                # Default thresholds (completion %, frequency days, etc.)
│   │   └── regions.go                 # Region-to-base-URL mapping
│   ├── models/
│   │   ├── finding.go                 # Finding struct (severity, control, resource, evidence)
│   │   ├── severity.go                # Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
│   │   ├── compliance.go              # Compliance mapping structs
│   │   ├── user.go                    # KnowBe4 user model
│   │   ├── campaign.go                # Phishing and training campaign models
│   │   └── metrics.go                 # Aggregated metric structs (phish-prone %, completion %)
│   └── tui/
│       ├── app.go                     # Bubble Tea TUI application
│       ├── views.go                   # TUI view components (dashboard, drill-down)
│       └── styles.go                  # Lip Gloss styling
├── pkg/
│   └── version/
│       └── version.go                 # Build version, commit, date (ldflags)
├── configs/
│   ├── controls.yaml                  # Control definitions and framework mappings
│   └── thresholds.yaml                # Configurable thresholds (completion %, frequency days)
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── spec.md
└── README.md
```

### Key Design Decisions

- **Custom HTTP client**: No official SDK exists; a thin Go HTTP client handles auth header injection, pagination (Link headers), and rate limit tracking
- **Rate limit awareness**: KnowBe4 Reporting API has daily quotas; the client tracks remaining calls and can pause/resume
- **PII handling**: User data (emails, names) flows through a redaction layer when `--redact-pii` is enabled
- **Trend analysis**: Phishing and training analyzers compute time-series metrics to detect worsening trends (not just point-in-time checks)
- **Multi-region**: Client supports all five KnowBe4 data center regions via configurable base URL

## 8. CLI Interface

```
knowbe4-sec-inspector [command] [flags]

Commands:
  scan          Run security awareness inspection
  report        Generate report from saved scan results
  list          List available controls, frameworks, or groups
  trends        Show phishing/training trend analysis
  version       Print version information

Scan Flags:
  --api-token string          KnowBe4 API token (or set KNOWBE4_API_TOKEN)
  --region string             API region: us, eu, ca, uk, de (default: us)
  --controls string           Comma-separated control IDs to run (default: all)
  --exclude-controls string   Comma-separated control IDs to skip
  --severity string           Minimum severity: CRITICAL,HIGH,MEDIUM,LOW,INFO (default: LOW)
  --lookback-days int         Analysis window in days (default: 90)
  --timeout duration          Maximum scan duration (default: 10m)

Output Flags:
  --output string             Output format: json, csv, html, compliance, table, trend (default: table)
  --output-file string        Write output to file (default: stdout)
  --redact-pii                Redact user emails and names in output
  --quiet                     Suppress progress output, print only results

Threshold Flags:
  --min-completion-pct float  Training completion threshold % (default: 90.0)
  --max-phish-prone-pct float Maximum acceptable phish-prone % (default: 15.0)
  --max-campaign-gap-days int Maximum days between phishing campaigns (default: 30)
  --min-report-rate-pct float Minimum phishing report rate % (default: 50.0)
  --max-admin-count int       Maximum admin users before flagging (default: 3)

Global Flags:
  --log-level string          Log level: debug, info, warn, error (default: info)
  --no-color                  Disable colored output
  --tui                       Launch interactive TUI mode
  --config string             Config file path (default: ~/.knowbe4-inspector/config.yaml)
```

### Usage Examples

```bash
# Full account scan with JSON output
knowbe4-sec-inspector scan --output json --output-file findings.json

# Scan EU region account, phishing controls only
knowbe4-sec-inspector scan --region eu --controls 1,2,6,7,9,19,20 --output table

# High severity findings with PII redacted
knowbe4-sec-inspector scan --severity HIGH --redact-pii --output html \
  --output-file report.html

# Custom thresholds for strict compliance
knowbe4-sec-inspector scan --min-completion-pct 95 --max-phish-prone-pct 10 \
  --max-campaign-gap-days 14

# Trend analysis over 180 days
knowbe4-sec-inspector trends --lookback-days 180 --output trend \
  --output-file trends.html

# Interactive TUI mode
knowbe4-sec-inspector --tui

# Generate compliance matrix
knowbe4-sec-inspector report --input findings.json --output compliance \
  --frameworks fedramp,cmmc,pci-dss
```

## 9. Build Sequence

```bash
# 1. Initialize Go module
go mod init github.com/hackIDLE/knowbe4-sec-inspector

# 2. Add dependencies
go get github.com/spf13/cobra@latest
go get github.com/charmbracelet/bubbletea@latest
go get github.com/charmbracelet/lipgloss@latest
go get gopkg.in/yaml.v3@latest
go get go.uber.org/zap@latest
go get golang.org/x/time/rate@latest

# 3. Build
go build -ldflags "-X pkg/version.Version=$(git describe --tags --always) \
  -X pkg/version.Commit=$(git rev-parse HEAD) \
  -X pkg/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/knowbe4-sec-inspector ./cmd/knowbe4-sec-inspector

# 4. Run tests
go test ./... -v -race -coverprofile=coverage.out

# 5. Lint
golangci-lint run ./...

# 6. Docker build
docker build -t knowbe4-sec-inspector:latest .

# 7. Cross-compile
GOOS=linux GOARCH=amd64 go build -o bin/knowbe4-sec-inspector-linux-amd64 ./cmd/knowbe4-sec-inspector
GOOS=darwin GOARCH=arm64 go build -o bin/knowbe4-sec-inspector-darwin-arm64 ./cmd/knowbe4-sec-inspector
GOOS=windows GOARCH=amd64 go build -o bin/knowbe4-sec-inspector-windows-amd64.exe ./cmd/knowbe4-sec-inspector
```

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build binary for current platform |
| `make test` | Run tests with race detection |
| `make lint` | Run golangci-lint |
| `make docker` | Build Docker image |
| `make release` | Cross-compile for linux/darwin/windows |
| `make clean` | Remove build artifacts |

## 10. Status

Not yet implemented. Spec only.
