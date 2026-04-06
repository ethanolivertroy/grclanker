---
slug: "veracode-sec-inspector"
name: "Veracode Security Inspector"
vendor: "Veracode"
category: "vulnerability-application-security"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/veracode-sec-inspector"
---

# Veracode Security Inspector - Architecture Specification

## 1. Overview

Veracode Security Inspector is a security compliance inspection tool for the Veracode Application Security Platform. It audits application scan coverage, policy compliance status, flaw aging, SCA library health, access controls, pipeline integration, and security program effectiveness across a Veracode enterprise account. The tool produces structured findings mapped to major compliance frameworks, enabling continuous compliance monitoring of application security programs.

Written in Go with a hybrid CLI/TUI architecture, it performs read-only inspection of Veracode platform data using both the REST and XML APIs and produces machine-readable JSON and human-readable reports.

## 2. APIs & SDKs

### Veracode REST APIs

| Service | Base URL | Key Endpoints | Purpose |
|---------|----------|---------------|---------|
| Applications API | `api.veracode.com/appsec/v1` | `/applications`, `/applications/{guid}`, `/applications/{guid}/sandboxes` | Application inventory and metadata |
| Findings API | `api.veracode.com/appsec/v2` | `/applications/{guid}/findings`, `/applications/{guid}/findings/{fid}` | SAST/DAST/SCA findings |
| Policy API | `api.veracode.com/appsec/v1` | `/policies`, `/policies/{guid}` | Policy definitions and compliance |
| Collections API | `api.veracode.com/appsec/v1` | `/collections`, `/collections/{guid}` | Application collections |
| Identity API | `api.veracode.com/api/authn/v2` | `/users`, `/users/{userId}`, `/teams`, `/teams/{teamId}`, `/roles` | User, team, and role management |
| SCA Agent API | `api.veracode.com/srcclr/v3` | `/workspaces`, `/workspaces/{id}/issues`, `/workspaces/{id}/libraries` | Software Composition Analysis |
| SCA (Linked) | `api.veracode.com/appsec/v2` | `/applications/{guid}/findings?scan_type=SCA` | SCA findings linked to applications |
| Summary Report API | `api.veracode.com/appsec/v2` | `/applications/{guid}/summary_report` | Most recent scan summary |

### Veracode XML APIs (Legacy)

| API | Endpoint | Purpose |
|-----|----------|---------|
| `getapplist.do` | `analysiscenter.veracode.com/api/5.0/getapplist.do` | Full application list (legacy) |
| `getbuildinfo.do` | `analysiscenter.veracode.com/api/5.0/getbuildinfo.do` | Build/scan status details |
| `detailedreport.do` | `analysiscenter.veracode.com/api/5.0/detailedreport.do` | Detailed scan report (XML) |
| `getprescanresults.do` | `analysiscenter.veracode.com/api/5.0/getprescanresults.do` | Prescan module selection results |
| `summaryreport.do` | `analysiscenter.veracode.com/api/5.0/summaryreport.do` | Summary scan report |

### API Details

- **Base URL**: `https://api.veracode.com` (US), `https://api.veracode.eu` (EU)
- **Pagination**: REST APIs use cursor-based pagination with `page` and `size` parameters; `_embedded` and `_links` (HAL format)
- **Rate Limits**: Documented as "fair use" with no published hard limits; in practice, sustained >100 req/s may trigger throttling
- **Response Format**: JSON (REST APIs), XML (legacy APIs)
- **API Versioning**: REST APIs are versioned in the URL path; XML APIs are versioned (v5.0 is current)

### SDKs and Libraries

| Tool | Language | Package | Notes |
|------|----------|---------|-------|
| `veracode-api-signing` | Go | `github.com/veracode/veracode-hmac-go` | Official HMAC signing library for Go |
| `veracode-api-py` | Python | `pip install veracode-api-py` | Community Python wrapper (widely used) |
| `veracode-hmac-python` | Python | `veracode_api_signing` | Official HMAC signing for Python |
| Veracode CLI | Binary | `veracode` | Official CLI for pipeline scans (upload, results) |
| Veracode API Wrappers | Various | Community maintained | REST and XML API wrappers in Java, .NET, Ruby |

## 3. Authentication

### HMAC-SHA-256 Request Signing

Veracode uses a custom HMAC-SHA-256 signature scheme (not bearer tokens, not OAuth). Every API request must be signed using an API ID and API Key pair.

| Component | Description |
|-----------|-------------|
| **API ID** | 32-character hex identifier (e.g., `a1b2c3d4e5f6...`) |
| **API Key** | 128-character hex secret key |
| **Signing Algorithm** | HMAC-SHA-256 with derived signing key |
| **Header** | `Authorization: VERACODE-HMAC-SHA-256 id={id},ts={timestamp},nonce={nonce},sig={signature}` |

### Signing Process

1. Generate a nonce (unique random hex string)
2. Compute timestamp (Unix epoch in milliseconds)
3. Derive signing key: `HMAC(HMAC(HMAC(HMAC(nonce, api_key), timestamp), "vcode_request_version_1"), "vcode_hmac_sha_256")`
4. Compute signature: `HMAC(signing_key, "id={id}&host={host}&url={url}&method={method}")` (lowercase hex)
5. Construct Authorization header with id, ts, nonce, sig fields

### Credential Storage

Credentials are stored in `~/.veracode/credentials`:

```ini
[default]
veracode_api_key_id = <api_id>
veracode_api_key_secret = <api_key>

[production]
veracode_api_key_id = <api_id>
veracode_api_key_secret = <api_key>
```

### Configuration Precedence

1. CLI flags (`--api-id`, `--api-key`)
2. Environment variables (`VERACODE_API_KEY_ID`, `VERACODE_API_KEY_SECRET`)
3. Credentials file (`~/.veracode/credentials`) with profile selection
4. Default profile: `default`

### Required Permissions

The API credentials require the following Veracode roles:
- **Security Lead** or **Results API** role: Read applications, findings, reports
- **Admin API** role: Read users, teams, roles (for access control audits)
- **Workspace Admin** or **Workspace Editor**: Read SCA workspace data

## 4. Security Controls

1. **Application scan coverage** - Verify all registered applications have at least one completed SAST scan in the last 90 days; flag applications with no recent scan
2. **Policy compliance status** - Check policy evaluation results for all applications; flag applications that do not pass their assigned policy
3. **Flaw aging (days open)** - Identify open flaws exceeding age thresholds: 30 days (Very High), 60 days (High), 90 days (Medium), 180 days (Low); flag critical flaws open >30 days
4. **Scan frequency compliance** - Verify applications are scanned at intervals meeting organizational policy (e.g., weekly for critical apps, monthly for others)
5. **SCA library currency** - Check third-party libraries for known vulnerabilities and outdated versions; flag libraries with CVSS 7.0+ vulnerabilities
6. **SCA license risk** - Identify open-source libraries with restrictive or copyleft licenses (GPL, AGPL) in commercial applications
7. **Team access controls** - Verify team-to-application mappings follow least privilege; flag teams with access to all applications
8. **User role audit** - Enumerate users by role; flag accounts with Administrator role, inactive users (no login in 90 days), and service accounts without team assignment
9. **API credential management** - Identify API credentials and their associated users; flag credentials older than 365 days
10. **Sandbox usage** - Verify development teams use sandboxes for pre-policy scans; flag applications with no sandbox activity
11. **Prescan module coverage** - Check that prescan module selection includes all relevant modules; flag scans with <80% module selection
12. **Mitigation approval workflow** - Audit mitigation proposals; flag mitigations that are proposed but not reviewed/approved, and bulk mitigations without justification
13. **Dynamic scan configuration** - Verify DAST scan configurations include authentication, sufficient crawl scope, and appropriate scan depth
14. **Pipeline integration status** - Check for recent pipeline scans (IDE, CI/CD) per application; flag applications relying only on manual upload
15. **Custom policy profiles** - Verify organization uses custom policies (not just Veracode default); check policy severity thresholds and grace periods match organizational requirements
16. **Finding false positive rate** - Analyze ratio of mitigated-as-false-positive findings; flag applications with >20% false positive rate (may indicate scan tuning issues)
17. **Very High/High flaw density** - Calculate flaw density (flaws per KLOC) for each application; flag applications exceeding organizational threshold
18. **SCA workspace coverage** - Verify all applications with third-party dependencies have associated SCA agent workspaces
19. **Scan completion rate** - Check for failed or incomplete scans; flag applications with repeated scan failures
20. **Collections compliance posture** - Analyze application collections for aggregate policy compliance; flag collections where >20% of applications are non-compliant

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS Controls v8 | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----------------|---------|------|------|-------|
| 1 | Application scan coverage | SA-11 | L2 3.14.1 | CC7.1 | 16.12 | 6.5 | SRG-APP-000456 | ISM-1143 | VM-01 |
| 2 | Policy compliance status | SA-11(1) | L2 3.14.3 | CC7.1 | 16.2 | 6.3 | SRG-APP-000456 | ISM-1143 | VM-02 |
| 3 | Flaw aging | SI-2 | L2 3.14.1 | CC7.1 | 7.4 | 6.3.3 | SRG-APP-000456 | ISM-1143 | VM-03 |
| 4 | Scan frequency | SA-11 | L2 3.14.1 | CC7.1 | 16.12 | 6.5.6 | SRG-APP-000456 | ISM-1143 | VM-01 |
| 5 | SCA library currency | SA-11(2) | L2 3.14.2 | CC7.1 | 16.4 | 6.3.2 | SRG-APP-000454 | ISM-1490 | VM-04 |
| 6 | SCA license risk | SA-4(2) | L2 3.4.2 | CC3.2 | 2.2 | 6.3.2 | SRG-APP-000516 | ISM-1490 | RM-01 |
| 7 | Team access controls | AC-6 | L2 3.1.5 | CC6.3 | 6.8 | 7.2.2 | SRG-APP-000340 | ISM-0432 | AC-01 |
| 8 | User role audit | AC-6(5) | L2 3.1.5 | CC6.3 | 5.4 | 7.2.1 | SRG-APP-000340 | ISM-0432 | AC-02 |
| 9 | API credential management | IA-5(1) | L2 3.5.8 | CC6.1 | 5.2 | 8.6.3 | SRG-APP-000174 | ISM-1590 | AM-01 |
| 10 | Sandbox usage | SA-11 | L2 3.14.1 | CC8.1 | 16.7 | 6.5 | SRG-APP-000456 | ISM-1143 | SD-01 |
| 11 | Prescan module coverage | SA-11 | L2 3.14.1 | CC7.1 | 16.12 | 6.5 | SRG-APP-000456 | ISM-1143 | VM-01 |
| 12 | Mitigation approval workflow | SI-2 | L2 3.14.1 | CC7.4 | 7.2 | 6.3.3 | SRG-APP-000456 | ISM-1143 | VM-05 |
| 13 | Dynamic scan configuration | SA-11(8) | L2 3.14.6 | CC7.1 | 16.6 | 6.6 | SRG-APP-000456 | ISM-1143 | VM-06 |
| 14 | Pipeline integration | SA-11 | L2 3.14.1 | CC8.1 | 16.12 | 6.5.6 | SRG-APP-000456 | ISM-1143 | SD-02 |
| 15 | Custom policy profiles | SA-11(1) | L2 3.14.3 | CC7.1 | 16.2 | 6.3 | SRG-APP-000516 | ISM-1143 | VM-02 |
| 16 | False positive rate | SA-11 | L2 3.14.1 | CC7.1 | 16.12 | 6.5 | SRG-APP-000456 | ISM-1143 | VM-07 |
| 17 | Flaw density | SA-11 | L2 3.14.1 | CC7.1 | 16.12 | 6.5 | SRG-APP-000456 | ISM-1143 | VM-03 |
| 18 | SCA workspace coverage | SA-11(2) | L2 3.14.2 | CC7.1 | 16.4 | 6.3.2 | SRG-APP-000454 | ISM-1490 | VM-04 |
| 19 | Scan completion rate | SA-11 | L2 3.14.1 | CC7.1 | 16.12 | 6.5 | SRG-APP-000456 | ISM-1143 | VM-01 |
| 20 | Collections compliance posture | SA-11(1) | L2 3.14.3 | CC7.1 | 16.2 | 6.3 | SRG-APP-000456 | ISM-1143 | VM-02 |

## 6. Existing Tools

| Tool | Type | Coverage | Limitations |
|------|------|----------|-------------|
| **Veracode Platform Analytics** | Native (Web UI) | Dashboards, trending, policy compliance views | Console-only; limited export; requires manual analysis for compliance mapping |
| **Veracode CLI** | Official CLI | Pipeline scan upload and results retrieval | Focused on individual scan operations; no cross-portfolio analysis or compliance reporting |
| **Veracode API Wrappers** | Community | REST and XML API access in Python/Java | Library-level access; no compliance logic or automated analysis |
| **veracode-api-py** | Community (Python) | Comprehensive API wrapper | Python wrapper only; no built-in analysis, reporting, or compliance mapping |
| **veracode-pipeline-scan** | Official | SAST pipeline scanning | Scan execution only; no portfolio-wide compliance assessment |
| **veracode-fix** | Official | AI-assisted flaw remediation | Fix suggestions only; no audit or compliance reporting |
| **Archer/ServiceNow integrations** | Enterprise | GRC platform integration | Heavyweight; requires separate GRC platform license and custom configuration |

### Differentiation

Veracode Security Inspector provides automated compliance auditing across an entire Veracode portfolio. Unlike Veracode's native dashboards (which focus on individual applications), this tool evaluates the security program holistically: scan coverage gaps, aging flaws, access control hygiene, SCA posture, and policy effectiveness. It maps findings to eight compliance frameworks, producing audit-ready reports from the command line.

## 7. Architecture

```
veracode-sec-inspector/
├── cmd/
│   └── veracode-sec-inspector/
│       └── main.go                    # Entry point, CLI parsing, TUI initialization
├── internal/
│   ├── analyzers/
│   │   ├── analyzer.go                # Analyzer interface and registry
│   │   ├── coverage.go                # Controls 1, 4, 11, 14, 19: Scan coverage, frequency, pipeline
│   │   ├── policy.go                  # Controls 2, 15, 20: Policy compliance, custom policies, collections
│   │   ├── flaws.go                   # Controls 3, 16, 17: Flaw aging, false positive rate, density
│   │   ├── sca.go                     # Controls 5, 6, 18: SCA library health, licenses, workspace coverage
│   │   ├── access.go                  # Controls 7, 8, 9: Teams, users, API credentials
│   │   ├── sandbox.go                 # Control 10: Sandbox usage analysis
│   │   ├── mitigation.go             # Control 12: Mitigation workflow audit
│   │   └── dynamic.go                # Control 13: DAST configuration analysis
│   ├── reporters/
│   │   ├── reporter.go                # Reporter interface
│   │   ├── json.go                    # JSON output (findings array, SARIF-compatible option)
│   │   ├── csv.go                     # CSV tabular output
│   │   ├── html.go                    # Styled HTML report with severity breakdown
│   │   ├── compliance.go              # Compliance matrix report (framework-mapped)
│   │   └── portfolio.go               # Portfolio-level summary report
│   ├── client/
│   │   ├── veracode.go                # Veracode API client (HMAC signing, base URL, HTTP methods)
│   │   ├── hmac.go                    # HMAC-SHA-256 signing implementation
│   │   ├── rest.go                    # REST API helpers (HAL pagination, JSON parsing)
│   │   ├── xml.go                     # XML API helpers (legacy API support)
│   │   └── ratelimit.go               # Rate limiter
│   ├── config/
│   │   ├── config.go                  # Configuration struct and loader
│   │   ├── defaults.go                # Default thresholds (flaw age, scan frequency, etc.)
│   │   └── credentials.go             # Veracode credentials file parser (~/.veracode/credentials)
│   ├── models/
│   │   ├── finding.go                 # Finding struct (severity, control, resource, evidence)
│   │   ├── severity.go                # Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
│   │   ├── compliance.go              # Compliance mapping structs
│   │   ├── application.go             # Veracode application model
│   │   ├── flaw.go                    # Flaw/finding model with CWE mapping
│   │   ├── policy.go                  # Policy model
│   │   └── sca.go                     # SCA workspace, library, issue models
│   └── tui/
│       ├── app.go                     # Bubble Tea TUI application
│       ├── views.go                   # TUI view components (portfolio, app detail, flaw list)
│       └── styles.go                  # Lip Gloss styling
├── pkg/
│   └── version/
│       └── version.go                 # Build version, commit, date (ldflags)
├── configs/
│   ├── controls.yaml                  # Control definitions and framework mappings
│   └── thresholds.yaml                # Configurable thresholds (flaw age, scan freq, etc.)
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── spec.md
└── README.md
```

### Key Design Decisions

- **HMAC signing**: Uses `github.com/veracode/veracode-hmac-go` (or custom implementation) for request signing per Veracode's custom HMAC-SHA-256 scheme
- **Dual API support**: REST APIs for modern endpoints (findings, identity); XML APIs for legacy-only data (prescan results, detailed reports)
- **HAL pagination**: REST APIs return HAL+JSON with `_embedded` and `_links`; the client auto-paginates using `_links.next`
- **Portfolio-level analysis**: Unlike per-app tools, analyzers aggregate findings across the entire application portfolio for program-level assessments
- **Finding deduplication**: Flaws that appear in both REST and XML API results are deduplicated by CWE + file + line
- **Credential isolation**: HMAC signing keys are never logged or included in report output; credentials file parsing redacts secrets in debug logs

## 8. CLI Interface

```
veracode-sec-inspector [command] [flags]

Commands:
  scan          Run security program inspection across Veracode portfolio
  report        Generate report from saved scan results
  list          List available controls, frameworks, applications, or policies
  version       Print version information

Scan Flags:
  --api-id string             Veracode API ID (or set VERACODE_API_KEY_ID)
  --api-key string            Veracode API Key (or set VERACODE_API_KEY_SECRET)
  --profile string            Credentials file profile (default: "default")
  --region string             API region: us, eu (default: us)
  --applications string       Comma-separated application GUIDs to inspect (default: all)
  --teams string              Comma-separated team names to scope inspection (default: all)
  --controls string           Comma-separated control IDs to run (default: all)
  --exclude-controls string   Comma-separated control IDs to skip
  --severity string           Minimum severity: CRITICAL,HIGH,MEDIUM,LOW,INFO (default: LOW)
  --include-sandboxes         Include sandbox scan data in analysis (default: false)
  --concurrency int           Number of parallel API requests (default: 5)
  --timeout duration          Maximum scan duration (default: 30m)

Output Flags:
  --output string             Output format: json, csv, html, compliance, table, portfolio (default: table)
  --output-file string        Write output to file (default: stdout)
  --sarif                     Output in SARIF format for CI integration
  --quiet                     Suppress progress output, print only results

Threshold Flags:
  --max-flaw-age-critical int   Max days for critical flaw before flagging (default: 30)
  --max-flaw-age-high int       Max days for high flaw before flagging (default: 60)
  --max-flaw-age-medium int     Max days for medium flaw before flagging (default: 90)
  --max-flaw-age-low int        Max days for low flaw before flagging (default: 180)
  --max-scan-age-days int       Max days since last scan before flagging (default: 90)
  --min-module-coverage-pct int Minimum prescan module selection % (default: 80)
  --max-fp-rate-pct int         Maximum false positive rate % (default: 20)
  --sca-cvss-threshold float    Minimum CVSS score to flag SCA issues (default: 7.0)

Global Flags:
  --log-level string          Log level: debug, info, warn, error (default: info)
  --no-color                  Disable colored output
  --tui                       Launch interactive TUI mode
  --config string             Config file path (default: ~/.veracode-inspector/config.yaml)
```

### Usage Examples

```bash
# Full portfolio scan with JSON output
veracode-sec-inspector scan --output json --output-file findings.json

# Scan specific applications, flaw analysis only
veracode-sec-inspector scan --applications guid1,guid2 \
  --controls 3,16,17 --output table

# Critical findings only, EU region, SARIF output for CI
veracode-sec-inspector scan --region eu --severity CRITICAL --sarif \
  --output-file results.sarif

# Portfolio summary with custom flaw aging thresholds
veracode-sec-inspector scan --max-flaw-age-critical 14 --max-flaw-age-high 30 \
  --output portfolio --output-file portfolio.html

# Using non-default credentials profile
veracode-sec-inspector scan --profile production --output html \
  --output-file report.html

# Interactive TUI mode
veracode-sec-inspector --tui

# List applications and their policy compliance
veracode-sec-inspector list applications --show-policy-status

# Generate compliance matrix for specific frameworks
veracode-sec-inspector report --input findings.json --output compliance \
  --frameworks fedramp,pci-dss,cmmc
```

## 9. Build Sequence

```bash
# 1. Initialize Go module
go mod init github.com/hackIDLE/veracode-sec-inspector

# 2. Add dependencies
go get github.com/spf13/cobra@latest
go get github.com/charmbracelet/bubbletea@latest
go get github.com/charmbracelet/lipgloss@latest
go get gopkg.in/yaml.v3@latest
go get go.uber.org/zap@latest
go get gopkg.in/ini.v1@latest
go get golang.org/x/time/rate@latest

# 3. Build
go build -ldflags "-X pkg/version.Version=$(git describe --tags --always) \
  -X pkg/version.Commit=$(git rev-parse HEAD) \
  -X pkg/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/veracode-sec-inspector ./cmd/veracode-sec-inspector

# 4. Run tests
go test ./... -v -race -coverprofile=coverage.out

# 5. Lint
golangci-lint run ./...

# 6. Docker build
docker build -t veracode-sec-inspector:latest .

# 7. Cross-compile
GOOS=linux GOARCH=amd64 go build -o bin/veracode-sec-inspector-linux-amd64 ./cmd/veracode-sec-inspector
GOOS=darwin GOARCH=arm64 go build -o bin/veracode-sec-inspector-darwin-arm64 ./cmd/veracode-sec-inspector
GOOS=windows GOARCH=amd64 go build -o bin/veracode-sec-inspector-windows-amd64.exe ./cmd/veracode-sec-inspector
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
