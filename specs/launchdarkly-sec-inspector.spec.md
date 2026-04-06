---
slug: "launchdarkly-sec-inspector"
name: "LaunchDarkly Security Inspector"
vendor: "LaunchDarkly"
category: "devops-developer-platforms"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/launchdarkly-sec-inspector"
---

# LaunchDarkly Security Inspector — Architecture Specification

## 1. Overview

LaunchDarkly Security Inspector is a hybrid CLI/TUI tool that audits the security posture of a LaunchDarkly account. It connects to the LaunchDarkly REST API v2 to evaluate identity and access management, feature flag hygiene, API token lifecycle, audit logging, and integration security. The tool produces structured findings mapped to enterprise compliance frameworks and outputs reports in JSON, CSV, and HTML formats.

The inspector targets LaunchDarkly accounts on Pro and Enterprise plans where advanced RBAC, SSO, and audit log capabilities are available. It operates in read-only mode and requires no agent installation.

## 2. APIs & SDKs

### LaunchDarkly REST API v2

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v2/members` | GET | List all account members and their roles |
| `/api/v2/members/{id}` | GET | Get member details including MFA status |
| `/api/v2/teams` | GET | List teams and their member/role mappings |
| `/api/v2/teams/{teamKey}` | GET | Get team details and permissions |
| `/api/v2/roles` | GET | List custom roles and their policies |
| `/api/v2/roles/{customRoleKey}` | GET | Get custom role policy statements |
| `/api/v2/projects` | GET | List all projects and their settings |
| `/api/v2/projects/{projectKey}` | GET | Get project configuration and environments |
| `/api/v2/projects/{projectKey}/environments` | GET | List environments within a project |
| `/api/v2/projects/{projectKey}/flags` | GET | List feature flags with targeting rules |
| `/api/v2/projects/{projectKey}/flags/{flagKey}` | GET | Get flag details, variations, prerequisites |
| `/api/v2/auditlog` | GET | Query audit log entries with date/action filters |
| `/api/v2/tokens` | GET | List API access tokens and their scopes |
| `/api/v2/tokens/{id}` | GET | Get token details including last-used timestamp |
| `/api/v2/integrations` | GET | List configured integrations |
| `/api/v2/integrations/{integrationKey}` | GET | Get integration configuration details |
| `/api/v2/relay-proxy-configs` | GET | List relay proxy configurations |
| `/api/v2/account` | GET | Get account-level settings (SSO, MFA, plan) |
| `/api/v2/webhooks` | GET | List webhook configurations |
| `/api/v2/webhooks/{id}` | GET | Get webhook details including signing status |

**Base URL:** `https://app.launchdarkly.com` (commercial), `https://app.launchdarkly.us` (federal), `https://app.eu.launchdarkly.com` (EU)

**Rate Limits:** Default 10 requests/second; burst to 30. Rate limit headers: `X-Ratelimit-Route-Remaining`, `X-Ratelimit-Reset`.

### Python SDK

| Package | Version | Notes |
|---------|---------|-------|
| `launchdarkly-api` | latest (auto-generated) | OpenAPI-generated client; covers all REST API v2 endpoints |

The `launchdarkly-api` package is auto-generated from the LaunchDarkly OpenAPI specification. It provides typed models for all API resources but can also be bypassed in favor of direct HTTP calls via `httpx` for simpler dependency management.

## 3. Authentication

| Method | Header Format | Use Case |
|--------|--------------|----------|
| Personal access token | `Authorization: {token}` | Interactive CLI use, developer audits |
| Service access token | `Authorization: {token}` | Automated pipelines, scheduled scans |

**Token requirements:**
- Reader role at minimum for read-only inspection
- Admin or Owner role recommended for full account-level checks (SSO status, MFA enforcement)
- Custom role with `viewProject`, `viewMembers`, `viewRoles`, `viewAuditLog` actions for least-privilege scanning

**Configuration precedence:**
1. `--token` CLI flag
2. `LAUNCHDARKLY_API_TOKEN` environment variable
3. `~/.config/launchdarkly-sec-inspector/config.toml`

The tool never writes, modifies, or stores tokens beyond the current session. Tokens are redacted from all log output and reports.

## 4. Security Controls

| # | Control | API Source | Severity |
|---|---------|-----------|----------|
| 1 | SSO/SAML enforcement enabled for the account | `/api/v2/account` | Critical |
| 2 | MFA required for all members | `/api/v2/account`, `/api/v2/members` | Critical |
| 3 | No members with Owner role beyond minimum required | `/api/v2/members` | High |
| 4 | Custom roles follow least-privilege principle (no wildcard actions) | `/api/v2/roles` | High |
| 5 | Custom role policies deny sensitive actions by default | `/api/v2/roles/{key}` | High |
| 6 | All members assigned to teams (no orphaned members) | `/api/v2/members`, `/api/v2/teams` | Medium |
| 7 | Team permissions use custom roles, not built-in admin | `/api/v2/teams` | Medium |
| 8 | API access tokens have expiration dates set | `/api/v2/tokens` | Critical |
| 9 | No API tokens unused beyond 90 days (stale tokens) | `/api/v2/tokens` | High |
| 10 | Service tokens scoped to minimum required roles | `/api/v2/tokens` | High |
| 11 | Personal tokens limited to individual member scope | `/api/v2/tokens` | Medium |
| 12 | Audit log retention meets compliance requirements (>= 90 days queryable) | `/api/v2/auditlog` | High |
| 13 | Audit log events present for critical actions (role changes, member adds) | `/api/v2/auditlog` | Medium |
| 14 | Flag targeting rules do not expose individual user keys in production | `/api/v2/projects/{proj}/flags` | Medium |
| 15 | Stale flags identified (not evaluated in > 30 days) and flagged for cleanup | `/api/v2/projects/{proj}/flags` | Low |
| 16 | Environment-level access controls restrict production modifications | `/api/v2/projects/{proj}/environments` | High |
| 17 | Approval workflows enabled for production environment changes | `/api/v2/projects/{proj}/environments` | High |
| 18 | Relay proxy configurations use secure mode | `/api/v2/relay-proxy-configs` | High |
| 19 | SDK keys rotated within policy period (< 365 days) | `/api/v2/projects/{proj}/environments` | Medium |
| 20 | Integrations use least-privilege scopes | `/api/v2/integrations` | Medium |
| 21 | Webhook endpoints use HTTPS and signing is enabled | `/api/v2/webhooks` | High |
| 22 | No test/temporary projects in production account | `/api/v2/projects` | Low |
| 23 | Environment critical settings (secure mode, default TTL) configured | `/api/v2/projects/{proj}/environments` | Medium |
| 24 | Member email domains match organization domain policy | `/api/v2/members` | Medium |
| 25 | Flag prerequisites do not create circular dependencies | `/api/v2/projects/{proj}/flags` | Low |

## 5. Compliance Framework Mappings

| Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 SSO/SAML enforcement | IA-2(1) | L2 3.5.3 | CC6.1 | 16.2 | 8.4.1 | SRG-APP-000148 | ISM-1546 | CPS-7.1 |
| 2 MFA required | IA-2(2) | L2 3.5.3 | CC6.1 | 16.3 | 8.4.2 | SRG-APP-000149 | ISM-1401 | CPS-7.2 |
| 3 Owner role minimization | AC-6(5) | L2 3.1.5 | CC6.3 | 16.8 | 7.1.1 | SRG-APP-000340 | ISM-1508 | CPS-8.1 |
| 4 Least-privilege custom roles | AC-6 | L2 3.1.7 | CC6.3 | 16.8 | 7.1.2 | SRG-APP-000342 | ISM-1507 | CPS-8.2 |
| 5 Deny-default role policies | AC-3 | L2 3.1.1 | CC6.1 | 16.8 | 7.1.3 | SRG-APP-000033 | ISM-1506 | CPS-8.3 |
| 6 No orphaned members | AC-2 | L2 3.1.1 | CC6.2 | 16.1 | 8.1.4 | SRG-APP-000025 | ISM-1503 | CPS-9.1 |
| 7 Team roles use custom roles | AC-3 | L2 3.1.2 | CC6.3 | 16.8 | 7.1.2 | SRG-APP-000033 | ISM-1507 | CPS-8.2 |
| 8 Token expiration set | AC-2(3) | L2 3.1.1 | CC6.1 | 16.9 | 8.1.5 | SRG-APP-000025 | ISM-1552 | CPS-9.2 |
| 9 No stale tokens | AC-2(3) | L2 3.1.12 | CC6.1 | 16.9 | 8.1.4 | SRG-APP-000025 | ISM-1552 | CPS-9.3 |
| 10 Service token scoping | AC-6(1) | L2 3.1.5 | CC6.3 | 16.8 | 7.1.2 | SRG-APP-000340 | ISM-1508 | CPS-8.1 |
| 11 Personal token scoping | AC-6(1) | L2 3.1.5 | CC6.3 | 16.8 | 7.1.2 | SRG-APP-000340 | ISM-1508 | CPS-8.1 |
| 12 Audit log retention | AU-11 | L2 3.3.1 | CC7.2 | 8.3 | 10.7 | SRG-APP-000515 | ISM-0859 | CPS-12.1 |
| 13 Audit log completeness | AU-12 | L2 3.3.1 | CC7.2 | 8.5 | 10.2.2 | SRG-APP-000507 | ISM-0580 | CPS-12.2 |
| 14 No user keys in targeting | SC-28 | L2 3.13.16 | CC6.7 | 14.6 | 6.5.3 | SRG-APP-000428 | ISM-0457 | CPS-11.1 |
| 15 Stale flag cleanup | CM-3 | L2 3.4.3 | CC8.1 | 4.8 | 6.3.2 | SRG-APP-000380 | ISM-1210 | CPS-10.1 |
| 16 Environment access controls | AC-3 | L2 3.1.1 | CC6.1 | 16.8 | 7.1.3 | SRG-APP-000033 | ISM-1506 | CPS-8.3 |
| 17 Approval workflows | CM-3(2) | L2 3.4.3 | CC8.1 | 4.8 | 6.4.2 | SRG-APP-000380 | ISM-1210 | CPS-10.2 |
| 18 Relay proxy secure mode | SC-8 | L2 3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000439 | ISM-0484 | CPS-11.2 |
| 19 SDK key rotation | SC-12(1) | L2 3.13.10 | CC6.1 | 16.4 | 3.6.4 | SRG-APP-000176 | ISM-1557 | CPS-7.3 |
| 20 Integration least-privilege | AC-6(1) | L2 3.1.5 | CC6.3 | 16.8 | 7.1.2 | SRG-APP-000340 | ISM-1508 | CPS-8.1 |
| 21 Webhook HTTPS and signing | SC-8(1) | L2 3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0484 | CPS-11.3 |
| 22 No test projects | CM-2 | L2 3.4.1 | CC8.1 | 4.1 | 2.2.1 | SRG-APP-000131 | ISM-1407 | CPS-10.3 |
| 23 Environment critical settings | CM-6 | L2 3.4.2 | CC8.1 | 4.1 | 2.2.2 | SRG-APP-000131 | ISM-1407 | CPS-10.4 |
| 24 Member domain validation | IA-4 | L2 3.5.5 | CC6.1 | 16.6 | 8.1.1 | SRG-APP-000163 | ISM-1547 | CPS-7.4 |
| 25 No circular flag prerequisites | CM-3 | L2 3.4.5 | CC8.1 | 4.8 | 6.3.2 | SRG-APP-000380 | ISM-1210 | CPS-10.5 |

## 6. Existing Tools

| Tool | Type | Overlap | Gap Addressed |
|------|------|---------|---------------|
| LaunchDarkly Audit Log (built-in) | Native | Partial — logs actions but does not evaluate posture | No automated compliance assessment or drift detection |
| LaunchDarkly Accelerate | Native | Metrics-focused (DORA) — no security posture analysis | No security control evaluation |
| ld-find-code-refs | CLI | Finds flag references in code — no API security audit | No account-level security inspection |
| Steampipe LaunchDarkly plugin | SQL query engine | Queries LD resources via SQL — general purpose | No built-in security benchmarks or compliance mappings |
| Prowler | Cloud security | AWS/Azure/GCP focused — no SaaS feature flag coverage | No LaunchDarkly-specific controls |
| ScoutSuite | Cloud security | Multi-cloud auditor — no SaaS platform support | No feature flag platform coverage |

## 7. Architecture

```
launchdarkly-sec-inspector/
├── cmd/
│   └── launchdarkly-sec-inspector/
│       └── main.go                  # Entrypoint, CLI argument parsing
├── internal/
│   ├── client/
│   │   ├── client.go                # HTTP client with auth, rate limiting, retry
│   │   ├── pagination.go            # Collection endpoint pagination handler
│   │   └── endpoints.go             # API endpoint path constants
│   ├── config/
│   │   ├── config.go                # TOML config loader, env var merging
│   │   └── validation.go            # Config validation and defaults
│   ├── analyzers/
│   │   ├── analyzer.go              # Analyzer interface definition
│   │   ├── registry.go              # Analyzer registration and discovery
│   │   ├── account.go               # Account-level: SSO, MFA, plan settings
│   │   ├── members.go               # Member roles, domain validation, orphans
│   │   ├── teams.go                 # Team composition and role assignments
│   │   ├── roles.go                 # Custom role policy analysis (wildcards, denies)
│   │   ├── tokens.go                # Token expiration, staleness, scoping
│   │   ├── flags.go                 # Flag hygiene: stale, targeting, prerequisites
│   │   ├── environments.go          # Environment access, approval workflows, SDK keys
│   │   ├── integrations.go          # Integration scope and configuration review
│   │   ├── webhooks.go              # Webhook HTTPS enforcement, signing
│   │   └── relay.go                 # Relay proxy secure mode validation
│   ├── reporters/
│   │   ├── reporter.go              # Reporter interface definition
│   │   ├── json.go                  # JSON findings output
│   │   ├── csv.go                   # CSV tabular output
│   │   ├── html.go                  # HTML report with severity charts
│   │   └── summary.go              # Terminal summary table (TUI/CLI)
│   ├── models/
│   │   ├── finding.go               # Finding struct: control, severity, evidence, mappings
│   │   ├── compliance.go            # Framework mapping definitions
│   │   └── report.go                # Report metadata and aggregation
│   └── tui/
│       ├── app.go                   # Bubble Tea TUI application
│       ├── views.go                 # Dashboard, findings list, detail views
│       └── styles.go                # Lip Gloss styling definitions
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── spec.md
└── .goreleaser.yaml
```

### Key Dependencies

| Dependency | Purpose |
|-----------|---------|
| `github.com/spf13/cobra` | CLI command structure |
| `github.com/charmbracelet/bubbletea` | Terminal TUI framework |
| `github.com/charmbracelet/lipgloss` | TUI styling |
| `github.com/pelletier/go-toml/v2` | Configuration parsing |
| `net/http` (stdlib) | HTTP client for API calls |
| `encoding/json` (stdlib) | JSON serialization/deserialization |

## 8. CLI Interface

```
launchdarkly-sec-inspector [command] [flags]

Commands:
  scan        Run all security analyzers against the LaunchDarkly account
  analyze     Run a specific analyzer (e.g., tokens, roles, flags)
  report      Generate report from previous scan results
  list        List available analyzers and controls
  version     Print version information

Global Flags:
  --token string          LaunchDarkly API access token
  --base-url string       API base URL (default "https://app.launchdarkly.com")
  --config string         Config file path (default "~/.config/launchdarkly-sec-inspector/config.toml")
  --output string         Output format: json, csv, html, summary (default "summary")
  --output-file string    Write report to file instead of stdout
  --severity string       Minimum severity to report: critical, high, medium, low (default "low")
  --project strings       Limit scan to specific project keys (comma-separated)
  --tui                   Launch interactive TUI dashboard
  --no-color              Disable colored output
  --verbose               Enable verbose logging
  --timeout duration      API request timeout (default 30s)

Examples:
  # Full scan with default settings
  launchdarkly-sec-inspector scan --token $LD_TOKEN

  # Scan specific analyzers with JSON output
  launchdarkly-sec-inspector analyze tokens,roles --output json --output-file report.json

  # Scan only production project, high severity and above
  launchdarkly-sec-inspector scan --project production --severity high

  # Launch interactive TUI
  launchdarkly-sec-inspector scan --tui

  # Federal instance
  launchdarkly-sec-inspector scan --base-url https://app.launchdarkly.us --token $LD_TOKEN
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/launchdarkly-sec-inspector

# 2. Install dependencies
go get github.com/spf13/cobra@latest
go get github.com/charmbracelet/bubbletea@latest
go get github.com/charmbracelet/lipgloss@latest
go get github.com/pelletier/go-toml/v2@latest
go mod tidy

# 3. Build binary
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o bin/launchdarkly-sec-inspector ./cmd/launchdarkly-sec-inspector/

# 4. Run tests
go test ./... -v -race -coverprofile=coverage.out

# 5. Lint
golangci-lint run ./...

# 6. Docker build
docker build -t launchdarkly-sec-inspector:latest .

# 7. Release (via GoReleaser)
goreleaser release --clean
```

## 10. Status

Not yet implemented. Spec only.
