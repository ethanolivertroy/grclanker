---
slug: "launchdarkly-sec-inspector"
name: "LaunchDarkly Security Inspector"
vendor: "LaunchDarkly"
category: "devops-developer-platforms"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
---

# LaunchDarkly Security Inspector: Architecture Specification

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
| LaunchDarkly Audit Log (built-in) | Native | Partial: logs actions but does not evaluate posture | No automated compliance assessment or drift detection |
| LaunchDarkly Accelerate | Native | Metrics-focused (DORA), no security posture analysis | No security control evaluation |
| ld-find-code-refs | CLI | Finds flag references in code, no API security audit | No account-level security inspection |
| Steampipe LaunchDarkly plugin | SQL query engine | Queries LD resources via SQL, general purpose | No built-in security benchmarks or compliance mappings |
| Prowler | Cloud security | AWS/Azure/GCP focused, no SaaS feature flag coverage | No LaunchDarkly-specific controls |
| ScoutSuite | Cloud security | Multi-cloud auditor, no SaaS platform support | No feature flag platform coverage |

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

### grclanker implementation

The shipped implementation lives in the grclanker CLI as a native TypeScript tool family (`cli/extensions/grc-tools/launchdarkly.ts`) rather than the standalone Go CLI/TUI sketched above. It registers seven read-only tools:

| Tool | Spec controls |
|------|---------------|
| `launchdarkly_check_access` | Probes caller identity and every required read surface before an assessment |
| `launchdarkly_assess_identity` | 1, 2, 3, 6, 7, 24 |
| `launchdarkly_assess_access_control` | 4, 5, 8, 9, 10, 11 |
| `launchdarkly_assess_environment_governance` | 16, 17, 19, 22, 23 |
| `launchdarkly_assess_flag_hygiene` | 14, 15, 25 |
| `launchdarkly_assess_monitoring_integrations` | 12, 13, 18, 20, 21 |
| `launchdarkly_export_audit_bundle` | All 25, written as `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log`, and a zip |

Findings are `{ id, control, title, severity, status, summary, evidence, mappings, frameworks }` with ids `LD-01` through `LD-25` and the framework references from section 5. Tests live in `cli/tests/launchdarkly.test.mjs`, the live smoke script is `npm --prefix cli run test:launchdarkly:live`, and the operator guide is `src/content/docs/docs/integrations/launchdarkly.md`.

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

Implemented in grclanker on 2026-09-21 as the native TypeScript tool family described in the "grclanker implementation" subsection. All 25 controls in section 4 produce a finding. Control 1 is always `manual` because the API does not expose the account SSO setting; the other 24 are evaluated from API evidence. Controls 18, 19, 20, and 24 fall back to `manual`, stating the evidence a reviewer must collect, when the account has no Relay Proxy automatic configurations, the beta SDK keys endpoint is unavailable, no integration subscriptions exist for the probed integration keys, or no approved email domain policy is supplied.

### Shipped

- Configuration precedence exactly as section 3 (tool argument, `LAUNCHDARKLY_API_TOKEN`, `~/.config/launchdarkly-sec-inspector/config.toml`), plus `LAUNCHDARKLY_BASE_URL`, `LAUNCHDARKLY_API_VERSION`, `LAUNCHDARKLY_TIMEOUT`, `LAUNCHDARKLY_ALLOWED_DOMAINS`, `LAUNCHDARKLY_PROJECTS`, and `LAUNCHDARKLY_CONFIG`, with `LD_ACCESS_TOKEN` and `LD_BASE_URI` accepted as fallbacks. The TOML file is parsed with a dependency-free reader (key/value pairs, arrays, sections, comments).
- API client with `Authorization: {token}`, `LD-API-Version` (`20240415` default, `beta` for SDK keys), `limit`/`offset` plus `_links.next` pagination, `429` retry driven by `X-Ratelimit-Reset` / `X-Ratelimit-Auth-Token-Reset` / `Retry-After`, exponential `5xx` retry, per-request timeouts, and token redaction in every error.
- Read-only assessments, executive summary, unified compliance matrix, and one report per framework in section 5 (FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, ISMAP).
- Secret masking for SDK keys, mobile keys, Relay Proxy keys, webhook secrets, and integration credentials before any snapshot is written.

### Deviations from this spec (official documentation wins)

- Language and shape: TypeScript tools inside grclanker instead of a Go CLI/TUI; output is the audit bundle (JSON, Markdown, zip) rather than CSV/HTML/TUI reporters.
- `/api/v2/account` (section 2, controls 1 and 2) does not exist. The REST API exposes no account SSO or Require MFA setting, so control 1 is `manual` and control 2 uses the per-member `mfa` and `mfaEnforced` fields from `/api/v2/members`.
- `/api/v2/projects/{projectKey}/flags` (controls 14, 15, 25) does not exist. Flags are read from `/api/v2/flags/{projectKey}` with the `env` filter, and evaluation recency from `/api/v2/flag-statuses/{projectKey}/{environmentKey}`.
- `/api/v2/relay-proxy-configs` (control 18) is actually `/api/v2/account/relay-auto-configs`.
- `/api/v2/integrations` (control 20) has no list-all form. `/api/v2/integrations/{integrationKey}` returns audit log subscriptions for one integration, so the inspector probes a configurable list of integration keys.
- SDK key age (control 19) is not available from `/api/v2/projects/{projectKey}/environments`, which returns only the current `apiKey`. The inspector uses the beta `/api/v2/projects/{projectKey}/environments/{environmentKey}/sdk-keys` endpoint with `LD-API-Version: beta` and reports `manual` when it is unavailable.
- `/api/v2/tokens` returns only the caller's tokens unless `showAll=true` is passed by an Admin or Owner token (controls 8 through 11). `/api/v2/caller-identity` exposes no role, so the inspector derives the caller's base role from its own token and member records in the listing, treats other members' personal tokens as proof of a complete inventory, and never passes controls 8 through 11 on a partial or unknown inventory (clean results degrade to `warn` with the caveat in the summary).
- Control 16 cannot be satisfied by the `critical` environment designation. LaunchDarkly documents that marking an environment critical only enables safeguards and UI prompts, and that access to critical environments is restricted through custom roles. The inspector passes only when a custom role statement denies, excludes (`notResources`), or scopes actions away from each production environment, matching resource specifiers with the documented `proj/<key>:env/<key>;tags,{critical:true}` syntax; critical-only environments are `warn`.
- Rate limits are not a fixed 10 requests/second with a burst of 30. LaunchDarkly documents global, route-level, access token, and IP-based limits over ten-second windows with `X-Ratelimit-*-Remaining` and epoch-millisecond `X-Ratelimit-Reset` / `X-Ratelimit-Auth-Token-Reset` headers plus `Retry-After`; the client programs against those headers.
- The `viewMembers`, `viewRoles`, and `viewAuditLog` actions named in section 3 do not exist in the role actions reference. A least-privilege audit role needs `basePermissions: reader` plus `viewProject` on the audited projects.
- The `launchdarkly-api` Python SDK and Go dependencies listed in sections 2 and 7 are not used; the implementation relies on `fetch` and Node built-ins.

### Remaining

- Account-level SSO and MFA enforcement settings (control 1, the account half of control 2) stay manual until LaunchDarkly exposes them through the API.
- Relay Proxy deployments that use static SDK keys instead of automatic configuration are outside API visibility and must be reviewed manually.
- Integration types beyond the probed audit log subscription keys are not enumerable through the API.
