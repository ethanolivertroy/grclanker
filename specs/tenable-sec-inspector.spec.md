---
slug: "tenable-sec-inspector"
name: "Tenable Security Inspector"
vendor: "Tenable"
category: "vulnerability-application-security"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/tenable-sec-inspector"
---

# tenable-sec-inspector

## 1. Overview

A security compliance inspection tool for **Tenable.io** (now Tenable Vulnerability Management) that audits scan configurations, asset discovery coverage, credential scan ratios, agent deployment status, user permissions, scanner health, and vulnerability management program maturity. The tool connects to the Tenable.io REST API to evaluate scan policy configurations, plugin update currency, network segmentation, access controls, and vulnerability prioritization effectiveness. Results are output as structured compliance reports mapped to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP controls.

## 2. APIs & SDKs

### Tenable.io REST API

| API Section | Base URL | Purpose |
|-------------|----------|---------|
| **Scans** | `https://cloud.tenable.com/scans` | Scan management, schedules, and results |
| **Policies** | `https://cloud.tenable.com/policies` | Scan policy templates and configurations |
| **Assets** | `https://cloud.tenable.com/assets` | Asset inventory and properties |
| **Vulnerabilities** | `https://cloud.tenable.com/vulns` | Vulnerability data and export |
| **Workbenches** | `https://cloud.tenable.com/workbenches` | Dashboard data (assets, vulns, summaries) |
| **Users** | `https://cloud.tenable.com/users` | User account management |
| **Groups** | `https://cloud.tenable.com/groups` | User group management |
| **Permissions** | `https://cloud.tenable.com/permissions` | Object-level permissions |
| **Access Groups** | `https://cloud.tenable.com/v2/access-groups` | Asset-based access control groups |
| **Agent Groups** | `https://cloud.tenable.com/scanners/{scanner_id}/agent-groups` | Nessus Agent group management |
| **Agents** | `https://cloud.tenable.com/scanners/{scanner_id}/agents` | Nessus Agent inventory |
| **Scanners** | `https://cloud.tenable.com/scanners` | Scanner appliance management |
| **Networks** | `https://cloud.tenable.com/networks` | Network zone definitions |
| **Credentials** | `https://cloud.tenable.com/credentials` | Managed credential store |
| **Audit Log** | `https://cloud.tenable.com/audit-log` | Administrative activity audit log |
| **Exclusions** | `https://cloud.tenable.com/exclusions` | Scan exclusion rules |
| **Tags** | `https://cloud.tenable.com/tags` | Asset tagging (tag values and categories) |
| **Exports** | `https://cloud.tenable.com/vulns/export` | Bulk vulnerability and asset export |
| **Target Groups** | `https://cloud.tenable.com/target-groups` | Target group definitions |
| **Plugins** | `https://cloud.tenable.com/plugins` | Plugin families and details |

### Key API Endpoints

**Scan Management:**
- `GET /scans` — List all scans with schedules, status, last run
- `GET /scans/{scan_id}` — Scan detail including hosts, history, schedule
- `GET /scans/{scan_id}/hosts/{host_id}` — Per-host vulnerability results
- `POST /scans` — Create new scan
- `GET /policies` — List scan policies with settings
- `GET /policies/{policy_id}` — Policy detail with plugin families, credentials

**Asset Management:**
- `GET /assets` — List all assets with last seen, agent status, network
- `GET /assets/{asset_id}` — Asset detail with operating system, IPs, FQDN
- `POST /assets/export` — Initiate bulk asset export
- `GET /assets/export/{export_uuid}/status` — Export status
- `GET /assets/export/{export_uuid}/chunks/{chunk_id}` — Download export chunk

**Vulnerability Management:**
- `POST /vulns/export` — Initiate bulk vulnerability export
- `GET /workbenches/vulnerabilities` — Vulnerability summary by severity
- `GET /workbenches/assets` — Asset workbench with vulnerability counts

**User and Access Control:**
- `GET /users` — List all user accounts with roles
- `GET /groups` — List user groups
- `GET /v2/access-groups` — List access groups (asset-scoped permissions)
- `GET /permissions/{object_type}/{object_id}` — Object-level permissions
- `GET /audit-log` — Administrative action audit log

**Scanner and Agent Management:**
- `GET /scanners` — List all scanners (cloud, linked, managed)
- `GET /scanners/{scanner_id}` — Scanner detail with version, status
- `GET /scanners/{scanner_id}/agents` — List agents linked to scanner
- `GET /scanners/{scanner_id}/agent-groups` — Agent groups
- `GET /networks` — Network zone definitions

**Configuration:**
- `GET /exclusions` — List scan exclusions
- `GET /credentials` — List managed credentials
- `GET /tags/values` — List tag values
- `GET /tags/categories` — List tag categories
- `GET /target-groups` — List target groups

### SDKs

| SDK | Language | Package |
|-----|----------|---------|
| **pyTenable** | Python | `pip install pytenable` (official, Tenable-maintained) |
| **goTenable** | Go | Community Go client |
| **tenable-io-sdk** | Python | `pip install tenable-io-sdk` (legacy official) |
| **Tenable CLI** | CLI | `pip install tenable-cli` (community) |

## 3. Authentication

### API Keys

Tenable.io uses API key pairs for authentication:

```
X-ApiKeys: accessKey={access_key};secretKey={secret_key}
```

API keys are generated per-user from **Settings > My Account > API Keys** in the Tenable.io web console.

### Required Permissions

The API user must have:
- **Administrator** role (for full configuration visibility) or
- **Scan Manager** + **Standard** user with broad access group membership

Specific permissions required:
- View all scans, policies, and scan results
- View user accounts and group memberships
- View scanner and agent inventory
- View managed credentials (metadata, not secrets)
- Read audit log
- View exclusion rules
- View access groups and permissions

### Configuration

```
TENABLE_ACCESS_KEY=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
TENABLE_SECRET_KEY=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
TENABLE_URL=https://cloud.tenable.com    # Optional: for Tenable.sc on-prem
```

## 4. Security Controls

1. **Scan policy configuration** — Audit scan policies for appropriate settings: port range (all ports vs. common), plugin families enabled, safe checks, performance tuning, and scan type (credentialed, agent, network)
2. **Scan schedule discipline** — Verify all asset networks have recurring scan schedules; flag networks with no active scans or scans not run in 30+ days
3. **Asset discovery coverage** — Compare Tenable asset inventory against expected network ranges; calculate coverage percentage and flag unmonitored subnets
4. **Credentialed scan ratio** — Calculate the percentage of assets scanned with credentials vs. unauthenticated; flag environments below 80% credential coverage
5. **Agent deployment status** — Audit Nessus Agent deployment across asset inventory; verify agent versions are current; flag stale or offline agents
6. **Agent group organization** — Verify agents are organized into logical groups matching network segments or business units; flag ungrouped agents
7. **Scanner health and version** — Audit linked scanner appliance status (connected, last seen), Nessus version currency, and plugin feed update recency
8. **Plugin update currency** — Verify plugin feed is current (updated within 24 hours); flag scanners with stale plugin sets
9. **Network zone configuration** — Audit network zone definitions; verify scanners are assigned to appropriate zones; flag zones without scanners
10. **User role and permission audit** — Enumerate all user accounts, roles (Basic, Scan Operator, Standard, Scan Manager, Administrator), and last login; flag inactive users and excessive admin accounts
11. **Access group review** — Audit access groups to verify asset-scoped permissions follow least privilege; flag overly broad access groups
12. **Managed credential hygiene** — Audit managed credentials for last modification date, credential type coverage (SSH, Windows, SNMP, database), and scope
13. **Scan exclusion audit** — Review all scan exclusions; flag permanent exclusions, overly broad IP ranges, and exclusions without documented justification
14. **Vulnerability prioritization (VPR)** — Verify VPR-based prioritization is active; audit the distribution of critical/high VPR scores and remediation rates
15. **Vulnerability SLA tracking** — Calculate mean time to remediate (MTTR) by severity; compare against defined SLA thresholds
16. **Asset tagging strategy** — Verify asset tags are applied consistently for compliance scope, business unit, and environment classification
17. **Compliance audit templates** — Verify compliance audit templates (CIS, DISA STIG, PCI) are configured and scheduled for in-scope assets
18. **Audit log review** — Analyze audit log for sensitive actions (scan deletion, user privilege escalation, exclusion creation, policy modification)
19. **Export and reporting automation** — Verify automated vulnerability exports or report schedules exist for stakeholder distribution
20. **Target group management** — Audit target groups for accuracy; flag overlapping or stale target definitions

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 | Scan policy configuration | RA-5 | 3.11.2 | CC7.1 | 7.3 | 11.3.1 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |
| 2 | Scan schedule discipline | RA-5(2) | 3.11.2 | CC7.1 | 7.1 | 11.3.1 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |
| 3 | Asset discovery coverage | CM-8 | 3.4.1 | CC6.1 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1599 | CPS.CM-8 |
| 4 | Credentialed scan ratio | RA-5(1) | 3.11.2 | CC7.1 | 7.2 | 11.3.2 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |
| 5 | Agent deployment status | CM-8(1) | 3.4.1 | CC6.1 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1599 | CPS.CM-8 |
| 6 | Agent group organization | CM-8(5) | 3.4.1 | CC6.1 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1599 | CPS.CM-8 |
| 7 | Scanner health and version | SI-2(2) | 3.14.1 | CC7.1 | — | 11.3.1 | SRG-APP-000456 | ISM-1163 | CPS.SI-2 |
| 8 | Plugin update currency | SI-2(2) | 3.14.1 | CC7.1 | — | 11.3.1 | SRG-APP-000456 | ISM-1143 | CPS.SI-2 |
| 9 | Network zone configuration | SC-7(5) | 3.13.5 | CC6.6 | — | 1.3.1 | SRG-APP-000001 | ISM-1528 | CPS.SC-7 |
| 10 | User role/permission audit | AC-6(5) | 3.1.5 | CC6.3 | — | 7.1.1 | SRG-APP-000340 | ISM-1507 | CPS.AC-6 |
| 11 | Access group review | AC-6(1) | 3.1.5 | CC6.3 | — | 7.1.2 | SRG-APP-000340 | ISM-1507 | CPS.AC-6 |
| 12 | Managed credential hygiene | IA-5(1) | 3.5.10 | CC6.1 | — | 8.6.3 | SRG-APP-000175 | ISM-1557 | CPS.IA-5 |
| 13 | Scan exclusion audit | RA-5(2) | 3.11.1 | CC7.1 | 7.3 | 11.3.1 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |
| 14 | Vulnerability prioritization | RA-5(3) | 3.11.1 | CC7.1 | 7.6 | 6.1 | SRG-APP-000456 | ISM-1690 | CPS.RA-5 |
| 15 | Vulnerability SLA tracking | RA-5(3) | 3.11.2 | CC7.1 | 7.4 | 6.1 | SRG-APP-000456 | ISM-1690 | CPS.RA-5 |
| 16 | Asset tagging strategy | CM-8(5) | 3.4.1 | CC6.1 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1599 | CPS.CM-8 |
| 17 | Compliance audit templates | CM-6(1) | 3.4.2 | CC8.1 | 4.1 | 2.2.1 | SRG-APP-000384 | ISM-1624 | CPS.CM-6 |
| 18 | Audit log review | AU-6 | 3.3.5 | CC7.2 | 8.2 | 10.6.1 | SRG-APP-000516 | ISM-0580 | CPS.AU-6 |
| 19 | Export/reporting automation | RA-5(4) | 3.11.3 | CC7.2 | — | 11.3.4 | SRG-APP-000516 | ISM-0109 | CPS.RA-5 |
| 20 | Target group management | RA-5 | 3.11.2 | CC7.1 | — | 11.3.1 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |

## 6. Existing Tools

| Tool | Description | Limitations |
|------|-------------|-------------|
| **Tenable.io Console** | Built-in web dashboard for scan management and reporting | No automated compliance audit of the scanning program itself |
| **pyTenable** | Official Python SDK for Tenable.io/Tenable.sc | API wrapper only, no security compliance logic |
| **Tenable Lumin** | Risk-based exposure analytics | Focuses on vulnerability risk, not scan program health |
| **Tenable.io Workbenches** | Built-in dashboards for asset and vulnerability analysis | Does not audit scanning configuration completeness |
| **CISA BOD 23-01** | Federal continuous diagnostics requirements | Requirements reference only, no Tenable-specific tooling |
| **Nessus Compliance Checks** | Built-in compliance auditing within Nessus | Audits target systems, not the Tenable platform configuration |

**Gap:** No open-source tool audits the health and compliance posture of a Tenable.io deployment (scan coverage gaps, credential hygiene, agent deployment completeness, user permissions). Existing tools consume Tenable vulnerability data but do not evaluate whether the scanning program itself meets compliance requirements for comprehensive vulnerability management.

## 7. Architecture

```
tenable-sec-inspector/
├── cmd/
│   └── tenable-sec-inspector/
│       └── main.go                  # CLI entrypoint
├── internal/
│   ├── client/
│   │   ├── tenable.go               # Core Tenable.io REST client
│   │   ├── export.go                # Bulk export client (vulns, assets)
│   │   └── ratelimit.go             # Rate limiter (Tenable: 5000 req/5 min)
│   ├── analyzers/
│   │   ├── scanpolicy.go            # Control 1: Scan policy configuration
│   │   ├── scanschedule.go          # Control 2: Scan schedule discipline
│   │   ├── assetcoverage.go         # Control 3: Asset discovery coverage
│   │   ├── credentialscan.go        # Control 4: Credentialed scan ratio
│   │   ├── agents.go                # Controls 5-6: Agent deployment and groups
│   │   ├── scannerhealth.go         # Controls 7-8: Scanner health and plugin currency
│   │   ├── networkzones.go          # Control 9: Network zone configuration
│   │   ├── userroles.go             # Controls 10-11: User roles and access groups
│   │   ├── credentials.go           # Control 12: Managed credential hygiene
│   │   ├── exclusions.go            # Control 13: Scan exclusion audit
│   │   ├── prioritization.go        # Controls 14-15: VPR and SLA tracking
│   │   ├── tagging.go               # Control 16: Asset tagging strategy
│   │   ├── compliance.go            # Control 17: Compliance audit templates
│   │   ├── auditlog.go              # Control 18: Audit log review
│   │   ├── reporting.go             # Control 19: Export and reporting automation
│   │   └── targetgroups.go          # Control 20: Target group management
│   ├── reporters/
│   │   ├── json.go                  # JSON output reporter
│   │   ├── csv.go                   # CSV output reporter
│   │   ├── markdown.go              # Markdown report with compliance matrix
│   │   ├── html.go                  # HTML dashboard report
│   │   └── sarif.go                 # SARIF format for CI/CD integration
│   ├── compliance/
│   │   ├── mapper.go                # Maps findings to framework controls
│   │   ├── fedramp.go               # FedRAMP control definitions
│   │   ├── cmmc.go                  # CMMC control definitions
│   │   ├── soc2.go                  # SOC 2 trust criteria
│   │   ├── cis.go                   # CIS Benchmark references
│   │   ├── pcidss.go                # PCI-DSS requirements
│   │   ├── stig.go                  # DISA STIG rules
│   │   ├── irap.go                  # IRAP ISM controls
│   │   └── ismap.go                 # ISMAP control references
│   ├── models/
│   │   ├── finding.go               # Finding severity, evidence, remediation
│   │   ├── control.go               # Security control definition
│   │   └── report.go                # Aggregate report model
│   └── tui/
│       ├── app.go                   # Bubble Tea TUI application
│       ├── views/
│       │   ├── dashboard.go         # Summary dashboard view
│       │   ├── controls.go          # Control detail drill-down
│       │   └── compliance.go        # Framework compliance matrix view
│       └── components/
│           ├── table.go             # Sortable findings table
│           ├── progress.go          # Scan progress indicator
│           └── severity.go          # Severity badge rendering
├── pkg/
│   └── version/
│       └── version.go               # Build version info
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── .goreleaser.yaml
└── spec.md
```

### Key Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/charmbracelet/bubbletea` | Terminal UI framework |
| `github.com/charmbracelet/lipgloss` | TUI styling |
| `net/http` | HTTP client for REST API (no official Go SDK) |

## 8. CLI Interface

```
tenable-sec-inspector [command] [flags]

Commands:
  scan          Run security compliance scan against Tenable.io
  report        Generate compliance report from scan results
  version       Print version information

Global Flags:
  --access-key string   Tenable.io API access key [$TENABLE_ACCESS_KEY]
  --secret-key string   Tenable.io API secret key [$TENABLE_SECRET_KEY]
  --url string          Tenable.io URL [$TENABLE_URL] (default "https://cloud.tenable.com")
  --output string       Output format: json, csv, markdown, html, sarif (default "json")
  --output-dir string   Directory for report output (default "./results")
  --severity string     Minimum severity to report: critical, high, medium, low, info (default "low")
  --controls string     Comma-separated list of control numbers to run (default: all)
  --quiet               Suppress progress output
  --no-color            Disable colored output
  --tui                 Launch interactive terminal UI

Scan Flags:
  --skip-exports        Skip bulk vulnerability/asset exports (faster scan)
  --skip-agents         Skip agent inventory checks
  --sla-critical int    Critical vuln SLA in days (default 15)
  --sla-high int        High vuln SLA in days (default 30)
  --sla-medium int      Medium vuln SLA in days (default 90)
  --credential-threshold float   Minimum credentialed scan percentage (default 0.8)
  --parallel int        Number of parallel API calls (default 4)
  --timeout duration    API call timeout (default 30s)

Examples:
  # Full Tenable.io platform audit
  tenable-sec-inspector scan --access-key ... --secret-key ...

  # Scan coverage and credential controls only
  tenable-sec-inspector scan --controls 1,2,3,4,5 --output markdown

  # Interactive TUI mode
  tenable-sec-inspector scan --tui

  # CI/CD pipeline with SARIF output, high severity only
  tenable-sec-inspector scan --output sarif --severity high --skip-exports
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/tenable-sec-inspector

# 2. Add dependencies
go get github.com/spf13/cobra
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss

# 3. Build
go build -ldflags "-X pkg/version.Version=$(git describe --tags)" \
  -o bin/tenable-sec-inspector ./cmd/tenable-sec-inspector/

# 4. Test
go test ./...

# 5. Lint
golangci-lint run

# 6. Docker
docker build -t tenable-sec-inspector .

# 7. Release
goreleaser release --snapshot
```

## 10. Status

Not yet implemented. Spec only.
