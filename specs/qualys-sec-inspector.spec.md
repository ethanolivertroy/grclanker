---
slug: "qualys-sec-inspector"
name: "Qualys Security Inspector"
vendor: "Qualys"
category: "vulnerability-application-security"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/qualys-sec-inspector"
---

# qualys-sec-inspector

## 1. Overview

A security compliance inspection tool for the **Qualys Cloud Platform** that audits vulnerability management configurations, policy compliance profiles, scan coverage, asset group hygiene, authentication records, scanner appliance status, and cloud connector settings. The tool connects to Qualys VM, PC, WAS, GAV, CSAM, and CloudView APIs to evaluate scan scheduling discipline, asset coverage completeness, credential scan ratios, vulnerability SLA adherence, and agent deployment status. Results are output as structured compliance reports mapped to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP controls.

## 2. APIs & SDKs

### Qualys APIs

| API | Base URL | Purpose |
|-----|----------|---------|
| **VM API v2** | `https://qualysapi.{platform}/api/2.0/fo/` | Vulnerability management: scans, reports, assets |
| **VMDR API** | `https://qualysapi.{platform}/qps/rest/2.0/` | Vulnerability management, detection, and response |
| **PC API** | `https://qualysapi.{platform}/api/2.0/fo/compliance/` | Policy compliance scanning and reporting |
| **WAS API** | `https://qualysapi.{platform}/qps/rest/3.0/` | Web application scanning |
| **GAV API** | `https://qualysapi.{platform}/qps/rest/2.0/` | Global AssetView (unified asset inventory) |
| **CSAM API** | `https://qualysapi.{platform}/qps/rest/2.0/` | CyberSecurity Asset Management |
| **CloudView API** | `https://qualysapi.{platform}/cloudview-api/rest/v1/` | Cloud security posture (AWS, Azure, GCP) |
| **User API** | `https://qualysapi.{platform}/msp/` | User and subscription management |

### Platform URLs

| Platform | API Server |
|----------|------------|
| US Platform 1 | `qualysapi.qualys.com` |
| US Platform 2 | `qualysapi.qg2.apps.qualys.com` |
| US Platform 3 | `qualysapi.qg3.apps.qualys.com` |
| EU Platform 1 | `qualysapi.qualys.eu` |
| EU Platform 2 | `qualysapi.qg2.apps.qualys.eu` |
| India | `qualysapi.qg1.apps.qualys.in` |
| Canada | `qualysapi.qg1.apps.qualys.ca` |
| UAE | `qualysapi.qg1.apps.qualys.ae` |
| Australia | `qualysapi.qg1.apps.qualys.com.au` |

### Key API Endpoints

**Vulnerability Management (VM API v2):**
- `POST /api/2.0/fo/scan/` — Launch, list, and manage vulnerability scans
- `POST /api/2.0/fo/scan/compliance/` — Launch and manage compliance scans
- `GET /api/2.0/fo/schedule/scan/` — List scheduled scan tasks
- `POST /api/2.0/fo/asset/host/` — List and manage host assets
- `GET /api/2.0/fo/asset/group/` — List asset groups and membership
- `POST /api/2.0/fo/asset/ip/` — IP address tracking and assignment
- `GET /api/2.0/fo/report/` — List and download reports
- `GET /api/2.0/fo/scan/option_profile/` — List option profiles (scan configs)
- `GET /api/2.0/fo/auth/` — List authentication records (credentialed scanning)
- `GET /api/2.0/fo/appliance/` — List scanner appliances and status
- `GET /api/2.0/fo/user/` — List user accounts and roles
- `GET /api/2.0/fo/activity_log/` — Audit activity log

**VMDR / Qualys Query Service (QPS):**
- `POST /qps/rest/2.0/search/am/hostasset` — Search host assets with QQL
- `POST /qps/rest/2.0/search/was/webapp` — Search web applications
- `GET /qps/rest/2.0/count/am/hostasset` — Count assets matching criteria

**Policy Compliance (PC API):**
- `GET /api/2.0/fo/compliance/policy/` — List compliance policies
- `GET /api/2.0/fo/compliance/posture/info/` — Policy compliance posture
- `GET /api/2.0/fo/compliance/control/` — List compliance controls

**Web Application Scanning (WAS API):**
- `POST /qps/rest/3.0/search/was/webapp` — List web applications
- `POST /qps/rest/3.0/search/was/wasscan` — List WAS scan results
- `POST /qps/rest/3.0/search/was/finding` — List WAS findings

**CloudView API:**
- `GET /cloudview-api/rest/v1/aws/connectors` — AWS cloud connectors
- `GET /cloudview-api/rest/v1/azure/connectors` — Azure cloud connectors
- `GET /cloudview-api/rest/v1/gcp/connectors` — GCP cloud connectors
- `GET /cloudview-api/rest/v1/evaluations` — Cloud resource evaluations

### SDKs

| SDK | Language | Package |
|-----|----------|---------|
| **qualysapi** | Python | `pip install qualysapi` (community) |
| **pyqualys** | Python | Community wrapper for Qualys APIs |
| **qualyspy** | Python | Community library for VM/PC APIs |
| **Qualys CLI** | CLI | Qualys provides limited CLI tooling |

## 3. Authentication

### Basic Authentication

The primary authentication method for Qualys APIs v1/v2:

```
Authorization: Basic base64(username:password)
```

### OAuth 2.0 Bearer Token

For newer APIs (VMDR, GAV, CSAM):

```bash
# Token request
curl -X POST "https://qualysapi.qualys.com/auth" \
  -d "username=USER&password=PASS&token=true"

# Returns JWT bearer token valid for 4 hours
Authorization: Bearer <jwt_token>
```

### Required Permissions

The API user account must have:
- **Manager** or **Unit Manager** role (for full configuration visibility)
- Access to all subscribed modules (VM, PC, WAS, GAV, CloudView)
- Permission to view all asset groups and scan schedules
- Access to user management APIs (for role auditing)

### Configuration

```
QUALYS_USERNAME=api_user
QUALYS_PASSWORD=...
QUALYS_PLATFORM=qualysapi.qualys.com
QUALYS_USE_OAUTH=true
```

## 4. Security Controls

1. **Scan schedule coverage** — Verify all asset groups have recurring vulnerability scans scheduled; flag groups with no active schedule or schedules older than 30 days
2. **Authenticated scan ratio** — Calculate the percentage of hosts scanned with credentials vs. unauthenticated; flag environments below 80% credentialed scan rate
3. **Scan option profile review** — Audit option profiles for aggressive vs. safe scan settings; verify profiles match environment requirements (internal vs. external)
4. **Asset group completeness** — Compare Qualys asset inventory against known CMDB/network ranges; flag unmonitored IP ranges and orphaned assets
5. **Cloud connector status** — Verify AWS, Azure, and GCP cloud connectors are active and successfully syncing; flag disconnected or erroring connectors
6. **Scanner appliance health** — Audit scanner appliance status (connected, heartbeat recency, version currency); flag offline or outdated appliances
7. **Agent deployment coverage** — Calculate Cloud Agent deployment coverage across asset inventory; flag asset groups with low agent penetration
8. **Authentication record completeness** — Verify authentication records exist for all target OS types (Windows, Linux, network devices); flag expired or failing credentials
9. **Policy compliance profile assignment** — Verify compliance policies are assigned to appropriate asset groups; flag unassigned or draft policies
10. **Vulnerability SLA adherence** — Audit open vulnerabilities against defined SLA windows (critical: 15 days, high: 30 days, medium: 90 days); calculate SLA compliance percentage
11. **Patch management tracking** — Verify patch availability tracking is enabled; audit patch age for open vulnerabilities
12. **Report template and distribution** — Verify automated report generation is configured; audit report distribution lists for appropriate recipients
13. **User role and permission audit** — Enumerate all Qualys user accounts and roles; flag inactive users, shared accounts, and excessive Manager-role assignments
14. **External scanner configuration** — Verify external perimeter scans are configured from Qualys external scanners; audit external scan frequency
15. **Web application inventory** — Audit WAS web application inventory completeness; flag web apps without recent scans or with stale authentication
16. **Exclusion list review** — Audit scan exclusion lists (excluded IPs, hosts, QIDs); flag overly broad exclusions that reduce coverage
17. **Vulnerability prioritization (VPR/QDS)** — Verify Qualys Detection Score (QDS) or CVSS-based prioritization is active; audit triage workflow
18. **Tag-based asset management** — Verify asset tagging strategy is implemented; audit tag coverage for compliance scope identification
19. **Activity log monitoring** — Verify activity log retention and review; flag sensitive admin actions (user creation, policy changes, scan deletions)
20. **Network segmentation scanning** — Verify separate scan schedules exist for different network segments (DMZ, internal, OT/ICS); flag flat scanning architectures

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 | Scan schedule coverage | RA-5 | 3.11.2 | CC7.1 | 7.1 | 11.3.1 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |
| 2 | Authenticated scan ratio | RA-5(1) | 3.11.2 | CC7.1 | 7.2 | 11.3.2 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |
| 3 | Scan option profile review | RA-5(2) | 3.11.1 | CC7.1 | 7.3 | 11.3.1 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |
| 4 | Asset group completeness | CM-8 | 3.4.1 | CC6.1 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1599 | CPS.CM-8 |
| 5 | Cloud connector status | CM-8(2) | 3.4.1 | CC6.1 | — | 2.4 | SRG-APP-000383 | ISM-1599 | CPS.CM-8 |
| 6 | Scanner appliance health | SI-2(2) | 3.14.1 | CC7.1 | — | 11.3.1 | SRG-APP-000456 | ISM-1163 | CPS.SI-2 |
| 7 | Agent deployment coverage | CM-8(1) | 3.4.1 | CC6.1 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1599 | CPS.CM-8 |
| 8 | Auth record completeness | RA-5(5) | 3.11.2 | CC7.1 | 7.2 | 11.3.2 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |
| 9 | Policy compliance assignment | CM-6(1) | 3.4.2 | CC8.1 | 4.1 | 2.2.1 | SRG-APP-000384 | ISM-1624 | CPS.CM-6 |
| 10 | Vulnerability SLA adherence | RA-5(3) | 3.11.2 | CC7.1 | 7.4 | 6.1 | SRG-APP-000456 | ISM-1690 | CPS.RA-5 |
| 11 | Patch management tracking | SI-2 | 3.14.1 | CC7.1 | 7.5 | 6.3.3 | SRG-APP-000456 | ISM-1143 | CPS.SI-2 |
| 12 | Report template/distribution | RA-5(4) | 3.11.3 | CC7.2 | — | 11.3.4 | SRG-APP-000516 | ISM-0109 | CPS.RA-5 |
| 13 | User role/permission audit | AC-6(5) | 3.1.5 | CC6.3 | — | 7.1.1 | SRG-APP-000340 | ISM-1507 | CPS.AC-6 |
| 14 | External scanner config | RA-5 | 3.11.2 | CC7.1 | — | 11.3.1 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |
| 15 | Web app inventory | RA-5(3) | 3.11.2 | CC7.1 | — | 6.4.1 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |
| 16 | Exclusion list review | RA-5(2) | 3.11.1 | CC7.1 | 7.3 | 11.3.1 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |
| 17 | Vulnerability prioritization | RA-5(3) | 3.11.1 | CC7.1 | 7.6 | 6.1 | SRG-APP-000456 | ISM-1690 | CPS.RA-5 |
| 18 | Tag-based asset management | CM-8(5) | 3.4.1 | CC6.1 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1599 | CPS.CM-8 |
| 19 | Activity log monitoring | AU-6 | 3.3.5 | CC7.2 | 8.2 | 10.6.1 | SRG-APP-000516 | ISM-0580 | CPS.AU-6 |
| 20 | Network segmentation scanning | RA-5 | 3.11.2 | CC7.1 | — | 11.3.1 | SRG-APP-000516 | ISM-1163 | CPS.RA-5 |

## 6. Existing Tools

| Tool | Description | Limitations |
|------|-------------|-------------|
| **Qualys Console** | Built-in web UI for configuration and reporting | Manual review; no automated compliance posture assessment of Qualys itself |
| **Qualys API Documentation** | Comprehensive API reference | Reference only, no pre-built audit tooling |
| **ScoutSuite** | Multi-cloud security auditing | Cloud-focused; no Qualys platform configuration audit |
| **qualysapi (Python)** | Community Python wrapper | API wrapper only, no security compliance logic |
| **Qualys VMDR Dashboard** | Built-in vulnerability management dashboard | Focuses on vulnerability findings, not scan program health |
| **CISA BOD 23-01** | Federal vulnerability scanning requirements | Requirements reference only, no Qualys-specific tooling |

**Gap:** No open-source tool audits the health and compliance posture of a Qualys deployment itself (scan coverage, credential hygiene, appliance health, user roles). Existing tools focus on consuming Qualys vulnerability data, not evaluating whether the Qualys scanning program meets compliance requirements.

## 7. Architecture

```
qualys-sec-inspector/
├── cmd/
│   └── qualys-sec-inspector/
│       └── main.go                  # CLI entrypoint
├── internal/
│   ├── client/
│   │   ├── vm.go                    # VM API v2 client
│   │   ├── qps.go                   # QPS/VMDR REST client
│   │   ├── pc.go                    # Policy Compliance API client
│   │   ├── was.go                   # WAS API client
│   │   ├── cloudview.go             # CloudView API client
│   │   ├── auth.go                  # Authentication (Basic + OAuth)
│   │   └── ratelimit.go             # Rate limiter (Qualys: 300 calls/hour default)
│   ├── analyzers/
│   │   ├── scanschedule.go          # Control 1: Scan schedule coverage
│   │   ├── authscan.go              # Control 2: Authenticated scan ratio
│   │   ├── optionprofile.go         # Control 3: Scan option profile review
│   │   ├── assetgroups.go           # Control 4: Asset group completeness
│   │   ├── cloudconnectors.go       # Control 5: Cloud connector status
│   │   ├── appliances.go            # Control 6: Scanner appliance health
│   │   ├── agents.go                # Control 7: Agent deployment coverage
│   │   ├── authrecords.go           # Control 8: Authentication record completeness
│   │   ├── policyassignment.go      # Control 9: Policy compliance profile assignment
│   │   ├── vulnsla.go               # Control 10: Vulnerability SLA adherence
│   │   ├── patching.go              # Control 11: Patch management tracking
│   │   ├── reports.go               # Control 12: Report template and distribution
│   │   ├── userroles.go             # Control 13: User role and permission audit
│   │   ├── externalscan.go          # Control 14: External scanner configuration
│   │   ├── webapps.go               # Control 15: Web application inventory
│   │   ├── exclusions.go            # Control 16: Exclusion list review
│   │   ├── prioritization.go        # Control 17: Vulnerability prioritization
│   │   ├── tagging.go               # Control 18: Tag-based asset management
│   │   ├── activitylog.go           # Control 19: Activity log monitoring
│   │   └── segmentation.go          # Control 20: Network segmentation scanning
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
| `encoding/xml` | Qualys VM API v2 returns XML responses |

## 8. CLI Interface

```
qualys-sec-inspector [command] [flags]

Commands:
  scan          Run security compliance scan against Qualys platform
  report        Generate compliance report from scan results
  version       Print version information

Global Flags:
  --username string     Qualys API username [$QUALYS_USERNAME]
  --password string     Qualys API password [$QUALYS_PASSWORD]
  --platform string     Qualys platform URL [$QUALYS_PLATFORM] (default "qualysapi.qualys.com")
  --oauth               Use OAuth bearer token instead of Basic auth
  --output string       Output format: json, csv, markdown, html, sarif (default "json")
  --output-dir string   Directory for report output (default "./results")
  --severity string     Minimum severity to report: critical, high, medium, low, info (default "low")
  --controls string     Comma-separated list of control numbers to run (default: all)
  --quiet               Suppress progress output
  --no-color            Disable colored output
  --tui                 Launch interactive terminal UI

Scan Flags:
  --skip-was            Skip Web Application Scanning checks
  --skip-cloudview      Skip CloudView connector checks
  --skip-pc             Skip Policy Compliance checks
  --sla-critical int    Critical vuln SLA in days (default 15)
  --sla-high int        High vuln SLA in days (default 30)
  --sla-medium int      Medium vuln SLA in days (default 90)
  --parallel int        Number of parallel API calls (default 2)
  --timeout duration    API call timeout (default 60s)

Examples:
  # Full platform audit with JSON output
  qualys-sec-inspector scan --username api_user --password ...

  # Scan coverage controls only
  qualys-sec-inspector scan --controls 1,2,4,7,8 --output markdown

  # Interactive TUI mode
  qualys-sec-inspector scan --tui

  # CI/CD pipeline with SARIF output
  qualys-sec-inspector scan --output sarif --severity high --skip-was
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/qualys-sec-inspector

# 2. Add dependencies
go get github.com/spf13/cobra
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss

# 3. Build
go build -ldflags "-X pkg/version.Version=$(git describe --tags)" \
  -o bin/qualys-sec-inspector ./cmd/qualys-sec-inspector/

# 4. Test
go test ./...

# 5. Lint
golangci-lint run

# 6. Docker
docker build -t qualys-sec-inspector .

# 7. Release
goreleaser release --snapshot
```

## 10. Status

Not yet implemented. Spec only.
