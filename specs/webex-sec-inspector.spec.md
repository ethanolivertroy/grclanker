---
slug: "webex-sec-inspector"
name: "Webex Security Inspector"
vendor: "Cisco"
category: "saas-collaboration"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/webex-sec-inspector"
---

# Cisco Webex Security Inspector — Architecture Specification

## 1. Overview

Cisco Webex Security Inspector is a hybrid CLI/TUI tool that audits the security posture of a Cisco Webex organization. It connects to the Webex REST API (webexapis.com/v1) to evaluate identity and access management, messaging policies, meeting security, recording governance, device management, hybrid infrastructure, and compliance controls. The tool produces structured findings mapped to enterprise compliance frameworks and outputs reports in JSON, CSV, and HTML formats.

The inspector targets Webex organizations on Business and Enterprise plans (including Webex Control Hub-managed orgs) where advanced security, compliance, and hybrid deployment capabilities are available. It operates in read-only mode and requires no agent installation.

## 2. APIs & SDKs

### Webex REST API (v1)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/people` | GET | List organization members, roles, login status |
| `/people/{personId}` | GET | Get member details including last activity |
| `/people/me` | GET | Get authenticated user profile and org context |
| `/organizations` | GET | List organizations visible to the account |
| `/organizations/{orgId}` | GET | Get organization details, settings, security config |
| `/roles` | GET | List available roles (admin, compliance, readonly) |
| `/licenses` | GET | List license assignments and usage |
| `/licenses/{licenseId}` | GET | Get license details and assigned users |
| `/events` | GET | List compliance events (messages, memberships, rooms) |
| `/recordings` | GET | List meeting recordings and storage locations |
| `/recordings/{recordingId}` | GET | Get recording details and access permissions |
| `/meetings` | GET | List meetings with security settings |
| `/meetings/{meetingId}` | GET | Get meeting details (encryption, lobby, password) |
| `/meetingPreferences` | GET | Get user/org meeting preference defaults |
| `/meetingPreferences/sites` | GET | List Webex meeting sites and their settings |
| `/admin/organizations/{orgId}/settings` | GET | Get organization-wide admin security settings |
| `/hybrid/clusters` | GET | List hybrid infrastructure clusters |
| `/hybrid/clusters/{clusterId}` | GET | Get cluster status, nodes, connectivity |
| `/hybrid/connectors` | GET | List hybrid connectors (Calendar, Call, etc.) |
| `/devices` | GET | List registered devices and their config |
| `/devices/{deviceId}` | GET | Get device details, firmware, security posture |
| `/workspaces` | GET | List workspaces (rooms/devices) and settings |
| `/rooms` | GET | List spaces/rooms with classification labels |
| `/rooms/{roomId}` | GET | Get room details, classification, retention policy |
| `/webhooks` | GET | List registered webhooks |
| `/webhooks/{webhookId}` | GET | Get webhook details (URL, events, secret) |
| `/resourceGroups` | GET | List resource groups for hybrid services |
| `/admin/organizations/{orgId}/security` | GET | Get security policies (DLP, file sharing, external comms) |

**Base URL:** `https://webexapis.com/v1`

**Rate Limits:** API calls are rate-limited per application. Response headers include `Retry-After` on 429 status. Typical limits: 100 requests/minute for most endpoints, lower for admin endpoints.

### Python SDKs

| Package | Version | Notes |
|---------|---------|-------|
| `webexpythonsdk` | 2.0.5+ | Community SDK; successor to `webexteamssdk`; Python 3.10+ |
| `webexteamssdk` | 1.7 (final) | Deprecated; last release; Python 2/3 compatible |

The `webexpythonsdk` package provides native Python objects for all Webex API resources with automatic pagination, rate-limit handling, and file upload support. For a Go implementation, direct HTTP calls via `net/http` are used since no official Go SDK exists.

## 3. Authentication

| Method | Header Format | Use Case |
|--------|--------------|----------|
| Bot token | `Authorization: Bearer {token}` | Automated scans; org-scoped, does not impersonate users |
| OAuth 2.0 integration | `Authorization: Bearer {token}` | User-delegated access with specific scopes |
| Service app | `Authorization: Bearer {token}` | Machine-to-machine; org-wide admin access without user context |

**Bot token setup:**
- Created via [developer.webex.com/my-apps](https://developer.webex.com/my-apps)
- Bot must be added to the organization by an admin
- Scope is limited to what the bot's org membership permits

**Service app setup:**
- Created in Webex Control Hub under "Apps > Service Apps"
- Uses OAuth 2.0 client_credentials grant
- Can be granted admin-level scopes without a user login

**Required scopes (minimum for full inspection):**
- `spark-admin:people_read` — member enumeration
- `spark-admin:organizations_read` — organization settings
- `spark-admin:roles_read` — role assignments
- `spark-admin:licenses_read` — license usage
- `spark-admin:devices_read` — device inventory
- `spark-admin:hybrid_clusters_read` — hybrid infrastructure
- `spark-admin:resource_groups_read` — resource group config
- `spark-compliance:events_read` — compliance events
- `spark-compliance:meetings_read` — meeting compliance data
- `spark-compliance:rooms_read` — room compliance data
- `meeting:admin_schedule_read` — meeting settings
- `meeting:admin_recordings_read` — recording inventory
- `meeting:admin_preferences_read` — meeting preferences

**Configuration precedence:**
1. `--token` CLI flag
2. `WEBEX_TOKEN` environment variable
3. `--client-id` / `--client-secret` for service app OAuth
4. `~/.config/webex-sec-inspector/config.toml`

The tool never stores tokens beyond the current session. Tokens and secrets are redacted from all log output and reports.

## 4. Security Controls

| # | Control | API Source | Severity |
|---|---------|-----------|----------|
| 1 | SSO enforcement enabled for the organization | `/admin/organizations/{orgId}/settings` | Critical |
| 2 | MFA required for all admin-role users | `/people` (filter: admin roles), org settings | Critical |
| 3 | Compliance Officer role assigned to designated personnel | `/people`, `/roles` | High |
| 4 | External communications policy restricts messaging to approved domains | `/admin/organizations/{orgId}/security` | High |
| 5 | File sharing restricted or limited by policy (block external, type filters) | `/admin/organizations/{orgId}/security` | High |
| 6 | Recording storage uses organization-controlled location (not personal) | `/recordings`, org settings | Medium |
| 7 | Recording auto-delete policy configured (retention limit set) | `/recordings`, org settings | Medium |
| 8 | Meeting default encryption set to end-to-end (E2EE) where supported | `/meetingPreferences`, org settings | High |
| 9 | Meeting lobby enabled by default for external participants | `/meetingPreferences` | High |
| 10 | Meeting password required by default | `/meetingPreferences` | Medium |
| 11 | eDiscovery/legal hold capability configured and compliance officer assigned | `/events`, org settings | High |
| 12 | Data retention policy configured with defined retention period | `/admin/organizations/{orgId}/settings`, `/rooms` | High |
| 13 | Guest access restricted or disabled for the organization | org settings | Medium |
| 14 | Space classification labels enabled and enforced | `/rooms` (classification field) | Medium |
| 15 | Hybrid cluster nodes healthy and running supported versions | `/hybrid/clusters/{id}` | High |
| 16 | Hybrid connectors registered and reporting active status | `/hybrid/connectors` | Medium |
| 17 | Device firmware up to date (no devices on EOL firmware) | `/devices/{id}` | High |
| 18 | Unmanaged/personal devices blocked or restricted from org access | `/devices`, org settings | Medium |
| 19 | Bot management: only approved bots active in the organization | org settings, `/people` (type: bot) | Medium |
| 20 | Webhook endpoints use HTTPS and have secret configured | `/webhooks` | High |
| 21 | Messaging DLP (Data Loss Prevention) policies configured | `/admin/organizations/{orgId}/security` | High |
| 22 | Calling security: SRTP encryption enforced for all calling profiles | org settings, calling config | High |
| 23 | Virtual background enforcement for meetings (prevent inappropriate content) | `/meetingPreferences` | Low |
| 24 | License utilization reviewed (no excessive unassigned licenses) | `/licenses` | Low |
| 25 | Admin activity audit: admin role changes logged and reviewed | `/events` (admin actions) | High |

## 5. Compliance Framework Mappings

| Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 SSO enforcement | IA-2(1) | L2 3.5.3 | CC6.1 | 16.2 | 8.4.1 | SRG-APP-000148 | ISM-1546 | CPS-7.1 |
| 2 Admin MFA | IA-2(2) | L2 3.5.3 | CC6.1 | 16.3 | 8.4.2 | SRG-APP-000149 | ISM-1401 | CPS-7.2 |
| 3 Compliance officer role | AU-1 | L2 3.3.2 | CC7.2 | 8.1 | 12.5.2 | SRG-APP-000516 | ISM-0042 | CPS-12.1 |
| 4 External communications | AC-4 | L2 3.1.3 | CC6.6 | 13.4 | 1.3.7 | SRG-APP-000100 | ISM-1528 | CPS-11.1 |
| 5 File sharing restrictions | AC-4(1) | L2 3.1.3 | CC6.7 | 13.4 | 1.3.7 | SRG-APP-000100 | ISM-0947 | CPS-11.2 |
| 6 Recording storage control | SC-28 | L2 3.13.16 | CC6.7 | 14.8 | 3.4.1 | SRG-APP-000428 | ISM-0457 | CPS-11.3 |
| 7 Recording retention | SI-12 | L2 3.8.9 | CC6.5 | 14.8 | 3.1 | SRG-APP-000504 | ISM-0859 | CPS-12.2 |
| 8 E2E meeting encryption | SC-8(1) | L2 3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0484 | CPS-11.4 |
| 9 Meeting lobby controls | AC-3 | L2 3.1.1 | CC6.1 | 16.7 | 7.1.3 | SRG-APP-000033 | ISM-1506 | CPS-8.1 |
| 10 Meeting password required | IA-5 | L2 3.5.7 | CC6.1 | 16.5 | 8.2.3 | SRG-APP-000170 | ISM-1557 | CPS-7.3 |
| 11 eDiscovery/legal hold | AU-11 | L2 3.3.1 | CC7.3 | 8.3 | 10.7 | SRG-APP-000515 | ISM-0859 | CPS-12.3 |
| 12 Data retention policy | SI-12 | L2 3.8.9 | CC6.5 | 14.8 | 3.1 | SRG-APP-000504 | ISM-0859 | CPS-12.4 |
| 13 Guest access restrictions | AC-14 | L2 3.1.1 | CC6.1 | 16.7 | 7.1.3 | SRG-APP-000033 | ISM-1506 | CPS-8.2 |
| 14 Space classification | AC-16 | L2 3.13.12 | CC6.7 | 14.1 | 9.6.1 | SRG-APP-000311 | ISM-0271 | CPS-11.5 |
| 15 Hybrid cluster health | CM-8 | L2 3.4.1 | CC6.8 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1409 | CPS-10.1 |
| 16 Hybrid connector status | SI-4 | L2 3.14.6 | CC7.1 | 1.1 | 10.6 | SRG-APP-000516 | ISM-0576 | CPS-12.5 |
| 17 Device firmware currency | SI-2 | L2 3.14.1 | CC7.1 | 7.4 | 6.2 | SRG-APP-000456 | ISM-1143 | CPS-13.1 |
| 18 Unmanaged device blocking | CM-8(3) | L2 3.4.1 | CC6.8 | 1.4 | 9.7.1 | SRG-APP-000383 | ISM-1482 | CPS-10.2 |
| 19 Bot management | CM-7 | L2 3.4.6 | CC6.8 | 4.8 | 2.2.2 | SRG-APP-000141 | ISM-1407 | CPS-10.3 |
| 20 Webhook HTTPS and signing | SC-8(1) | L2 3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0484 | CPS-11.6 |
| 21 Messaging DLP | SC-7(8) | L2 3.13.1 | CC6.7 | 13.4 | 1.3.7 | SRG-APP-000516 | ISM-0947 | CPS-11.7 |
| 22 SRTP calling encryption | SC-8 | L2 3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000439 | ISM-0484 | CPS-11.8 |
| 23 Virtual background policy | AC-3 | L2 3.1.1 | CC6.1 | — | — | SRG-APP-000033 | — | — |
| 24 License utilization | CM-8 | L2 3.4.1 | CC6.8 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1409 | CPS-10.4 |
| 25 Admin audit logging | AU-12 | L2 3.3.1 | CC7.2 | 8.5 | 10.2.2 | SRG-APP-000507 | ISM-0580 | CPS-12.6 |

## 6. Existing Tools

| Tool | Type | Overlap | Gap Addressed |
|------|------|---------|---------------|
| Webex Control Hub | Native admin console | Full admin visibility — but manual, no automated compliance checks | No automated posture scoring or compliance framework mapping |
| Webex Control Hub Alerts | Native | Alerts on specific events — not comprehensive posture analysis | No holistic security control evaluation |
| Webex Pro Pack for Control Hub | Add-on | Enhanced compliance features — still requires manual review | No automated security benchmark or drift detection |
| Cisco ThousandEyes (Webex integration) | Monitoring | Network/performance monitoring — no security posture | No IAM, policy, or compliance assessment |
| webexpythonsdk / webexteamssdk | SDK | API wrapper — no security analysis logic | Building block only, no compliance controls |
| Prowler | Cloud security | AWS/Azure/GCP focused — no SaaS collaboration platform coverage | No Webex-specific controls |
| ScoutSuite | Cloud security | Multi-cloud auditor — no SaaS platform support | No Webex platform coverage |

## 7. Architecture

```
webex-sec-inspector/
├── cmd/
│   └── webex-sec-inspector/
│       └── main.go                  # Entrypoint, CLI argument parsing
├── internal/
│   ├── client/
│   │   ├── client.go                # HTTP client with auth, rate limiting, retry
│   │   ├── auth.go                  # Token management (bot, OAuth, service app)
│   │   ├── pagination.go            # Cursor/link-based pagination handler
│   │   └── endpoints.go             # API endpoint path constants
│   ├── config/
│   │   ├── config.go                # TOML config loader, env var merging
│   │   └── validation.go            # Config validation and org ID resolution
│   ├── analyzers/
│   │   ├── analyzer.go              # Analyzer interface definition
│   │   ├── registry.go              # Analyzer registration and discovery
│   │   ├── identity.go              # SSO, MFA, admin roles, compliance officer
│   │   ├── messaging.go             # External comms, file sharing, DLP, classification
│   │   ├── meetings.go              # Encryption, lobby, passwords, virtual backgrounds
│   │   ├── recordings.go            # Recording storage, retention, access controls
│   │   ├── compliance.go            # eDiscovery, legal hold, data retention, audit events
│   │   ├── hybrid.go                # Cluster health, connector status, resource groups
│   │   ├── devices.go               # Device firmware, managed/unmanaged, workspaces
│   │   ├── bots.go                  # Bot inventory, approval status
│   │   ├── webhooks.go              # Webhook HTTPS enforcement, signing secrets
│   │   ├── calling.go               # SRTP enforcement, calling security profiles
│   │   ├── licenses.go              # License utilization and assignment review
│   │   └── guests.go                # Guest access policy evaluation
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
webex-sec-inspector [command] [flags]

Commands:
  scan        Run all security analyzers against the Webex organization
  analyze     Run a specific analyzer (e.g., identity, meetings, hybrid, devices)
  report      Generate report from previous scan results
  list        List available analyzers and controls
  version     Print version information

Global Flags:
  --token string           Webex bot or integration access token
  --client-id string       Service app client ID (OAuth client_credentials)
  --client-secret string   Service app client secret
  --org-id string          Organization ID to inspect (auto-detected if not set)
  --config string          Config file path (default "~/.config/webex-sec-inspector/config.toml")
  --output string          Output format: json, csv, html, summary (default "summary")
  --output-file string     Write report to file instead of stdout
  --severity string        Minimum severity to report: critical, high, medium, low (default "low")
  --tui                    Launch interactive TUI dashboard
  --no-color               Disable colored output
  --verbose                Enable verbose logging
  --timeout duration       API request timeout (default 30s)

Examples:
  # Full scan with bot token
  webex-sec-inspector scan --token $WEBEX_TOKEN

  # Scan specific analyzers with JSON output
  webex-sec-inspector analyze identity,meetings,hybrid --output json --output-file report.json

  # Scan high severity and above only
  webex-sec-inspector scan --severity high

  # Launch interactive TUI
  webex-sec-inspector scan --tui

  # Service app authentication
  webex-sec-inspector scan --client-id $WEBEX_CLIENT_ID --client-secret $WEBEX_CLIENT_SECRET

  # Target specific organization
  webex-sec-inspector scan --token $WEBEX_TOKEN --org-id Y2lzY29zcGFyazovL3VzL09SR...
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/webex-sec-inspector

# 2. Install dependencies
go get github.com/spf13/cobra@latest
go get github.com/charmbracelet/bubbletea@latest
go get github.com/charmbracelet/lipgloss@latest
go get github.com/pelletier/go-toml/v2@latest
go mod tidy

# 3. Build binary
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o bin/webex-sec-inspector ./cmd/webex-sec-inspector/

# 4. Run tests
go test ./... -v -race -coverprofile=coverage.out

# 5. Lint
golangci-lint run ./...

# 6. Docker build
docker build -t webex-sec-inspector:latest .

# 7. Release (via GoReleaser)
goreleaser release --clean
```

## 10. Status

Not yet implemented. Spec only.
