---
slug: "slack-sec-inspector"
name: "Slack Security Inspector"
vendor: "Slack"
category: "saas-collaboration"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/slack-sec-inspector"
---

# slack-sec-inspector

## 1. Overview

A security compliance inspection tool for **Slack Enterprise Grid** that audits workspace and organization-level security configurations against industry compliance frameworks. The tool connects to Slack's management and audit APIs to evaluate SSO enforcement, MFA policies, data loss prevention settings, external sharing controls, app management, session policies, and audit log configurations. Results are output as structured compliance reports mapped to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP controls.

## 2. APIs & SDKs

### Slack APIs

| API | Base URL | Purpose |
|-----|----------|---------|
| **Web API** | `https://slack.com/api/` | Core workspace and user management methods |
| **SCIM API** | `https://api.slack.com/scim/v2/` | User and group provisioning (Enterprise Grid) |
| **Audit Logs API** | `https://api.slack.com/audit/v1/logs` | Organization-level audit event retrieval (Enterprise Grid) |
| **Admin API** | `https://slack.com/api/admin.*` | Enterprise administration methods |
| **Discovery API** | `https://slack.com/api/discovery.*` | DLP and eDiscovery content access (Enterprise Grid) |

### Key API Methods

**Admin API (admin.* methods):**
- `admin.teams.settings.info` — Workspace-level security settings
- `admin.teams.settings.setDiscoverability` — Control workspace discoverability
- `admin.users.session.list` / `admin.users.session.invalidate` — Session management
- `admin.users.session.setSettings` — Session duration and idle timeout policies
- `admin.conversations.setConversationPrefs` — Channel posting restrictions
- `admin.conversations.restrictAccess.addGroup` — IDP group channel restrictions
- `admin.apps.approve` / `admin.apps.restrict` — App management
- `admin.apps.approved.list` / `admin.apps.restricted.list` — App audit
- `admin.emoji.add` / `admin.emoji.list` — Custom emoji management
- `admin.teams.admins.list` — Admin role enumeration
- `admin.users.list` — User management with deactivation status
- `admin.usergroups.addTeams` — IDP group workspace assignment
- `admin.barriers.create` / `admin.barriers.list` — Information barriers

**SCIM API:**
- `GET /Users` — List provisioned users with attributes
- `GET /Groups` — List provisioned groups
- `PATCH /Users/{id}` — Update user provisioning attributes
- `GET /ServiceProviderConfig` — SCIM endpoint capabilities

**Audit Logs API:**
- `GET /audit/v1/logs` — Retrieve audit events with action-based filtering
- `GET /audit/v1/schemas` — Available audit event schemas
- Supported actions: `user_login`, `user_logout`, `file_downloaded`, `app_installed`, `role_change_to_admin`, `pref_sso_setting_changed`, `pref_two_factor_auth_changed`, etc.

**Discovery API:**
- `discovery.enterprise.info` — Organization-level DLP settings
- `discovery.conversations.list` — Enumerate conversations for DLP scanning
- `discovery.conversations.history` — Retrieve message content for DLP

### SDKs

| SDK | Language | Package |
|-----|----------|---------|
| **slack_sdk** | Python | `pip install slack_sdk` (official, Slack Technologies) |
| **slack-bolt** | Python | `pip install slack-bolt` (app framework) |
| **Slack CLI** | CLI | `slack` CLI tool for Slack platform apps |
| **node-slack-sdk** | Node.js | `@slack/web-api` (official) |

## 3. Authentication

### Token Types

| Token | Prefix | Scope |
|-------|--------|-------|
| **Bot Token** | `xoxb-` | Workspace-level bot permissions |
| **User Token** | `xoxp-` | User-level API access; required for admin.* methods |
| **Org-Level Token** | `xoxp-` | Enterprise Grid org-level admin token |
| **SCIM Token** | Bearer | SCIM provisioning API access |

### Required OAuth Scopes

For a comprehensive security audit, the following scopes are required on an **org-level user token**:

- `admin.teams:read` — Read workspace settings
- `admin.users:read` — List users and session info
- `admin.users.session:read` — Read session settings
- `admin.conversations:read` — Read conversation preferences
- `admin.apps:read` — Read approved/restricted apps
- `admin.barriers:read` — Read information barriers
- `admin.roles:read` — Read admin role assignments
- `auditlogs:read` — Read audit log events (Enterprise Grid)
- `discovery:read` — Read DLP/eDiscovery data (Enterprise Grid)
- `users:read` — Basic user enumeration
- `team:read` — Workspace info

### SCIM Authentication

SCIM API uses a separate bearer token issued from the Enterprise Grid admin dashboard under **Settings > Authentication > SCIM Provisioning**.

### Configuration

```
SLACK_USER_TOKEN=xoxp-...
SLACK_SCIM_TOKEN=...
SLACK_ORG_ID=E0123456789
```

## 4. Security Controls

1. **SSO enforcement** — Verify SAML SSO is required for all users (not optional) via org-level authentication policy
2. **Two-factor authentication** — Confirm 2FA is mandated org-wide; enumerate users without 2FA enrolled
3. **Session duration limits** — Validate maximum session duration is set (recommended: 24h or less)
4. **Session idle timeout** — Ensure idle session timeout is configured (recommended: 30 minutes or less)
5. **Mobile session controls** — Verify mobile app session duration and jailbreak/root detection policies
6. **File upload restrictions** — Check whether file uploads are restricted by type or disabled for external channels
7. **External sharing controls** — Audit whether Slack Connect (external organizations) channels are permitted and which workspaces allow them
8. **Information barriers** — Verify information barriers are configured between restricted groups (e.g., compliance walls)
9. **App management policy** — Confirm app installation requires admin approval; enumerate approved and restricted apps
10. **Custom app restrictions** — Verify that only approved custom integrations and bots are permitted
11. **DLP policy configuration** — Check that Discovery API is enabled and DLP scanning is active for sensitive content patterns
12. **Channel retention policies** — Audit message and file retention settings per workspace; verify compliance-required retention periods
13. **Audit log streaming** — Confirm audit logs are being streamed to an external SIEM (Amazon S3, Splunk, etc.)
14. **Admin role inventory** — Enumerate all org admins, workspace admins, and owners; flag excessive admin privileges
15. **Guest account controls** — Audit single-channel and multi-channel guest accounts; verify guest expiration policies
16. **Email domain restrictions** — Verify workspace signup is restricted to approved email domains
17. **Workspace discoverability** — Ensure workspace discoverability is set appropriately (not open to all org members if sensitive)
18. **Channel posting restrictions** — Audit channels where posting is restricted to admins or specific groups
19. **Custom emoji restrictions** — Verify whether custom emoji uploads are restricted to admins
20. **External email ingestion** — Check whether email-to-channel forwarding is enabled and restricted
21. **Link previews and URL unfurling** — Audit whether link previews expose sensitive content in channels
22. **SCIM provisioning status** — Verify SCIM provisioning is active and user lifecycle management is automated
23. **Deactivated user audit** — Enumerate deactivated users and verify timely deprovisioning matches HR/IdP records
24. **Workspace analytics access** — Verify analytics export access is restricted to authorized admins
25. **Token rotation and revocation** — Audit API token age and ensure legacy tokens are revoked

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 | SSO enforcement | IA-2(1) | 3.5.3 | CC6.1 | 16.2 | 8.4.1 | SRG-APP-000149 | ISM-1546 | CPS.AT-1 |
| 2 | Two-factor authentication | IA-2(6) | 3.5.3 | CC6.1 | 16.3 | 8.4.2 | SRG-APP-000150 | ISM-1504 | CPS.AT-2 |
| 3 | Session duration limits | AC-12 | 3.1.10 | CC6.1 | 16.4 | 8.2.8 | SRG-APP-000295 | ISM-1164 | CPS.AC-7 |
| 4 | Session idle timeout | AC-11 | 3.1.11 | CC6.1 | 16.5 | 8.2.8 | SRG-APP-000190 | ISM-1164 | CPS.AC-7 |
| 5 | Mobile session controls | AC-19 | 3.1.18 | CC6.7 | — | 8.2.8 | SRG-APP-000394 | ISM-1082 | CPS.MP-1 |
| 6 | File upload restrictions | SC-7 | 3.13.6 | CC6.6 | — | 1.3.2 | SRG-APP-000001 | ISM-0331 | CPS.SC-7 |
| 7 | External sharing controls | AC-21 | 3.1.20 | CC6.6 | — | 7.1.2 | SRG-APP-000378 | ISM-0661 | CPS.AC-4 |
| 8 | Information barriers | AC-4 | 3.1.3 | CC6.6 | — | 7.1.1 | SRG-APP-000039 | ISM-1528 | CPS.AC-4 |
| 9 | App management policy | CM-7 | 3.4.8 | CC6.8 | 2.7 | 6.3.2 | SRG-APP-000141 | ISM-1624 | CPS.CM-7 |
| 10 | Custom app restrictions | CM-7(4) | 3.4.8 | CC6.8 | 2.7 | 6.3.2 | SRG-APP-000386 | ISM-1624 | CPS.CM-7 |
| 11 | DLP policy configuration | SC-7(8) | 3.13.6 | CC6.7 | — | — | SRG-APP-000400 | ISM-0261 | CPS.SC-7 |
| 12 | Channel retention policies | AU-11 | 3.3.1 | CC7.2 | — | 10.7.1 | SRG-APP-000515 | ISM-0859 | CPS.AU-11 |
| 13 | Audit log streaming | AU-6(3) | 3.3.5 | CC7.2 | 8.2 | 10.5.1 | SRG-APP-000516 | ISM-0580 | CPS.AU-6 |
| 14 | Admin role inventory | AC-6(5) | 3.1.5 | CC6.3 | 16.8 | 7.1.1 | SRG-APP-000340 | ISM-1507 | CPS.AC-6 |
| 15 | Guest account controls | AC-2(2) | 3.1.1 | CC6.2 | 16.7 | 7.1.2 | SRG-APP-000024 | ISM-0415 | CPS.AC-2 |
| 16 | Email domain restrictions | IA-5 | 3.5.7 | CC6.1 | — | 8.3.1 | SRG-APP-000173 | ISM-1557 | CPS.IA-5 |
| 17 | Workspace discoverability | AC-3 | 3.1.1 | CC6.1 | — | 7.1.1 | SRG-APP-000033 | ISM-0432 | CPS.AC-3 |
| 18 | Channel posting restrictions | AC-3(7) | 3.1.2 | CC6.1 | — | 7.1.1 | SRG-APP-000033 | ISM-0405 | CPS.AC-3 |
| 19 | Custom emoji restrictions | CM-5 | 3.4.5 | CC8.1 | — | — | SRG-APP-000380 | ISM-1624 | CPS.CM-5 |
| 20 | External email ingestion | SC-7(4) | 3.13.6 | CC6.6 | — | 1.3.2 | SRG-APP-000001 | ISM-0264 | CPS.SC-7 |
| 21 | Link previews and URL unfurling | SC-7 | 3.13.1 | CC6.6 | — | — | SRG-APP-000001 | ISM-0260 | CPS.SC-7 |
| 22 | SCIM provisioning status | AC-2(1) | 3.1.1 | CC6.2 | — | 7.1.1 | SRG-APP-000023 | ISM-1594 | CPS.AC-2 |
| 23 | Deactivated user audit | AC-2(3) | 3.1.12 | CC6.2 | 16.9 | 8.1.4 | SRG-APP-000025 | ISM-1591 | CPS.AC-2 |
| 24 | Workspace analytics access | AC-6(9) | 3.1.7 | CC6.3 | — | 7.1.2 | SRG-APP-000343 | ISM-0988 | CPS.AC-6 |
| 25 | Token rotation and revocation | IA-5(1) | 3.5.10 | CC6.1 | — | 8.6.3 | SRG-APP-000175 | ISM-1557 | CPS.IA-5 |

## 6. Existing Tools

| Tool | Description | Limitations |
|------|-------------|-------------|
| **Slack Enterprise Audit Dashboard** | Built-in admin analytics and audit log viewer | No automated compliance mapping; manual review only |
| **Slack SIEM Integrations** (Splunk, Datadog) | Audit log forwarding and alerting | Focused on detection, not configuration compliance |
| **Resmo** | SaaS security posture management with Slack integration | Commercial; limited to their predefined checks |
| **Nudge Security** | SaaS discovery and governance | Focused on shadow IT, not deep config audit |
| **AppOmni** | SaaS security posture management | Commercial; expensive enterprise pricing |
| **Valence Security** | SaaS security remediation | Commercial; focused on remediation workflows |
| **ScoutSuite** | Multi-cloud security auditing | Cloud-focused, no Slack support |

**Gap:** No open-source tool performs comprehensive Slack Enterprise security configuration auditing with multi-framework compliance mapping. Existing tools are either commercial SaaS platforms, focused on log analysis rather than configuration posture, or lack the depth of controls covered here.

## 7. Architecture

```
slack-sec-inspector/
├── cmd/
│   └── slack-sec-inspector/
│       └── main.go                  # CLI entrypoint
├── internal/
│   ├── client/
│   │   ├── slack.go                 # Slack Web API client wrapper
│   │   ├── scim.go                  # SCIM API client
│   │   ├── audit.go                 # Audit Logs API client
│   │   └── ratelimit.go            # Tier-aware rate limiter (Tier 1-4)
│   ├── analyzers/
│   │   ├── sso.go                   # Control 1: SSO enforcement
│   │   ├── mfa.go                   # Control 2: Two-factor authentication
│   │   ├── sessions.go              # Controls 3-5: Session policies
│   │   ├── fileuploads.go           # Control 6: File upload restrictions
│   │   ├── externalsharing.go       # Controls 7, 20: External sharing and email ingestion
│   │   ├── barriers.go              # Control 8: Information barriers
│   │   ├── apps.go                  # Controls 9-10: App management
│   │   ├── dlp.go                   # Control 11: DLP policy configuration
│   │   ├── retention.go             # Control 12: Channel retention policies
│   │   ├── auditlogs.go            # Control 13: Audit log streaming
│   │   ├── adminroles.go           # Control 14: Admin role inventory
│   │   ├── guests.go               # Control 15: Guest account controls
│   │   ├── domains.go              # Control 16: Email domain restrictions
│   │   ├── discoverability.go      # Control 17: Workspace discoverability
│   │   ├── channels.go             # Control 18: Channel posting restrictions
│   │   ├── emoji.go                # Control 19: Custom emoji restrictions
│   │   ├── urlpreviews.go          # Control 21: Link previews
│   │   ├── scim.go                 # Control 22: SCIM provisioning status
│   │   ├── users.go                # Control 23: Deactivated user audit
│   │   ├── analytics.go            # Control 24: Workspace analytics access
│   │   └── tokens.go               # Control 25: Token rotation and revocation
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
| `github.com/slack-go/slack` | Go Slack API client |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/charmbracelet/bubbletea` | Terminal UI framework |
| `github.com/charmbracelet/lipgloss` | TUI styling |

## 8. CLI Interface

```
slack-sec-inspector [command] [flags]

Commands:
  scan          Run security compliance scan against Slack org
  report        Generate compliance report from scan results
  version       Print version information

Global Flags:
  --token string        Slack user token (xoxp-...) [$SLACK_USER_TOKEN]
  --scim-token string   SCIM bearer token [$SLACK_SCIM_TOKEN]
  --org-id string       Enterprise Grid organization ID [$SLACK_ORG_ID]
  --output string       Output format: json, csv, markdown, html, sarif (default "json")
  --output-dir string   Directory for report output (default "./results")
  --severity string     Minimum severity to report: critical, high, medium, low, info (default "low")
  --controls string     Comma-separated list of control numbers to run (default: all)
  --quiet               Suppress progress output
  --no-color            Disable colored output
  --tui                 Launch interactive terminal UI

Scan Flags:
  --workspace string    Limit scan to specific workspace ID
  --skip-scim           Skip SCIM provisioning checks
  --skip-discovery      Skip Discovery API (DLP) checks
  --skip-audit-logs     Skip Audit Logs API checks
  --parallel int        Number of parallel API calls (default 4)
  --timeout duration    API call timeout (default 30s)

Examples:
  # Full org-level scan with JSON output
  slack-sec-inspector scan --token xoxp-... --scim-token ... --org-id E01234

  # Scan specific controls with markdown report
  slack-sec-inspector scan --controls 1,2,3,14 --output markdown

  # Interactive TUI mode
  slack-sec-inspector scan --tui

  # Generate SARIF for CI/CD pipeline
  slack-sec-inspector scan --output sarif --severity high
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/slack-sec-inspector

# 2. Add dependencies
go get github.com/slack-go/slack
go get github.com/spf13/cobra
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss

# 3. Build
go build -ldflags "-X pkg/version.Version=$(git describe --tags)" \
  -o bin/slack-sec-inspector ./cmd/slack-sec-inspector/

# 4. Test
go test ./...

# 5. Lint
golangci-lint run

# 6. Docker
docker build -t slack-sec-inspector .

# 7. Release
goreleaser release --snapshot
```

## 10. Status

Not yet implemented. Spec only.
