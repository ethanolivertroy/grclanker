---
slug: "box-sec-inspector"
name: "Box Security Inspector"
vendor: "Box"
category: "saas-collaboration"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/box-sec-inspector"
---

# Box Enterprise Security Inspector — Architecture Specification

## 1. Overview

**box-sec-inspector** is a security compliance inspection tool for Box Enterprise environments. It audits authentication policies, external collaboration settings, sharing controls, data governance (retention, legal hold, classification), device trust, Shield smart access policies, and admin role assignments via the Box REST API. The tool produces structured findings mapped to major compliance frameworks, enabling security teams to identify misconfigurations, enforce data protection policies, and maintain continuous compliance posture.

Written in Go with a hybrid CLI/TUI architecture, it supports both automated pipeline execution (JSON/SARIF output) and interactive exploration of findings.

## 2. APIs & SDKs

### Box REST API (Content API v2.0)

| Endpoint | Purpose |
|----------|---------|
| `GET /2.0/users` | List enterprise users, roles, status |
| `GET /2.0/users/{id}` | User details, login, 2FA status |
| `GET /2.0/groups` | Enterprise groups and membership |
| `GET /2.0/groups/{id}/memberships` | Group membership details |
| `GET /2.0/events?stream_type=admin_logs` | Enterprise event stream (audit) |
| `GET /2.0/events?stream_type=admin_logs_streaming` | Real-time admin event stream |
| `GET /2.0/device_pins` | Device trust/pinned devices |
| `GET /2.0/device_pins/{id}` | Device pin details |
| `GET /2.0/retention_policies` | Data retention policies |
| `GET /2.0/retention_policies/{id}` | Retention policy details |
| `GET /2.0/retention_policies/{id}/assignments` | Retention policy assignments |
| `GET /2.0/legal_hold_policies` | Legal hold policies |
| `GET /2.0/legal_hold_policies/{id}` | Legal hold policy details |
| `GET /2.0/legal_hold_policies/{id}/assignments` | Legal hold assignments |
| `GET /2.0/shield_information_barriers` | Shield information barriers |
| `GET /2.0/shield_information_barrier_segments` | Shield barrier segments |
| `GET /2.0/collaboration_whitelist_entries` | External collaboration allowlist |
| `GET /2.0/collaboration_whitelist_exempt_targets` | Collaboration exemptions |
| `GET /2.0/enterprises/{id}` | Enterprise settings |
| `GET /2.0/folders/{id}` | Folder details and shared link settings |
| `GET /2.0/folders/{id}/collaborations` | Folder collaboration audit |
| `GET /2.0/metadata_templates/enterprise` | Classification labels/templates |
| `GET /2.0/terms_of_services` | Custom terms of service |
| `GET /2.0/invites` | Pending enterprise invitations |

**Base URL:** `https://api.box.com`
**Upload URL:** `https://upload.box.com`

### Box Events API (for Audit)

Key event types for security auditing:
- `LOGIN` / `FAILED_LOGIN` — Authentication events
- `ADD_LOGIN_ACTIVITY_DEVICE` / `REMOVE_LOGIN_ACTIVITY_DEVICE` — Device trust events
- `CHANGE_ADMIN_ROLE` — Admin role changes
- `SHARE` / `UNSHARE` / `COLLABORATION_INVITE` — Sharing events
- `DOWNLOAD` / `PREVIEW` — Content access events
- `POLICY_VIOLATION` — Shield policy violations
- `CONTENT_ACCESS` — Access to sensitive content

### SDKs and Libraries

| Name | Language | Notes |
|------|----------|-------|
| `box-go-sdk` | Go | Community Go SDK |
| `boxsdk` | Python | Official Python SDK (box-python-sdk) |
| `box-java-sdk` | Java | Official Java SDK |
| `box-node-sdk` | Node.js | Official Node.js SDK |
| Box CLI | Node.js | Official CLI tool |
| Terraform Provider (community) | HCL | Limited Box resource coverage |

## 3. Authentication

### JWT (Server Authentication) — Recommended

```json
{
  "boxAppSettings": {
    "clientID": "...",
    "clientSecret": "...",
    "appAuth": {
      "publicKeyID": "...",
      "privateKey": "-----BEGIN ENCRYPTED PRIVATE KEY-----\n...",
      "passphrase": "..."
    }
  },
  "enterpriseID": "12345"
}
```

- Service account with enterprise-level access
- No user interaction required; ideal for automated scanning
- Requires Admin Console app authorization

### OAuth 2.0 (User Authentication)

```
Authorization: Bearer <access-token>
```

- User-level access with OAuth 2.0 flow
- Requires user with Co-Admin or Admin role
- Token refresh handled automatically

### Client Credentials Grant (CCG)

```
POST https://api.box.com/oauth2/token
grant_type=client_credentials
client_id=<client_id>
client_secret=<client_secret>
box_subject_type=enterprise
box_subject_id=<enterprise_id>
```

- Server-to-server without JWT key management
- Simpler setup than JWT

### Required Scopes/Permissions

| Permission | Purpose |
|------------|---------|
| `Manage Enterprise Properties` | Read enterprise settings |
| `Manage Users` | Enumerate users, roles, status |
| `Manage Groups` | Group and membership audit |
| `Manage Retention Policies` | Retention and legal hold review |
| `Manage Enterprise Events` | Enterprise event stream access |
| `Manage Device Pins` | Device trust audit |
| `Manage Shield` | Shield information barriers |
| `Manage Collaboration Allowlist` | External collaboration settings |

### Configuration

```bash
export BOX_JWT_CONFIG_PATH="/path/to/box_config.json"
# Or for CCG:
export BOX_CLIENT_ID="your-client-id"
export BOX_CLIENT_SECRET="your-client-secret"
export BOX_ENTERPRISE_ID="12345"
```

Alternatively, configure via `~/.box-sec-inspector/config.yaml` or CLI flags.

## 4. Security Controls

1. **SSO Enforcement** — Verify external SSO is configured and enforced for all users (not optional or disabled).
2. **2FA for Admins** — Confirm two-factor authentication is required for all admin and co-admin accounts.
3. **2FA for All Users** — Check if 2FA is enforced enterprise-wide, not just for admins.
4. **External Collaboration Restrictions** — Verify external collaboration is restricted to allowlisted domains only.
5. **Collaboration Allowlist Audit** — Review the external collaboration allowlist for stale or overly broad domain entries.
6. **Sharing Link Policies** — Ensure shared links default to "People in this company" or more restrictive; detect "Open" default links.
7. **Shared Link Expiration** — Verify shared links have mandatory expiration dates configured.
8. **Shared Link Password Policy** — Check if password protection is required for externally shared links.
9. **Watermarking Enabled** — Verify watermarking is enabled for sensitive content to deter unauthorized distribution.
10. **Device Trust/Pins** — Audit device pin configuration; ensure only approved devices can access enterprise content.
11. **Classification Labels** — Verify classification labels are defined and applied to sensitive content.
12. **Retention Policies** — Confirm retention policies exist and are assigned to appropriate folders/metadata for compliance.
13. **Legal Hold Policies** — Verify legal hold policies are properly configured and assigned for litigation readiness.
14. **Shield Smart Access Policies** — Audit Box Shield policies for anomaly detection, smart access rules, and threat detection.
15. **Shield Information Barriers** — Verify information barrier segments prevent unauthorized data flow between groups.
16. **Enterprise Event Streaming** — Confirm enterprise event streaming is active for audit trail and SIEM integration.
17. **Admin Role Minimization** — Detect excessive Admin/Co-Admin role assignments; ensure least-privilege.
18. **Co-Admin Permission Scoping** — Verify co-admin roles have appropriately scoped permissions (not full admin equivalent).
19. **App Approval Process** — Check that custom/third-party app access requires admin approval (not open by default).
20. **Custom Terms of Service** — Verify custom ToS is configured and required for users before accessing content.
21. **Password Policy Strength** — Validate enterprise password policy meets minimum complexity and length requirements.
22. **Session Duration Limits** — Confirm session timeout and maximum session duration are appropriately configured.
23. **IP Allowlisting** — Verify IP-based access restrictions are configured for the enterprise.
24. **Inactive User Detection** — Identify user accounts that have not logged in within 90 days.
25. **Content Access Monitoring** — Verify Shield or event monitoring is configured for sensitive content access patterns.

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 | SSO Enforcement | IA-2 | AC.L2-3.1.1 | CC6.1 | 1.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | CPS-04 |
| 2 | 2FA for Admins | IA-2(1) | IA.L2-3.5.3 | CC6.1 | 4.1 | 8.4.2 | SRG-APP-000149 | ISM-1401 | CPS-06 |
| 3 | 2FA for All Users | IA-2(1) | IA.L2-3.5.3 | CC6.1 | 4.2 | 8.4.2 | SRG-APP-000149 | ISM-1401 | CPS-06 |
| 4 | External Collab Restrictions | AC-4 | AC.L2-3.1.3 | CC6.6 | 6.1 | 7.2.3 | SRG-APP-000039 | ISM-1148 | CPS-11 |
| 5 | Collab Allowlist Audit | AC-4 | AC.L2-3.1.3 | CC6.6 | 6.2 | 7.2.3 | SRG-APP-000039 | ISM-1148 | CPS-11 |
| 6 | Sharing Link Policies | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.3 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 7 | Shared Link Expiration | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.4 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 8 | Shared Link Password | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.5 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 9 | Watermarking | SC-28 | SC.L2-3.13.16 | CC6.7 | 3.1 | 3.4 | SRG-APP-000231 | ISM-0457 | CPS-09 |
| 10 | Device Trust/Pins | IA-3 | IA.L2-3.5.1 | CC6.1 | 1.2 | 2.4 | SRG-APP-000158 | ISM-1482 | CPS-04 |
| 11 | Classification Labels | MP-4 | MP.L2-3.8.5 | CC6.7 | 3.2 | 9.6.1 | SRG-APP-000231 | ISM-0272 | CPS-09 |
| 12 | Retention Policies | AU-11 | AU.L2-3.3.1 | CC7.4 | 8.1 | 3.1 | SRG-APP-000515 | ISM-0859 | CPS-10 |
| 13 | Legal Hold Policies | AU-11 | AU.L2-3.3.1 | CC7.4 | 8.2 | 3.1 | SRG-APP-000515 | ISM-0859 | CPS-10 |
| 14 | Shield Smart Access | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.6 | 7.2.1 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 15 | Information Barriers | AC-4 | AC.L2-3.1.3 | CC6.6 | 6.7 | 7.2.3 | SRG-APP-000039 | ISM-1148 | CPS-11 |
| 16 | Event Streaming | AU-2 | AU.L2-3.3.1 | CC7.2 | 8.3 | 10.2.1 | SRG-APP-000089 | ISM-0580 | CPS-10 |
| 17 | Admin Role Minimization | AC-6(5) | AC.L2-3.1.5 | CC6.3 | 6.8 | 7.2.2 | SRG-APP-000340 | ISM-1507 | CPS-07 |
| 18 | Co-Admin Scoping | AC-6 | AC.L2-3.1.5 | CC6.3 | 6.9 | 7.2.2 | SRG-APP-000340 | ISM-0432 | CPS-07 |
| 19 | App Approval Process | CM-7(5) | CM.L2-3.4.8 | CC8.1 | 10.1 | 6.3.2 | SRG-APP-000386 | ISM-1490 | CPS-12 |
| 20 | Custom Terms of Service | PS-6 | AT.L2-3.2.1 | CC1.4 | 11.1 | 12.6.1 | SRG-APP-000516 | ISM-0252 | CPS-13 |
| 21 | Password Policy Strength | IA-5(1) | IA.L2-3.5.7 | CC6.1 | 5.1 | 8.3.6 | SRG-APP-000166 | ISM-0421 | CPS-05 |
| 22 | Session Duration | AC-11 | AC.L2-3.1.10 | CC6.1 | 7.1 | 8.2.8 | SRG-APP-000190 | ISM-0853 | CPS-08 |
| 23 | IP Allowlisting | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.1 | 1.3.2 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 24 | Inactive User Detection | AC-2(3) | AC.L2-3.1.1 | CC6.2 | 7.2 | 8.1.4 | SRG-APP-000025 | ISM-1404 | CPS-07 |
| 25 | Content Access Monitoring | AU-6 | AU.L2-3.3.5 | CC7.2 | 8.4 | 10.6.1 | SRG-APP-000108 | ISM-0580 | CPS-10 |

## 6. Existing Tools

| Tool | Type | Limitations |
|------|------|-------------|
| Box Admin Console | Built-in | Manual configuration review, no automated compliance reporting |
| Box Shield | Built-in | Threat detection and smart access, but no comprehensive config posture assessment |
| Box Governance | Add-on | Retention and legal hold management, not security configuration auditing |
| Box CLI | CLI | Management operations, no security assessment capability |
| Box Reports (Admin) | Reporting | Usage analytics, not security posture analysis |
| Custom Event Stream Scripts | Custom | No structured compliance mapping or standardized output |

**Gap:** No existing tool provides automated security posture assessment of Box Enterprise configurations — including Shield policies, collaboration restrictions, device trust, and data governance settings — mapped to compliance frameworks. box-sec-inspector fills this gap.

## 7. Architecture

```
box-sec-inspector/
├── cmd/
│   └── box-sec-inspector/
│       └── main.go                 # Entrypoint, CLI bootstrap
├── internal/
│   ├── analyzers/
│   │   ├── analyzer.go             # Analyzer interface and registry
│   │   ├── sso.go                  # SSO enforcement checks
│   │   ├── mfa.go                  # 2FA for admins and all users
│   │   ├── collaboration.go        # External collab restrictions, allowlist
│   │   ├── sharing.go              # Shared link policies, expiration, passwords
│   │   ├── watermark.go            # Watermarking configuration
│   │   ├── devices.go              # Device trust/pin audit
│   │   ├── classification.go       # Classification label audit
│   │   ├── retention.go            # Retention and legal hold policies
│   │   ├── shield.go               # Shield smart access and info barriers
│   │   ├── events.go               # Enterprise event streaming checks
│   │   ├── admins.go               # Admin role minimization and scoping
│   │   ├── apps.go                 # App approval process audit
│   │   ├── tos.go                  # Terms of service configuration
│   │   ├── password.go             # Password policy strength
│   │   ├── sessions.go             # Session duration and timeout
│   │   ├── network.go              # IP allowlisting
│   │   └── users.go                # Inactive user detection
│   ├── client/
│   │   ├── client.go               # Box API client
│   │   ├── jwt.go                  # JWT authentication
│   │   ├── oauth.go                # OAuth 2.0 authentication
│   │   ├── ccg.go                  # Client Credentials Grant auth
│   │   ├── ratelimit.go            # Rate limiter (10 req/sec per user)
│   │   └── pagination.go           # Marker-based pagination handler
│   ├── config/
│   │   ├── config.go               # Configuration loading and validation
│   │   └── redact.go               # Credential redaction for logging
│   ├── models/
│   │   ├── user.go                 # User, group, role models
│   │   ├── policy.go               # Retention, legal hold, Shield models
│   │   ├── collaboration.go        # Collaboration and sharing models
│   │   ├── device.go               # Device pin model
│   │   ├── event.go                # Enterprise event model
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

- **Multi-auth support**: JWT (recommended for automation), OAuth 2.0 (interactive), and CCG (simplified server-to-server)
- **Enterprise event analysis**: Leverages the enterprise event stream for historical security event correlation
- **Rate limiting**: Box enforces 10 API calls per second per user; built-in token bucket rate limiter
- **Marker-based pagination**: All list endpoints use marker pagination; client handles transparently
- **Shield-aware**: Dedicated analyzers for Box Shield features (smart access, information barriers, threat detection)

## 8. CLI Interface

```
box-sec-inspector [command] [flags]

Commands:
  scan        Run all or selected security analyzers
  list        List available analyzers and their descriptions
  version     Print version information

Scan Flags:
  --jwt-config string      Path to Box JWT config file (env: BOX_JWT_CONFIG_PATH)
  --client-id string       Box app client ID (env: BOX_CLIENT_ID)
  --client-secret string   Box app client secret (env: BOX_CLIENT_SECRET)
  --enterprise-id string   Box enterprise ID (env: BOX_ENTERPRISE_ID)
  --auth-method string     Auth method: jwt, ccg, oauth (default "jwt")
  --analyzers strings      Run specific analyzers (comma-separated)
  --exclude strings        Exclude specific analyzers
  --severity string        Minimum severity to report: critical,high,medium,low,info
  --format string          Output format: table,json,sarif,csv,html (default "table")
  --output string          Output file path (default: stdout)
  --tui                    Launch interactive TUI
  --no-color               Disable colored output
  --config string          Path to config file (default "~/.box-sec-inspector/config.yaml")
  --event-window duration  Event stream lookback window (default 30d)
  --timeout duration       API request timeout (default 30s)
  --verbose                Enable verbose logging
```

### Usage Examples

```bash
# Full scan with JWT auth
box-sec-inspector scan --jwt-config /path/to/box_config.json

# Scan with Client Credentials Grant
box-sec-inspector scan --auth-method ccg

# Collaboration and sharing checks only
box-sec-inspector scan --analyzers collaboration,sharing

# Generate SARIF for CI/CD pipeline
box-sec-inspector scan --format sarif --output results.sarif

# JSON output for SIEM integration
box-sec-inspector scan --format json --output results.json

# Interactive TUI
box-sec-inspector scan --tui

# List available analyzers
box-sec-inspector list
```

## 9. Build Sequence

```bash
# Prerequisites
go 1.22+

# Clone and build
git clone https://github.com/hackIDLE/box-sec-inspector.git
cd box-sec-inspector
go mod download
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o bin/box-sec-inspector ./cmd/box-sec-inspector/

# Run tests
go test ./...

# Build Docker image
docker build -t box-sec-inspector .

# Run via Docker
docker run --rm \
  -v /path/to/box_config.json:/config/box_config.json:ro \
  -e BOX_JWT_CONFIG_PATH=/config/box_config.json \
  box-sec-inspector scan --format json
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
