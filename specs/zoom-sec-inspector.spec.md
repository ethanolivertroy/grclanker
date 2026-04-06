---
slug: "zoom-sec-inspector"
name: "Zoom Security Inspector"
vendor: "Zoom"
category: "saas-collaboration"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/zoom-sec-inspector"
---

# Zoom Security Inspector

## 1. Overview

A security compliance inspection tool for **Zoom for Government** and Zoom Workplace environments. Audits account-level and user-level security settings, meeting policies, recording controls, authentication enforcement, and communication restrictions against enterprise security baselines and government compliance frameworks.

Targets Zoom accounts using the Zoom REST API v2 to evaluate configuration posture, identify misconfigurations, and generate compliance-mapped findings.

## 2. APIs & SDKs

### Zoom REST API v2

Base URL: `https://api.zoom.us/v2` (commercial) / `https://api.zoomgov.com/v2` (GovCloud)

| Endpoint | Purpose |
|----------|---------|
| `GET /accounts/{accountId}/settings` | Account-level security and meeting settings |
| `GET /accounts/{accountId}/lock_settings` | Locked (enforced) settings at account level |
| `GET /users` | List all users, pagination |
| `GET /users/{userId}/settings` | Per-user meeting, recording, telephony settings |
| `GET /users/{userId}/token` | User ZAK token info |
| `GET /roles` | List all custom roles |
| `GET /roles/{roleId}` | Role detail and privileges |
| `GET /roles/{roleId}/members` | Members assigned to a role |
| `GET /groups` | List all groups |
| `GET /groups/{groupId}/settings` | Group-level setting overrides |
| `GET /groups/{groupId}/lock_settings` | Locked settings at group level |
| `GET /report/meetings` | Meeting usage reports |
| `GET /report/operationlogs` | Admin operation/audit logs |
| `GET /im/groups` | IM (chat) group configuration |
| `GET /im/groups/{imGroupId}` | IM group detail and members |
| `GET /accounts/{accountId}/managed_domains` | Managed/associated domains |
| `GET /accounts/{accountId}/trusted_domains` | Trusted external domains |
| `GET /phone/call_handling/settings` | Zoom Phone call handling settings |
| `GET /phone/recording` | Zoom Phone recording policies |

### Rate Limits

- Per-second rate limits vary by endpoint category (heavy: 1 req/s, medium: 10 req/s, light: 30 req/s)
- Daily rate limits apply to report endpoints (60 requests/day for some)
- Response header `X-RateLimit-Remaining` for tracking

### SDKs & Tools

| Tool | Type | Notes |
|------|------|-------|
| `zoom-python` | Community Python SDK | Wraps REST API v2, not officially maintained |
| `zoomus` | Community Python SDK | Alternative community wrapper |
| Zoom CLI | Official CLI | Limited to meeting/webinar management |
| `httpx` / `requests` | HTTP client | Direct API calls recommended for reliability |

## 3. Authentication

### Server-to-Server OAuth (Recommended)

- Created in Zoom App Marketplace as "Server-to-Server OAuth" app type
- Provides `account_id`, `client_id`, `client_secret`
- Token endpoint: `POST https://zoom.us/oauth/token?grant_type=account_credentials&account_id={account_id}`
- Tokens expire in 1 hour, must be refreshed
- Scopes required: `account:read:admin`, `user:read:admin`, `group:read:admin`, `role:read:admin`, `report:read:admin`, `im:read:admin`, `phone:read:admin`
- Best for automated/headless inspection

### OAuth 2.0 (User-Level)

- Authorization Code flow for interactive use
- Redirect URI required
- Scopes granted per-user

### JWT (Deprecated)

- Deprecated June 2023, removed September 2023
- Should not be used; detect and warn if configured

### Configuration

```
ZOOM_ACCOUNT_ID=<account_id>
ZOOM_CLIENT_ID=<client_id>
ZOOM_CLIENT_SECRET=<client_secret>
ZOOM_BASE_URL=https://api.zoom.us/v2       # or https://api.zoomgov.com/v2
```

## 4. Security Controls

| # | Control | API Source | Severity |
|---|---------|-----------|----------|
| 1 | Meeting password enforcement enabled | `/accounts/{id}/settings` → `schedule_meeting.require_password_for_scheduling_new_meetings` | Critical |
| 2 | Waiting room enabled by default | `/accounts/{id}/settings` → `in_meeting.waiting_room` | Critical |
| 3 | Screen sharing restricted to host only | `/accounts/{id}/settings` → `in_meeting.screen_sharing` | High |
| 4 | Recording consent notification enabled | `/accounts/{id}/settings` → `recording.recording_disclaimer` | High |
| 5 | SSO enforcement for all users | `/users` → `login_type` field analysis | Critical |
| 6 | Two-factor authentication for admins | `/users/{id}/settings` → `feature.two_factor_auth` | Critical |
| 7 | End-to-end encryption available and default | `/accounts/{id}/settings` → `in_meeting.e2e_encryption` | High |
| 8 | Chat encryption enabled | `/accounts/{id}/settings` → `in_meeting.chat` encryption settings | Medium |
| 9 | File transfer in meetings restricted | `/accounts/{id}/settings` → `in_meeting.file_transfer` | Medium |
| 10 | Cloud recording auto-delete policy configured | `/accounts/{id}/settings` → `recording.auto_delete_cmr` | High |
| 11 | Cloud recording auto-delete days ≤ retention policy | `/accounts/{id}/settings` → `recording.auto_delete_cmr_days` | Medium |
| 12 | External contacts restricted | `/accounts/{id}/settings` → `in_meeting.allow_participants_to_rename` | Medium |
| 13 | Vanity URL configured and secured | `/accounts/{id}/settings` → account vanity URL | Low |
| 14 | Managed domains verified | `/accounts/{id}/managed_domains` | High |
| 15 | IM group restrictions enforced | `/im/groups` → group settings analysis | Medium |
| 16 | Sign-in methods restricted (no personal email) | `/users` → `login_type` analysis | High |
| 17 | Session timeout configured ≤ organizational policy | `/accounts/{id}/settings` → `security.session_duration` | Medium |
| 18 | Data routing control enabled (GovCloud/data residency) | `/accounts/{id}/settings` → `in_meeting.data_center_regions` | Critical |
| 19 | Zoom Phone recording policies enforced | `/phone/recording` | High |
| 20 | Local recording disabled or restricted | `/accounts/{id}/settings` → `recording.local_recording` | High |
| 21 | Meeting password locked at account level | `/accounts/{id}/lock_settings` → password settings | Critical |
| 22 | Embed password in join link disabled | `/accounts/{id}/settings` → `schedule_meeting.embed_password_in_join_link` | Medium |
| 23 | Only authenticated users can join meetings | `/accounts/{id}/settings` → `schedule_meeting.meeting_authentication` | High |
| 24 | Admin operation log retention verified | `/report/operationlogs` | Medium |
| 25 | Personal Meeting ID (PMI) usage restricted | `/accounts/{id}/settings` → `schedule_meeting.use_pmi_for_scheduled_meetings` | Medium |

## 5. Compliance Framework Mappings

| Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---------|---------|------|-------|-----|---------|------|------|-------|
| 1. Meeting password enforcement | AC-3 | AC.L2-3.1.1 | CC6.1 | 5.2 | 8.3.1 | SRG-APP-000033 | ISM-0974 | 8.1.1 |
| 2. Waiting room enabled | AC-3 | AC.L2-3.1.2 | CC6.1 | 5.2 | 7.1.1 | SRG-APP-000033 | ISM-0974 | 8.1.1 |
| 3. Screen sharing restricted | AC-3 | AC.L2-3.1.5 | CC6.1 | 5.3 | 7.1.2 | SRG-APP-000038 | ISM-1146 | 8.1.2 |
| 4. Recording consent | AU-14 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.1 | SRG-APP-000092 | ISM-0580 | 12.1.1 |
| 5. SSO enforcement | IA-2 | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 6. 2FA for admins | IA-2(1) | IA.L2-3.5.3 | CC6.1 | 4.5 | 8.3.2 | SRG-APP-000149 | ISM-1401 | 8.2.2 |
| 7. E2E encryption | SC-8(1) | SC.L2-3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0487 | 10.1.1 |
| 8. Chat encryption | SC-8 | SC.L2-3.13.1 | CC6.7 | 14.4 | 4.1 | SRG-APP-000439 | ISM-0487 | 10.1.1 |
| 9. File transfer restricted | SC-7 | SC.L2-3.13.6 | CC6.6 | 13.1 | 1.3.1 | SRG-APP-000383 | ISM-1284 | 10.2.1 |
| 10. Cloud recording auto-delete | SI-12 | MP.L2-3.8.3 | CC6.5 | 3.1 | 3.1 | SRG-APP-000504 | ISM-0261 | 7.1.1 |
| 11. Recording retention days | SI-12 | MP.L2-3.8.3 | CC6.5 | 3.1 | 3.1 | SRG-APP-000504 | ISM-0261 | 7.1.1 |
| 12. External contacts restricted | AC-4 | AC.L2-3.1.3 | CC6.6 | 13.4 | 1.3.4 | SRG-APP-000039 | ISM-1284 | 8.1.3 |
| 13. Vanity URL secured | IA-8 | IA.L2-3.5.2 | CC6.1 | 4.1 | 8.1.1 | SRG-APP-000153 | ISM-1557 | 8.2.1 |
| 14. Managed domains verified | IA-8 | IA.L2-3.5.2 | CC6.1 | 4.1 | 8.1.1 | SRG-APP-000153 | ISM-1557 | 8.2.1 |
| 15. IM group restrictions | AC-4 | AC.L2-3.1.3 | CC6.6 | 13.4 | 7.1.2 | SRG-APP-000039 | ISM-1284 | 8.1.3 |
| 16. Sign-in methods restricted | IA-5 | IA.L2-3.5.7 | CC6.1 | 4.1 | 8.2.1 | SRG-APP-000170 | ISM-1557 | 8.2.3 |
| 17. Session timeout | AC-12 | AC.L2-3.1.10 | CC6.1 | 5.6 | 8.1.8 | SRG-APP-000295 | ISM-1164 | 8.3.1 |
| 18. Data routing control | SC-7 | SC.L2-3.13.1 | CC6.6 | 13.1 | 1.3.1 | SRG-APP-000383 | ISM-1037 | 10.2.1 |
| 19. Phone recording policies | AU-14 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.1 | SRG-APP-000092 | ISM-0580 | 12.1.1 |
| 20. Local recording restricted | AC-3 | MP.L2-3.8.1 | CC6.1 | 3.1 | 3.4.1 | SRG-APP-000033 | ISM-0261 | 7.1.2 |
| 21. Password locked at account | AC-3 | AC.L2-3.1.1 | CC6.1 | 5.2 | 8.3.1 | SRG-APP-000033 | ISM-0974 | 8.1.1 |
| 22. Embed password in link disabled | IA-5 | IA.L2-3.5.10 | CC6.1 | 5.2 | 8.2.1 | SRG-APP-000170 | ISM-0974 | 8.2.3 |
| 23. Authenticated users only | IA-2 | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 24. Audit log retention | AU-11 | AU.L2-3.3.1 | CC7.2 | 8.3 | 10.7 | SRG-APP-000515 | ISM-0859 | 12.1.2 |
| 25. PMI usage restricted | AC-3 | AC.L2-3.1.5 | CC6.1 | 5.3 | 8.1.1 | SRG-APP-000038 | ISM-0974 | 8.1.2 |

## 6. Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| Zoom Admin Dashboard | Built-in | Manual review of settings, no automation |
| ScoutSuite | Open source | Multi-cloud; no Zoom provider |
| Prowler | Open source | AWS/Azure/GCP focus; no Zoom |
| Drata / Vanta | Commercial SaaS | Zoom integration for compliance, closed source |
| Resmo | Commercial SaaS | Zoom asset inventory, limited security checks |
| **No open-source Zoom security inspector exists** | Gap | This tool fills the gap |

## 7. Architecture

```
zoom-sec-inspector/
├── cmd/
│   └── zoom-sec-inspector/
│       └── main.go                 # Entry point, CLI parsing
├── internal/
│   ├── auth/
│   │   ├── oauth.go                # Server-to-Server OAuth token management
│   │   └── config.go               # Credential loading, validation
│   ├── client/
│   │   ├── zoom.go                 # HTTP client with rate limiting, retries
│   │   ├── accounts.go             # Account settings API calls
│   │   ├── users.go                # User listing and settings
│   │   ├── groups.go               # Group and IM group calls
│   │   ├── roles.go                # Role enumeration
│   │   ├── reports.go              # Report and audit log calls
│   │   └── phone.go                # Zoom Phone API calls
│   ├── analyzers/
│   │   ├── analyzer.go             # Analyzer interface definition
│   │   ├── meeting_security.go     # Controls 1-3, 21-23, 25
│   │   ├── authentication.go       # Controls 5, 6, 16
│   │   ├── encryption.go           # Controls 7, 8
│   │   ├── recording.go            # Controls 4, 10, 11, 19, 20
│   │   ├── communication.go        # Controls 9, 12, 15
│   │   ├── account_hygiene.go      # Controls 13, 14, 17, 24
│   │   └── data_residency.go       # Control 18
│   ├── models/
│   │   ├── settings.go             # Account/user/group settings structs
│   │   ├── finding.go              # Security finding with severity, mapping
│   │   └── compliance.go           # Framework mapping definitions
│   └── reporters/
│       ├── reporter.go             # Reporter interface
│       ├── json.go                 # JSON output
│       ├── csv.go                  # CSV output
│       ├── html.go                 # HTML dashboard report
│       └── sarif.go                # SARIF for CI/CD integration
├── pkg/
│   └── version/
│       └── version.go              # Build version info
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── spec.md
└── README.md
```

## 8. CLI Interface

```
zoom-sec-inspector [flags]

Flags:
  --account-id string       Zoom account ID (or ZOOM_ACCOUNT_ID env)
  --client-id string        OAuth client ID (or ZOOM_CLIENT_ID env)
  --client-secret string    OAuth client secret (or ZOOM_CLIENT_SECRET env)
  --base-url string         API base URL (default: https://api.zoom.us/v2)
  --govcloud                Use ZoomGov base URL (https://api.zoomgov.com/v2)
  --controls string         Comma-separated control IDs to run (default: all)
  --skip-controls string    Comma-separated control IDs to skip
  --severity string         Minimum severity to report: critical,high,medium,low (default: low)
  --format string           Output format: json,csv,html,sarif (default: json)
  --output string           Output file path (default: stdout)
  --include-users           Include per-user setting analysis (slower)
  --include-groups          Include per-group setting analysis
  --concurrency int         Max concurrent API requests (default: 5)
  --timeout duration        HTTP request timeout (default: 30s)
  --verbose                 Enable verbose/debug logging
  --version                 Print version and exit
  --help                    Show help
```

### Example Usage

```bash
# Full inspection with JSON output
zoom-sec-inspector --govcloud --format json --output report.json

# Critical controls only, HTML report
zoom-sec-inspector --severity critical --format html --output dashboard.html

# Specific controls with user analysis
zoom-sec-inspector --controls 1,2,5,6,18 --include-users --format json
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/zoom-sec-inspector

# 2. Define models and interfaces
#    - internal/models/finding.go (Finding struct, Severity enum)
#    - internal/models/compliance.go (framework mapping tables)
#    - internal/analyzers/analyzer.go (Analyzer interface)
#    - internal/reporters/reporter.go (Reporter interface)

# 3. Implement authentication
#    - internal/auth/config.go (env/flag loading)
#    - internal/auth/oauth.go (S2S OAuth token refresh)

# 4. Build API client
#    - internal/client/zoom.go (base client, rate limiter)
#    - internal/client/accounts.go, users.go, groups.go, etc.

# 5. Implement analyzers (one per control group)
#    - internal/analyzers/meeting_security.go
#    - internal/analyzers/authentication.go
#    - ... (all 7 analyzer files)

# 6. Implement reporters
#    - internal/reporters/json.go, csv.go, html.go, sarif.go

# 7. Wire CLI entry point
#    - cmd/zoom-sec-inspector/main.go

# 8. Test and build
go test ./...
go build -ldflags "-X pkg/version.Version=$(git describe --tags)" \
  -o bin/zoom-sec-inspector ./cmd/zoom-sec-inspector/
```

## 10. Status

Not yet implemented. Spec only.
