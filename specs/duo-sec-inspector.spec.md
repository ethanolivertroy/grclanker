---
slug: "duo-sec-inspector"
name: "Duo Security Inspector"
vendor: "Cisco"
category: "identity-access-management"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-04-14"
source_repo: "https://github.com/hackIDLE/grclanker"
legacy_repo: "https://github.com/hackIDLE/duo-sec-inspector"
reference_docs: "https://duo.com/docs/adminapi"
---

# duo-sec-inspector

## 1. Overview

A read-only Duo compliance inspection surface for **grclanker** that audits MFA configuration, policy posture, privileged administration, integration hygiene, Trust Monitor coverage, and audit telemetry through the Duo Admin API. The implementation intentionally stays Admin API–first so GRC engineers can assess a tenant with one read-only audit principal instead of juggling multiple application types on day one.

The current tool family is:

- `duo_check_access`
- `duo_assess_authentication`
- `duo_assess_admin_access`
- `duo_assess_integrations`
- `duo_assess_monitoring`
- `duo_export_audit_bundle`

## 2. APIs & SDKs

### Duo APIs

| API | Base URL | Purpose |
|-----|----------|---------|
| **Admin API** | `https://{api-hostname}/admin/v1/` | User, integration, policy, and log management |
| **Auth API** | `https://{api-hostname}/auth/v1/` | Authentication verification and status |
| **Accounts API** | `https://{api-hostname}/accounts/v1/` | MSP child account management |

### Admin API Endpoints

**User Management:**
- `GET /admin/v1/users` — List all users with enrollment status, MFA devices, groups
- `GET /admin/v1/users/{user_id}` — Individual user detail
- `GET /admin/v1/users/{user_id}/bypass_codes` — List active bypass codes for a user
- `GET /admin/v1/users/{user_id}/tokens` — Hardware token associations
- `GET /admin/v1/users/{user_id}/webauthncredentials` — WebAuthn/FIDO2 credentials
- `GET /admin/v1/users/{user_id}/u2ftokens` — U2F security key tokens

**Integration Management:**
- `GET /admin/v1/integrations` — List all protected applications/integrations
- `GET /admin/v1/integrations/{integration_key}` — Integration detail with policy settings
- `GET /admin/v1/policies/v2` — List all authentication policies
- `GET /admin/v1/policies/v2/{policy_key}` — Policy detail (MFA methods, device health, etc.)

**Logging and Monitoring:**
- `GET /admin/v1/logs/authentication` — Authentication log events (success, failure, fraud)
- `GET /admin/v1/logs/administrator` — Admin action audit log
- `GET /admin/v1/logs/telephony` — Telephony (SMS/call) usage log
- `GET /admin/v1/logs/offline_enrollment` — Offline access enrollment events
- `GET /admin/v2/trust_monitor/events` — Trust Monitor risk-based alerts

**Administrative:**
- `GET /admin/v1/admins` — List administrator accounts and roles
- `GET /admin/v1/info/summary` — Account summary (users, integrations, telephony credits)
- `GET /admin/v1/info/authentication_attempts` — Authentication attempt statistics
- `GET /admin/v1/settings` — Global Duo account settings
- `GET /admin/v1/tokens` — Hardware OTP tokens inventory
- `GET /admin/v1/groups` — User groups for policy assignment

### Auth API Endpoints

- `POST /auth/v1/check` — Verify API connectivity and credentials
- `POST /auth/v1/enroll_status` — Check enrollment status for a user
- `POST /auth/v1/preauth` — Pre-authentication check (devices, capabilities)
- `POST /auth/v1/auth` — Perform authentication (push, passcode, phone, SMS)

### Accounts API Endpoints (MSP)

- `POST /accounts/v1/account/list` — List child accounts
- `POST /accounts/v1/account/create` — Create child account

### SDKs

| SDK | Language | Package |
|-----|----------|---------|
| **duo_client** | Python | `pip install duo_client` (official, Cisco/Duo) |
| **duo_client_golang** | Go | `github.com/duosecurity/duo_client_golang` (official) |
| **duo_api_java** | Java | Official Java client |
| **duo_api_csharp** | C# | Official .NET client |

## 3. Authentication

### Signed Requests

The current grclanker implementation follows the official Duo Admin API and Duo Node client signing model:

- Standard Admin API endpoints use HMAC-SHA512 request signing over the canonical v2 string.
- Newer Admin API v3 integration endpoints use the current v5 canonical form and signature path.

Each request includes:

- **Integration Key (ikey)** — Identifies the application/API client
- **Secret Key (skey)** — Used to sign requests (never transmitted)
- **API Hostname** — Account-specific hostname (`api-XXXXXXXX.duosecurity.com`)

The standard canonical string is computed over: `{date}\n{method}\n{host}\n{path}\n{params}` and sent as HTTP Basic Auth where username = `ikey` and password = the derived HMAC-SHA512 signature. For newer v3 integration endpoints, grclanker uses the current v5 canonical form from the official Duo client behavior.

### Required Permissions

The Admin API integration must have the following permissions:

- **Grant read information** — Read users, integrations, policies
- **Grant read log** — Read authentication and admin logs
- **Grant settings** — Read global settings
- **Grant read resource** — Read bypass codes, tokens, WebAuthn credentials

### Configuration

```
DUO_IKEY=DIXXXXXXXXXXXXXXXXXX
DUO_SKEY=YourSecretKeyHere
DUO_API_HOST=api-XXXXXXXX.duosecurity.com
```

## 4. Security Controls

1. **Global MFA policy** — Verify the global policy enforces MFA (not "bypass" or "allow without MFA") and uses phishing-resistant methods (push with Verified Duo Push, WebAuthn/FIDO2)
2. **User enrollment completeness** — Enumerate all users and flag those with status "bypass" or "not enrolled"; calculate enrollment percentage
3. **Bypass code audit** — List all active bypass codes across users; flag codes older than 24 hours or with unlimited uses
4. **Inactive user detection** — Identify users who have not authenticated in 90+ days; flag for access review
5. **Admin role review** — Enumerate all administrator accounts; flag excessive "Owner" roles and verify least privilege
6. **Trusted endpoint policy** — Verify Duo Device Health Application or Trusted Endpoints policy is enforced (managed devices required)
7. **Device health requirements** — Audit device health policy: OS version requirements, firewall enabled, disk encryption, screen lock
8. **Remembered devices policy** — Verify remembered devices duration is within acceptable limits (or disabled for high-security integrations)
9. **Authentication method restrictions** — Verify deprecated methods (SMS, phone callback) are disabled; only push/WebAuthn/hardware token allowed
10. **New user policy** — Verify the new user policy requires enrollment (not "allow access without MFA")
11. **User lockout policy** — Confirm account lockout is enabled after failed authentication attempts (recommended: 10 or fewer)
12. **Integration policy assignments** — Verify each protected application/integration has an explicit policy assigned (not relying only on global policy)
13. **Unprotected application detection** — Compare known critical applications against Duo integrations to find applications lacking MFA protection
14. **Trust Monitor configuration** — Verify Trust Monitor is enabled and alerts are being reviewed; audit unresolved alert count
15. **Authentication log anomalies** — Analyze authentication logs for patterns: fraud reports, denied logins, geographically impossible travel
16. **Telephony credit monitoring** — Check remaining telephony credits and usage trends; flag low credit balance
17. **U2F/WebAuthn credential inventory** — Audit FIDO2/WebAuthn and U2F token registrations; verify phishing-resistant method adoption rate
18. **Offline access configuration** — Verify offline access (Duo MFA for Windows/macOS logon when offline) is configured securely with reactivation limits
19. **Self-service portal policy** — Audit whether users can add/remove devices without admin approval
20. **API permission audit** — Enumerate all Admin API integrations and their permission levels; flag overly permissive API access

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 | Global MFA policy | IA-2(1) | 3.5.3 | CC6.1 | 6.3 | 8.4.2 | SRG-APP-000149 | ISM-1504 | CPS.AT-2 |
| 2 | User enrollment completeness | IA-2(2) | 3.5.3 | CC6.1 | 6.3 | 8.4.1 | SRG-APP-000150 | ISM-1504 | CPS.AT-2 |
| 3 | Bypass code audit | IA-5(1) | 3.5.10 | CC6.1 | — | 8.6.3 | SRG-APP-000175 | ISM-1557 | CPS.IA-5 |
| 4 | Inactive user detection | AC-2(3) | 3.1.12 | CC6.2 | 5.3 | 8.1.4 | SRG-APP-000025 | ISM-1591 | CPS.AC-2 |
| 5 | Admin role review | AC-6(5) | 3.1.5 | CC6.3 | 6.5 | 7.1.1 | SRG-APP-000340 | ISM-1507 | CPS.AC-6 |
| 6 | Trusted endpoint policy | CM-8(3) | 3.4.1 | CC6.7 | — | 2.4 | SRG-APP-000383 | ISM-1599 | CPS.CM-8 |
| 7 | Device health requirements | CM-6 | 3.4.2 | CC6.7 | — | 2.2.1 | SRG-APP-000384 | ISM-1082 | CPS.CM-6 |
| 8 | Remembered devices policy | AC-12 | 3.1.10 | CC6.1 | — | 8.2.8 | SRG-APP-000295 | ISM-1164 | CPS.AC-7 |
| 9 | Auth method restrictions | IA-2(6) | 3.5.3 | CC6.1 | 6.4 | 8.4.3 | SRG-APP-000156 | ISM-1515 | CPS.IA-2 |
| 10 | New user policy | AC-2(2) | 3.1.1 | CC6.2 | — | 8.2.1 | SRG-APP-000024 | ISM-0415 | CPS.AC-2 |
| 11 | User lockout policy | AC-7 | 3.1.8 | CC6.1 | 5.4 | 8.3.4 | SRG-APP-000065 | ISM-1403 | CPS.AC-7 |
| 12 | Integration policy assignments | CM-2 | 3.4.1 | CC6.8 | — | 2.2.1 | SRG-APP-000386 | ISM-1624 | CPS.CM-2 |
| 13 | Unprotected app detection | CM-8 | 3.4.1 | CC6.1 | — | 2.4 | SRG-APP-000383 | ISM-1599 | CPS.CM-8 |
| 14 | Trust Monitor configuration | SI-4 | 3.14.6 | CC7.2 | — | 10.6.1 | SRG-APP-000516 | ISM-0580 | CPS.SI-4 |
| 15 | Auth log anomalies | AU-6 | 3.3.5 | CC7.2 | — | 10.6.1 | SRG-APP-000516 | ISM-0109 | CPS.AU-6 |
| 16 | Telephony credit monitoring | SA-9 | 3.13.2 | CC9.1 | — | — | SRG-APP-000516 | ISM-0888 | CPS.SA-9 |
| 17 | U2F/WebAuthn inventory | IA-2(12) | 3.5.3 | CC6.1 | 6.4 | 8.4.3 | SRG-APP-000395 | ISM-1515 | CPS.IA-2 |
| 18 | Offline access configuration | IA-2(11) | 3.5.3 | CC6.1 | — | 8.4.1 | SRG-APP-000394 | ISM-1504 | CPS.IA-2 |
| 19 | Self-service portal policy | AC-2(1) | 3.1.1 | CC6.2 | — | 8.2.4 | SRG-APP-000023 | ISM-1594 | CPS.AC-2 |
| 20 | API permission audit | AC-6(10) | 3.1.7 | CC6.3 | — | 7.1.2 | SRG-APP-000343 | ISM-0988 | CPS.AC-6 |

## 6. Existing Tools

| Tool | Description | Limitations |
|------|-------------|-------------|
| **Duo Admin Panel** | Built-in web dashboard for configuration and reporting | Manual review; no automated compliance mapping |
| **Duo Trust Monitor** | Built-in anomaly detection for authentication events | Detection-focused, not configuration compliance |
| **Cisco SecureX** | Integrated security platform with Duo telemetry | Requires SecureX license; limited config audit depth |
| **Duo Device Insight** | Endpoint visibility and device posture | Focused on device inventory, not policy compliance |
| **CISA MFA Guidance** | Federal MFA implementation guidance | Reference only, no tooling |
| **CrowdStrike Falcon Identity** | Identity threat detection and response | Commercial; detection-focused, not Duo-specific config audit |

**Current state:** grclanker now ships a native TypeScript Duo assessment surface with read-only access checks, focused posture assessments, and audit-bundle export. The remaining gap is real-tenant smoke validation and future deeper vendor-specific expansion, not the absence of an open-source Duo posture tool.

## 7. Architecture

The current implementation lives in grclanker as native TypeScript under `cli/extensions/grc-tools/duo.ts`, with tests in `cli/tests/duo.test.mjs` and an optional smoke path in `cli/scripts/duo-live-smoke.mjs`.

The legacy tree below is preserved as historical design context from the original standalone concept:

```
duo-sec-inspector/
├── cmd/
│   └── duo-sec-inspector/
│       └── main.go                  # CLI entrypoint
├── internal/
│   ├── client/
│   │   ├── admin.go                 # Admin API client with HMAC-SHA1 signing
│   │   ├── auth.go                  # Auth API client
│   │   ├── accounts.go              # Accounts API client (MSP)
│   │   └── ratelimit.go             # Rate limiter (Duo: 20 req/sec for most endpoints)
│   ├── analyzers/
│   │   ├── globalpolicy.go          # Control 1: Global MFA policy
│   │   ├── enrollment.go            # Control 2: User enrollment completeness
│   │   ├── bypasscodes.go           # Control 3: Bypass code audit
│   │   ├── inactive.go              # Control 4: Inactive user detection
│   │   ├── adminroles.go            # Control 5: Admin role review
│   │   ├── trustedendpoints.go      # Control 6: Trusted endpoint policy
│   │   ├── devicehealth.go          # Control 7: Device health requirements
│   │   ├── remembered.go            # Control 8: Remembered devices policy
│   │   ├── authmethods.go           # Control 9: Authentication method restrictions
│   │   ├── newuserpolicy.go         # Control 10: New user policy
│   │   ├── lockout.go               # Control 11: User lockout policy
│   │   ├── integrations.go          # Controls 12-13: Integration policy and unprotected apps
│   │   ├── trustmonitor.go          # Control 14: Trust Monitor configuration
│   │   ├── authlogs.go              # Control 15: Authentication log anomalies
│   │   ├── telephony.go             # Control 16: Telephony credit monitoring
│   │   ├── webauthn.go              # Control 17: U2F/WebAuthn inventory
│   │   ├── offlineaccess.go         # Control 18: Offline access configuration
│   │   ├── selfservice.go           # Control 19: Self-service portal policy
│   │   └── apipermissions.go        # Control 20: API permission audit
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
| `github.com/duosecurity/duo_client_golang` | Official Duo API client and signing reference |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/charmbracelet/bubbletea` | Terminal UI framework |
| `github.com/charmbracelet/lipgloss` | TUI styling |

## 8. CLI Interface

```
duo-sec-inspector [command] [flags]

Commands:
  scan          Run security compliance scan against Duo account
  report        Generate compliance report from scan results
  version       Print version information

Global Flags:
  --ikey string         Duo integration key [$DUO_IKEY]
  --skey string         Duo secret key [$DUO_SKEY]
  --api-host string     Duo API hostname [$DUO_API_HOST]
  --output string       Output format: json, csv, markdown, html, sarif (default "json")
  --output-dir string   Directory for report output (default "./results")
  --severity string     Minimum severity to report: critical, high, medium, low, info (default "low")
  --controls string     Comma-separated list of control numbers to run (default: all)
  --quiet               Suppress progress output
  --no-color            Disable colored output
  --tui                 Launch interactive terminal UI

Scan Flags:
  --skip-auth-logs      Skip authentication log analysis (faster scan)
  --skip-trust-monitor  Skip Trust Monitor event retrieval
  --log-days int        Days of authentication logs to analyze (default 30)
  --parallel int        Number of parallel API calls (default 4)
  --timeout duration    API call timeout (default 30s)

Examples:
  # Full Duo account scan with JSON output
  duo-sec-inspector scan --ikey DIXX... --skey ... --api-host api-XXXX.duosecurity.com

  # Scan MFA policy controls only
  duo-sec-inspector scan --controls 1,2,9,10,11 --output markdown

  # Interactive TUI mode
  duo-sec-inspector scan --tui

  # CI/CD pipeline with SARIF output, high severity only
  duo-sec-inspector scan --output sarif --severity high
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/duo-sec-inspector

# 2. Add dependencies
go get github.com/duosecurity/duo_client_golang
go get github.com/spf13/cobra
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss

# 3. Build
go build -ldflags "-X pkg/version.Version=$(git describe --tags)" \
  -o bin/duo-sec-inspector ./cmd/duo-sec-inspector/

# 4. Test
go test ./...

# 5. Lint
golangci-lint run

# 6. Docker
docker build -t duo-sec-inspector .

# 7. Release
goreleaser release --snapshot
```

## 10. Status

Not yet implemented. Spec only.
