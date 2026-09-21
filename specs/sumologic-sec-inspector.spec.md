---
slug: "sumologic-sec-inspector"
name: "Sumo Logic Security Inspector"
vendor: "Sumo Logic"
category: "monitoring-logging-observability"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
---

# Sumo Logic Security Inspector: Architecture Specification

## 1. Overview

**sumologic-sec-inspector** is a security compliance inspection tool for Sumo Logic environments. It audits authentication policies, access controls, data governance, and operational security settings across a Sumo Logic organization via the Management API. The tool produces structured findings mapped to major compliance frameworks, enabling security teams to identify misconfigurations, enforce least-privilege access, and maintain continuous compliance posture.

Written in Go with a hybrid CLI/TUI architecture, it supports both automated pipeline execution (JSON/SARIF output) and interactive exploration of findings.

### grclanker implementation

The shipped implementation lives in `cli/extensions/grc-tools/sumologic.ts` as native grclanker tools (TypeScript, read-only Management API access with basic auth):

- `sumologic_check_access`: probes 18 read surfaces and reports missing role capabilities
- `sumologic_assess_identity`: controls 1 to 5
- `sumologic_assess_access_control`: controls 6, 7, 8, 13, 14
- `sumologic_assess_data_governance`: controls 9, 10, 12, 16, 17
- `sumologic_assess_content_sharing`: controls 11, 15, 18, 19, 20
- `sumologic_export_audit_bundle`: raw snapshots, normalized findings, executive summary, unified matrix, per-framework reports, error log, zip

Findings use the statuses `pass`, `warn`, `fail`, and `manual`; unreadable, empty, or partial evidence never yields `pass`. See `src/content/docs/docs/integrations/sumologic.md` for setup and status semantics.

## 2. APIs & SDKs

### Sumo Logic Management API

| Endpoint | Purpose |
|----------|---------|
| `GET /v1/users` | List all users, inspect roles and status |
| `GET /v1/roles` | Enumerate roles and capability assignments |
| `GET /v1/saml/identityProviders` | SAML SSO configuration and enforcement |
| `GET /v1/saml/allowlistedUsers` | Users bypassing SAML enforcement |
| `GET /v1/accessKeys` | List access keys, detect stale/unused keys |
| `GET /v1/passwordPolicy` | Password complexity and rotation policy |
| `GET /v1/account/audit` | Audit index configuration |
| `GET /v1/collectors` | Installed/hosted collector inventory |
| `GET /v1/connections` | Outbound connection/webhook destinations |
| `GET /v1/content/folders/personal` | Content sharing and permission model |
| `GET /v1/monitors` | Monitor and alert configurations |
| `GET /v1/serviceAllowlist/addresses` | Service allowlist (IP restrictions) |
| `GET /v1/lookupTables` | Lookup table access and configurations |
| `GET /v1/ingestBudgets` | Ingest budget limits and assignments |
| `GET /v1/scheduledViews` | Scheduled view configurations |
| `GET /v1/partitions` | Data partition and retention settings |

**Base URL pattern:** `https://api.{deployment}.sumologic.com/api`
- US1: `api.sumologic.com`
- US2: `api.us2.sumologic.com`
- EU: `api.eu.sumologic.com`
- AU: `api.au.sumologic.com`
- JP: `api.jp.sumologic.com`
- CA: `api.ca.sumologic.com`
- IN: `api.in.sumologic.com`
- FED: `api.fed.sumologic.com`

### SDKs and Libraries

| Name | Language | Notes |
|------|----------|-------|
| `sumologic-sdk-python` | Python | Community SDK, wraps REST API |
| Sumo Logic Terraform Provider | HCL | `sumologic_*` resources for IaC auditing |
| Sumo Logic CLI | Go | Official CLI tool |
| OpenAPI Spec | - | Available at docs.sumologic.com for codegen |

## 3. Authentication

### Access ID + Access Key (HTTP Basic Auth)

```
Authorization: Basic base64(accessId:accessKey)
```

- Access keys are created per-user in the Sumo Logic UI or via API
- Keys inherit the RBAC permissions of the creating user
- The inspector requires a key with **Administrator** role or equivalent read-only capabilities

### Required Capabilities

| Capability | Purpose |
|------------|---------|
| `viewUsers` | Enumerate users |
| `viewRoles` | Enumerate roles and capabilities |
| `viewCollectors` | List collector inventory |
| `viewConnections` | Inspect outbound connections |
| `managePasswordPolicy` | Read password policy (read implied) |
| `viewAccountOverview` | Account-level settings |
| `viewAuditLog` | Audit index status |

### Configuration

```bash
export SUMOLOGIC_ACCESS_ID="your-access-id"
export SUMOLOGIC_ACCESS_KEY="your-access-key"
export SUMOLOGIC_ENDPOINT="https://api.sumologic.com/api"
```

Alternatively, configure via `~/.sumologic-sec-inspector/config.yaml` or pass `--access-id` / `--access-key` / `--endpoint` flags.

## 4. Security Controls

1. **SAML SSO Enforcement**: Verify SAML identity provider is configured and SSO is enforced for all users (no local-only auth).
2. **SAML Allowlisted Users Minimized**: Ensure the SAML bypass allowlist contains only break-glass accounts, not regular users.
3. **Password Policy Strength**: Validate minimum length >= 12, complexity requirements enabled, lockout after failed attempts.
4. **Password Expiration Policy**: Confirm password rotation is enforced with a maximum age <= 90 days.
5. **MFA Enforcement**: Verify multi-factor authentication is required for all users (when not using SSO).
6. **Role-Based Access Control**: Ensure roles follow least-privilege; detect overly permissive roles with admin capabilities.
7. **Access Key Rotation**: Identify access keys older than 90 days without rotation.
8. **Inactive Access Keys**: Detect access keys that have not been used in 90+ days.
9. **Audit Index Enabled**: Confirm the audit index is enabled and actively receiving events.
10. **Data Forwarding Destinations Reviewed**: Validate outbound connections (webhooks, S3, etc.) point to approved destinations.
11. **Content Sharing Permissions**: Detect overly broad content sharing (dashboards, searches shared to "org" unnecessarily).
12. **Collector Management**: Identify unmanaged, offline, or ephemeral collectors; verify collector versions are current.
13. **Service Allowlist Configured**: Verify IP-based service allowlist restricts API and UI access to corporate networks.
14. **Session Timeout Policy**: Confirm session timeout is set to <= 15 minutes of inactivity.
15. **Scheduled Search Permissions**: Ensure scheduled searches run with appropriate role bindings, not shared admin credentials.
16. **Ingest Budget Controls**: Verify ingest budgets are configured to prevent runaway data ingestion costs and DoS.
17. **Data Retention Policies**: Confirm partition retention periods align with compliance requirements (e.g., 365 days for audit data).
18. **Lookup Table Access**: Verify lookup tables containing sensitive data have restricted access permissions.
19. **Dashboard Sharing Restrictions**: Detect dashboards shared externally or with overly broad audience.
20. **Monitor Alert Routing**: Verify alert notifications route to approved channels (not personal emails or unapproved webhooks).

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 | SAML SSO Enforcement | IA-2 | AC.L2-3.1.1 | CC6.1 | 1.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | CPS-04 |
| 2 | SAML Allowlist Minimized | IA-2(1) | AC.L2-3.1.1 | CC6.1 | 1.2 | 8.3.2 | SRG-APP-000149 | ISM-1558 | CPS-04 |
| 3 | Password Policy Strength | IA-5(1) | IA.L2-3.5.7 | CC6.1 | 5.1 | 8.3.6 | SRG-APP-000166 | ISM-0421 | CPS-05 |
| 4 | Password Expiration | IA-5(1) | IA.L2-3.5.8 | CC6.1 | 5.2 | 8.3.9 | SRG-APP-000174 | ISM-0422 | CPS-05 |
| 5 | MFA Enforcement | IA-2(1) | IA.L2-3.5.3 | CC6.1 | 4.1 | 8.4.2 | SRG-APP-000149 | ISM-1401 | CPS-06 |
| 6 | Role-Based Access Control | AC-2 | AC.L2-3.1.1 | CC6.3 | 6.1 | 7.2.1 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 7 | Access Key Rotation | IA-5(1) | IA.L2-3.5.8 | CC6.1 | 5.3 | 8.6.3 | SRG-APP-000175 | ISM-1590 | CPS-05 |
| 8 | Inactive Access Keys | AC-2(3) | AC.L2-3.1.1 | CC6.2 | 5.4 | 8.1.4 | SRG-APP-000025 | ISM-1404 | CPS-07 |
| 9 | Audit Index Enabled | AU-2 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.2.1 | SRG-APP-000089 | ISM-0580 | CPS-10 |
| 10 | Data Forwarding Reviewed | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.1 | 1.3.1 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 11 | Content Sharing Permissions | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.2 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 12 | Collector Management | CM-8 | CM.L2-3.4.1 | CC8.1 | 10.1 | 6.3.2 | SRG-APP-000456 | ISM-1490 | CPS-12 |
| 13 | Service Allowlist | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.2 | 1.3.2 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 14 | Session Timeout | AC-11 | AC.L2-3.1.10 | CC6.1 | 7.1 | 8.2.8 | SRG-APP-000190 | ISM-0853 | CPS-08 |
| 15 | Scheduled Search Perms | AC-6 | AC.L2-3.1.5 | CC6.3 | 6.3 | 7.2.2 | SRG-APP-000340 | ISM-0432 | CPS-07 |
| 16 | Ingest Budget Controls | SC-5 | SC.L2-3.13.6 | CC7.2 | 9.3 | 6.5.10 | SRG-APP-000246 | ISM-1020 | CPS-11 |
| 17 | Data Retention Policies | AU-11 | AU.L2-3.3.1 | CC7.4 | 8.2 | 3.1 | SRG-APP-000515 | ISM-0859 | CPS-10 |
| 18 | Lookup Table Access | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.4 | 7.2.3 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 19 | Dashboard Sharing | AC-3 | AC.L2-3.1.3 | CC6.3 | 6.5 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 20 | Monitor Alert Routing | AU-5 | AU.L2-3.3.4 | CC7.3 | 8.3 | 10.6.1 | SRG-APP-000108 | ISM-0580 | CPS-10 |

## 6. Existing Tools

| Tool | Type | Limitations |
|------|------|-------------|
| Sumo Logic Security Dashboard | Built-in | Focuses on ingested security data, not org config posture |
| Sumo Logic Terraform Provider | IaC | Can enforce config-as-code but no drift detection or reporting |
| Sumo Logic CSE (Cloud SIEM) | SIEM | Detects threats in log data, not org-level misconfigurations |
| Cloud Custodian (sumologic plugin) | Policy | Limited Sumo Logic resource coverage |
| Manual API scripts | Custom | No structured compliance mapping or reporting |

**Gap:** No existing tool provides automated security posture assessment of Sumo Logic organization-level configurations mapped to compliance frameworks. sumologic-sec-inspector fills this gap.

## 7. Architecture

```
sumologic-sec-inspector/
├── cmd/
│   └── sumologic-sec-inspector/
│       └── main.go                 # Entrypoint, CLI bootstrap
├── internal/
│   ├── analyzers/
│   │   ├── analyzer.go             # Analyzer interface and registry
│   │   ├── saml.go                 # SAML SSO enforcement checks
│   │   ├── password.go             # Password policy strength/expiration
│   │   ├── mfa.go                  # MFA enforcement checks
│   │   ├── rbac.go                 # Role-based access control audit
│   │   ├── accesskeys.go           # Access key rotation and staleness
│   │   ├── audit.go                # Audit index enabled check
│   │   ├── collectors.go           # Collector management checks
│   │   ├── connections.go          # Data forwarding destination review
│   │   ├── content.go              # Content sharing permissions
│   │   ├── network.go              # Service allowlist, session timeout
│   │   ├── ingest.go               # Ingest budget controls
│   │   ├── retention.go            # Data retention policy checks
│   │   └── monitors.go             # Monitor alert routing checks
│   ├── client/
│   │   ├── client.go               # Sumo Logic API client
│   │   ├── auth.go                 # Basic auth with access ID/key
│   │   ├── ratelimit.go            # Rate limiter (4 req/sec default)
│   │   └── endpoints.go            # Regional endpoint resolution
│   ├── config/
│   │   ├── config.go               # Configuration loading and validation
│   │   └── redact.go               # Credential redaction for logging
│   ├── models/
│   │   ├── user.go                 # User, role, capability models
│   │   ├── saml.go                 # SAML provider model
│   │   ├── collector.go            # Collector model
│   │   ├── connection.go           # Connection/webhook model
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

- **Regional endpoint resolution**: Auto-detect deployment region from API endpoint or allow explicit configuration
- **Rate limiting**: Sumo Logic enforces 4 requests/second; built-in token bucket rate limiter
- **Pagination**: All list endpoints use token-based pagination; client handles transparently
- **Capability-aware**: Pre-flight check validates the access key has required capabilities before running analyzers

## 8. CLI Interface

```
sumologic-sec-inspector [command] [flags]

Commands:
  scan        Run all or selected security analyzers
  list        List available analyzers and their descriptions
  version     Print version information

Scan Flags:
  --access-id string       Sumo Logic Access ID (env: SUMOLOGIC_ACCESS_ID)
  --access-key string      Sumo Logic Access Key (env: SUMOLOGIC_ACCESS_KEY)
  --endpoint string        API endpoint URL (env: SUMOLOGIC_ENDPOINT)
  --analyzers strings      Run specific analyzers (comma-separated)
  --exclude strings        Exclude specific analyzers
  --severity string        Minimum severity to report: critical,high,medium,low,info
  --format string          Output format: table,json,sarif,csv,html (default "table")
  --output string          Output file path (default: stdout)
  --tui                    Launch interactive TUI
  --no-color               Disable colored output
  --config string          Path to config file (default "~/.sumologic-sec-inspector/config.yaml")
  --timeout duration       API request timeout (default 30s)
  --verbose                Enable verbose logging
```

### Usage Examples

```bash
# Full scan with table output
sumologic-sec-inspector scan

# Scan specific controls with JSON output
sumologic-sec-inspector scan --analyzers saml,password,mfa --format json

# Generate SARIF report for CI/CD integration
sumologic-sec-inspector scan --format sarif --output results.sarif

# Interactive TUI mode
sumologic-sec-inspector scan --tui

# List available analyzers
sumologic-sec-inspector list
```

## 9. Build Sequence

```bash
# Prerequisites
go 1.22+

# Clone and build
git clone https://github.com/hackIDLE/sumologic-sec-inspector.git
cd sumologic-sec-inspector
go mod download
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o bin/sumologic-sec-inspector ./cmd/sumologic-sec-inspector/

# Run tests
go test ./...

# Build Docker image
docker build -t sumologic-sec-inspector .

# Run via Docker
docker run --rm \
  -e SUMOLOGIC_ACCESS_ID \
  -e SUMOLOGIC_ACCESS_KEY \
  -e SUMOLOGIC_ENDPOINT \
  sumologic-sec-inspector scan --format json
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

Implemented in grclanker as six native TypeScript tools (see "grclanker implementation" in section 1). The Go CLI/TUI, SARIF/CSV/HTML reporters, and Docker packaging described in sections 7 to 9 were not built; grclanker's export bundle (markdown plus JSON plus zip) replaces them.

### Shipped

- Basic-auth Management API client with `token` cursor pagination, `limit`/`offset` pagination for collectors and monitor search, 429 and 5xx retry with backoff honoring `Retry-After`, request timeouts, and access key redaction.
- Deployment mapping for the union of the two official deployment tables: the OpenAPI definition (which lists IN but not ESC) and the current help-docs endpoint table (which lists ESC and has dropped IN). Supported codes: au, ca, ch, de, esc, eu, fed, in, jp, kr, us1, us2.
- Configuration precedence: explicit arguments, then `SUMOLOGIC_ACCESS_ID` / `SUMOLOGIC_ACCESS_KEY` / `SUMOLOGIC_ENDPOINT` (or `SUMOLOGIC_DEPLOYMENT`), then `~/.sumologic-sec-inspector/config.yaml` (or `SUMOLOGIC_CONFIG_FILE`).
- All 20 controls emit a finding with the section 5 framework mappings. Controls 1, 15, and 18 are `manual` by design (see deviations); every other control can reach `pass` only with complete, readable evidence.
- Verdict safety: unreadable endpoints, empty inventories, capability-limited views, unfollowed cursors, and personal-folder samples smaller than the folder never yield `pass`. Control 6 also downgrades on custom roles without a `filterPredicate` and on admin members who are dormant or have no `lastLoginTimestamp`; control 7 downgrades when `accessKeysLifetimeInDays` is `0`, absent, or unreadable and always states the policy value.
- Mocked regression tests in `cli/tests/sumologic.test.mjs`, including false-pass self-checks for all-403, all-empty, and partial-inventory fixtures, and a live smoke script (`npm --prefix cli run test:sumologic:live`).

### Deviations from this spec, following the official documentation

- Endpoints: content folders are served at `/v2/content/folders/personal` (not `/v1`), monitors are listed through `/v1/monitors/search` (there is no plain `/v1/monitors` list), ingest budgets use `/v2/ingestBudgets`, and the audit index is read from `/v1/policies/audit` plus `/v1/partitions?viewTypes=AuditIndex` (there is no `/v1/account/audit`). Lookup tables have no list endpoint (`/v1/lookupTables` only supports create), so control 18 is manual.
- Capabilities: the official capability names differ from the table in section 3. Users and roles require `manageUsersAndRoles`; org-wide access keys require `manageAccessKeys`; policies require `manageOrgSettings`; the audit index is a partition read (`viewPartitions`) plus a policy read rather than `viewAuditLog`.
- SAML enforcement: `/v1/saml/lockdown/enable` and `/disable` exist, but there is no status GET, so control 1 reports `manual` (or `warn` on debug mode or a missing certificate) once an identity provider exists and `fail` on zero providers.
- Deployments: the deployment list is the union of the OpenAPI table (lists IN, not ESC) and the current help-docs table (lists ESC, dropped IN); CH and ESC are supported beyond the list in section 2, and IN is retained because the OpenAPI still documents it.
- Data forwarding review (control 10) and monitor alert routing (control 20) accept optional approved domain lists; without them, non-empty destination inventories are reported as `manual` because approval is a human decision.

### Remaining

- Admin Recommended and Global folder permission sweeps (asynchronous job endpoints) for controls 11 and 18.
- Proof of audit event flow via the Search Job API (control 9 currently verifies configuration only).
- Cloud SIEM and Cloud SOAR posture, which are outside this spec's 20 controls.
