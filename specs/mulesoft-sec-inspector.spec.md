---
slug: "mulesoft-sec-inspector"
name: "MuleSoft Security Inspector"
vendor: "MuleSoft"
category: "devops-developer-platforms"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
---

# MuleSoft Anypoint Platform Security Inspector - Architecture Specification

## 1. Overview

MuleSoft Anypoint Platform Security Inspector is a hybrid CLI/TUI tool that audits the security posture of a MuleSoft Anypoint Platform organization. It connects to the Anypoint Platform REST APIs to evaluate identity and access management, API gateway policies, runtime security, environment isolation, and audit logging. The tool produces structured findings mapped to enterprise compliance frameworks and outputs reports in JSON, CSV, and HTML formats.

The inspector targets Anypoint Platform organizations on Enterprise and Titanium tiers where advanced RBAC, external identity management, and dedicated infrastructure capabilities are available. It operates in read-only mode and requires no agent installation on CloudHub workers or runtime servers.

### grclanker implementation

The shipped implementation is the native TypeScript module `cli/extensions/grc-tools/mulesoft.ts` in [grclanker](https://github.com/hackIDLE/grclanker), not the standalone Go binary sketched in sections 7 to 9. It registers six read-only tools:

| Tool | Covers |
|------|--------|
| `mulesoft_check_access` | Probes every read surface used below and names the missing permission for each 401 or 403 |
| `mulesoft_assess_identity_access` | Controls 1-6, 18, 19, 25 |
| `mulesoft_assess_api_gateway` | Controls 7-9, 20 |
| `mulesoft_assess_runtime_infrastructure` | Controls 10-16, 21-23 |
| `mulesoft_assess_audit_monitoring` | Controls 17, 24 |
| `mulesoft_export_audit_bundle` | Runs the access check and all four assessments, then writes the evidence bundle and `.zip` |

Finding ids follow `MULESOFT-IAM-nn`, `MULESOFT-API-nn`, `MULESOFT-RT-nn`, and `MULESOFT-AUD-nn`, where `nn` is the control number from section 4. Every finding carries the eight framework mappings from section 5. Setup, permissions, and status semantics are documented in `src/content/docs/docs/integrations/mulesoft.md`.

## 2. APIs & SDKs

### Anypoint Platform REST APIs

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/accounts/api/organizations/{orgId}` | GET | Organization settings, entitlements, IdP config |
| `/accounts/api/organizations/{orgId}/members` | GET | List organization members and their roles |
| `/accounts/api/organizations/{orgId}/users/{userId}` | GET | Get user details including MFA status |
| `/accounts/api/organizations/{orgId}/rolegroups` | GET | List role groups and their scope |
| `/accounts/api/organizations/{orgId}/rolegroups/{rolegroupId}` | GET | Get role group details and permissions |
| `/accounts/api/organizations/{orgId}/rolegroups/{rolegroupId}/roles` | GET | List roles within a role group |
| `/accounts/api/organizations/{orgId}/environments` | GET | List environments and their types |
| `/accounts/api/organizations/{orgId}/environments/{envId}` | GET | Get environment details and settings |
| `/accounts/api/organizations/{orgId}/connectedApplications` | GET | List connected apps and their scopes |
| `/accounts/api/organizations/{orgId}/identityProviders` | GET | List external identity providers (SAML, OIDC) |
| `/apimanager/api/v1/organizations/{orgId}/environments/{envId}/apis` | GET | List managed APIs and their policies |
| `/apimanager/api/v1/organizations/{orgId}/environments/{envId}/apis/{apiId}/policies` | GET | List API gateway policies (rate limiting, auth) |
| `/exchange/api/v2/assets` | GET | List Exchange assets and governance status |
| `/cloudhub/api/v2/applications` | GET | List CloudHub applications and worker config |
| `/cloudhub/api/v2/applications/{domain}` | GET | Get application details (workers, region, logging) |
| `/cloudhub/api/v2/vpcs` | GET | List VPC configurations |
| `/cloudhub/api/v2/vpcs/{vpcId}` | GET | Get VPC details (CIDR, firewall rules) |
| `/cloudhub/api/v2/dlbs` | GET | List dedicated load balancers |
| `/cloudhub/api/v2/dlbs/{dlbId}` | GET | Get DLB details (SSL config, cipher suites) |
| `/armui/api/v1/organizations/{orgId}/environments/{envId}/servers` | GET | List hybrid runtime servers |
| `/armui/api/v1/organizations/{orgId}/environments/{envId}/serverGroups` | GET | List server groups and clusters |
| `/audit/v2/organizations/{orgId}/query` | POST | Query audit log entries with filters |
| `/audit/v2/organizations/{orgId}/platforms` | GET | Get available audit log platforms |
| `/mq/admin/api/v1/organizations/{orgId}/environments/{envId}/regions` | GET | List MQ regions and access config |
| `/mq/admin/api/v1/organizations/{orgId}/environments/{envId}/regions/{regionId}/queues` | GET | List message queues |
| `/secrets/api/v1/organizations/{orgId}/environments/{envId}/secretGroups` | GET | List Secrets Manager groups |
| `/monitoring/api/v1/organizations/{orgId}/environments/{envId}/applications` | GET | List monitored applications and alert config |

**Base URL:** `https://anypoint.mulesoft.com` (US), `https://eu1.anypoint.mulesoft.com` (EU), `https://gov.anypoint.mulesoft.com` (Gov Cloud)

**Rate Limits:** Vary by control plane. Audit API: 700 req/min (US), 40 req/min (EU/Gov). General APIs: documented per-endpoint.

### Python SDK

There is no official Python SDK for the Anypoint Platform management APIs. The inspector uses direct HTTP calls via `net/http` (Go stdlib) or `httpx` (Python). Community wrappers exist but are not maintained to production standards.

| Package | Notes |
|---------|-------|
| Direct REST via `net/http` | Recommended approach: full API coverage, no third-party dependency |
| `anypoint-cli` (MuleSoft official) | Node.js CLI, reference implementation for endpoint behavior |

## 3. Authentication

| Method | Header Format | Use Case |
|--------|--------------|----------|
| Bearer token (username/password) | `Authorization: Bearer {token}` | Interactive CLI use; obtained via `/accounts/login` |
| Connected App (client credentials) | `Authorization: Bearer {token}` | Automated pipelines; OAuth client_credentials grant |
| Connected App (authorization code) | `Authorization: Bearer {token}` | Delegated user context; OAuth authorization_code grant |

**Token acquisition, client credentials flow:**
```
POST https://anypoint.mulesoft.com/accounts/api/v2/oauth2/token
Content-Type: application/json

{"grant_type": "client_credentials", "client_id": "...", "client_secret": "..."}
```

**Token acquisition, username/password:**
```
POST https://anypoint.mulesoft.com/accounts/login
Content-Type: application/json

{"username": "...", "password": "..."}
```

**Required permissions:**
- Organization Administrator or custom role with read access to Access Management, API Manager, Runtime Manager, Exchange, and Audit Log
- Connected App scoped to: `General`, `Design Center`, `Runtime Manager`, `API Manager`, `Exchange`, `Audit Logs`

**Configuration precedence:**
1. `--client-id` / `--client-secret` CLI flags
2. `ANYPOINT_CLIENT_ID` / `ANYPOINT_CLIENT_SECRET` environment variables
3. `ANYPOINT_USERNAME` / `ANYPOINT_PASSWORD` environment variables
4. `~/.config/mulesoft-sec-inspector/config.toml`

The tool never stores credentials beyond the current session. Tokens and secrets are redacted from all log output and reports.

## 4. Security Controls

| # | Control | API Source | Severity |
|---|---------|-----------|----------|
| 1 | SSO/SAML or OIDC external identity provider configured | `/accounts/api/organizations/{orgId}/identityProviders` | Critical |
| 2 | MFA enforced for all organization members | `/accounts/api/organizations/{orgId}`, `/accounts/api/.../users` | Critical |
| 3 | No members with Organization Administrator role beyond minimum | `/accounts/api/organizations/{orgId}/members` | High |
| 4 | Role groups follow least-privilege principle | `/accounts/api/organizations/{orgId}/rolegroups` | High |
| 5 | Role groups scoped to specific environments (not all environments) | `/accounts/api/.../rolegroups/{id}/roles` | High |
| 6 | Environment isolation enforced (production separated from sandbox) | `/accounts/api/organizations/{orgId}/environments` | Critical |
| 7 | API gateway policies enforce authentication on all production APIs | `/apimanager/.../apis/{id}/policies` | Critical |
| 8 | API gateway rate-limiting policies configured on public APIs | `/apimanager/.../apis/{id}/policies` | High |
| 9 | Client credentials (client ID/secret) rotated within policy period | `/apimanager/.../apis` | Medium |
| 10 | CloudHub workers use supported Mule runtime version | `/cloudhub/api/v2/applications` | High |
| 11 | CloudHub workers configured with appropriate sizing (no over-provisioning) | `/cloudhub/api/v2/applications` | Low |
| 12 | CloudHub persistent queues encrypted | `/cloudhub/api/v2/applications/{domain}` | Medium |
| 13 | VPC configured with restrictive firewall rules | `/cloudhub/api/v2/vpcs/{vpcId}` | High |
| 14 | VPC does not allow 0.0.0.0/0 ingress rules | `/cloudhub/api/v2/vpcs/{vpcId}` | Critical |
| 15 | Dedicated load balancer enforces TLS 1.2+ and strong cipher suites | `/cloudhub/api/v2/dlbs/{dlbId}` | High |
| 16 | DLB SSL certificates not expired or expiring within 30 days | `/cloudhub/api/v2/dlbs/{dlbId}` | High |
| 17 | Audit logging enabled and queryable (entries present within 24 hours) | `/audit/v2/organizations/{orgId}/query` | High |
| 18 | Connected apps use minimum required scopes | `/accounts/api/.../connectedApplications` | High |
| 19 | Connected apps reviewed for active usage (no stale apps) | `/accounts/api/.../connectedApplications` | Medium |
| 20 | Exchange assets follow governance review process | `/exchange/api/v2/assets` | Medium |
| 21 | Anypoint MQ access controls restrict queue access by environment | `/mq/admin/.../queues` | Medium |
| 22 | Secrets Manager used for sensitive configuration (no hardcoded secrets) | `/secrets/api/v1/.../secretGroups` | High |
| 23 | Hybrid runtime servers registered and reporting status | `/armui/api/v1/.../servers` | Medium |
| 24 | Anypoint Monitoring alerts configured for production applications | `/monitoring/api/v1/.../applications` | Medium |
| 25 | Business groups use separate sub-organizations for tenant isolation | `/accounts/api/organizations/{orgId}` | Medium |

## 5. Compliance Framework Mappings

| Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 SSO/SAML/OIDC configured | IA-2(1) | L2 3.5.3 | CC6.1 | 16.2 | 8.4.1 | SRG-APP-000148 | ISM-1546 | CPS-7.1 |
| 2 MFA enforced | IA-2(2) | L2 3.5.3 | CC6.1 | 16.3 | 8.4.2 | SRG-APP-000149 | ISM-1401 | CPS-7.2 |
| 3 Admin role minimization | AC-6(5) | L2 3.1.5 | CC6.3 | 16.8 | 7.1.1 | SRG-APP-000340 | ISM-1508 | CPS-8.1 |
| 4 Least-privilege role groups | AC-6 | L2 3.1.7 | CC6.3 | 16.8 | 7.1.2 | SRG-APP-000342 | ISM-1507 | CPS-8.2 |
| 5 Environment-scoped roles | AC-3 | L2 3.1.2 | CC6.1 | 16.8 | 7.1.3 | SRG-APP-000033 | ISM-1506 | CPS-8.3 |
| 6 Environment isolation | SC-7 | L2 3.13.1 | CC6.6 | 12.1 | 1.3.1 | SRG-APP-000516 | ISM-1528 | CPS-11.1 |
| 7 API authentication policies | IA-3 | L2 3.5.2 | CC6.1 | 16.7 | 8.3.1 | SRG-APP-000158 | ISM-1550 | CPS-7.3 |
| 8 API rate limiting | SC-5 | L2 3.13.6 | CC6.6 | 13.10 | 6.6 | SRG-APP-000246 | ISM-1019 | CPS-11.2 |
| 9 Client credential rotation | SC-12(1) | L2 3.13.10 | CC6.1 | 16.4 | 3.6.4 | SRG-APP-000176 | ISM-1557 | CPS-7.4 |
| 10 Supported runtime versions | SI-2 | L2 3.14.1 | CC7.1 | 7.4 | 6.2 | SRG-APP-000456 | ISM-1143 | CPS-13.1 |
| 11 Worker sizing review | CM-2 | L2 3.4.1 | CC8.1 | 4.1 | 2.2.1 | SRG-APP-000131 | ISM-1407 | CPS-10.1 |
| 12 Persistent queue encryption | SC-28 | L2 3.13.16 | CC6.7 | 14.8 | 3.4.1 | SRG-APP-000428 | ISM-0457 | CPS-11.3 |
| 13 VPC firewall rules | SC-7(5) | L2 3.13.1 | CC6.6 | 12.3 | 1.3.2 | SRG-APP-000142 | ISM-1416 | CPS-11.4 |
| 14 No open VPC ingress | SC-7 | L2 3.13.1 | CC6.6 | 12.3 | 1.3.4 | SRG-APP-000142 | ISM-1416 | CPS-11.5 |
| 15 DLB TLS enforcement | SC-8(1) | L2 3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0484 | CPS-11.6 |
| 16 DLB certificate validity | SC-17 | L2 3.13.15 | CC6.7 | 14.2 | 4.1 | SRG-APP-000175 | ISM-1557 | CPS-7.5 |
| 17 Audit logging active | AU-12 | L2 3.3.1 | CC7.2 | 8.5 | 10.2 | SRG-APP-000507 | ISM-0580 | CPS-12.1 |
| 18 Connected app scoping | AC-6(1) | L2 3.1.5 | CC6.3 | 16.8 | 7.1.2 | SRG-APP-000340 | ISM-1508 | CPS-8.1 |
| 19 Stale connected app review | AC-2(3) | L2 3.1.12 | CC6.2 | 16.9 | 8.1.4 | SRG-APP-000025 | ISM-1552 | CPS-9.1 |
| 20 Exchange asset governance | CM-3 | L2 3.4.3 | CC8.1 | 4.8 | 6.4.2 | SRG-APP-000380 | ISM-1210 | CPS-10.2 |
| 21 MQ environment access | AC-3 | L2 3.1.1 | CC6.1 | 16.8 | 7.1.3 | SRG-APP-000033 | ISM-1506 | CPS-8.3 |
| 22 Secrets Manager usage | SC-28(1) | L2 3.13.16 | CC6.1 | 14.8 | 3.4.1 | SRG-APP-000429 | ISM-0457 | CPS-11.7 |
| 23 Hybrid server health | CM-8 | L2 3.4.1 | CC6.8 | 1.1 | 2.4 | SRG-APP-000383 | ISM-1409 | CPS-10.3 |
| 24 Monitoring alerts configured | SI-4 | L2 3.14.6 | CC7.2 | 8.11 | 10.6.1 | SRG-APP-000516 | ISM-0576 | CPS-12.2 |
| 25 Business group isolation | AC-4 | L2 3.1.3 | CC6.6 | 12.1 | 7.1.4 | SRG-APP-000100 | ISM-1528 | CPS-11.8 |

## 6. Existing Tools

| Tool | Type | Overlap | Gap Addressed |
|------|------|---------|---------------|
| Anypoint CLI (`anypoint-cli`) | Official CLI | Operational management, no security posture analysis | No automated compliance assessment |
| Anypoint Monitoring | Native | Performance/availability metrics, no security controls | No security control evaluation or compliance mapping |
| MuleSoft Audit Log (built-in) | Native | Logs actions but does not evaluate posture | No automated security posture scoring |
| API Governance (Exchange) | Native | API conformance checks, no platform-level security | No IAM, runtime, or infrastructure security review |
| Prowler | Cloud security | AWS/Azure/GCP focused, no SaaS integration platform coverage | No MuleSoft-specific controls |
| ScoutSuite | Cloud security | Multi-cloud auditor, no SaaS platform support | No Anypoint Platform coverage |
| Steampipe | SQL query engine | No MuleSoft plugin available | No Anypoint Platform data source |

## 7. Architecture

```
mulesoft-sec-inspector/
├── cmd/
│   └── mulesoft-sec-inspector/
│       └── main.go                  # Entrypoint, CLI argument parsing
├── internal/
│   ├── client/
│   │   ├── client.go                # HTTP client with auth, rate limiting, retry
│   │   ├── auth.go                  # Token acquisition (client_credentials, password grant)
│   │   ├── pagination.go            # Cursor-based and offset pagination handler
│   │   └── endpoints.go             # API endpoint path constants and URL builder
│   ├── config/
│   │   ├── config.go                # TOML config loader, env var merging
│   │   └── validation.go            # Config validation, org ID resolution
│   ├── analyzers/
│   │   ├── analyzer.go              # Analyzer interface definition
│   │   ├── registry.go              # Analyzer registration and discovery
│   │   ├── identity.go              # SSO, MFA, identity provider configuration
│   │   ├── members.go               # Member roles, admin count, access review
│   │   ├── rolegroups.go            # Role group permissions, environment scoping
│   │   ├── environments.go          # Environment isolation, type enforcement
│   │   ├── api_gateway.go           # API policies: authentication, rate limiting
│   │   ├── cloudhub.go              # Worker config, runtime versions, encryption
│   │   ├── vpc.go                   # VPC firewall rules, CIDR validation
│   │   ├── dlb.go                   # DLB TLS config, certificate expiry
│   │   ├── audit.go                 # Audit log availability and completeness
│   │   ├── connected_apps.go        # Connected app scopes and staleness
│   │   ├── exchange.go              # Exchange asset governance review
│   │   ├── mq.go                    # Anypoint MQ access controls
│   │   ├── secrets.go               # Secrets Manager usage validation
│   │   ├── servers.go               # Hybrid runtime server health
│   │   └── monitoring.go            # Monitoring alert configuration
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
| `crypto/tls` (stdlib) | TLS certificate inspection for DLB checks |

## 8. CLI Interface

```
mulesoft-sec-inspector [command] [flags]

Commands:
  scan        Run all security analyzers against the Anypoint Platform organization
  analyze     Run a specific analyzer (e.g., identity, api_gateway, cloudhub, vpc)
  report      Generate report from previous scan results
  list        List available analyzers and controls
  version     Print version information

Global Flags:
  --client-id string       Connected App client ID
  --client-secret string   Connected App client secret
  --username string        Anypoint Platform username (fallback auth)
  --password string        Anypoint Platform password (fallback auth)
  --org-id string          Organization ID to inspect
  --base-url string        API base URL (default "https://anypoint.mulesoft.com")
  --config string          Config file path (default "~/.config/mulesoft-sec-inspector/config.toml")
  --output string          Output format: json, csv, html, summary (default "summary")
  --output-file string     Write report to file instead of stdout
  --severity string        Minimum severity to report: critical, high, medium, low (default "low")
  --environment strings    Limit scan to specific environment names (comma-separated)
  --tui                    Launch interactive TUI dashboard
  --no-color               Disable colored output
  --verbose                Enable verbose logging
  --timeout duration       API request timeout (default 30s)

Examples:
  # Full scan with connected app credentials
  mulesoft-sec-inspector scan --client-id $AP_CLIENT_ID --client-secret $AP_CLIENT_SECRET --org-id $AP_ORG_ID

  # Scan specific analyzers with JSON output
  mulesoft-sec-inspector analyze identity,api_gateway,vpc --output json --output-file report.json

  # Scan only production environment, high severity and above
  mulesoft-sec-inspector scan --environment production --severity high

  # Launch interactive TUI
  mulesoft-sec-inspector scan --tui

  # EU control plane
  mulesoft-sec-inspector scan --base-url https://eu1.anypoint.mulesoft.com --org-id $AP_ORG_ID

  # Gov Cloud
  mulesoft-sec-inspector scan --base-url https://gov.anypoint.mulesoft.com --org-id $AP_ORG_ID
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/mulesoft-sec-inspector

# 2. Install dependencies
go get github.com/spf13/cobra@latest
go get github.com/charmbracelet/bubbletea@latest
go get github.com/charmbracelet/lipgloss@latest
go get github.com/pelletier/go-toml/v2@latest
go mod tidy

# 3. Build binary
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o bin/mulesoft-sec-inspector ./cmd/mulesoft-sec-inspector/

# 4. Run tests
go test ./... -v -race -coverprofile=coverage.out

# 5. Lint
golangci-lint run ./...

# 6. Docker build
docker build -t mulesoft-sec-inspector:latest .

# 7. Release (via GoReleaser)
goreleaser release --clean
```

## 10. Status

Implemented in grclanker as the native TypeScript module `cli/extensions/grc-tools/mulesoft.ts`, with mocked API coverage in `cli/tests/mulesoft.test.mjs`, a live smoke script at `cli/scripts/mulesoft-live-smoke.mjs` (`npm --prefix cli run test:mulesoft:live`, skips when no credentials are present), and an integration guide at `src/content/docs/docs/integrations/mulesoft.md`. Sections 7 to 9 describe the original standalone Go design and are retained for reference only.

### Shipped

- Six read-only tools: `mulesoft_check_access`, `mulesoft_assess_identity_access`, `mulesoft_assess_api_gateway`, `mulesoft_assess_runtime_infrastructure`, `mulesoft_assess_audit_monitoring`, and `mulesoft_export_audit_bundle`. No tool issues a write request other than the token exchange and the audit log query (`POST` by API design).
- All 25 controls in section 4 produce a finding with the framework mappings from section 5. Controls 9 (client credential rotation) and 20 (Exchange governance review) are always `manual` because no public API exposes the evidence; controls 2, 13, 14, 16, 19, 21, and 25 return `manual` with the exact evidence to collect when the API cannot settle them (no MFA exemptions found, no Anypoint VPC, TLS probe unreachable, no connected app usage data, MQ inventory only, no business groups).
- Authentication: connected app client credentials (`POST /accounts/api/v2/oauth2/token`), username and password (`POST /accounts/login`), and a pre-issued bearer token, chosen in the order token, connected app, credentials. Every setting resolves as explicit tool argument, then environment variable, then `~/.config/mulesoft-sec-inspector/config.toml` (path override: `config_file` argument or `MULESOFT_SEC_INSPECTOR_CONFIG`). Environment variables: `ANYPOINT_ORG_ID`, `ANYPOINT_CLIENT_ID`, `ANYPOINT_CLIENT_SECRET`, `ANYPOINT_USERNAME`, `ANYPOINT_PASSWORD`, `ANYPOINT_TOKEN`, `ANYPOINT_CONTROL_PLANE`, `ANYPOINT_BASE_URL`, `ANYPOINT_ENVIRONMENTS`, `ANYPOINT_TIMEOUT`.
- Control planes `us`, `eu`, and `gov` map to the base URLs in section 2; `base_url` accepts any other host.
- Client: organization and environment scoping (`X-ANYPNT-ORG-ID`, `X-ANYPNT-ENV-ID`), `limit` and `offset` pagination, retry with backoff on 429 and 5xx, per-request timeouts, and redaction of secrets, tokens, and passwords in errors, tool output, and bundle snapshots.
- Audit bundle: `core_data/` raw snapshots, `analysis/` findings and category summaries, `compliance/` executive summary, unified matrix, and one report per framework in section 5, `QUICK_REFERENCE.md`, `_errors.log` on partial collection failure, and a `.zip`, written under an output path that rejects traversal and symlinked parents.

### Deviations from this spec

Where this document and the official Anypoint Platform API specifications on Anypoint Exchange disagreed, the implementation follows the published specifications:

| This spec | Implementation | Source |
|-----------|----------------|--------|
| `/cloudhub/api/v2/vpcs`, `/cloudhub/api/v2/vpcs/{vpcId}`, `/cloudhub/api/v2/dlbs` | `/cloudhub/api/organizations/{orgId}/vpcs`, `/cloudhub/api/organizations/{orgId}/vpcs/{vpcId}`, `/cloudhub/api/organizations/{orgId}/loadbalancers` | CloudHub API |
| `/cloudhub/api/v2/applications` with no scoping | Same path plus the `X-ANYPNT-ENV-ID` header; `/cloudhub/api/v2/alerts` added for control 24 | CloudHub API |
| `/armui/api/v1/organizations/{orgId}/environments/{envId}/servers` | `/hybrid/api/v1/servers` and `/hybrid/api/v1/alerts` scoped by `X-ANYPNT-ORG-ID` and `X-ANYPNT-ENV-ID` headers | ARM REST Services |
| `/exchange/api/v2/assets` | `/exchange/api/v2/assets/search` with `limit` and `offset` | Exchange API v2 |
| `/mq/admin/api/v1/.../regions/{regionId}/queues` | `/mq/admin/api/v1/organizations/{orgId}/environments/{envId}/regions/{regionId}/destinations/queues` and `/environments/{envId}/clients` | Anypoint MQ Admin API |
| `/secrets/api/v1/.../secretGroups` | `/secrets-manager/api/v1/organizations/{orgId}/environments/{envId}/secretGroups` | Secrets Manager API |
| `/monitoring/api/v1/.../applications` | No public Anypoint Monitoring alerts API exists; control 24 uses CloudHub and Runtime Manager alerts and asks for Anypoint Monitoring exports as manual evidence | Anypoint Monitoring docs |
| `/accounts/api/organizations/{orgId}/users/{userId}` for per-user MFA status | `/accounts/api/organizations/{orgId}/users?mfaVerificationExcluded=true`; organization-wide MFA enforcement is not exposed, so control 2 fails only on exempt users and is otherwise manual | Access Management API |
| DLB cipher suites and certificate expiry from `/dlbs/{dlbId}` | The load balancer API returns TLS version flags and `httpMode` but no certificate dates or cipher list; control 16 performs a live TLS handshake with `node:tls` and control 15 evaluates the version flags only | CloudHub API |
| Configuration precedence with username and password ranked below client credentials environment variables | Argument, environment variable, then config file for every setting; the auth mode is selected from whichever credential set is complete | grclanker convention |
| JSON, CSV, HTML reports and a Bubble Tea TUI | grclanker findings plus the Markdown, JSON, and `.zip` audit bundle; no standalone binary | grclanker tool model |

### Remaining

- Live validation against a real Anypoint Platform organization on each control plane; the smoke script is wired but has only been exercised against mocked responses.
- CloudHub 2.0 private spaces and Runtime Fabric inventory; controls 13 and 14 fall back to `manual` when no Anypoint VPC is visible.
- Anypoint Monitoring alert inventory if MuleSoft publishes a public alerts API.
- API Governance conformance results and client secret rotation timestamps if Exchange or API Manager expose them (controls 9 and 20).
- Rate limit figures in section 2 were not confirmed against current documentation; the client relies on 429 retry rather than fixed budgets.
