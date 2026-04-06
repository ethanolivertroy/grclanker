---
slug: "cloudflare-sec-inspector"
name: "Cloudflare Security Inspector"
vendor: "Cloudflare"
category: "security-network-infrastructure"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/cloudflare-sec-inspector"
---

# Cloudflare Security Inspector — Architecture Specification

## 1. Overview

**cloudflare-sec-inspector** is a security compliance inspection tool for Cloudflare environments. It audits WAF configurations, Zero Trust access policies, SSL/TLS settings, DDoS protections, DNS security, API token permissions, and account-level security controls across all zones and accounts via the Cloudflare API v4. The tool produces structured findings mapped to major compliance frameworks, enabling security teams to identify misconfigurations, enforce defense-in-depth, and maintain continuous compliance posture.

Written in Go with a hybrid CLI/TUI architecture, it supports both automated pipeline execution (JSON/SARIF output) and interactive exploration of findings.

## 2. APIs & SDKs

### Cloudflare API v4

| Endpoint | Purpose |
|----------|---------|
| `GET /client/v4/zones` | List all zones in the account |
| `GET /client/v4/zones/{zone_id}/settings` | Zone-level security settings (SSL, HSTS, TLS, etc.) |
| `GET /client/v4/zones/{zone_id}/firewall/rules` | Firewall rules inventory |
| `GET /client/v4/zones/{zone_id}/firewall/waf/packages` | WAF managed rulesets |
| `GET /client/v4/zones/{zone_id}/firewall/waf/packages/{pkg_id}/groups` | WAF rule groups |
| `GET /client/v4/zones/{zone_id}/rulesets` | Zone rulesets (new WAF engine) |
| `GET /client/v4/zones/{zone_id}/dns_records` | DNS records for DNSSEC and record audit |
| `GET /client/v4/zones/{zone_id}/dnssec` | DNSSEC status |
| `GET /client/v4/zones/{zone_id}/ssl/certificate_packs` | SSL certificate inventory |
| `GET /client/v4/zones/{zone_id}/ssl/universal/settings` | Universal SSL settings |
| `GET /client/v4/zones/{zone_id}/bot_management` | Bot management configuration |
| `GET /client/v4/zones/{zone_id}/rate_limits` | Rate limiting rules |
| `GET /client/v4/zones/{zone_id}/pagerules` | Page rules (security-relevant) |
| `GET /client/v4/accounts/{account_id}/access/apps` | Zero Trust Access applications |
| `GET /client/v4/accounts/{account_id}/access/policies` | Zero Trust Access policies |
| `GET /client/v4/accounts/{account_id}/access/identity_providers` | Identity provider config |
| `GET /client/v4/accounts/{account_id}/gateway/rules` | Gateway (SWG) rules |
| `GET /client/v4/accounts/{account_id}/audit_logs` | Account audit log |
| `GET /client/v4/accounts/{account_id}/members` | Account member roles |
| `GET /client/v4/user/tokens` | API token inventory |
| `GET /client/v4/user/tokens/verify` | Verify current token permissions |
| `GET /client/v4/accounts/{account_id}/firewall/access_rules/rules` | IP access rules |

**Base URL:** `https://api.cloudflare.com`

### SDKs and Libraries

| Name | Language | Notes |
|------|----------|-------|
| `cloudflare-go` | Go | Official Go SDK |
| `cloudflare` (python-cloudflare) | Python | Community Python SDK |
| `wrangler` | Node.js | Workers CLI with API access |
| `flarectl` | Go | Official CLI tool |
| Terraform Provider (`cloudflare`) | HCL | Official IaC provider |

## 3. Authentication

### API Token (Recommended)

```
Authorization: Bearer <api-token>
```

- Scoped tokens with specific zone/account permissions
- Created via Cloudflare Dashboard > My Profile > API Tokens
- Supports fine-grained permission control

### Global API Key (Legacy)

```
X-Auth-Email: user@example.com
X-Auth-Key: <global-api-key>
```

- Full account access, not recommended for production use
- The inspector will warn if a global API key is detected

### Required Token Permissions

| Permission | Scope | Purpose |
|------------|-------|---------|
| Zone Settings: Read | All zones | Read zone security settings |
| Firewall Services: Read | All zones | WAF, firewall rules, rate limits |
| Zone: Read | All zones | Zone listing and metadata |
| DNS: Read | All zones | DNSSEC and DNS record audit |
| SSL and Certificates: Read | All zones | TLS/SSL configuration |
| Access: Apps and Policies: Read | Account | Zero Trust app/policy audit |
| Account Settings: Read | Account | Member roles, audit logs |
| API Tokens: Read | User | Token inventory and permissions |
| Bot Management: Read | All zones | Bot management config |
| Page Rules: Read | All zones | Page rule security review |

### Configuration

```bash
export CLOUDFLARE_API_TOKEN="your-api-token"
# Or for global key (not recommended):
# export CLOUDFLARE_API_KEY="your-global-key"
# export CLOUDFLARE_EMAIL="user@example.com"
export CLOUDFLARE_ACCOUNT_ID="your-account-id"  # Optional: scope to specific account
```

Alternatively, configure via `~/.cloudflare-sec-inspector/config.yaml` or CLI flags.

## 4. Security Controls

1. **WAF Managed Rules Enabled** — Verify Cloudflare WAF managed rulesets (OWASP, Cloudflare Managed) are enabled on all zones.
2. **WAF Custom Rules** — Audit custom WAF rules for appropriate blocking actions and coverage of common attack vectors.
3. **DDoS Protection Settings** — Verify L3/L4 and L7 DDoS protection is enabled with appropriate sensitivity levels.
4. **Bot Management Configuration** — Check that bot management or Super Bot Fight Mode is enabled and configured appropriately.
5. **SSL/TLS Mode Full Strict** — Ensure all zones use "Full (Strict)" SSL mode, not "Flexible" or "Off".
6. **Minimum TLS Version** — Verify minimum TLS version is set to 1.2 or higher across all zones.
7. **HSTS Enabled** — Confirm HTTP Strict Transport Security is enabled with appropriate max-age (>= 6 months), includeSubDomains, and preload.
8. **DNSSEC Enabled** — Verify DNSSEC is active on all zones to prevent DNS spoofing.
9. **Zero Trust Access Policies** — Audit Access applications and policies for proper identity provider integration and policy coverage.
10. **Zero Trust Identity Providers** — Verify Access identity providers are configured with SSO/MFA-capable providers.
11. **Audit Logging Active** — Confirm account audit logs are being generated and retained.
12. **API Token Permissions Scoped** — Detect API tokens with overly broad permissions; flag use of Global API Key.
13. **API Token Expiration** — Identify API tokens without expiration dates set.
14. **Account Member Roles** — Audit member roles for least-privilege; detect excessive Super Administrator assignments.
15. **Page Rules Security** — Review page rules for security-degrading configurations (e.g., SSL disabled, cache everything on sensitive paths).
16. **Rate Limiting Rules** — Verify rate limiting is configured on authentication endpoints and sensitive API paths.
17. **IP Access Rules** — Audit IP allowlist/blocklist rules for appropriateness and staleness.
18. **Origin Certificate Validation** — Check that authenticated origin pulls are enabled for origin server verification.
19. **Browser Integrity Check** — Verify Browser Integrity Check is enabled to block requests with suspicious headers.
20. **Email Address Obfuscation** — Confirm email obfuscation is enabled to prevent harvesting.
21. **Always Use HTTPS** — Verify "Always Use HTTPS" is enabled on all zones.
22. **Automatic HTTPS Rewrites** — Check that automatic HTTPS rewrites are enabled to fix mixed content.
23. **Security Headers** — Audit transform rules for security headers (X-Frame-Options, CSP, X-Content-Type-Options).
24. **Gateway SWG Policies** — Review Cloudflare Gateway policies for DNS/HTTP filtering rules and security categories.
25. **Universal SSL Status** — Verify Universal SSL certificates are active and not disabled on any zone.

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 | WAF Managed Rules | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.1 | 6.6 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 2 | WAF Custom Rules | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.2 | 6.6 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 3 | DDoS Protection | SC-5 | SC.L2-3.13.6 | CC6.6 | 9.3 | 6.5.10 | SRG-APP-000246 | ISM-1020 | CPS-11 |
| 4 | Bot Management | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.4 | 6.6 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 5 | SSL/TLS Full Strict | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.1 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 6 | Minimum TLS Version | SC-8(1) | SC.L2-3.13.8 | CC6.7 | 3.2 | 4.1 | SRG-APP-000219 | ISM-1369 | CPS-09 |
| 7 | HSTS Enabled | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.3 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 8 | DNSSEC Enabled | SC-20 | SC.L2-3.13.15 | CC6.7 | 3.4 | — | SRG-APP-000516 | ISM-1183 | CPS-09 |
| 9 | Zero Trust Access Policies | AC-3 | AC.L2-3.1.2 | CC6.1 | 1.1 | 7.2.1 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 10 | Zero Trust IdP Config | IA-2 | AC.L2-3.1.1 | CC6.1 | 1.2 | 8.3.1 | SRG-APP-000148 | ISM-1557 | CPS-04 |
| 11 | Audit Logging | AU-2 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.2.1 | SRG-APP-000089 | ISM-0580 | CPS-10 |
| 12 | API Token Scoping | AC-6 | AC.L2-3.1.5 | CC6.3 | 5.1 | 7.2.1 | SRG-APP-000340 | ISM-0432 | CPS-07 |
| 13 | API Token Expiration | IA-5(1) | IA.L2-3.5.8 | CC6.1 | 5.2 | 8.6.3 | SRG-APP-000175 | ISM-1590 | CPS-05 |
| 14 | Member Role Audit | AC-2 | AC.L2-3.1.1 | CC6.3 | 6.1 | 7.2.2 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 15 | Page Rules Security | CM-6 | CM.L2-3.4.2 | CC8.1 | 10.1 | 2.2 | SRG-APP-000386 | ISM-0380 | CPS-12 |
| 16 | Rate Limiting | SC-5 | SC.L2-3.13.6 | CC6.6 | 9.5 | 6.5.10 | SRG-APP-000246 | ISM-1020 | CPS-11 |
| 17 | IP Access Rules | SC-7(5) | SC.L2-3.13.1 | CC6.6 | 9.6 | 1.3.2 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 18 | Origin Certificate Auth | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.5 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 19 | Browser Integrity Check | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.7 | 6.6 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 20 | Email Obfuscation | SC-7 | SC.L2-3.13.1 | CC6.7 | 3.6 | — | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 21 | Always Use HTTPS | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.7 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 22 | HTTPS Rewrites | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.8 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 23 | Security Headers | SC-7 | SC.L2-3.13.1 | CC6.7 | 9.8 | 6.5.10 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 24 | Gateway SWG Policies | SC-7 | SC.L2-3.13.1 | CC6.6 | 9.9 | 1.3.1 | SRG-APP-000383 | ISM-1148 | CPS-11 |
| 25 | Universal SSL Status | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.9 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |

## 6. Existing Tools

| Tool | Type | Limitations |
|------|------|-------------|
| Cloudflare Security Center | Built-in | Focuses on security insights for managed zones, not comprehensive compliance mapping |
| Cloudflare Terraform Provider | IaC | Enforces desired state but no compliance drift detection or reporting |
| flarectl | CLI | Management tool, no security assessment capability |
| ScoutSuite (Cloudflare module) | Scanner | Limited Cloudflare coverage, focused primarily on cloud IaaS |
| cf-terraforming | Tool | Generates Terraform from existing config, no security analysis |
| Prowler (limited) | Scanner | Minimal Cloudflare support |

**Gap:** No existing tool provides automated, comprehensive security posture assessment of Cloudflare zone and account configurations mapped to compliance frameworks. cloudflare-sec-inspector fills this gap with deep coverage of WAF, Zero Trust, TLS, and DNS security controls.

## 7. Architecture

```
cloudflare-sec-inspector/
├── cmd/
│   └── cloudflare-sec-inspector/
│       └── main.go                 # Entrypoint, CLI bootstrap
├── internal/
│   ├── analyzers/
│   │   ├── analyzer.go             # Analyzer interface and registry
│   │   ├── waf.go                  # WAF managed rules and custom rules
│   │   ├── ddos.go                 # DDoS protection settings
│   │   ├── bots.go                 # Bot management configuration
│   │   ├── tls.go                  # SSL/TLS mode, min version, HSTS, certs
│   │   ├── dns.go                  # DNSSEC, DNS records audit
│   │   ├── access.go               # Zero Trust Access apps, policies, IdPs
│   │   ├── gateway.go              # Gateway SWG policy review
│   │   ├── audit.go                # Audit logging checks
│   │   ├── tokens.go               # API token permissions and expiration
│   │   ├── members.go              # Account member role audit
│   │   ├── pagerules.go            # Page rules security review
│   │   ├── ratelimit.go            # Rate limiting rule audit
│   │   ├── iprules.go              # IP access rules audit
│   │   ├── origin.go               # Origin certificate and auth pulls
│   │   ├── headers.go              # Security headers and browser checks
│   │   └── https.go                # HTTPS enforcement and rewrites
│   ├── client/
│   │   ├── client.go               # Cloudflare API v4 client
│   │   ├── auth.go                 # Token and global key auth
│   │   ├── ratelimit.go            # Rate limiter (1200 req/5min default)
│   │   ├── pagination.go           # Cursor-based pagination handler
│   │   └── zones.go                # Zone discovery and filtering
│   ├── config/
│   │   ├── config.go               # Configuration loading and validation
│   │   └── redact.go               # Credential redaction for logging
│   ├── models/
│   │   ├── zone.go                 # Zone and zone settings models
│   │   ├── firewall.go             # WAF, firewall rule, rate limit models
│   │   ├── access.go               # Zero Trust app, policy, IdP models
│   │   ├── member.go               # Account member and role models
│   │   ├── token.go                # API token model
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

- **Zone-aware scanning**: Iterates all zones (or filtered subset) and applies zone-level analyzers per zone
- **Rate limiting**: Cloudflare allows 1200 requests per 5 minutes; built-in token bucket rate limiter with zone-count-aware pacing
- **Dual auth support**: Supports both scoped API tokens (recommended) and global API key (warns if detected)
- **Account + Zone scope**: Separates account-level checks (members, Access, tokens) from zone-level checks (WAF, TLS, DNS)

## 8. CLI Interface

```
cloudflare-sec-inspector [command] [flags]

Commands:
  scan        Run all or selected security analyzers
  list        List available analyzers and their descriptions
  version     Print version information

Scan Flags:
  --api-token string       Cloudflare API token (env: CLOUDFLARE_API_TOKEN)
  --api-key string         Cloudflare Global API key (env: CLOUDFLARE_API_KEY)
  --email string           Cloudflare account email (env: CLOUDFLARE_EMAIL)
  --account-id string      Scope to specific account (env: CLOUDFLARE_ACCOUNT_ID)
  --zone strings           Scan specific zones by name or ID (default: all zones)
  --exclude-zone strings   Exclude zones by name or ID
  --analyzers strings      Run specific analyzers (comma-separated)
  --exclude strings        Exclude specific analyzers
  --severity string        Minimum severity to report: critical,high,medium,low,info
  --format string          Output format: table,json,sarif,csv,html (default "table")
  --output string          Output file path (default: stdout)
  --tui                    Launch interactive TUI
  --no-color               Disable colored output
  --config string          Path to config file (default "~/.cloudflare-sec-inspector/config.yaml")
  --timeout duration       API request timeout (default 30s)
  --verbose                Enable verbose logging
```

### Usage Examples

```bash
# Full scan of all zones
cloudflare-sec-inspector scan

# Scan specific zone
cloudflare-sec-inspector scan --zone example.com

# TLS and WAF checks only
cloudflare-sec-inspector scan --analyzers tls,waf

# Generate SARIF for CI/CD pipeline
cloudflare-sec-inspector scan --format sarif --output results.sarif

# JSON output for specific account
cloudflare-sec-inspector scan --account-id abc123 --format json

# Interactive TUI
cloudflare-sec-inspector scan --tui
```

## 9. Build Sequence

```bash
# Prerequisites
go 1.22+

# Clone and build
git clone https://github.com/hackIDLE/cloudflare-sec-inspector.git
cd cloudflare-sec-inspector
go mod download
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o bin/cloudflare-sec-inspector ./cmd/cloudflare-sec-inspector/

# Run tests
go test ./...

# Build Docker image
docker build -t cloudflare-sec-inspector .

# Run via Docker
docker run --rm \
  -e CLOUDFLARE_API_TOKEN \
  cloudflare-sec-inspector scan --format json
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
