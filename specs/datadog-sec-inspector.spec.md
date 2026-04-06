---
slug: "datadog-sec-inspector"
name: "Datadog Security Inspector"
vendor: "Datadog"
category: "monitoring-logging-observability"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/datadog-sec-inspector"
---

# datadog-sec-inspector

Security compliance inspector for Datadog for Government environments.

## 1. Overview

Datadog is a cloud-scale monitoring and security platform that provides infrastructure monitoring, application performance monitoring (APM), log management, Cloud SIEM, and Cloud Security Management (CSM). Datadog for Government operates on a FedRAMP-authorized infrastructure at `ddog-gov.com`, holding FedRAMP Moderate authorization with FedRAMP High "In Process" status.

Compliance matters because Datadog tenants are the control plane for observability and security across an organization's entire technology stack. Misconfigured RBAC, unrotated API keys, disabled audit logs, or overly permissive sharing settings can expose sensitive telemetry data, security signals, and compliance posture information. Federal and regulated environments require continuous validation that Datadog organization settings, user access, key management, and security monitoring configurations meet the requirements of FedRAMP, CMMC, PCI-DSS, SOC 2, and other frameworks.

`datadog-sec-inspector` programmatically audits a Datadog organization's security configuration against 20 controls mapped to eight compliance frameworks, producing machine-readable findings and human-readable reports.

## 2. APIs & SDKs

### Datadog API v1 Endpoints

| Endpoint | Method | Description | Permission Required |
|---|---|---|---|
| `/api/v1/org` | GET | Organization settings (SAML, sharing, data retention) | `org_management` |
| `/api/v1/validate` | GET | Validate API key is active | API key only |
| `/api/v1/logs/config/pipelines` | GET | List all log pipelines | `logs_read_config` |
| `/api/v1/logs/config/pipeline-order` | GET | Get pipeline processing order | `logs_read_config` |
| `/api/v1/security_analytics/signals/search` | POST | Search security signals | `security_monitoring_signals_read` |
| `/api/v1/dashboard` | GET | List all dashboards (check sharing status) | `dashboards_read` |
| `/api/v1/monitor` | GET | List monitors (notification channel audit) | `monitors_read` |
| `/api/v1/integration/{source}` | GET | List configured integrations | varies |

### Datadog API v2 Endpoints

| Endpoint | Method | Description | Permission Required |
|---|---|---|---|
| `/api/v2/users` | GET | List all users (status, roles, MFA) | `user_access_read` |
| `/api/v2/users/{user_id}` | GET | Get single user detail | `user_access_read` |
| `/api/v2/roles` | GET | List all roles (custom and default) | `user_access_read` |
| `/api/v2/roles/{role_id}/permissions` | GET | List permissions granted to a role | `user_access_read` |
| `/api/v2/permissions` | GET | List all available permissions | `user_access_read` |
| `/api/v2/audit/events` | GET | List audit log events | `audit_logs_read` |
| `/api/v2/audit/events/search` | POST | Search audit events with filters | `audit_logs_read` |
| `/api/v2/security_monitoring/rules` | GET | List security detection rules | `security_monitoring_rules_read` |
| `/api/v2/security_monitoring/rules/{rule_id}` | GET | Get detection rule detail | `security_monitoring_rules_read` |
| `/api/v2/security_monitoring/signals` | GET | List security signals | `security_monitoring_signals_read` |
| `/api/v2/api_keys` | GET | List all API keys | `api_keys_read` |
| `/api/v2/api_keys/{api_key_id}` | GET | Get API key detail (created, last used) | `api_keys_read` |
| `/api/v2/application_keys` | GET | List all application keys | `user_access_read` |
| `/api/v2/application_keys/{app_key_id}` | GET | Get application key detail | `user_access_read` |
| `/api/v2/current_user/application_keys` | GET | List current user's application keys | none (scoped) |
| `/api/v2/validate_keys` | POST | Validate API and application key pair | API key only |
| `/api/v2/ip_allowlist` | GET | Get IP allowlist configuration | `org_management` |
| `/api/v2/ip_allowlist` | PATCH | Update IP allowlist entries | `org_management` |
| `/api/v2/sensitive-data-scanner/config` | GET | List sensitive data scanner groups/rules | `data_scanner_read` |
| `/api/v2/sensitive-data-scanner/config` | PATCH | Update scanner configuration | `data_scanner_write` |
| `/api/v2/security_monitoring/configuration/critical_assets` | POST | Manage critical assets | `security_monitoring_critical_assets_write` |
| `/api/v2/restriction_policy/{resource_id}` | GET | Get restriction policy for a resource | varies |

### SDKs

| SDK | Language | Install | Notes |
|---|---|---|---|
| `datadog-api-client-go` | Go | `go get github.com/DataDog/datadog-api-client-go/v2` | Official. Supports v1 and v2 APIs. Used by this tool. |
| `datadog-api-client-python` | Python | `pip install datadog-api-client` | Official. Async support via `[async]` extra. |
| `datadogpy` | Python | `pip install datadog` | Older library. Includes `dogshell` CLI (`dog` command). |
| `datadog-api-client-java` | Java | Maven/Gradle | Official. |
| `datadog-api-client-typescript` | TypeScript | `npm install @datadog/datadog-api-client` | Official. |
| `datadog-api-client-ruby` | Ruby | `gem install datadog_api_client` | Official. |

### CLIs

| Tool | Description |
|---|---|
| `dogshell` (`dog`) | CLI bundled with `datadogpy`. Configure via `~/.dogrc`. Supports metrics, events, monitors, dashboards. |
| Datadog Terraform Provider | `hashicorp/datadog` provider for IaC management of Datadog resources. |

## 3. Authentication

### Credential Types

| Credential | Header | Description |
|---|---|---|
| API Key | `DD-API-KEY` | Organization-level key. Required for all API calls. Identifies the organization. Does not grant user-level permissions alone. |
| Application Key | `DD-APPLICATION-KEY` | User-scoped key. Required for most read/write operations. Inherits the permissions of the user who created it. Scoped application keys can further restrict permissions. |

### Environment Variables

| Variable | Description | Example |
|---|---|---|
| `DD_API_KEY` | Datadog API key | `abcdef1234567890abcdef1234567890` |
| `DD_APP_KEY` | Datadog Application key | `abcdef1234567890abcdef1234567890abcdef12` |
| `DD_SITE` | Datadog site/region | `datadoghq.com` (default), `ddog-gov.com` (GovCloud), `datadoghq.eu`, `us3.datadoghq.com`, `us5.datadoghq.com`, `ap1.datadoghq.com`, `ap2.datadoghq.com` |

### Authentication Flow

```
1. Read DD_API_KEY, DD_APP_KEY, DD_SITE from environment (or config file / flags).
2. Construct base URL: https://api.{DD_SITE}/
3. Set headers: DD-API-KEY and DD-APPLICATION-KEY on every request.
4. Validate credentials via GET /api/v1/validate before proceeding.
5. All subsequent API calls inherit the permissions of the Application Key's owner.
```

### Additional Auth Mechanisms

- **OAuth (limited):** Datadog supports OAuth for partner integrations and Datadog Apps. Not applicable for compliance auditing.
- **SAML SSO:** Organization-level SSO via SAML 2.0 (Okta, Azure AD, PingOne, etc.). Configurable via `/api/v1/org` endpoint. Inspector checks whether SAML is enforced.
- **Scoped Application Keys:** Application keys can be created with a subset of the owner's permissions. Inspector should flag unscoped keys.

## 4. Security Controls

| # | Control | API Source | What the Inspector Checks |
|---|---|---|---|
| 1 | SAML SSO Enforcement | `GET /api/v1/org` | SAML is enabled and IdP-initiated login is configured. Strict mode enforced (password login disabled). |
| 2 | MFA Status | `GET /api/v2/users` | All active users have MFA enabled. No users rely solely on password authentication. |
| 3 | RBAC Configuration (Custom Roles) | `GET /api/v2/roles`, `GET /api/v2/roles/{id}/permissions` | Custom roles follow least-privilege. No custom roles grant `org_management` or `admin` equivalent. Default roles are not over-assigned. |
| 4 | User Access Review | `GET /api/v2/users` | No disabled/deprovisioned users with active sessions. No users inactive >90 days. Service accounts are identified and justified. |
| 5 | API Key Rotation | `GET /api/v2/api_keys` | All API keys have been rotated within policy window (e.g., 90 days). Keys not used in >30 days are flagged. Key names follow naming convention. |
| 6 | Application Key Audit | `GET /api/v2/application_keys` | Application keys are scoped (not full-permission). Keys tied to active users only. No orphaned keys from deprovisioned users. Last-used date is recent. |
| 7 | Audit Log Enabled and Retained | `GET /api/v2/audit/events/search` | Audit Trail is enabled. Events are being recorded. Retention meets policy requirements (e.g., 90+ days). |
| 8 | Security Detection Rules Enabled | `GET /api/v2/security_monitoring/rules` | Cloud SIEM detection rules are enabled. Critical rule categories (authentication, privilege escalation, data exfiltration) have active rules. No default rules have been disabled. |
| 9 | Security Signals Review | `POST /api/v1/security_analytics/signals/search` | Unresolved HIGH/CRITICAL security signals are flagged. Signals older than SLA threshold trigger findings. |
| 10 | Log Pipeline Security | `GET /api/v1/logs/config/pipelines` | Log pipelines do not drop security-relevant logs. Sensitive fields are redacted. Archive destinations are configured. |
| 11 | Sensitive Data Scanner | `GET /api/v2/sensitive-data-scanner/config` | Sensitive Data Scanner is enabled. Scanning groups cover logs, APM, RUM, and events. PII/PCI patterns are active. |
| 12 | Cloud Security Posture Management (CSPM) | `GET /api/v2/security_monitoring/rules` (type: `cloud_configuration`) | CSPM is enabled. Compliance rules are active for applicable frameworks (CIS, PCI-DSS, SOC 2, HIPAA). Passing rate meets threshold. |
| 13 | Compliance Rule Coverage | `GET /api/v2/security_monitoring/rules` | Detection rules cover all required compliance frameworks. No gaps in CIS, PCI-DSS, SOC 2, HIPAA rule sets. |
| 14 | Public Dashboard Restrictions | `GET /api/v1/dashboard`, `GET /api/v1/org` | No dashboards are publicly shared without authentication. Org settings restrict public sharing. Shared dashboards require email-domain allowlisting. |
| 15 | IP Allowlisting | `GET /api/v2/ip_allowlist` | IP allowlist is enabled. Allowlist entries are present and reviewed. No overly broad CIDR ranges (e.g., /0, /8). |
| 16 | Session Timeout | `GET /api/v1/org` | Organization session timeout is configured. Timeout does not exceed policy maximum (e.g., 15 minutes for High, 30 minutes for Moderate). |
| 17 | Monitor Notification Channels | `GET /api/v1/monitor` | Security-critical monitors send to approved channels (PagerDuty, Slack security channel, email DLs). No monitors send to personal email only. |
| 18 | Integration Permissions | `GET /api/v1/integration/{source}` | Third-party integrations use least-privilege API keys. No integrations have full admin access. Webhooks use HTTPS endpoints only. |
| 19 | Service Account Audit | `GET /api/v2/users`, `GET /api/v2/application_keys` | Service accounts are identified (naming convention). Service accounts do not have interactive login. Service account keys are rotated per policy. |
| 20 | Organization Settings (Data Retention & Sharing) | `GET /api/v1/org` | Data retention meets policy minimums. Cross-org data sharing is disabled or restricted. Widget sharing outside org is disabled. |

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC 2.0 | SOC 2 | CIS | PCI-DSS 4.0 | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | SAML SSO Enforcement | AC-2, IA-2, IA-8 | AC.L2-3.1.1 | CC6.1, CC6.2 | CIS 5.1 | 8.3.1, 8.3.2 | SRG-APP-000023 | ISM-1546 | CPS-9.1 |
| 2 | MFA Status | IA-2(1), IA-2(2) | IA.L2-3.5.3 | CC6.1, CC6.6 | CIS 5.2 | 8.4.1, 8.4.2 | SRG-APP-000149 | ISM-1401 | CPS-9.2 |
| 3 | RBAC Configuration | AC-2, AC-3, AC-6 | AC.L2-3.1.5, AC.L2-3.1.6 | CC6.1, CC6.3 | CIS 5.4 | 7.1.1, 7.2.1 | SRG-APP-000033 | ISM-1508 | CPS-7.1 |
| 4 | User Access Review | AC-2(3), PS-4 | AC.L2-3.1.1 | CC6.2, CC6.3 | CIS 5.3 | 7.2.4, 7.2.5 | SRG-APP-000024 | ISM-1503 | CPS-7.2 |
| 5 | API Key Rotation | IA-5(1) | IA.L2-3.5.7, IA.L2-3.5.8 | CC6.1 | CIS 5.5 | 8.3.9, 8.6.3 | SRG-APP-000175 | ISM-1590 | CPS-9.3 |
| 6 | Application Key Audit | IA-5, AC-6(10) | IA.L2-3.5.1 | CC6.1, CC6.3 | CIS 5.6 | 8.6.1, 8.6.2 | SRG-APP-000176 | ISM-1551 | CPS-9.4 |
| 7 | Audit Log Retention | AU-2, AU-3, AU-6, AU-11 | AU.L2-3.3.1, AU.L2-3.3.2 | CC7.2, CC7.3 | CIS 6.1 | 10.1, 10.2, 10.7 | SRG-APP-000092 | ISM-0580 | CPS-11.1 |
| 8 | Security Detection Rules | SI-4, IR-4 | SI.L2-3.14.6, SI.L2-3.14.7 | CC7.2, CC7.3 | CIS 6.2 | 10.4.1, 10.6.1 | SRG-APP-000095 | ISM-0576 | CPS-11.2 |
| 9 | Security Signals Review | IR-4, IR-5, IR-6 | IR.L2-3.6.1, IR.L2-3.6.2 | CC7.3, CC7.4 | CIS 6.3 | 10.6.1, 12.10.5 | SRG-APP-000516 | ISM-0123 | CPS-12.1 |
| 10 | Log Pipeline Security | AU-2, AU-3, SI-4 | AU.L2-3.3.1 | CC7.2 | CIS 6.4 | 10.2.1, 10.3.1 | SRG-APP-000093 | ISM-0585 | CPS-11.3 |
| 11 | Sensitive Data Scanner | SC-28, SI-4, MP-6 | SC.L2-3.13.16 | CC6.1, CC6.7 | CIS 3.1 | 3.4.1, 3.5.1 | SRG-APP-000231 | ISM-1187 | CPS-8.1 |
| 12 | CSPM Enabled | CA-7, CM-6, RA-5 | CA.L2-3.12.3 | CC7.1 | CIS 2.1 | 6.3.1, 11.3.1 | SRG-APP-000456 | ISM-1163 | CPS-6.1 |
| 13 | Compliance Rule Coverage | CA-2, CA-7 | CA.L2-3.12.1 | CC4.1 | CIS 2.2 | 12.1.1 | SRG-APP-000454 | ISM-1526 | CPS-6.2 |
| 14 | Public Dashboard Restrictions | AC-3, AC-22 | AC.L2-3.1.22 | CC6.1, CC6.6 | CIS 4.1 | 7.2.1, 9.4.1 | SRG-APP-000033 | ISM-1532 | CPS-7.3 |
| 15 | IP Allowlisting | AC-3, SC-7 | SC.L2-3.13.1, SC.L2-3.13.6 | CC6.1, CC6.6 | CIS 4.2 | 1.3.1, 1.4.1 | SRG-APP-000142 | ISM-1170 | CPS-10.1 |
| 16 | Session Timeout | AC-11, AC-12 | AC.L2-3.1.10, AC.L2-3.1.11 | CC6.1 | CIS 5.7 | 8.2.8 | SRG-APP-000190 | ISM-1164 | CPS-9.5 |
| 17 | Monitor Notification Channels | IR-6, SI-4 | IR.L2-3.6.2 | CC7.3, CC7.4 | CIS 6.5 | 10.6.1, 12.10.1 | SRG-APP-000516 | ISM-0125 | CPS-12.2 |
| 18 | Integration Permissions | AC-6, SA-9 | AC.L2-3.1.5 | CC6.3, CC9.2 | CIS 4.3 | 12.8.1, 12.8.5 | SRG-APP-000342 | ISM-1567 | CPS-7.4 |
| 19 | Service Account Audit | AC-2(1), IA-4 | AC.L2-3.1.1, IA.L2-3.5.1 | CC6.1, CC6.2 | CIS 5.8 | 8.6.1, 8.6.3 | SRG-APP-000163 | ISM-1548 | CPS-9.6 |
| 20 | Org Settings (Retention & Sharing) | CM-6, SC-8, MP-6 | CM.L2-3.4.2 | CC6.1, CC7.1 | CIS 3.2 | 3.1.1, 9.4.1 | SRG-APP-000231 | ISM-0289 | CPS-8.2 |

## 6. Existing Tools

| Tool | Description | Relevance |
|---|---|---|
| **Datadog CSPM (built-in)** | Cloud Security Posture Management with 1,000+ out-of-the-box compliance rules. Supports CIS, PCI-DSS, SOC 2, HIPAA, GDPR. | Covers cloud resource misconfigurations but does NOT audit Datadog's own tenant settings (RBAC, keys, org config). |
| **Datadog CSM Threats** | Runtime threat detection for workloads. | Complements but does not replace tenant configuration auditing. |
| **DataDog/security-agent-policies** (GitHub) | Open-source Rego-based policies for compliance checks (Docker, Kubernetes CIS benchmarks). | Reference for rule structure. Does not cover Datadog tenant settings. |
| **Datadog Terraform Provider** (`hashicorp/datadog`) | IaC provider for managing Datadog resources. Can enforce configuration via Terraform plans. | Useful for remediation. Does not perform compliance assessment. |
| **Datadog Compliance Reports (UI)** | Built-in UI dashboards showing compliance posture per framework. | Manual-only. Not API-accessible as structured findings. |
| **dogshell (`dog`)** | CLI tool for interacting with Datadog API (metrics, events, monitors). | Limited to operational commands. No compliance auditing. |
| **Pulumi Datadog Provider** | IaC alternative to Terraform for Datadog resources. | Remediation path. Not an auditor. |

**Gap:** No existing open-source tool performs a comprehensive security compliance audit of Datadog tenant configuration (RBAC, keys, audit logs, org settings, SAML, IP allowlisting) against multiple compliance frameworks. `datadog-sec-inspector` fills this gap.

## 7. Architecture

### Source Layout (Go, mirroring okta-inspector)

```
datadog-sec-inspector/
├── cmd/
│   └── datadog-sec-inspector/
│       └── main.go                  # Entrypoint, cobra root command
├── internal/
│   ├── client/
│   │   └── client.go               # Datadog API client wrapper (wraps datadog-api-client-go)
│   ├── collector/
│   │   └── collector.go            # Data collection orchestrator (parallel API calls)
│   ├── models/
│   │   ├── org.go                  # Organization settings model
│   │   ├── user.go                 # User, role, permission models
│   │   ├── key.go                  # API key, application key models
│   │   ├── audit.go                # Audit event models
│   │   ├── security.go             # Security rules, signals models
│   │   ├── log.go                  # Log pipeline, sensitive data scanner models
│   │   ├── dashboard.go            # Dashboard sharing models
│   │   ├── monitor.go              # Monitor notification models
│   │   ├── integration.go          # Integration models
│   │   └── finding.go              # Compliance finding (pass/fail/warn, severity, evidence)
│   ├── engine/
│   │   └── engine.go               # Evaluation engine: runs controls, produces findings
│   ├── analyzers/
│   │   ├── base.go                 # Analyzer interface and common helpers
│   │   ├── fedramp.go              # FedRAMP control mapping and analysis
│   │   ├── cmmc.go                 # CMMC 2.0 control mapping
│   │   ├── soc2.go                 # SOC 2 trust criteria mapping
│   │   ├── cis.go                  # CIS Benchmark mapping
│   │   ├── pci_dss.go              # PCI-DSS 4.0 control mapping
│   │   ├── stig.go                 # DISA STIG mapping
│   │   ├── irap.go                 # IRAP (Australian ISM) mapping
│   │   └── ismap.go                # ISMAP mapping
│   ├── reporters/
│   │   ├── base.go                 # Reporter interface
│   │   ├── executive.go            # Executive summary (pass/fail/warn counts)
│   │   ├── matrix.go               # Cross-framework compliance matrix
│   │   ├── fedramp.go              # FedRAMP-specific report
│   │   ├── cmmc.go                 # CMMC-specific report
│   │   ├── soc2.go                 # SOC 2-specific report
│   │   ├── pci_dss.go              # PCI-DSS-specific report
│   │   ├── stig.go                 # STIG checklist report
│   │   ├── irap.go                 # IRAP report
│   │   ├── ismap.go                # ISMAP report
│   │   └── validation.go           # Finding validation and evidence formatting
│   ├── framework/
│   │   └── custom/                 # Custom framework definitions (YAML)
│   └── tui/
│       ├── app.go                  # Bubble Tea TUI application
│       ├── components/             # Reusable TUI components
│       └── views/                  # TUI views (dashboard, findings, detail)
├── testdata/
│   └── fixtures/                   # API response fixtures for testing
├── go.mod
├── go.sum
├── Makefile
├── COPYING
├── README.md
└── spec.md
```

### Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌──────────┐     ┌───────────┐     ┌───────────┐
│   CLI/TUI   │────▶│  Collector  │────▶│  Engine  │────▶│ Analyzers │────▶│ Reporters │
│  (cobra +   │     │  (parallel  │     │ (control │     │ (framework│     │  (output  │
│  bubbletea) │     │  API calls) │     │  eval)   │     │  mapping) │     │  formats) │
└─────────────┘     └─────────────┘     └──────────┘     └───────────┘     └───────────┘
                          │                                                       │
                    ┌─────┴─────┐                                          ┌──────┴──────┐
                    │  Client   │                                          │   Output    │
                    │ (DD API   │                                          │ JSON, CSV,  │
                    │  wrapper) │                                          │ HTML, OSCAL │
                    └───────────┘                                          └─────────────┘
```

### Key Design Decisions

- **Go** for single-binary distribution, strong typing, and concurrency (parallel API collection).
- **`datadog-api-client-go`** as the official SDK, wrapped in `internal/client/` for testability.
- **Hybrid CLI/TUI** using Cobra for headless CI/CD runs and Bubble Tea for interactive exploration.
- **OSCAL output** for integration into GRC pipelines (compliance-trestle, etc.).

## 8. CLI Interface

```bash
# Set credentials
export DD_API_KEY="your-api-key"
export DD_APP_KEY="your-application-key"
export DD_SITE="ddog-gov.com"  # or datadoghq.com

# Run full audit (all controls, all frameworks)
datadog-sec-inspector audit

# Run specific controls
datadog-sec-inspector audit --controls 1,2,3,5,6

# Run for a specific framework
datadog-sec-inspector audit --framework fedramp
datadog-sec-inspector audit --framework cmmc
datadog-sec-inspector audit --framework pci-dss

# Output formats
datadog-sec-inspector audit --output json
datadog-sec-inspector audit --output csv
datadog-sec-inspector audit --output html
datadog-sec-inspector audit --output oscal

# Save to file
datadog-sec-inspector audit --output json -f results.json

# Interactive TUI mode
datadog-sec-inspector tui

# Validate credentials only
datadog-sec-inspector validate

# List available controls
datadog-sec-inspector controls list

# Show control detail
datadog-sec-inspector controls show 5

# Generate compliance matrix
datadog-sec-inspector matrix --framework fedramp,cmmc,soc2

# Specify Datadog site explicitly
datadog-sec-inspector audit --site us5.datadoghq.com

# Verbose/debug output
datadog-sec-inspector audit -v
datadog-sec-inspector audit --debug
```

## 9. Build Sequence

### Phase 1: Foundation (MVP)

- [ ] Project scaffolding: `go.mod`, Makefile, CI config
- [ ] `internal/client/`: Datadog API client wrapper around `datadog-api-client-go`
- [ ] `internal/models/`: Core data models (org, user, key, finding)
- [ ] `internal/collector/`: Data collection with parallel API calls
- [ ] Credential validation (`/api/v1/validate`)
- [ ] Controls 1-6: SAML SSO, MFA, RBAC, user access review, API key rotation, application key audit
- [ ] `internal/engine/`: Basic evaluation engine
- [ ] JSON output reporter
- [ ] CLI with `audit` and `validate` commands

### Phase 2: Security Monitoring & Logs

- [ ] Controls 7-11: Audit log retention, security detection rules, security signals, log pipeline security, sensitive data scanner
- [ ] `internal/models/`: Audit, security, and log models
- [ ] CSV and HTML reporters
- [ ] Executive summary reporter

### Phase 3: Compliance Posture & Org Settings

- [ ] Controls 12-16: CSPM enabled, compliance rule coverage, public dashboard restrictions, IP allowlisting, session timeout
- [ ] Controls 17-20: Monitor notification channels, integration permissions, service account audit, org settings
- [ ] `internal/analyzers/`: All eight framework analyzers
- [ ] Cross-framework compliance matrix reporter
- [ ] OSCAL output for GRC pipeline integration

### Phase 4: TUI & Polish

- [ ] `internal/tui/`: Bubble Tea interactive interface
- [ ] Dashboard view (pass/fail/warn summary)
- [ ] Findings detail view with evidence
- [ ] Framework drill-down view
- [ ] Custom framework definitions (YAML)
- [ ] Testdata fixtures and comprehensive unit tests
- [ ] `goreleaser` for cross-platform binary distribution

## 10. Status

Not yet implemented. Spec only.
