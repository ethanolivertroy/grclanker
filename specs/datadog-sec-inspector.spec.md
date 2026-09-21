---
slug: "datadog-sec-inspector"
name: "Datadog Security Inspector"
vendor: "Datadog"
category: "monitoring-logging-observability"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
legacy_repo: "https://github.com/hackIDLE/datadog-sec-inspector"
reference_docs: "https://docs.datadoghq.com/api/latest/"
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
| `/api/v2/validate_keys` | GET | Validate API and application key pair | none (`OPEN` permission, both key headers) |
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

### grclanker implementation

The shipped implementation lives in grclanker as native TypeScript (`cli/extensions/grc-tools/datadog.ts`) rather than the Go layout above. It calls the Datadog v1 and v2 REST APIs directly with `fetch` (no SDK), resolves credentials from explicit arguments, then `DD_API_KEY`, `DD_APP_KEY`, `DD_SITE`, `DD_HOST`, then a dogshell-style `~/.dogrc`, and registers these read-only tools:

| Tool | Controls |
|---|---|
| `datadog_check_access` | Validates the API key (`GET /api/v1/validate`) and the key pair (`GET /api/v2/validate_keys`), then probes every read surface including `org_connections`, reporting missing application key permissions |
| `datadog_assess_identity` | 1, 2, 3, 4, 16, 19 |
| `datadog_assess_access_controls` | 5, 6, 14, 15, 18 |
| `datadog_assess_security_monitoring` | 8, 9, 12, 13, 17 |
| `datadog_assess_data_protection` | 7, 10, 11, 20 |
| `datadog_export_audit_bundle` | All 20 controls: `core_data/`, `analysis/`, `compliance/` (executive summary, unified matrix, one report per framework), `QUICK_REFERENCE.md`, `_errors.log`, and a zip archive |

Findings are normalized as `{ id: DD-NN, title, severity, status: pass | warn | fail | manual, summary, evidence, mappings[] }` and carry the framework references from section 5. Tests live in `cli/tests/datadog.test.mjs`, the live smoke script is `npm --prefix cli run test:datadog:live`, and the user guide is `src/content/docs/docs/integrations/datadog.md`.

Every finding follows the same verdict-safety rules: an unreadable, forbidden (401 or 403), or errored endpoint yields `manual` with the cause and the evidence to collect; an empty inventory never passes by default and each control states whether emptiness is `fail` (audit events, detection rules, scanning groups, compliance rules) or `manual` (users, roles, keys, indexes, monitors, cloud footprint); controls the API cannot observe are `manual`; items without a date are bucketed and cap the verdict at `warn`; a partial or truncated inventory flags the partial view and downgrades a would-be `pass` to `warn`; every enabling flag the verdict depends on is read explicitly and an absent flag yields `manual`; and export reruns never overwrite a prior bundle.

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

Implemented in grclanker as native TypeScript on 2026-09-21 (see the grclanker implementation subsection in section 7). The Go, Cobra, Bubble Tea, and OSCAL plans in sections 7 through 9 are retained as the original design record and are not part of the shipped implementation.

### What shipped

- Configuration resolution with the precedence explicit arguments, then environment variables (`DD_API_KEY`, `DD_APP_KEY` or `DD_APPLICATION_KEY`, `DD_SITE`, `DD_HOST`, `DD_CONFIG_FILE`, `DD_TIMEOUT`, `DD_MAX_RETRIES`), then a dogshell-style `~/.dogrc` `[Connection]` section. Every site in section 3 plus `ap2`, `uk1`, and `us2.ddog-gov.com` (aliases `us2-fed` and `us2gov`, alongside `us1-fed` for `ddog-gov.com`) maps to `https://api.<site>`, following the sites guide and the OpenAPI `servers` list.
- A `fetch`-based API client that sends `DD-API-KEY` and `DD-APPLICATION-KEY`, follows each endpoint's documented pagination to completion (`page[size]` and `page[number]`; `page[limit]` and `page[cursor]` with `meta.page.after` or `meta.page.cursor`; `page` and `page_size`; `count` and `start`; `limit` and `offset`), records truncation when a configured limit is reached, retries 429 honoring `X-RateLimit-Reset`, retries 5xx with backoff, enforces timeouts, and redacts both keys from errors.
- `datadog_check_access` (validating the API key with `GET /api/v1/validate` and the key pair with `GET /api/v2/validate_keys`) plus four assessment tools covering all 20 controls, and `datadog_export_audit_bundle` producing raw snapshots, normalized findings, an executive summary, a unified compliance matrix, eight framework reports, a quick reference, an error log on partial collection, and a zip archive named after the allocated bundle directory so reruns never overwrite a prior bundle.
- Verdict-safety rules applied to all 20 findings (see the grclanker implementation subsection in section 7), with regression tests for each rule and false-pass fixtures (every endpoint 403, every list empty, partial inventory) run through the built module.
- Mocked test coverage in `cli/tests/datadog.test.mjs` and a live smoke script that skips without credentials.

### Deviations from this spec (official docs win)

- Security signals: `POST /api/v1/security_analytics/signals/search` (control 9, section 2) is not in the official API reference. The implementation uses `GET /api/v2/security_monitoring/signals` with `filter[query]`, `filter[from]`, `filter[to]`, `sort`, `page[limit]`, and `page[cursor]`.
- Key validation: `/api/v2/validate_keys` exists as `GET` (not `POST` as originally listed in section 2) with the `OPEN` permission and validates the API key and application key pair. `datadog_check_access` calls it alongside `GET /api/v1/validate`.
- MFA (control 2): the API exposes only Datadog-native `mfa_enabled`. SAML strict mode disables password login but says nothing about IdP-enforced MFA, so a strict-mode org whose users lack native MFA is a `manual` finding naming the IdP authentication policy to capture, never `pass`.
- Cloud integrations (controls 12 and 18): `GET /api/v1/integration/aws` and `GET /api/v1/integration/gcp` are marked `deprecated: true` in the OpenAPI definitions (the replacements are `GET /api/v2/integration/aws/accounts` and `GET /api/v2/integration/gcp/accounts`); `GET /api/v1/integration/azure` is not deprecated. The implementation still reads the v1 endpoints because they remain documented and return the CSPM resource collection flags the controls depend on.
- Application keys: `GET /api/v2/application_keys` requires `org_app_keys_read`, not `user_access_read` as listed in section 2. Owners are resolved through `include=owned_by`.
- Audit Trail: the implementation reads `GET /api/v2/audit/events` (cursor paginated) instead of `POST /api/v2/audit/events/search`. Retention is inferred from the oldest event available inside the required window because the retention setting is not exposed by the API.
- CSPM (control 12): enablement is derived from enabled `cloud_configuration` rules plus the `cspm_resource_collection_enabled`, `is_cspm_enabled`, and `cspm_enabled` flags on AWS, GCP, and Azure integrations, and the passing rate comes from `GET /api/v2/posture_management/findings` with `filter[evaluation]=pass|fail`, using `meta.page.total_filtered_count` when present and otherwise paging by `page[cursor]` up to `finding_limit` (a hit limit marks the count truncated and the verdict `warn`). That endpoint is marked legacy in the OpenAPI definition but remains the documented list endpoint. The finding is `manual` when the rules, the integrations, or either findings query is unreadable.
- Compliance coverage (control 13): derived from `framework:`, `compliance_framework:`, and `requirement_framework:` tags on enabled `cloud_configuration` and `infrastructure_configuration` rules.
- Session timeout (control 16): `GET /api/v1/org` does not return a session duration, so this control is always a `manual` finding that names the console setting to capture.
- Integration permissions (control 18): the Datadog API exposes the AWS, GCP, and Azure integration inventory (including AWS accounts using static access keys instead of role delegation) but not cloud-side IAM policies or webhook URLs (webhooks are only retrievable by exact name). This control is always a `manual` finding with the inventory attached as evidence.
- Dashboards (control 14): `GET /api/v1/dashboard?filter[shared]=true` reports shared dashboards but not the share type, so shared dashboards produce `warn`; `private_widget_share` on the organization produces `fail`.
- Organization settings (control 20): data retention is read from log index `num_retention_days` (`GET /api/v1/logs/config/indexes`) and cross-org sharing from `GET /api/v2/org_connections` (`limit` and `offset` pagination, documented default limit 1000, paged to completion), because `GET /api/v1/org` exposes neither. An unreadable `org_connections` surface makes the finding `manual` rather than counting as zero connections.
- `GET /api/v1/logs/config/pipeline-order`, `GET /api/v2/audit/events/search`, `GET /api/v2/restriction_policy/{id}`, and the write endpoints listed in section 2 are not used; the tools are read-only.

### What remains

- Session timeout (16) and integration permissions (18) stay manual until Datadog exposes those settings through the public API.
- The share type (public versus invite-only) of each shared dashboard is not exposed by the dashboard list endpoint and is not collected; shared dashboards surface as `warn` for human review.
- OSCAL output, CSV and HTML reporters, and the interactive TUI from the original build sequence are not implemented; the bundle ships JSON findings and Markdown reports instead.
- Migrating the AWS and GCP integration inventory from the deprecated v1 endpoints to `GET /api/v2/integration/aws/accounts` and `GET /api/v2/integration/gcp/accounts` (with their `aws_configuration_read` and `gcp_configuration_read` permissions) is pending.
- Live validation against a Datadog for Government (`ddog-gov.com`, `us2.ddog-gov.com`) organization has not been performed; the site mapping and endpoints follow the official documentation.
