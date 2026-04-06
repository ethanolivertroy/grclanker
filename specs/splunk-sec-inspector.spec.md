---
slug: "splunk-sec-inspector"
name: "Splunk Security Inspector"
vendor: "Splunk"
category: "monitoring-logging-observability"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/splunk-sec-inspector"
---

# splunk-sec-inspector — Architecture Specification

## 1. Overview

**Splunk Cloud** is a cloud-hosted security information and event management (SIEM) and observability platform used by enterprises to collect, index, search, and analyze machine-generated data at scale. Organizations rely on Splunk Cloud for log aggregation, security monitoring, incident response, and compliance reporting.

Misconfigurations in Splunk Cloud — weak authentication, overly permissive roles, unencrypted data transport, disabled audit logging, or insecure HTTP Event Collector (HEC) tokens — can expose sensitive log data, enable unauthorized searches across security-relevant indexes, and undermine the integrity of an organization's security monitoring pipeline. Because Splunk often ingests the most sensitive data in an environment (authentication logs, network flows, endpoint telemetry), a compromised or misconfigured Splunk instance represents an outsized risk.

**splunk-sec-inspector** is an automated compliance inspection tool that connects to a Splunk Cloud instance via its REST API and Admin Config Service (ACS) API, collects security-relevant configuration data, evaluates it against hardened baselines derived from multiple compliance frameworks, and produces actionable reports with framework-specific control mappings.

## 2. APIs & SDKs

### 2.1 Splunk REST API (splunkd)

The core Splunk REST API is served by the `splunkd` daemon and provides access to all configuration, search, and administrative functions. Base URL: `https://<instance>.splunkcloud.com:8089`.

#### Authentication & Authorization Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/services/auth/login` | POST | Obtain session key via username/password |
| `/services/authentication/users` | GET | List all local and LDAP/SAML-mapped users |
| `/services/authentication/users/{name}` | GET | Get individual user details (roles, type, email) |
| `/services/authentication/providers/SAML` | GET | SAML identity provider configuration |
| `/services/authentication/providers/LDAP` | GET | LDAP provider configuration |
| `/services/authorization/roles` | GET | List all roles and their capabilities |
| `/services/authorization/roles/{name}` | GET | Get role details (imported roles, capabilities, search filters) |
| `/services/admin/SAML-groups` | GET | SAML group-to-role mappings |
| `/services/authentication/tokens` | GET | List authentication tokens |
| `/services/authentication/tokens/{id}` | GET/DELETE | Manage individual tokens |

#### Server & System Configuration Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/services/server/settings` | GET | Server-wide settings (server name, SSL, session timeout) |
| `/services/server/settings/settings` | GET | Detailed server configuration |
| `/services/server/info` | GET | Server version, OS, license, GUID |
| `/services/server/status` | GET | Server health and resource status |
| `/services/properties/server` | GET | server.conf properties |
| `/services/properties/web` | GET | web.conf properties (SSL, session timeouts) |
| `/services/properties/authentication` | GET | authentication.conf properties |
| `/services/properties/authorize` | GET | authorize.conf properties |
| `/services/properties/passwords` | GET | Password policy settings |
| `/services/admin/conf-authentication` | GET | Authentication configuration stanzas |
| `/services/admin/conf-authorize` | GET | Authorization configuration stanzas |

#### Data & Input Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/services/data/inputs/tcp/cooked` | GET | Cooked TCP data inputs (forwarder connections) |
| `/services/data/inputs/tcp/raw` | GET | Raw TCP data inputs |
| `/services/data/inputs/tcp/ssl` | GET | SSL-enabled TCP inputs |
| `/services/data/inputs/udp` | GET | UDP data inputs |
| `/services/data/inputs/http` | GET | HTTP Event Collector (HEC) token configurations |
| `/services/data/inputs/http/{name}` | GET | Individual HEC token details |
| `/services/data/inputs/monitor` | GET | File/directory monitoring inputs |
| `/services/data/inputs/script` | GET | Scripted inputs |
| `/services/data/indexes` | GET | List all indexes and their configurations |
| `/services/data/indexes/{name}` | GET | Individual index settings (retention, encryption, ACL) |

#### Knowledge & Search Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/services/saved/searches` | GET | All saved searches, alerts, and reports |
| `/services/saved/searches/{name}` | GET | Individual saved search (owner, sharing, schedule) |
| `/services/saved/searches/{name}/acl` | GET | ACL permissions on a saved search |
| `/services/data/lookup-table-files` | GET | Lookup table files |
| `/services/data/transforms/lookups` | GET | Lookup definitions |
| `/services/configs/conf-macros` | GET | Search macros |
| `/services/storage/collections/config` | GET | KV Store collections configuration |

#### Audit & Monitoring Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/services/admin/audit` | GET | Audit trail configuration |
| `/services/search/jobs` | POST | Execute audit searches (e.g., `index=_audit`) |
| `/services/messages` | GET | System messages and alerts |
| `/services/licenser/usage` | GET | License usage details |

#### Application Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/services/apps/local` | GET | Installed apps and their permissions |
| `/services/apps/local/{name}` | GET | Individual app details |
| `/services/admin/app-install` | GET | App installation settings |

### 2.2 Splunk Cloud Admin Config Service (ACS) API

The ACS API provides cloud-specific administrative functions not available via the standard REST API. Base URL: `https://admin.splunk.com/{stack}/adminconfig/v2`.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/access/{feature}/ipallowlists` | GET | IPv4 IP allow list per feature (search-api, hec, s2s, etc.) |
| `/access/{feature}/ipallowlists-v6` | GET | IPv6 IP allow list per feature |
| `/tokens` | GET | List all authentication tokens |
| `/tokens/{id}` | GET/DELETE | Manage individual tokens |
| `/inputs/http-event-collectors` | GET | List HEC token configurations |
| `/inputs/http-event-collectors/{name}` | GET | Individual HEC token |
| `/indexes` | GET | List all indexes |
| `/indexes/{name}` | GET | Individual index configuration |
| `/maintenance-windows` | GET | Scheduled maintenance windows |
| `/apps/victoria` | GET | Installed apps (Victoria Experience) |
| `/apps/victoria/{name}` | GET | Individual app details |
| `/limits` | GET | limits.conf configuration overrides |
| `/restarts` | POST | Restart management |
| `/outbound-ports` | GET | Outbound port allow lists |
| `/encryption-keys` | GET | Enterprise Managed Encryption Keys (EMEK) status |

### 2.3 SDKs and CLIs

| Tool | Language | Package | Notes |
|------|----------|---------|-------|
| **splunk-sdk-python** | Python | `pip install splunk-sdk` | Official Splunk Enterprise SDK; provides `splunklib` with `Service`, `Job`, and `Entity` abstractions |
| **splunk-sdk-go** | Go | `github.com/splunk/splunk-cloud-sdk-go` | Official Splunk Cloud SDK for Go; covers ACS and search APIs |
| **splunk-sdk-javascript** | JS/TS | `npm install splunk-sdk` | Official JavaScript SDK |
| **Splunk CLI** | Python | Built-in (`splunk` binary) | Shipped with Splunk Enterprise; not available for Cloud |
| **ACS CLI** | Python | Splunk-provided | Cloud-specific CLI wrapping the ACS API |
| **splunk-sdk-csharp** | C# | `Splunk.Client` NuGet | Official .NET SDK |

### 2.4 Internal Audit Indexes

| Index | Purpose |
|-------|---------|
| `_audit` | Authentication events, search activity, configuration changes |
| `_internal` | Splunk internal metrics, logs, and diagnostics |
| `_introspection` | Resource usage and performance data |
| `_telemetry` | Anonymized usage data |

## 3. Authentication

### 3.1 Splunk Auth Token (Bearer Token)

```bash
export SPLUNK_URL="https://your-instance.splunkcloud.com:8089"
export SPLUNK_TOKEN="your-jwt-or-session-token"
```

Create a token via Splunk Web: **Settings > Tokens > New Token**. Tokens can be scoped to specific users and have configurable expiration. The token is passed as a `Bearer` token in the `Authorization` header.

### 3.2 Username/Password Authentication

```bash
export SPLUNK_URL="https://your-instance.splunkcloud.com:8089"
export SPLUNK_USERNAME="admin"
export SPLUNK_PASSWORD="your-password"
```

Authenticate via `POST /services/auth/login` to obtain a session key. The session key is then passed as the `Authorization` header for subsequent requests. Session keys expire based on the `sessionTimeout` setting in `web.conf`.

### 3.3 ACS API Authentication

```bash
export SPLUNK_STACK="your-stack-name"
export SPLUNK_ACS_TOKEN="your-acs-jwt-token"
```

The ACS API requires a JSON Web Token (JWT) generated from the Splunk Cloud Platform UI or via the ACS token endpoint. The `sc_admin` role is required. Tokens are passed as `Bearer` tokens against `https://admin.splunk.com/{stack}/adminconfig/v2/`.

### 3.4 SAML SSO

When SAML is configured, API access typically still uses tokens or service accounts. The inspector checks whether SAML is the enforced authentication method and evaluates the SAML IdP configuration.

### 3.5 Environment Variables (splunk-sec-inspector)

| Variable | Required | Description |
|----------|----------|-------------|
| `SPLUNK_URL` | Yes | Base URL of Splunk instance (e.g., `https://org.splunkcloud.com:8089`) |
| `SPLUNK_TOKEN` | Yes* | Splunk authentication token (Bearer) |
| `SPLUNK_USERNAME` | Alt* | Username for session-key auth |
| `SPLUNK_PASSWORD` | Alt* | Password for session-key auth |
| `SPLUNK_STACK` | Optional | Stack name for ACS API access |
| `SPLUNK_ACS_TOKEN` | Optional | JWT for ACS API (defaults to `SPLUNK_TOKEN`) |
| `SPLUNK_VERIFY_SSL` | Optional | Set `false` to skip TLS verification (not recommended) |

*Either `SPLUNK_TOKEN` or both `SPLUNK_USERNAME`/`SPLUNK_PASSWORD` are required.

## 4. Security Controls

### Authentication & Identity

| # | Control | Severity | What Is Checked |
|---|---------|----------|-----------------|
| 1 | **Authentication Method Enforcement** | Critical | Verify SAML or LDAP is configured as the primary authentication method; local authentication should be disabled or restricted to break-glass accounts only |
| 2 | **Password Policy Compliance** | High | Check `minPasswordLength`, `minPasswordUppercase`, `minPasswordLowercase`, `minPasswordDigit`, `minPasswordSpecial`, `expirePasswordDays`, `forceWeakPasswordChange` in authentication.conf |
| 3 | **Multi-Factor Authentication** | Critical | Verify MFA/Duo/RSA integration is enabled via `/services/admin/Rsa-MFA` or SAML IdP MFA enforcement |
| 4 | **Session Timeout Configuration** | Medium | Validate `sessionTimeout` in web.conf is set to organizational policy (e.g., 60 minutes or less); check `tools.sessions.timeout` |
| 5 | **Concurrent Session Limits** | Medium | Check whether concurrent session controls are enforced; verify max sessions per user |
| 6 | **Authentication Token Hygiene** | High | Enumerate all tokens; flag tokens with no expiration, tokens older than 90 days, tokens assigned to disabled users, and ephemeral vs. persistent token ratios |

### Authorization & Access Control

| # | Control | Severity | What Is Checked |
|---|---------|----------|-----------------|
| 7 | **Role-Based Access Control (RBAC)** | Critical | Audit all roles; flag roles with `admin_all_objects`, `delete_by_keyword`, `edit_tcp`, `edit_user`, or other high-risk capabilities; check for least-privilege adherence |
| 8 | **Admin Role Minimization** | High | Count users with `admin` or `sc_admin` roles; flag if more than 3 users have full admin access |
| 9 | **Search Head Access Controls** | High | Validate `srchFilter`, `srchIndexesAllowed`, `srchIndexesDefault` on each role to ensure users cannot search beyond their authorized indexes |
| 10 | **Index Access Control** | High | Verify each role's `srchIndexesAllowed` and `importRoles` restrict access to only necessary indexes; flag roles with access to `_audit` or `_internal` |
| 11 | **Knowledge Object Permissions** | Medium | Audit saved searches, dashboards, reports, and lookups for `sharing=global` with `write` permissions; flag objects shared with all roles that modify system state |
| 12 | **User Capabilities Audit** | High | Enumerate all capabilities granted to each role; flag overly permissive capability assignments especially `run_commands_on_forwarder`, `edit_server`, `change_authentication` |

### Data Protection & Encryption

| # | Control | Severity | What Is Checked |
|---|---------|----------|-----------------|
| 13 | **TLS/SSL Configuration** | Critical | Verify `enableSplunkdSSL=true` in server.conf; check `sslVersions`, `cipherSuite`, `requireClientCert` for all listeners; flag TLS < 1.2 |
| 14 | **Data Encryption at Rest** | High | Check index encryption settings; verify EMEK (Enterprise Managed Encryption Keys) status via ACS API if applicable |
| 15 | **Forwarding Encryption** | High | Validate that all forwarder-to-indexer communication uses TLS; check `data/inputs/tcp/ssl` settings and `outputs.conf` for `sslPassword`, `sslCertPath` |
| 16 | **HEC Token Security** | High | Audit all HEC tokens: flag tokens with `useACK=false`, tokens bound to permissive indexes, tokens without `sourcetype` restrictions, disabled SSL on HEC port |

### Audit & Monitoring

| # | Control | Severity | What Is Checked |
|---|---------|----------|-----------------|
| 17 | **Audit Logging Enabled** | Critical | Verify `_audit` index is active; check that `auditTrail` is enabled in audit.conf; validate audit events include authentication, search, and configuration changes |
| 18 | **Audit Log Integrity** | High | Check that `_audit` index has restricted write access; verify no roles can delete audit events (`delete_by_keyword` capability on `_audit`) |

### Network & Platform Security

| # | Control | Severity | What Is Checked |
|---|---------|----------|-----------------|
| 19 | **IP Allow Listing** | High | Via ACS API, verify IP allow lists are configured for `search-api`, `hec`, `s2s`, and `search-ui` features; flag if any feature has no IP restrictions |
| 20 | **App Installation Restrictions** | Medium | Audit installed apps; flag third-party apps not from Splunkbase; check if app installation is restricted to admins only |
| 21 | **KV Store Access Controls** | Medium | Verify KV Store collections have appropriate ACLs; flag collections with global read/write access |
| 22 | **Saved Search Permissions** | Medium | Audit saved searches that run as `owner` with elevated privileges; flag scheduled searches that run across all indexes or with `dispatch.earliest_time=-0s` |
| 23 | **Splunk-to-Splunk (S2S) Port Security** | High | Verify S2S receiving ports require TLS and certificate-based authentication; flag unencrypted S2S listeners |

## 5. Compliance Framework Mappings

| # | Control | FedRAMP (800-53 r5) | CMMC 2.0 | SOC 2 (TSC) | CIS Splunk Benchmark | PCI-DSS 4.0 | DISA STIG | IRAP (ISM) | ISMAP |
|---|---------|---------------------|----------|-------------|---------------------|-------------|-----------|------------|-------|
| 1 | Authentication Method Enforcement | IA-2, IA-8 | AC.L2-3.1.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 5.1.1 |
| 2 | Password Policy Compliance | IA-5(1) | IA.L2-3.5.7 | CC6.1 | 4.2 | 8.3.6 | SRG-APP-000166 | ISM-0421 | 5.1.2 |
| 3 | Multi-Factor Authentication | IA-2(1), IA-2(2) | IA.L2-3.5.3 | CC6.1 | 4.3 | 8.4.2 | SRG-APP-000149 | ISM-1401 | 5.1.3 |
| 4 | Session Timeout Configuration | AC-12 | AC.L2-3.1.10 | CC6.1 | 4.5 | 8.2.8 | SRG-APP-000295 | ISM-1164 | 5.1.4 |
| 5 | Concurrent Session Limits | AC-10 | AC.L2-3.1.11 | CC6.1 | 4.6 | 8.2.7 | SRG-APP-000190 | ISM-1380 | 5.1.5 |
| 6 | Authentication Token Hygiene | IA-5(13), SC-12 | IA.L2-3.5.10 | CC6.1, CC6.6 | 4.7 | 8.6.3 | SRG-APP-000175 | ISM-1590 | 5.1.6 |
| 7 | Role-Based Access Control | AC-3, AC-6 | AC.L2-3.1.5 | CC6.3 | 5.1 | 7.2.1 | SRG-APP-000033 | ISM-1508 | 5.2.1 |
| 8 | Admin Role Minimization | AC-6(5) | AC.L2-3.1.6 | CC6.3 | 5.2 | 7.2.2 | SRG-APP-000340 | ISM-1509 | 5.2.2 |
| 9 | Search Head Access Controls | AC-3(7) | AC.L2-3.1.3 | CC6.1, CC6.3 | 5.3 | 7.2.3 | SRG-APP-000328 | ISM-0405 | 5.2.3 |
| 10 | Index Access Control | AC-3, AC-6(1) | AC.L2-3.1.4 | CC6.3 | 5.4 | 7.2.4 | SRG-APP-000340 | ISM-1510 | 5.2.4 |
| 11 | Knowledge Object Permissions | AC-3, AC-6 | AC.L2-3.1.5 | CC6.3, CC6.8 | 5.5 | 7.2.5 | SRG-APP-000033 | ISM-0405 | 5.2.5 |
| 12 | User Capabilities Audit | AC-6(10) | AC.L2-3.1.7 | CC6.3 | 5.6 | 7.2.6 | SRG-APP-000342 | ISM-1511 | 5.2.6 |
| 13 | TLS/SSL Configuration | SC-8, SC-8(1) | SC.L2-3.13.8 | CC6.1, CC6.7 | 6.1 | 4.2.1 | SRG-APP-000439 | ISM-1139 | 5.3.1 |
| 14 | Data Encryption at Rest | SC-28, SC-28(1) | SC.L2-3.13.16 | CC6.1, CC6.7 | 6.2 | 3.5.1 | SRG-APP-000429 | ISM-1080 | 5.3.2 |
| 15 | Forwarding Encryption | SC-8, SC-8(1) | SC.L2-3.13.8 | CC6.7 | 6.3 | 4.2.1 | SRG-APP-000442 | ISM-1139 | 5.3.3 |
| 16 | HEC Token Security | IA-5, SC-8 | SC.L2-3.13.8 | CC6.6 | 6.4 | 8.6.2 | SRG-APP-000175 | ISM-1590 | 5.3.4 |
| 17 | Audit Logging Enabled | AU-2, AU-3, AU-12 | AU.L2-3.3.1 | CC7.2, CC7.3 | 7.1 | 10.2.1 | SRG-APP-000095 | ISM-0580 | 5.4.1 |
| 18 | Audit Log Integrity | AU-9, AU-9(4) | AU.L2-3.3.8 | CC7.2 | 7.2 | 10.3.2 | SRG-APP-000119 | ISM-0859 | 5.4.2 |
| 19 | IP Allow Listing | SC-7, AC-17 | SC.L2-3.13.1 | CC6.1, CC6.6 | 8.1 | 1.3.1 | SRG-APP-000142 | ISM-1416 | 5.5.1 |
| 20 | App Installation Restrictions | CM-7(5), CM-11 | CM.L2-3.4.8 | CC6.8, CC8.1 | 8.2 | 6.3.2 | SRG-APP-000386 | ISM-1490 | 5.5.2 |
| 21 | KV Store Access Controls | AC-3 | AC.L2-3.1.3 | CC6.3 | 8.3 | 7.2.1 | SRG-APP-000033 | ISM-0405 | 5.5.3 |
| 22 | Saved Search Permissions | AC-3, AC-6 | AC.L2-3.1.5 | CC6.3, CC6.8 | 5.7 | 7.2.5 | SRG-APP-000033 | ISM-0405 | 5.2.7 |
| 23 | S2S Port Security | SC-8(1), SC-23 | SC.L2-3.13.8 | CC6.7 | 6.5 | 4.2.1 | SRG-APP-000439 | ISM-1139 | 5.3.5 |

## 6. Existing Tools

| Tool | Type | Relevance |
|------|------|-----------|
| **Splunk Security Essentials (SSE)** | Splunk App | Splunk-developed app providing security use case library, data source onboarding guides, and mapping to MITRE ATT&CK, NIST, CIS, and Kill Chain frameworks |
| **CIS Splunk Enterprise Benchmark** | PDF/Benchmark | Center for Internet Security benchmark for hardening Splunk Enterprise deployments; covers authentication, authorization, encryption, and logging controls |
| **Splunk App for PCI Compliance** | Splunk App | Provides PCI DSS reporting dashboards and compliance monitoring within Splunk |
| **SA-CIM_Validator** | Splunk App | Validates data model compliance against the Common Information Model |
| **Splunk SOAR (Phantom)** | Platform | Security orchestration platform with playbooks for automated response; complementary but not a configuration auditor |
| **splunk-ansible** | Ansible Roles | `splunk/splunk-ansible` GitHub project for automated Splunk deployment with hardened configurations |
| **Prowler** | CLI Tool | Multi-cloud security assessment tool; includes some Splunk-related checks when Splunk is the SIEM target |
| **splunk-cloud-auth** | Python Library | `splunk/splunk-cloud-auth` for programmatic authentication to Splunk Cloud services |

## 7. Architecture

The project is written in Go and mirrors the modular architecture of [okta-inspector](https://github.com/ethanolivertroy/okta-inspector).

```
splunk-sec-inspector/
├── cmd/
│   └── splunk-sec-inspector/
│       └── main.go                  # Entrypoint, CLI parsing, orchestration
├── internal/
│   ├── client/
│   │   ├── client.go                # HTTP client for Splunk REST API
│   │   ├── acs.go                   # ACS API client
│   │   ├── auth.go                  # Token & session-key authentication
│   │   └── ratelimit.go             # Rate limiting and retry logic
│   ├── collector/
│   │   ├── collector.go             # Top-level data collector orchestrator
│   │   ├── users.go                 # Collect users, roles, capabilities
│   │   ├── auth.go                  # Collect authentication config (SAML, LDAP, passwords)
│   │   ├── server.go                # Collect server settings, SSL, session config
│   │   ├── inputs.go                # Collect data inputs (HEC, TCP, UDP, S2S)
│   │   ├── indexes.go               # Collect index configurations
│   │   ├── searches.go              # Collect saved searches, alerts, reports
│   │   ├── apps.go                  # Collect installed applications
│   │   ├── kvstore.go               # Collect KV Store configurations
│   │   ├── network.go               # Collect IP allow lists (ACS)
│   │   └── audit.go                 # Collect audit configuration
│   ├── models/
│   │   ├── splunkdata.go            # SplunkData: container for all collected API data
│   │   ├── finding.go               # ComplianceFinding: individual check result
│   │   └── result.go                # AuditResult: aggregated audit output
│   ├── analyzers/
│   │   ├── base.go                  # Analyzer interface and registry
│   │   ├── common.go                # Shared analysis helpers
│   │   ├── fedramp.go               # FedRAMP (NIST 800-53 r5) analyzer
│   │   ├── cmmc.go                  # CMMC 2.0 analyzer
│   │   ├── soc2.go                  # SOC 2 (TSC) analyzer
│   │   ├── cis.go                   # CIS Splunk Benchmark analyzer
│   │   ├── pci_dss.go               # PCI-DSS 4.0 analyzer
│   │   ├── stig.go                  # DISA STIG analyzer
│   │   ├── irap.go                  # IRAP (ISM) analyzer
│   │   └── ismap.go                 # ISMAP analyzer
│   ├── reporters/
│   │   ├── base.go                  # Reporter interface and registry
│   │   ├── executive.go             # Executive summary (pass/fail counts, risk score)
│   │   ├── matrix.go                # Cross-framework compliance matrix
│   │   ├── fedramp.go               # FedRAMP-formatted report
│   │   ├── cmmc.go                  # CMMC-formatted report
│   │   ├── soc2.go                  # SOC 2 formatted report
│   │   ├── cis.go                   # CIS benchmark report
│   │   ├── pci_dss.go               # PCI-DSS 4.0 report
│   │   ├── stig.go                  # DISA STIG checklist (CKL/XCCDF)
│   │   ├── irap.go                  # IRAP assessment report
│   │   ├── ismap.go                 # ISMAP assessment report
│   │   └── validation.go            # Finding validation and deduplication
│   ├── engine/
│   │   └── engine.go                # AuditEngine: collect → analyze → report → archive
│   └── tui/
│       ├── app.go                   # Bubble Tea TUI application
│       ├── components/
│       │   ├── spinner.go           # Progress spinner
│       │   ├── table.go             # Results table
│       │   └── summary.go           # Summary dashboard
│       └── views/
│           ├── audit.go             # Audit progress view
│           └── results.go           # Results browser view
├── testdata/
│   ├── fixtures/                    # Mock API response JSON files
│   └── golden/                      # Golden file test outputs
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── .goreleaser.yml
├── .github/
│   └── workflows/
│       ├── ci.yml                   # Lint, test, build
│       └── release.yml              # GoReleaser publish
├── COPYING                          # GPL v3
├── README.md
└── spec.md                          # This file
```

### Data Flow

```
┌─────────────┐     ┌──────────────┐     ┌────────────┐     ┌────────────┐
│   Client     │────>│  Collector   │────>│  Analyzers │────>│  Reporters │
│ (REST + ACS) │     │ (SplunkData) │     │ (Findings) │     │ (Reports)  │
└─────────────┘     └──────────────┘     └────────────┘     └────────────┘
       │                                        │
       │              ┌────────────┐            │
       └─────────────>│   Engine   │<───────────┘
                      │ (Orchestr.)│
                      └────────────┘
```

## 8. CLI Interface

```bash
# Basic audit with token authentication
splunk-sec-inspector audit \
  --url https://your-org.splunkcloud.com:8089 \
  --token $SPLUNK_TOKEN

# Audit with username/password
splunk-sec-inspector audit \
  --url https://your-org.splunkcloud.com:8089 \
  --username admin \
  --password $SPLUNK_PASSWORD

# Include ACS API checks (requires stack name and ACS token)
splunk-sec-inspector audit \
  --url https://your-org.splunkcloud.com:8089 \
  --token $SPLUNK_TOKEN \
  --stack your-stack-name \
  --acs-token $SPLUNK_ACS_TOKEN

# Run only specific frameworks
splunk-sec-inspector audit \
  --url https://your-org.splunkcloud.com:8089 \
  --token $SPLUNK_TOKEN \
  --frameworks fedramp,stig,pci-dss

# Output to custom directory
splunk-sec-inspector audit \
  --url https://your-org.splunkcloud.com:8089 \
  --token $SPLUNK_TOKEN \
  --output-dir ./splunk-audit-results

# JSON-only output (no TUI)
splunk-sec-inspector audit \
  --url https://your-org.splunkcloud.com:8089 \
  --token $SPLUNK_TOKEN \
  --format json \
  --quiet

# List available frameworks
splunk-sec-inspector frameworks

# Validate connectivity
splunk-sec-inspector validate \
  --url https://your-org.splunkcloud.com:8089 \
  --token $SPLUNK_TOKEN

# Environment variable usage (all flags have env var equivalents)
export SPLUNK_URL="https://your-org.splunkcloud.com:8089"
export SPLUNK_TOKEN="your-token"
export SPLUNK_STACK="your-stack"
export SPLUNK_ACS_TOKEN="your-acs-token"
splunk-sec-inspector audit
```

## 9. Build Sequence

### Phase 1 — Foundation (Weeks 1-2)
- [ ] Initialize Go module, project scaffolding, CI/CD pipeline
- [ ] Implement `internal/client/` — REST API client with token and session-key auth
- [ ] Implement `internal/models/` — `SplunkData`, `ComplianceFinding`, `AuditResult`
- [ ] Implement `internal/collector/` — users, roles, server settings, authentication config
- [ ] Write unit tests with mock API responses in `testdata/fixtures/`

### Phase 2 — Core Analyzers (Weeks 3-4)
- [ ] Implement `internal/analyzers/base.go` — analyzer interface and registry
- [ ] Implement controls 1-12 (authentication, authorization, access control)
- [ ] Implement `internal/analyzers/common.go` — shared helpers
- [ ] Build first analyzer: `fedramp.go`
- [ ] Build `stig.go` and `cmmc.go` analyzers

### Phase 3 — Data Protection & Network (Weeks 5-6)
- [ ] Implement `internal/client/acs.go` — ACS API client
- [ ] Implement collectors for inputs, indexes, HEC, IP allow lists
- [ ] Implement controls 13-23 (encryption, audit, network, apps)
- [ ] Build remaining analyzers: `soc2.go`, `cis.go`, `pci_dss.go`, `irap.go`, `ismap.go`

### Phase 4 — Reporting & CLI (Weeks 7-8)
- [ ] Implement `internal/reporters/` — all report formatters
- [ ] Implement `internal/engine/engine.go` — orchestration pipeline
- [ ] Implement `cmd/splunk-sec-inspector/main.go` — CLI with cobra or stdlib flags
- [ ] STIG CKL/XCCDF export support
- [ ] JSON, CSV, and Markdown output formats

### Phase 5 — TUI & Polish (Weeks 9-10)
- [ ] Implement `internal/tui/` — Bubble Tea interactive interface
- [ ] Dockerfile and GoReleaser configuration
- [ ] Integration tests against a Splunk Cloud trial instance
- [ ] Documentation, README, and usage examples
- [ ] Golden file tests for report output stability

## 10. Status

**Not yet implemented. Spec only.**
