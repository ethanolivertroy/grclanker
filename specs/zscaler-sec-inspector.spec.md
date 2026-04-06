---
slug: "zscaler-sec-inspector"
name: "Zscaler Security Inspector"
vendor: "Zscaler"
category: "security-network-infrastructure"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/zscaler-sec-inspector"
---

# zscaler-sec-inspector -- Architecture Specification

## 1. Overview

Zscaler is a cloud-native security platform that delivers Zero Trust network access through two core products:

1. **Zscaler Internet Access (ZIA)** -- Secure Web Gateway providing URL filtering, firewall-as-a-service, DLP, SSL inspection, sandboxing, DNS security, CASB, and bandwidth control for all internet-bound traffic.
2. **Zscaler Private Access (ZPA)** -- Zero Trust Network Access (ZTNA) replacing traditional VPNs with identity- and context-based access to private applications through application segmentation, access policies, and posture-based controls.

Additionally, **Zscaler Digital Experience (ZDX)** provides end-user experience monitoring that can surface compliance-relevant availability and performance data.

Organizations deploying Zscaler in regulated environments must verify that URL filtering policies block prohibited categories, DLP engines inspect sensitive data, SSL inspection covers required traffic, admin accounts enforce MFA and RBAC, application segmentation follows least privilege, and all policy changes are logged and auditable.

**zscaler-sec-inspector** is a security compliance inspector that programmatically audits Zscaler ZIA and ZPA configurations against 25 security controls mapped to FedRAMP, CMMC 2.0, SOC 2, CIS Benchmarks, PCI-DSS 4.0, DISA STIG, IRAP, and ISMAP frameworks.

## 2. APIs & SDKs

### 2.1 Zscaler Internet Access (ZIA) API

**Base URL:** `https://<cloud>.api.zscaler.net/api/v1` (cloud name determined by tenant: `zscaler`, `zscalerone`, `zscalertwo`, `zscalerthree`, `zscloud`, `zscalerbeta`, `zscalergov`)

| Category | Key Endpoints | Method |
|---|---|---|
| Authentication | `/authenticatedSession` | POST/DELETE |
| Activation | `/status/activate` | POST |
| Admin Users | `/adminUsers`, `/adminUsers/{id}` | GET/POST/PUT/DELETE |
| Admin Roles | `/adminRoles/lite` | GET |
| Admin Audit Logs | `/auditlogEntryReport` | GET |
| URL Categories | `/urlCategories`, `/urlCategories/{id}`, `/urlCategories/lite` | GET/POST/PUT/DELETE |
| URL Filtering Rules | `/urlFilteringRules`, `/urlFilteringRules/{id}` | GET/POST/PUT/DELETE |
| Firewall Filtering Rules | `/firewallRules`, `/firewallRules/{id}` | GET/POST/PUT/DELETE |
| Firewall DNS Rules | `/firewallDnsRules`, `/firewallDnsRules/{id}` | GET/POST/PUT/DELETE |
| Firewall IP Dest Groups | `/ipDestinationGroups`, `/ipDestinationGroups/{id}` | GET/POST/PUT/DELETE |
| Firewall IP Source Groups | `/ipSourceGroups`, `/ipSourceGroups/{id}` | GET/POST/PUT/DELETE |
| Network Services | `/networkServices`, `/networkServices/{id}` | GET/POST/PUT/DELETE |
| Network Application Groups | `/networkApplicationGroups`, `/networkApplicationGroups/{id}` | GET/POST/PUT/DELETE |
| DLP Dictionaries | `/dlpDictionaries`, `/dlpDictionaries/{id}` | GET/POST/PUT/DELETE |
| DLP Engines | `/dlpEngines`, `/dlpEngines/{id}` | GET/POST/PUT/DELETE |
| DLP Notification Templates | `/dlpNotificationTemplates`, `/dlpNotificationTemplates/{id}` | GET/POST/PUT/DELETE |
| Web DLP Rules | `/webApplicationRules`, `/webApplicationRules/{id}` | GET/POST/PUT/DELETE |
| SSL Inspection Rules | `/sslSettings`, `/sslSettings/exemptedUrls` | GET/PUT |
| SSL Inspection CA Cert | `/sslSettings/downloadcert`, `/sslSettings/certchain/verify` | GET |
| Sandbox Settings | `/behavioralAnalysisAdvancedSettings` | GET/PUT |
| Sandbox Report | `/sandbox/report/{md5Hash}` | GET |
| Security Policy | `/securitySettings`, `/securitySettings/whitelistUrls` | GET/PUT |
| Location Management | `/locations`, `/locations/{id}`, `/locations/lite` | GET/POST/PUT/DELETE |
| Location Groups | `/locationGroups`, `/locationGroups/{id}` | GET/POST/PUT/DELETE |
| User Management | `/users`, `/users/{id}` | GET/POST/PUT/DELETE |
| User Groups | `/groups`, `/groups/{id}` | GET |
| Department Management | `/departments`, `/departments/{id}` | GET |
| Traffic Forwarding - GRE | `/greTunnels`, `/greTunnels/{id}` | GET/POST/PUT/DELETE |
| Traffic Forwarding - VPN | `/vpnCredentials`, `/vpnCredentials/{id}` | GET/POST/PUT/DELETE |
| Traffic Forwarding - Static IP | `/staticIP`, `/staticIP/{id}` | GET/POST/PUT/DELETE |
| Bandwidth Control | `/bandwidthControl/rules`, `/bandwidthControl/rules/{id}` | GET/POST/PUT/DELETE |
| Cloud App Control | `/cloudApplications`, `/cloudApplicationRules` | GET |
| Isolation Profile | `/isolationProfile`, `/isolationProfile/{id}` | GET |
| Forwarding Control | `/forwardingRules`, `/forwardingRules/{id}` | GET/POST/PUT/DELETE |
| Device Management | `/deviceGroups`, `/deviceGroups/{id}` | GET |
| Authentication Settings | `/authSettings/exemptedUrls` | GET/PUT |
| Rule Labels | `/ruleLabels`, `/ruleLabels/{id}` | GET/POST/PUT/DELETE |

### 2.2 Zscaler Private Access (ZPA) API

**Base URL:** `https://config.private.zscaler.com/mgmtconfig/v1/admin/customers/{customerId}` (varies by cloud: `config.zpabeta.net`, `config.zpath.net`, `config.zpagov.net`)

| Category | Key Endpoints | Method |
|---|---|---|
| Authentication | `/signin` (OAuth2 at `https://config.private.zscaler.com/signin`) | POST |
| Application Segments | `/application`, `/application/{id}` | GET/POST/PUT/DELETE |
| Application Segments PRA | `/application/pra`, `/application/pra/{id}` | GET/POST/PUT/DELETE |
| Browser Access Segments | `/application/ba`, `/application/ba/{id}` | GET/POST/PUT/DELETE |
| Segment Groups | `/segmentGroup`, `/segmentGroup/{id}` | GET/POST/PUT/DELETE |
| Server Groups | `/serverGroup`, `/serverGroup/{id}` | GET/POST/PUT/DELETE |
| Application Servers | `/applicationServer`, `/applicationServer/{id}` | GET/POST/PUT/DELETE |
| Access Policies | `/policySet/rules`, `/policySet/rules/{ruleId}` | GET/POST/PUT/DELETE |
| Timeout Policies | `/policySet/rules/timeout` | GET/POST/PUT/DELETE |
| Forwarding Policies | `/policySet/rules/forwarding` | GET/POST/PUT/DELETE |
| Client Forwarding Policies | `/policySet/rules/clientForwarding` | GET/POST/PUT/DELETE |
| Inspection Policies | `/policySet/rules/inspection` | GET/POST/PUT/DELETE |
| Isolation Policies | `/policySet/rules/isolation` | GET/POST/PUT/DELETE |
| App Connector Groups | `/appConnectorGroup`, `/appConnectorGroup/{id}` | GET/POST/PUT/DELETE |
| Connectors | `/connector`, `/connector/{id}` | GET/PUT/DELETE |
| Service Edges | `/serviceEdge`, `/serviceEdge/{id}` | GET/PUT/DELETE |
| Service Edge Groups | `/serviceEdgeGroup`, `/serviceEdgeGroup/{id}` | GET/POST/PUT/DELETE |
| Posture Profiles | `/posture`, `/posture/{id}` | GET/POST/PUT/DELETE |
| Trusted Networks | `/trustedNetwork`, `/trustedNetwork/{id}` | GET/POST/PUT/DELETE |
| IdP Controllers | `/idp`, `/idp/{id}` | GET/POST/PUT/DELETE |
| SAML Attributes | `/samlAttribute`, `/samlAttribute/{id}` | GET |
| SCIM Attributes | `/scimAttribute/idpId/{idpId}` | GET |
| SCIM Groups | `/scimGroup/idpId/{idpId}` | GET |
| Machine Groups | `/machineGroup`, `/machineGroup/{id}` | GET |
| Enrollment Certificates | `/enrollmentCert`, `/enrollmentCert/{id}` | GET |
| Browser Access Certificates | `/clientlessCertificate`, `/clientlessCertificate/{id}` | GET |
| Provisioning Keys | `/associationType/{type}/provisioningKey` | GET/POST/PUT/DELETE |
| Cloud Connector Groups | `/cloudConnectorGroup`, `/cloudConnectorGroup/{id}` | GET |
| Emergency Access | `/emergencyAccess`, `/emergencyAccess/{id}` | GET/POST/PUT/DELETE |
| Admin Users (ZPA) | `/admin/users`, `/admin/users/{id}` | GET/POST/PUT/DELETE |
| Admin Roles (ZPA) | `/admin/roles`, `/admin/roles/{id}` | GET |
| Audit Logs (ZPA) | `/auditlogEntryReport` | POST |

### 2.3 Zscaler Digital Experience (ZDX) API

**Base URL:** `https://api.zdxcloud.net/v1`

| Category | Key Endpoints | Method |
|---|---|---|
| Authentication | `/oauth2/token` | POST |
| Devices | `/devices`, `/devices/{deviceId}` | GET |
| Applications | `/apps`, `/apps/{appId}` | GET |
| Alerts | `/alerts`, `/alerts/{alertId}` | GET |
| Scores | `/devices/{deviceId}/apps/{appId}/score` | GET |
| Administration | `/administration` | GET |

### 2.4 SDKs and CLIs

| Tool | Language | Description |
|---|---|---|
| `zscaler-sdk-python` | Python | Official Zscaler SDK for ZIA, ZPA, ZDX, ZCC; supports OneAPI OAuth2 framework |
| `zscaler-sdk-go` | Go | Official Zscaler SDK for Go; supports ZIA/ZPA/ZDX/ZCC/ZTW APIs |
| `pyZscaler` (legacy) | Python | Community SDK by mitchos; widely used but being superseded by official SDK |
| Terraform `zscaler/zia` | HCL/Go | Terraform provider for ZIA resource management |
| Terraform `zscaler/zpa` | HCL/Go | Terraform provider for ZPA resource management |
| `zscaler-cli` | Python | CLI wrapper for Zscaler API operations |

## 3. Authentication

### 3.1 ZIA Authentication

| Parameter | Source | Description |
|---|---|---|
| `ZIA_CLOUD` | Env var | Cloud name (e.g., `zscaler`, `zscalerone`, `zscalergov`) |
| `ZIA_API_KEY` | Env var | API key from `Administration > Cloud Service API Security > API Key` |
| `ZIA_USERNAME` | Env var | Admin username with API permissions |
| `ZIA_PASSWORD` | Env var | Admin password |

**Flow:**
1. Obfuscate the API key using a timestamp-based algorithm (Zscaler-specific obfuscation):
   - Take current epoch milliseconds as string
   - Derive seed from last 6 chars of timestamp
   - XOR/index into API key to produce obfuscated key
2. POST `/authenticatedSession` with `{"apiKey": "<obfuscated>", "username": "<user>", "password": "<pass>", "timestamp": "<epoch_ms>"}`.
3. Response sets `JSESSIONID` cookie for session-based auth.
4. All subsequent requests include the `JSESSIONID` cookie.
5. Call `/authenticatedSession` with DELETE to end session.

**Rate limits:** ZIA API is rate-limited; recommended max 40 requests/10-second window.

### 3.2 ZPA Authentication (OAuth2)

| Parameter | Source | Description |
|---|---|---|
| `ZPA_CLIENT_ID` | Env var | OAuth2 client ID from `Administration > API Keys` |
| `ZPA_CLIENT_SECRET` | Env var | OAuth2 client secret |
| `ZPA_CUSTOMER_ID` | Env var | ZPA tenant customer ID |
| `ZPA_CLOUD` | Env var | Cloud name (e.g., `PRODUCTION`, `BETA`, `GOV`, `GOVUS`) |

**Flow:**
1. POST `https://config.private.zscaler.com/signin` with `{"client_id": "<ID>", "client_secret": "<SECRET>"}`.
2. Response returns a Bearer token.
3. Include `Authorization: Bearer <token>` header on all subsequent requests.
4. Customer ID is required in endpoint URL paths.

### 3.3 ZDX Authentication (OAuth2)

| Parameter | Source | Description |
|---|---|---|
| `ZDX_CLIENT_ID` | Env var | OAuth2 client ID |
| `ZDX_CLIENT_SECRET` | Env var | OAuth2 client secret |

**Flow:**
1. POST `https://api.zdxcloud.net/v1/oauth2/token` with client credentials.
2. Response returns a Bearer token for subsequent requests.

### 3.4 OneAPI (Unified Auth -- New Framework)

Zscaler is migrating to a unified OAuth2 framework called OneAPI. The `zscaler-sdk-python` and `zscaler-sdk-go` SDKs support OneAPI via a single HTTP client across all products.

| Parameter | Source | Description |
|---|---|---|
| `ZSCALER_CLIENT_ID` | Env var | Unified OAuth2 client ID |
| `ZSCALER_CLIENT_SECRET` | Env var | Unified OAuth2 client secret |
| `ZSCALER_VANITY_DOMAIN` | Env var | Tenant vanity domain |
| `ZSCALER_CLOUD` | Env var | Cloud environment identifier |

## 4. Security Controls

| # | Control Name | Description | API Source |
|---|---|---|---|
| 1 | URL Filtering Policy Audit | Verify URL filtering rules block high-risk categories (malware, phishing, C2, adult, gambling, anonymizers); confirm default action is block | ZIA: `/urlFilteringRules`, `/urlCategories` |
| 2 | Firewall Rule Audit | Validate cloud firewall rules enforce least privilege; detect overly permissive any/any rules; verify rule ordering | ZIA: `/firewallRules` |
| 3 | DLP Engine Configuration | Confirm DLP engines are enabled, dictionaries include PII/PCI/PHI patterns, and DLP rules cover web and cloud app traffic | ZIA: `/dlpEngines`, `/dlpDictionaries`, `/webApplicationRules` |
| 4 | SSL Inspection Coverage | Verify SSL inspection is enabled for all required traffic categories; audit exemptions list for unnecessary entries | ZIA: `/sslSettings`, `/sslSettings/exemptedUrls` |
| 5 | Cloud Sandbox Analysis | Confirm advanced threat protection sandbox is enabled; verify file types forwarded for analysis; check sandbox policy settings | ZIA: `/behavioralAnalysisAdvancedSettings`, `/securitySettings` |
| 6 | Admin MFA Enforcement | Verify all admin accounts have MFA enabled; check for local-only auth bypasses | ZIA: `/adminUsers`; ZPA: `/admin/users` |
| 7 | RBAC & Admin Role Audit | Audit admin roles for least privilege; identify superadmin accounts; verify separation of duties between ZIA and ZPA admin roles | ZIA: `/adminUsers`, `/adminRoles/lite`; ZPA: `/admin/users`, `/admin/roles` |
| 8 | Application Segmentation | Verify application segments follow least privilege (no wildcard domains, specific ports); confirm segment grouping is logical | ZPA: `/application`, `/segmentGroup` |
| 9 | Zero Trust Access Policies | Audit access policy rules for overly permissive conditions; verify policies require identity + posture + context | ZPA: `/policySet/rules` |
| 10 | Posture Profile Enforcement | Confirm posture profiles check OS version, disk encryption, firewall, AV status; verify profiles are attached to access policies | ZPA: `/posture`, `/policySet/rules` |
| 11 | App Connector Health & Coverage | Verify connector groups have redundancy (2+ connectors); check connector health status; confirm connectors cover all application segments | ZPA: `/appConnectorGroup`, `/connector` |
| 12 | IdP Integration & SAML Config | Validate IdP controllers are configured with SAML/SCIM; verify SAML attributes for group-based policy; check SCIM provisioning | ZPA: `/idp`, `/samlAttribute`, `/scimAttribute`, `/scimGroup` |
| 13 | Session Timeout Configuration | Verify ZIA and ZPA session timeouts meet compliance requirements; audit timeout policies for sensitive applications | ZIA: auth settings; ZPA: `/policySet/rules/timeout` |
| 14 | Audit Logging Enabled | Confirm audit logging is active for both ZIA and ZPA; verify log retention and export configuration | ZIA: `/auditlogEntryReport`; ZPA: `/auditlogEntryReport` |
| 15 | Trusted Network Detection | Audit trusted network configurations; verify on-net/off-net policies differentiate correctly; check for overly broad trusted definitions | ZPA: `/trustedNetwork` |
| 16 | Bandwidth Control Policies | Verify bandwidth control rules enforce fair-use policies; confirm streaming and large download categories are throttled | ZIA: `/bandwidthControl/rules` |
| 17 | Browser Isolation Policies | Confirm browser isolation is configured for high-risk categories; verify isolation profiles are applied to appropriate rules | ZIA: `/isolationProfile`; ZPA: `/policySet/rules/isolation` |
| 18 | Location & GRE/VPN Configuration | Verify all locations are configured with appropriate authentication; audit GRE tunnels and VPN credentials for stale entries | ZIA: `/locations`, `/greTunnels`, `/vpnCredentials` |
| 19 | Cloud Application Control | Audit CASB-inline policies for sanctioned/unsanctioned app classification; verify shadow IT discovery is active | ZIA: `/cloudApplications`, `/cloudApplicationRules` |
| 20 | DNS Security Configuration | Verify DNS filtering rules block malicious domains; confirm DNS tunneling protection is enabled | ZIA: `/firewallDnsRules` |
| 21 | Service Edge Deployment | Verify service edge groups have redundancy; check service edge health; confirm geographic coverage | ZPA: `/serviceEdge`, `/serviceEdgeGroup` |
| 22 | Forwarding Policy Audit | Audit client forwarding and forwarding policies for correct traffic steering; verify bypass rules are minimal and justified | ZPA: `/policySet/rules/forwarding`, `/policySet/rules/clientForwarding` |
| 23 | Emergency Access Configuration | Verify emergency access users are configured for break-glass scenarios; confirm they are restricted and audited | ZPA: `/emergencyAccess` |
| 24 | Certificate Management | Audit enrollment certificates, browser access certificates, and SSL CA cert chain for expiration and validity | ZPA: `/enrollmentCert`, `/clientlessCertificate`; ZIA: `/sslSettings/certchain/verify` |
| 25 | Security Policy Baseline | Validate ZIA security policy settings (malware protection, advanced threat protection, phishing detection) against best-practice baseline | ZIA: `/securitySettings` |

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC 2.0 | SOC 2 | CIS | PCI-DSS 4.0 | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | URL Filtering Policy | SC-7, SI-4 | C.3.13, C.5.3 | CC6.1, CC6.8 | CIS CSC 9 | 1.2, 6.2 | V-XXXXX | ISM-0261 | 7.3.1 |
| 2 | Firewall Rule Audit | AC-4, SC-7 | C.3.13, C.4.6 | CC6.1, CC6.6 | CIS CSC 9, 12 | 1.2, 1.3 | V-XXXXX | ISM-1416 | 7.1.1 |
| 3 | DLP Engine Config | SC-28, SI-4 | C.3.8, C.5.3 | CC6.1, CC6.7 | CIS CSC 3 | 3.4, 3.5 | V-XXXXX | ISM-0457 | 7.2.1 |
| 4 | SSL Inspection Coverage | SC-8, SI-4 | C.3.8, C.5.3 | CC6.1, CC6.7 | CIS CSC 9 | 4.1, 4.2 | V-XXXXX | ISM-0490 | 7.2.2 |
| 5 | Cloud Sandbox Analysis | SI-3, SI-4 | C.5.2, C.5.3 | CC6.8, CC7.1 | CIS CSC 8, 10 | 5.2 | V-XXXXX | ISM-1288 | 8.2.1 |
| 6 | Admin MFA Enforcement | IA-2, IA-5 | C.1.1, C.3.7 | CC6.1, CC6.2 | CIS CSC 5, 6 | 8.3, 8.4 | V-XXXXX | ISM-1504 | 6.2.1 |
| 7 | RBAC & Admin Roles | AC-2, AC-6 | C.1.1, C.1.4 | CC6.1, CC6.3 | CIS CSC 5, 6 | 7.1, 7.2 | V-XXXXX | ISM-1506 | 6.1.1 |
| 8 | Application Segmentation | SC-7, AC-4 | C.3.12, C.3.13 | CC6.1, CC6.6 | CIS CSC 12 | 1.2, 1.4 | V-XXXXX | ISM-1181 | 7.1.2 |
| 9 | Zero Trust Access Policies | AC-3, AC-4 | C.1.1, C.3.13 | CC6.1, CC6.3 | CIS CSC 6, 14 | 7.1, 7.2 | V-XXXXX | ISM-1416 | 6.1.2 |
| 10 | Posture Profile Enforcement | CM-6, SI-4 | C.2.3, C.5.3 | CC6.1, CC6.8 | CIS CSC 4, 10 | 5.2, 5.3 | V-XXXXX | ISM-1407 | 5.1.1 |
| 11 | Connector Health | SI-4, CM-8 | C.2.4, C.5.1 | CC6.1, CC7.1 | CIS CSC 1, 2 | 11.4 | V-XXXXX | ISM-1034 | 8.1.1 |
| 12 | IdP Integration | IA-2, IA-8 | C.1.1, C.3.7 | CC6.1, CC6.2 | CIS CSC 5, 16 | 8.3 | V-XXXXX | ISM-1504 | 6.2.2 |
| 13 | Session Timeout | AC-11, AC-12 | C.1.10, C.3.7 | CC6.1 | CIS CSC 4, 16 | 8.6 | V-XXXXX | ISM-0853 | 6.3.1 |
| 14 | Audit Logging | AU-2, AU-6 | C.3.1, C.3.3 | CC7.2, CC7.3 | CIS CSC 6, 8 | 10.1, 10.2 | V-XXXXX | ISM-0580 | 8.4.1 |
| 15 | Trusted Network Detection | AC-17, SC-7 | C.3.7, C.3.13 | CC6.1, CC6.6 | CIS CSC 12 | 1.2 | V-XXXXX | ISM-1416 | 7.1.3 |
| 16 | Bandwidth Control | SC-7, SC-5 | C.3.13, C.4.6 | CC6.1 | CIS CSC 9 | 1.2 | V-XXXXX | ISM-1416 | 7.4.1 |
| 17 | Browser Isolation | SC-7, SI-3 | C.5.2, C.5.3 | CC6.1, CC6.8 | CIS CSC 9 | 5.2, 6.2 | V-XXXXX | ISM-1288 | 8.2.2 |
| 18 | Location & Tunnel Config | SC-8, AC-17 | C.3.7, C.3.8 | CC6.1, CC6.6 | CIS CSC 12 | 4.1 | V-XXXXX | ISM-0490 | 7.1.4 |
| 19 | Cloud App Control | SC-7, SI-4 | C.3.13, C.5.3 | CC6.1, CC6.8 | CIS CSC 2, 9 | 1.2, 6.2 | V-XXXXX | ISM-0261 | 7.3.2 |
| 20 | DNS Security | SC-7, SI-4 | C.3.13, C.5.3 | CC6.1, CC6.8 | CIS CSC 9 | 1.2 | V-XXXXX | ISM-1416 | 7.1.5 |
| 21 | Service Edge Deployment | SI-4, CM-8 | C.2.4, C.5.1 | CC6.1, CC7.1 | CIS CSC 1, 2 | 11.4 | V-XXXXX | ISM-1034 | 8.1.2 |
| 22 | Forwarding Policy Audit | AC-4, SC-7 | C.3.13, C.4.6 | CC6.1, CC6.6 | CIS CSC 9, 12 | 1.2, 1.3 | V-XXXXX | ISM-1416 | 7.1.6 |
| 23 | Emergency Access | AC-2, CP-2 | C.1.1, C.3.6 | CC6.1, A1.2 | CIS CSC 5, 16 | 8.6 | V-XXXXX | ISM-1610 | 6.4.1 |
| 24 | Certificate Management | SC-12, SC-17 | C.3.8, C.3.10 | CC6.1, CC6.7 | CIS CSC 3 | 4.1 | V-XXXXX | ISM-0490 | 7.2.3 |
| 25 | Security Policy Baseline | SI-3, SI-4 | C.5.2, C.5.3 | CC6.8, CC7.1 | CIS CSC 8, 10 | 5.2, 5.3 | V-XXXXX | ISM-1288 | 8.2.3 |

## 6. Existing Tools

| Tool | Description | Relevance |
|---|---|---|
| [zscaler-sdk-python](https://github.com/zscaler/zscaler-sdk-python) | Official Zscaler Python SDK for ZIA, ZPA, ZDX, ZCC; supports OneAPI OAuth2 | Primary SDK for data collection; wraps all ZIA and ZPA endpoints |
| [zscaler-sdk-go](https://github.com/zscaler/zscaler-sdk-go) | Official Zscaler Go SDK for all products; designed for OneAPI | Alternative if implementing in Go |
| [pyZscaler](https://github.com/mitchos/pyZscaler) | Community Python SDK (legacy); widely referenced in examples | Reference for API interaction patterns; being superseded by official SDK |
| [Terraform Provider ZIA](https://registry.terraform.io/providers/zscaler/zia/latest) | Terraform provider for managing ZIA resources as code | Reference for ZIA resource models and configuration patterns |
| [Terraform Provider ZPA](https://registry.terraform.io/providers/zscaler/zpa/latest) | Terraform provider for managing ZPA resources as code | Reference for ZPA resource models and access policy patterns |
| Zscaler Compliance Reports | Built-in compliance reporting in ZIA/ZPA admin portals | Baseline comparison for inspector findings |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud security auditing tool by NCC Group | Reference architecture for security posture report generation |

## 7. Architecture

The project mirrors the structure of [okta-inspector](https://github.com/ethanolivertroy/okta-inspector):

```
zscaler-sec-inspector/
├── spec.md
├── pyproject.toml
├── src/
│   └── zscaler_inspector/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py                  # Click/Typer CLI entrypoint
│       ├── client.py               # API client abstraction (ZIA + ZPA + ZDX)
│       ├── clients/
│       │   ├── __init__.py
│       │   ├── zia.py              # ZIA API client (session-based auth)
│       │   ├── zpa.py              # ZPA API client (OAuth2)
│       │   └── zdx.py              # ZDX API client (OAuth2)
│       ├── collector.py            # Orchestrates data collection across all clients
│       ├── engine.py               # Compliance evaluation engine
│       ├── models.py               # Data models (controls, findings, severities)
│       ├── output.py               # Output formatting (JSON, table, summary)
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── base.py             # Base analyzer class
│       │   ├── common.py           # Shared control evaluation logic
│       │   ├── zia.py              # ZIA controls (1-5, 16, 18-20, 25)
│       │   ├── zpa.py              # ZPA controls (8-12, 15, 21-23)
│       │   ├── cross_platform.py   # Cross-platform controls (6-7, 13-14, 17, 24)
│       │   ├── fedramp.py          # FedRAMP-specific evaluation
│       │   ├── cmmc.py             # CMMC 2.0-specific evaluation
│       │   ├── soc2.py             # SOC 2-specific evaluation
│       │   ├── pci_dss.py          # PCI-DSS 4.0-specific evaluation
│       │   ├── stig.py             # DISA STIG-specific evaluation
│       │   ├── irap.py             # IRAP-specific evaluation
│       │   └── ismap.py            # ISMAP-specific evaluation
│       └── reporters/
│           ├── __init__.py
│           ├── base.py             # Base reporter class
│           ├── executive.py        # Executive summary reporter
│           ├── matrix.py           # Cross-framework compliance matrix
│           ├── fedramp.py          # FedRAMP SSP-ready output
│           ├── cmmc.py             # CMMC assessment report
│           ├── soc2.py             # SOC 2 evidence report
│           ├── pci_dss.py          # PCI-DSS compliance report
│           ├── stig.py             # DISA STIG checklist (CKL format)
│           ├── irap.py             # IRAP assessment report
│           ├── ismap.py            # ISMAP assessment report
│           └── validation.py       # Finding validation and dedup
├── tests/
│   ├── conftest.py
│   ├── test_zia_analyzer.py
│   ├── test_zpa_analyzer.py
│   ├── test_cross_platform.py
│   ├── test_engine.py
│   └── testdata/
│       ├── zia_url_filtering_rules.json
│       ├── zia_firewall_rules.json
│       ├── zia_dlp_engines.json
│       ├── zia_ssl_settings.json
│       ├── zia_admin_users.json
│       ├── zpa_application_segments.json
│       ├── zpa_access_policies.json
│       ├── zpa_connectors.json
│       ├── zpa_posture_profiles.json
│       └── zpa_admin_users.json
└── COPYING
```

**Key design decisions:**
- **Separate clients** (`clients/` subpackage) because ZIA uses session-based auth (JSESSIONID cookie) while ZPA and ZDX use OAuth2 Bearer tokens -- fundamentally different auth models.
- **Analyzer per product** (`zia.py`, `zpa.py`) keeps ZIA-specific URL filtering/firewall/DLP logic separate from ZPA-specific segmentation/access-policy logic.
- **Cross-platform analyzer** handles controls that span both products (admin MFA, RBAC, session timeout, audit logging, browser isolation, certificates).
- **Framework-specific analyzers** map the 25 controls to specific framework requirements with detailed evidence collection.
- **Reporter per framework** generates framework-specific output formats (e.g., STIG CKL XML, FedRAMP SSP narrative).

## 8. CLI Interface

```bash
# Full audit across ZIA and ZPA
zscaler-inspector audit \
  --zia-cloud "$ZIA_CLOUD" \
  --zia-api-key "$ZIA_API_KEY" \
  --zia-username "$ZIA_USERNAME" \
  --zia-password "$ZIA_PASSWORD" \
  --zpa-client-id "$ZPA_CLIENT_ID" \
  --zpa-client-secret "$ZPA_CLIENT_SECRET" \
  --zpa-customer-id "$ZPA_CUSTOMER_ID" \
  --format json \
  --output report.json

# ZIA-only audit
zscaler-inspector audit --scope zia \
  --zia-cloud "$ZIA_CLOUD" \
  --zia-api-key "$ZIA_API_KEY" \
  --zia-username "$ZIA_USERNAME" \
  --zia-password "$ZIA_PASSWORD" \
  --framework fedramp \
  --format table

# ZPA-only audit
zscaler-inspector audit --scope zpa \
  --zpa-client-id "$ZPA_CLIENT_ID" \
  --zpa-client-secret "$ZPA_CLIENT_SECRET" \
  --zpa-customer-id "$ZPA_CUSTOMER_ID" \
  --controls 8,9,10,11,12

# Using OneAPI unified auth
zscaler-inspector audit \
  --client-id "$ZSCALER_CLIENT_ID" \
  --client-secret "$ZSCALER_CLIENT_SECRET" \
  --vanity-domain "$ZSCALER_VANITY_DOMAIN" \
  --framework stig \
  --format stig-ckl \
  --output zscaler-stig.ckl

# Generate executive summary
zscaler-inspector report executive \
  --input report.json \
  --format html

# Generate compliance matrix
zscaler-inspector report matrix \
  --input report.json \
  --frameworks fedramp,cmmc,pci-dss \
  --format csv

# List available controls
zscaler-inspector controls list --scope all

# Validate connectivity
zscaler-inspector test-connection \
  --zia-cloud "$ZIA_CLOUD" \
  --zia-api-key "$ZIA_API_KEY" \
  --zia-username "$ZIA_USERNAME" \
  --zia-password "$ZIA_PASSWORD" \
  --zpa-client-id "$ZPA_CLIENT_ID" \
  --zpa-client-secret "$ZPA_CLIENT_SECRET" \
  --zpa-customer-id "$ZPA_CUSTOMER_ID"
```

## 9. Build Sequence

| Phase | Scope | Deliverables |
|---|---|---|
| **Phase 1: Foundation** | Project scaffold, models, CLI skeleton | `pyproject.toml`, `models.py`, `cli.py`, `engine.py`, `output.py` |
| **Phase 2: ZIA Client** | ZIA API client, session auth, obfuscation, connection test | `clients/zia.py`, `test_connection` command |
| **Phase 3: ZIA Analyzers** | Controls 1-5, 16, 18-20, 25 (URL filtering, firewall, DLP, SSL, sandbox, bandwidth, locations, CASB, DNS, security baseline) | `analyzers/zia.py`, test fixtures, `testdata/zia_*.json` |
| **Phase 4: ZPA Client** | ZPA OAuth2 client, bearer auth, customer ID routing | `clients/zpa.py` |
| **Phase 5: ZPA Analyzers** | Controls 8-12, 15, 21-23 (segmentation, access policies, posture, connectors, IdP, trusted networks, service edges, forwarding, emergency access) | `analyzers/zpa.py`, `testdata/zpa_*.json` |
| **Phase 6: Cross-Platform** | Controls 6-7, 13-14, 17, 24 (admin MFA, RBAC, session timeout, audit logging, isolation, certificates) | `analyzers/cross_platform.py` |
| **Phase 7: ZDX Client** | ZDX OAuth2 client (optional enrichment for availability/experience data) | `clients/zdx.py` |
| **Phase 8: Framework Analyzers** | Framework-specific mapping and evidence logic | `analyzers/{fedramp,cmmc,soc2,pci_dss,stig,irap,ismap}.py` |
| **Phase 9: Reporters** | Framework-specific report generation | `reporters/` (all framework reporters, matrix, executive) |
| **Phase 10: OneAPI Migration** | Unified auth support via OneAPI OAuth2 framework | Updated `clients/`, CLI flags |
| **Phase 11: Testing & Polish** | Integration tests, CI pipeline, documentation | `tests/`, CI config, README |

## 10. Status

**Not yet implemented. Spec only.**
