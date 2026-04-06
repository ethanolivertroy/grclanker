---
slug: "paloalto-sec-inspector"
name: "Palo Alto Security Inspector"
vendor: "Palo Alto Networks"
category: "security-network-infrastructure"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/paloalto-sec-inspector"
---

# paloalto-sec-inspector -- Architecture Specification

## 1. Overview

Palo Alto Networks is a leading cybersecurity platform that provides network security (PAN-OS firewalls and Panorama), cloud security (Prisma Cloud CSPM/CWPP/CIEM), and security operations (Cortex XSIAM/XSOAR). Organizations operating in regulated industries depend on Palo Alto products to enforce network segmentation, threat prevention, encryption policies, workload protection, and cloud security posture management.

**paloalto-sec-inspector** is a security compliance inspector that programmatically audits Palo Alto Networks environments across three primary surfaces:

1. **Prisma Cloud CSPM** -- Cloud Security Posture Management: compliance posture, policy enforcement, alert configuration, IAM analysis, asset inventory, and cloud account governance.
2. **Prisma Cloud CWPP** -- Cloud Workload Protection Platform: container image vulnerabilities, host compliance, runtime defense policies, defender deployment, and registry scanning.
3. **PAN-OS Firewalls / Panorama** -- Network security device configuration: security rules, zone segmentation, threat prevention profiles, SSL/TLS decryption, GlobalProtect VPN, WildFire analysis, URL filtering, admin roles, and logging.

The tool produces compliance-mapped audit reports against FedRAMP, CMMC 2.0, SOC 2, CIS Benchmarks, PCI-DSS 4.0, DISA STIG, IRAP, and ISMAP frameworks.

## 2. APIs & SDKs

### 2.1 Prisma Cloud CSPM API

**Base URL:** `https://api<N>.prismacloud.io` (region-dependent; check `Administration > API URLs` in console)

| Category | Key Endpoints | Method |
|---|---|---|
| Authentication | `/login` | POST |
| Alerts | `/alert`, `/v2/alert`, `/alert/policy` | GET/POST |
| Compliance Posture | `/compliance/posture`, `/compliance/posture/trend`, `/compliance/posture/{complianceId}` | GET/POST |
| Compliance Standards | `/compliance`, `/compliance/{complianceId}/requirement`, `/compliance/{complianceId}/requirement/{requirementId}/section` | GET |
| Asset Inventory | `/v2/inventory`, `/filter/inventory`, `/inventory/trend` | GET/POST |
| Cloud Accounts | `/cloud`, `/cloud/{cloudType}/{id}`, `/cloud/name` | GET/POST/PUT |
| IAM | `/api/v1/permission`, `/api/v1/permission/access`, `/iam/query` | GET/POST |
| Policy | `/policy`, `/v2/policy`, `/policy/{policyId}` | GET/POST/PUT/DELETE |
| Settings | `/settings/{type}`, `/ip_allowlist_login` | GET/PUT |
| User Roles | `/user/role`, `/user/role/{id}` | GET/POST/PUT/DELETE |
| Resource Scan Info | `/resource/scan_info` | POST |
| Reports | `/report`, `/report/{id}/download` | GET/POST |
| Vulnerabilities Dashboard | `/v2/vulnerabilities/dashboard` | POST |
| Integrations | `/integration`, `/integration/{id}` | GET/POST/PUT/DELETE |
| Audit Logs | `/audit/redlock`, `/audit/logs` | GET |
| Account Groups | `/cloud/group`, `/cloud/group/{id}` | GET/POST/PUT/DELETE |

### 2.2 Prisma Cloud CWPP (Compute) API

**Base URL:** `https://<CONSOLE>/api/v<VERSION>` (port 8083 for self-hosted; SaaS path from CSPM console)

| Category | Key Endpoints | Method |
|---|---|---|
| Authentication | `/api/v1/authenticate` (or use CSPM JWT) | POST |
| Images | `/images`, `/images/names`, `/images/scan` | GET/POST |
| Containers | `/containers`, `/containers/scan`, `/containers/count` | GET/POST |
| Hosts | `/hosts`, `/hosts/scan`, `/hosts/info` | GET/POST |
| Vulnerabilities | `/stats/vulnerabilities`, `/vms`, `/serverless` | GET |
| Compliance | `/compliance`, `/compliance/download`, `/compliance/progress` | GET |
| Defenders | `/defenders`, `/defenders/summary`, `/defenders/names` | GET |
| Runtime | `/audits/runtime/container`, `/audits/runtime/host`, `/policies/runtime/container` | GET |
| Registry | `/registry`, `/registry/scan`, `/registry/names` | GET/POST |
| Policies | `/policies/compliance/container`, `/policies/compliance/host`, `/policies/vulnerability/images` | GET/PUT |
| Collections | `/collections`, `/collections/{id}` | GET/POST/PUT/DELETE |
| CI/CD Scans | `/scans`, `/scans/{id}` | GET |
| Custom Rules | `/custom-rules`, `/custom-rules/{id}` | GET/POST/PUT/DELETE |
| Cloud Discovery | `/cloud/discovery`, `/cloud/discovery/entities` | GET |
| Trust | `/trust/data` | GET |
| Settings | `/settings/system`, `/settings/defender` | GET/PUT |

### 2.3 PAN-OS XML API (Firewalls & Panorama)

**Base URL:** `https://<FIREWALL_IP>/api/` or `https://<PANORAMA_IP>/api/`

| Request Type | Action | Description |
|---|---|---|
| `type=config` | `action=get` | Retrieve running/candidate configuration XPath |
| `type=config` | `action=show` | Show active configuration XPath |
| `type=config` | `action=set` | Set configuration element |
| `type=config` | `action=edit` | Replace configuration element |
| `type=config` | `action=delete` | Delete configuration element |
| `type=op` | N/A | Execute operational mode command |
| `type=report` | N/A | Generate/retrieve reports |
| `type=log` | `log-type=traffic/threat/system/config/url` | Retrieve log entries |
| `type=export` | N/A | Export configuration, certificates, logs |
| `type=import` | N/A | Import configuration, certificates |
| `type=user-id` | N/A | User-ID agent operations |
| `type=commit` | N/A | Commit candidate configuration |
| `type=keygen` | N/A | Generate API key |

**Key Configuration XPaths (for audit):**

| XPath | What It Returns |
|---|---|
| `/config/devices/entry/vsys/entry/rulebase/security/rules` | Security policy rules |
| `/config/devices/entry/vsys/entry/zone` | Zone configuration |
| `/config/devices/entry/vsys/entry/profiles/virus` | Antivirus profiles |
| `/config/devices/entry/vsys/entry/profiles/spyware` | Anti-spyware profiles |
| `/config/devices/entry/vsys/entry/profiles/vulnerability` | Vulnerability protection profiles |
| `/config/devices/entry/vsys/entry/profiles/url-filtering` | URL filtering profiles |
| `/config/devices/entry/vsys/entry/profiles/file-blocking` | File blocking profiles |
| `/config/devices/entry/vsys/entry/profiles/wildfire-analysis` | WildFire analysis profiles |
| `/config/devices/entry/vsys/entry/profile-group` | Security profile groups |
| `/config/shared/ssl-tls-service-profile` | SSL/TLS service profiles |
| `/config/shared/ssl-decrypt` | SSL decryption rules |
| `/config/devices/entry/vsys/entry/rulebase/decryption/rules` | Decryption policy rules |
| `/config/shared/global-protect` | GlobalProtect configuration |
| `/config/shared/log-settings` | Logging configuration |
| `/config/mgt-config/users` | Admin user accounts |
| `/config/devices/entry/deviceconfig/system` | System settings (NTP, DNS, banners) |
| `/config/devices/entry/deviceconfig/setting` | Device settings (idle timeout, etc.) |

### 2.4 PAN-OS REST API (PAN-OS 9.0+)

**Base URL:** `https://<FIREWALL_IP>/restapi/v<VERSION>/`

| Endpoint | Description |
|---|---|
| `/restapi/v10.2/Objects/Addresses` | Address objects |
| `/restapi/v10.2/Objects/AddressGroups` | Address groups |
| `/restapi/v10.2/Policies/SecurityRules` | Security policy rules |
| `/restapi/v10.2/Policies/NATRules` | NAT rules |
| `/restapi/v10.2/Policies/DecryptionRules` | Decryption rules |
| `/restapi/v10.2/Network/Zones` | Network zones |
| `/restapi/v10.2/Network/Interfaces` | Network interfaces |
| `/restapi/v10.2/Device/Administrators` | Admin accounts |
| `/restapi/v10.2/Device/SystemSettings` | System settings |

### 2.5 SDKs and CLIs

| Tool | Language | Description |
|---|---|---|
| `pan-os-python` | Python | Official PAN-OS SDK; classes for `Firewall`, `Panorama`, `SecurityRule`, `Zone`, `AddressObject`, `SecurityProfileGroup` |
| `prismacloud-api` (PyPI) | Python | Official Prisma Cloud SDK for CSPM, CWPP, and CCS APIs |
| `pango` | Go | Community PAN-OS SDK for Go |
| `prismacloud-cli` | Python | CLI tool wrapping Prisma Cloud APIs |
| `pan-python` | Python | Low-level PAN-OS and WildFire API library |
| Terraform Provider `panos` | HCL/Go | Infrastructure as Code for PAN-OS |
| Terraform Provider `prismacloud` | HCL/Go | IaC for Prisma Cloud |
| Checkov | Python | Open-source IaC scanner (Bridgecrew / Prisma Cloud) with 750+ policies |

## 3. Authentication

### 3.1 Prisma Cloud (CSPM + CWPP)

| Parameter | Source | Description |
|---|---|---|
| `PRISMA_API_URL` | Env var | Tenant API base URL (e.g., `https://api2.prismacloud.io`) |
| `PRISMA_ACCESS_KEY_ID` | Env var | Access Key ID generated in `Settings > Access Keys` |
| `PRISMA_SECRET_KEY` | Env var | Corresponding secret key |

**Flow:**
1. POST `{PRISMA_API_URL}/login` with `{"username": "<ACCESS_KEY_ID>", "password": "<SECRET_KEY>"}`.
2. Response returns a JWT token (valid 10 minutes).
3. Include `x-redlock-auth: <JWT>` header on subsequent CSPM requests.
4. For CWPP/Compute, use the same JWT or authenticate separately at the Compute console endpoint.

### 3.2 PAN-OS (Firewall / Panorama)

| Parameter | Source | Description |
|---|---|---|
| `PANOS_HOST` | Env var | Firewall or Panorama management IP/hostname |
| `PANOS_API_KEY` | Env var | Pre-generated API key |
| `PANOS_USERNAME` | Env var (alt) | Admin username (for key generation) |
| `PANOS_PASSWORD` | Env var (alt) | Admin password (for key generation) |

**Flow (API Key):**
1. Generate key: GET `https://<HOST>/api/?type=keygen&user=<USER>&password=<PASS>`.
2. Response XML contains `<key>LUFRPT...</key>`.
3. Include `key=<API_KEY>` query parameter on all subsequent requests.

**Flow (pan-os-python SDK):**
```python
from panos.firewall import Firewall
fw = Firewall('10.0.0.1', api_key='LUFRPT...')
# or
fw = Firewall('10.0.0.1', 'admin', 'password')
```

## 4. Security Controls

| # | Control Name | Description | API Source |
|---|---|---|---|
| 1 | CSPM Compliance Posture | Verify overall compliance scores across enabled standards (CIS, NIST, SOC 2, PCI-DSS, HIPAA) | CSPM: `/compliance/posture` |
| 2 | Alert Policy Coverage | Ensure critical alert rules are enabled and not dismissed; verify alert rule severity mappings | CSPM: `/alert/policy`, `/v2/alert` |
| 3 | IAM Overprivileged Access | Identify overprivileged IAM entities across cloud accounts using effective permissions analysis | CSPM: `/api/v1/permission`, `/iam/query` |
| 4 | Cloud Account Governance | Verify all cloud accounts are onboarded, monitored, and assigned to account groups | CSPM: `/cloud`, `/cloud/group` |
| 5 | Network Exposure Analysis | Detect publicly exposed resources, unrestricted security groups, and open ports | CSPM: `/v2/inventory`, policy rules |
| 6 | Encryption-at-Rest Verification | Confirm storage volumes, databases, and object stores use encryption with customer-managed keys | CSPM: compliance policies |
| 7 | Container Image Vulnerability | Scan deployed and registry container images for critical/high CVEs and ensure thresholds are enforced | CWPP: `/images`, `/stats/vulnerabilities` |
| 8 | Host Compliance Posture | Verify CIS benchmark compliance for Linux/Windows hosts monitored by Defenders | CWPP: `/compliance`, `/hosts` |
| 9 | Runtime Protection Policies | Confirm runtime defense policies are enabled for containers and hosts (process, network, filesystem) | CWPP: `/policies/runtime/container`, `/audits/runtime` |
| 10 | Defender Deployment Coverage | Ensure Defenders are deployed on all hosts/clusters and are connected and up-to-date | CWPP: `/defenders`, `/defenders/summary` |
| 11 | Registry Scanning Configuration | Verify container registries are configured for periodic scanning with vulnerability thresholds | CWPP: `/registry`, `/settings/registry` |
| 12 | Firewall Security Rule Audit | Analyze security rules for overly permissive rules (any/any), shadowed rules, and missing logging | PAN-OS: `/rulebase/security/rules` |
| 13 | Zone Segmentation Verification | Confirm proper zone architecture: inter-zone rules enforce least privilege, intra-zone traffic is denied by default | PAN-OS: `/zone`, `/rulebase/security/rules` |
| 14 | SSL/TLS Decryption Coverage | Verify decryption policies cover required traffic categories; audit certificate configuration and exemptions | PAN-OS: `/rulebase/decryption/rules`, `/ssl-decrypt` |
| 15 | GlobalProtect VPN Configuration | Audit portal/gateway config: MFA, certificate auth, HIP profiles, split-tunnel policies, idle timeout | PAN-OS: `/global-protect` |
| 16 | Threat Prevention Profiles | Verify antivirus, anti-spyware, and vulnerability protection profiles use strict/best-practice settings and are applied to all rules | PAN-OS: `/profiles/virus`, `/profiles/spyware`, `/profiles/vulnerability` |
| 17 | WildFire Analysis Configuration | Confirm WildFire profiles forward all file types, all applications; verify WildFire cloud connectivity | PAN-OS: `/profiles/wildfire-analysis` |
| 18 | URL Filtering Enforcement | Validate URL filtering profiles block high-risk categories; check credential phishing protections | PAN-OS: `/profiles/url-filtering` |
| 19 | Admin Role & Access Audit | Verify least-privilege admin roles, enforce MFA for admin access, check password complexity, audit superuser count | PAN-OS: `/mgt-config/users`; CSPM: `/user/role` |
| 20 | Logging & SIEM Integration | Confirm all rules log at session end/start, syslog/Panorama forwarding is configured, log retention meets requirements | PAN-OS: `/log-settings`; CSPM: `/integration` |
| 21 | Data Loss Prevention | Verify DLP policies are configured for sensitive data patterns in Prisma Cloud and file blocking on PAN-OS | CSPM: DLP policies; PAN-OS: `/profiles/file-blocking` |
| 22 | File Blocking Policies | Ensure dangerous file types (PE, ELF, scripts) are blocked across all zones | PAN-OS: `/profiles/file-blocking` |
| 23 | System Hardening | Verify NTP sync, DNS settings, login banner, idle timeout, SNMP community strings, permitted IPs for management | PAN-OS: `/deviceconfig/system`, `/deviceconfig/setting` |
| 24 | Cloud Discovery & Shadow IT | Detect unprotected cloud assets, unmanaged registries, and serverless functions not covered by Defenders | CWPP: `/cloud/discovery` |
| 25 | CI/CD Pipeline Security | Verify CI/CD image scanning is integrated, vulnerability gates are enforced, and admission control is configured | CWPP: `/scans`, admission policies |

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC 2.0 | SOC 2 | CIS | PCI-DSS 4.0 | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | CSPM Compliance Posture | CA-7, RA-5 | C.2.4, C.3.4 | CC7.1 | CIS CSC 4 | 6.3, 11.3 | V-XXXXX | ISM-1526 | 8.1.1 |
| 2 | Alert Policy Coverage | SI-4, IR-5 | C.2.1, C.5.3 | CC7.2, CC7.3 | CIS CSC 6 | 10.4, 12.10 | V-XXXXX | ISM-0120 | 8.2.1 |
| 3 | IAM Overprivileged Access | AC-6, AC-2 | C.1.1, C.1.4 | CC6.1, CC6.3 | CIS CSC 5, 6 | 7.1, 7.2 | V-XXXXX | ISM-1506 | 6.1.1 |
| 4 | Cloud Account Governance | CA-2, CM-8 | C.2.2, C.4.1 | CC6.6, CC8.1 | CIS CSC 1 | 2.4, 12.5 | V-XXXXX | ISM-1555 | 4.1.1 |
| 5 | Network Exposure Analysis | SC-7, AC-4 | C.3.13, C.4.6 | CC6.1, CC6.6 | CIS CSC 9, 12 | 1.2, 1.3 | V-XXXXX | ISM-1416 | 7.1.1 |
| 6 | Encryption at Rest | SC-28, SC-12 | C.3.8, C.3.10 | CC6.1, CC6.7 | CIS CSC 3 | 3.4, 3.5 | V-XXXXX | ISM-0457 | 7.2.1 |
| 7 | Container Image Vuln | RA-5, SI-2 | C.3.4, C.5.2 | CC7.1 | CIS CSC 7 | 6.3, 11.3 | V-XXXXX | ISM-1143 | 8.1.2 |
| 8 | Host Compliance Posture | CM-6, CM-2 | C.2.3, C.3.1 | CC6.1, CC8.1 | CIS CSC 4 | 2.2, 2.3 | V-XXXXX | ISM-1407 | 5.1.1 |
| 9 | Runtime Protection | SI-4, SI-7 | C.5.3, C.5.2 | CC7.2 | CIS CSC 8 | 11.5 | V-XXXXX | ISM-1233 | 8.3.1 |
| 10 | Defender Deployment | SI-4, CM-8 | C.2.4, C.5.1 | CC6.1, CC7.1 | CIS CSC 1, 2 | 11.4 | V-XXXXX | ISM-1034 | 8.1.3 |
| 11 | Registry Scanning | RA-5, CM-3 | C.3.4, C.5.2 | CC7.1, CC8.1 | CIS CSC 7 | 6.3 | V-XXXXX | ISM-1143 | 8.1.4 |
| 12 | Firewall Rule Audit | AC-4, SC-7 | C.3.13, C.4.6 | CC6.1, CC6.6 | CIS CSC 9 | 1.2, 1.3 | V-207184 | ISM-1416 | 7.1.2 |
| 13 | Zone Segmentation | SC-7, AC-4 | C.3.12, C.3.13 | CC6.1, CC6.6 | CIS CSC 12 | 1.2, 1.4 | V-207187 | ISM-1181 | 7.1.3 |
| 14 | SSL/TLS Decryption | SC-8, SI-4 | C.3.8, C.5.3 | CC6.1, CC6.7 | CIS CSC 9 | 4.1, 4.2 | V-207190 | ISM-0490 | 7.2.2 |
| 15 | GlobalProtect Config | IA-2, AC-17 | C.1.1, C.3.7 | CC6.1, CC6.2 | CIS CSC 13 | 8.3, 8.4 | V-207193 | ISM-1504 | 6.2.1 |
| 16 | Threat Prevention | SI-3, SI-4 | C.5.2, C.5.3 | CC6.8, CC7.1 | CIS CSC 8, 10 | 5.2, 5.3 | V-207196 | ISM-1288 | 8.2.2 |
| 17 | WildFire Analysis | SI-3, SI-4 | C.5.2, C.5.3 | CC6.8, CC7.1 | CIS CSC 8, 10 | 5.2 | V-207199 | ISM-1288 | 8.2.3 |
| 18 | URL Filtering | SC-7, SI-4 | C.3.13, C.5.3 | CC6.1, CC6.8 | CIS CSC 9 | 1.2, 6.2 | V-207202 | ISM-0261 | 7.3.1 |
| 19 | Admin Role Audit | AC-2, AC-6 | C.1.1, C.1.4 | CC6.1, CC6.3 | CIS CSC 5, 6 | 7.1, 8.2 | V-207205 | ISM-1506 | 6.1.2 |
| 20 | Logging & SIEM | AU-2, AU-6 | C.3.1, C.3.3 | CC7.2, CC7.3 | CIS CSC 6, 8 | 10.1, 10.2 | V-207208 | ISM-0580 | 8.4.1 |
| 21 | Data Loss Prevention | SC-28, SI-4 | C.3.8, C.5.3 | CC6.1, CC6.7 | CIS CSC 3 | 3.4, 3.5 | V-XXXXX | ISM-0457 | 7.2.3 |
| 22 | File Blocking | SI-3, SC-7 | C.5.2, C.5.3 | CC6.8 | CIS CSC 8, 10 | 5.2 | V-XXXXX | ISM-1288 | 8.2.4 |
| 23 | System Hardening | CM-6, CM-7 | C.2.3, C.3.1 | CC6.1, CC8.1 | CIS CSC 4 | 2.2, 2.3 | V-207211 | ISM-0380 | 5.1.2 |
| 24 | Cloud Discovery | CM-8, RA-5 | C.2.2, C.2.4 | CC6.1, CC7.1 | CIS CSC 1 | 11.2 | V-XXXXX | ISM-1034 | 4.1.2 |
| 25 | CI/CD Pipeline Security | SA-11, CM-3 | C.3.4, C.5.2 | CC8.1 | CIS CSC 7 | 6.3, 6.5 | V-XXXXX | ISM-1143 | 9.1.1 |

## 6. Existing Tools

| Tool | Description | Relevance |
|---|---|---|
| [Checkov](https://github.com/bridgecrewio/checkov) | Open-source IaC security scanner by Bridgecrew (now Prisma Cloud); 750+ built-in policies for Terraform, CloudFormation, Kubernetes, Docker | Reference for CSPM policy logic; can be invoked alongside paloalto-sec-inspector for IaC scanning |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud security auditing tool by NCC Group; generates HTML reports from API-gathered cloud configuration data | Reference for cloud posture data collection patterns and report generation |
| [pan-os-python](https://github.com/PaloAltoNetworks/pan-os-python) | Official PAN-OS SDK for Python; object model for Firewall, Panorama, SecurityRule, Zone, etc. | Primary SDK for PAN-OS configuration auditing; use as data collection layer |
| [prismacloud-api-python](https://github.com/PaloAltoNetworks/prismacloud-api-python) | Official Prisma Cloud Python SDK for CSPM, CWPP, and CCS APIs with reference scripts | SDK for Prisma Cloud data collection |
| [prismacloud-cli](https://pypi.org/project/prismacloud-cli/) | CLI tool wrapping Prisma Cloud APIs for operational workflows | Reference for CLI patterns and API interaction |
| [pango](https://github.com/PaloAltoNetworks/pango) | Go library for PAN-OS (community/Palo Alto); alternative to pan-os-python for Go implementations | Potential Go SDK for PAN-OS auditing if building in Go |
| [Iron-Skillet](https://github.com/PaloAltoNetworks/iron-skillet) | Day-one security best practice configuration templates for PAN-OS | Reference for security baseline comparison |

## 7. Architecture

The project mirrors the structure of [okta-inspector](https://github.com/ethanolivertroy/okta-inspector):

```
paloalto-sec-inspector/
├── spec.md
├── pyproject.toml
├── src/
│   └── paloalto_inspector/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py                  # Click/Typer CLI entrypoint
│       ├── client.py               # API client abstraction (Prisma Cloud + PAN-OS)
│       ├── clients/
│       │   ├── __init__.py
│       │   ├── prisma_cspm.py      # Prisma Cloud CSPM API client
│       │   ├── prisma_cwpp.py      # Prisma Cloud CWPP/Compute API client
│       │   └── panos.py            # PAN-OS XML/REST API client
│       ├── collector.py            # Orchestrates data collection across all clients
│       ├── engine.py               # Compliance evaluation engine
│       ├── models.py               # Data models (controls, findings, severities)
│       ├── output.py               # Output formatting (JSON, table, summary)
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── base.py             # Base analyzer class
│       │   ├── common.py           # Shared control evaluation logic
│       │   ├── cspm.py             # Prisma Cloud CSPM controls (1-6)
│       │   ├── cwpp.py             # Prisma Cloud CWPP controls (7-11, 24-25)
│       │   ├── panos.py            # PAN-OS controls (12-18, 21-23)
│       │   ├── cross_platform.py   # Cross-platform controls (19-20)
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
│   ├── test_cspm_analyzer.py
│   ├── test_cwpp_analyzer.py
│   ├── test_panos_analyzer.py
│   ├── test_engine.py
│   └── testdata/
│       ├── prisma_compliance_posture.json
│       ├── prisma_alerts.json
│       ├── cwpp_images.json
│       ├── cwpp_defenders.json
│       ├── panos_security_rules.xml
│       ├── panos_zones.xml
│       └── panos_system_config.xml
└── COPYING
```

**Key design decisions:**
- **Multiple clients** (`clients/` subpackage) because the tool interfaces with three distinct APIs (CSPM, CWPP, PAN-OS), each with different auth and transport.
- **Analyzer per domain** (`cspm.py`, `cwpp.py`, `panos.py`) plus cross-platform analyzers for controls that span APIs (e.g., admin roles exist in both Prisma Cloud and PAN-OS).
- **Framework-specific analyzers** map the 25 controls to specific framework requirements with detailed evidence collection.
- **Reporter per framework** generates framework-specific output formats (e.g., STIG CKL XML, FedRAMP SSP narrative).

## 8. CLI Interface

```bash
# Full audit across all three surfaces
paloalto-inspector audit \
  --prisma-url "$PRISMA_API_URL" \
  --prisma-access-key "$PRISMA_ACCESS_KEY_ID" \
  --prisma-secret-key "$PRISMA_SECRET_KEY" \
  --panos-host "$PANOS_HOST" \
  --panos-api-key "$PANOS_API_KEY" \
  --format json \
  --output report.json

# CSPM-only audit
paloalto-inspector audit --scope cspm \
  --prisma-url "$PRISMA_API_URL" \
  --prisma-access-key "$PRISMA_ACCESS_KEY_ID" \
  --prisma-secret-key "$PRISMA_SECRET_KEY" \
  --framework fedramp \
  --format table

# CWPP-only audit (containers and hosts)
paloalto-inspector audit --scope cwpp \
  --prisma-url "$PRISMA_API_URL" \
  --prisma-access-key "$PRISMA_ACCESS_KEY_ID" \
  --prisma-secret-key "$PRISMA_SECRET_KEY" \
  --controls 7,8,9,10,11

# PAN-OS firewall audit
paloalto-inspector audit --scope panos \
  --panos-host 10.0.0.1 \
  --panos-api-key "$PANOS_API_KEY" \
  --framework stig \
  --format stig-ckl \
  --output firewall-stig.ckl

# Panorama-managed multi-firewall audit
paloalto-inspector audit --scope panos \
  --panos-host panorama.corp.com \
  --panos-api-key "$PANOS_API_KEY" \
  --panorama \
  --device-group "Production-DG" \
  --format json

# Generate executive summary
paloalto-inspector report executive \
  --input report.json \
  --format html

# Generate compliance matrix
paloalto-inspector report matrix \
  --input report.json \
  --frameworks fedramp,cmmc,pci-dss \
  --format csv

# List available controls
paloalto-inspector controls list --scope all

# Validate connectivity
paloalto-inspector test-connection \
  --prisma-url "$PRISMA_API_URL" \
  --prisma-access-key "$PRISMA_ACCESS_KEY_ID" \
  --prisma-secret-key "$PRISMA_SECRET_KEY" \
  --panos-host "$PANOS_HOST" \
  --panos-api-key "$PANOS_API_KEY"
```

## 9. Build Sequence

| Phase | Scope | Deliverables |
|---|---|---|
| **Phase 1: Foundation** | Project scaffold, models, CLI skeleton | `pyproject.toml`, `models.py`, `cli.py`, `engine.py`, `output.py` |
| **Phase 2: PAN-OS Client** | PAN-OS XML/REST API client, auth, connection test | `clients/panos.py`, `test_connection` command |
| **Phase 3: PAN-OS Analyzers** | Controls 12-18, 21-23 (firewall/Panorama auditing) | `analyzers/panos.py`, test fixtures, `testdata/*.xml` |
| **Phase 4: Prisma CSPM Client** | CSPM API client, JWT auth, compliance posture collection | `clients/prisma_cspm.py` |
| **Phase 5: CSPM Analyzers** | Controls 1-6 (cloud posture, IAM, encryption, alerts) | `analyzers/cspm.py`, `testdata/prisma_*.json` |
| **Phase 6: CWPP Client** | Compute API client, image/host/defender collection | `clients/prisma_cwpp.py` |
| **Phase 7: CWPP Analyzers** | Controls 7-11, 24-25 (container, host, runtime, CI/CD) | `analyzers/cwpp.py`, `testdata/cwpp_*.json` |
| **Phase 8: Cross-Platform** | Controls 19-20 (admin roles, logging spanning APIs) | `analyzers/cross_platform.py` |
| **Phase 9: Framework Analyzers** | Framework-specific mapping and evidence logic | `analyzers/{fedramp,cmmc,soc2,pci_dss,stig,irap,ismap}.py` |
| **Phase 10: Reporters** | Framework-specific report generation | `reporters/` (all framework reporters, matrix, executive) |
| **Phase 11: Testing & Polish** | Integration tests, CI pipeline, documentation | `tests/`, CI config, README |

## 10. Status

**Not yet implemented. Spec only.**
