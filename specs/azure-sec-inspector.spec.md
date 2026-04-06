---
slug: "azure-sec-inspector"
name: "Azure Security Inspector"
vendor: "Microsoft"
category: "cloud-infrastructure"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/azure-sec-inspector"
---

# azure-sec-inspector

Multi-framework security compliance audit tool for Azure and Microsoft 365 environments.

## 1. Overview

**azure-sec-inspector** is a command-line tool that audits the security posture of Azure subscriptions and Microsoft 365 tenants against eight compliance frameworks. It pulls data from Microsoft Graph API (Entra ID, Intune, Purview, Security), Azure Resource Manager (Defender for Cloud, networking, Key Vault, RBAC), and Defender for Cloud REST API, then correlates findings into unified compliance reports.

Why it matters: Azure and Microsoft 365 share a single identity plane (Entra ID) but split their security data across Graph API, ARM, and Defender for Cloud. Microsoft Secure Score gives a number but not framework-specific evidence. This tool bridges that gap, producing auditable, control-level reports mapped to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP.

## 2. APIs & SDKs

### Microsoft Graph API (graph.microsoft.com)

#### Entra ID (Azure AD)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1.0/users` | GET | Enumerate all users, properties, licenses |
| `/v1.0/users/{id}/authentication/methods` | GET | MFA methods per user |
| `/v1.0/groups` | GET | Group membership, dynamic groups |
| `/v1.0/directoryRoles` | GET | Active directory roles |
| `/v1.0/directoryRoles/{id}/members` | GET | Members of privileged roles |
| `/v1.0/identity/conditionalAccess/policies` | GET | All conditional access policies |
| `/v1.0/policies/authorizationPolicy` | GET | Tenant-wide authorization settings |
| `/v1.0/policies/authenticationMethodsPolicy` | GET | Allowed authentication methods |
| `/v1.0/policies/identitySecurityDefaultsEnforcementPolicy` | GET | Security defaults status |
| `/v1.0/domains` | GET | Domain configuration, federation |
| `/v1.0/subscribedSkus` | GET | License assignments (E3, E5, P1, P2) |
| `/v1.0/applications` | GET | App registrations |
| `/v1.0/servicePrincipals` | GET | Service principals and permissions |

#### Audit & Sign-In Logs

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1.0/auditLogs/directoryAudits` | GET | Directory audit events (30-day window) |
| `/v1.0/auditLogs/signIns` | GET | Sign-in logs with risk data (30-day window) |
| `/v1.0/auditLogs/provisioning` | GET | Provisioning logs |
| `/beta/reports/authenticationMethods/userRegistrationDetails` | GET | MFA registration status per user |

#### Security

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1.0/security/secureScores` | GET | Microsoft Secure Score history |
| `/v1.0/security/secureScoreControlProfiles` | GET | Individual Secure Score controls |
| `/v1.0/security/alerts_v2` | GET | Unified security alerts |
| `/v1.0/security/incidents` | GET | Security incidents |

#### Identity Protection

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1.0/identityProtection/riskyUsers` | GET | Users flagged as risky |
| `/v1.0/identityProtection/riskDetections` | GET | Individual risk detections |
| `/v1.0/identityProtection/riskyServicePrincipals` | GET | Risky service principals |

#### Intune / Endpoint Management

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1.0/deviceManagement/deviceCompliancePolicies` | GET | Device compliance policies |
| `/v1.0/deviceManagement/managedDevices` | GET | Managed device inventory |
| `/v1.0/deviceManagement/deviceConfigurations` | GET | Device configuration profiles |
| `/v1.0/deviceManagement/deviceCompliancePolicySettingStateSummaries` | GET | Compliance setting summaries |

#### Purview / Information Protection

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1.0/informationProtection/sensitivityLabels` | GET | Sensitivity label definitions |
| `/beta/security/informationProtection/sensitivityLabels/evaluate` | POST | Label evaluation |
| `/v1.0/security/labels/retentionLabels` | GET | Retention labels |

#### Mail & Collaboration

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1.0/users/{id}/mailboxSettings` | GET | Mailbox settings incl. forwarding |
| `/v1.0/admin/sharepoint/settings` | GET | SharePoint sharing settings |
| `/beta/teamwork/teamTemplates` | GET | Teams templates and policies |

### Azure Resource Manager (management.azure.com)

#### Defender for Cloud

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/providers/Microsoft.Security/alerts` | GET | Defender security alerts |
| `/providers/Microsoft.Security/assessments` | GET | Security assessments and recommendations |
| `/providers/Microsoft.Security/complianceResults` | GET | Regulatory compliance results |
| `/providers/Microsoft.Security/regulatoryComplianceStandards` | GET | Enabled compliance standards |
| `/providers/Microsoft.Security/regulatoryComplianceControls` | GET | Control-level compliance |
| `/providers/Microsoft.Security/regulatoryComplianceAssessments` | GET | Assessment-level compliance |
| `/providers/Microsoft.Security/securityContacts` | GET | Security contact configuration |
| `/providers/Microsoft.Security/autoProvisioningSettings` | GET | Auto-provisioning status |
| `/providers/Microsoft.Security/pricings` | GET | Defender plan enablement per resource type |

#### Networking

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/providers/Microsoft.Network/networkSecurityGroups` | GET | NSG rules |
| `/providers/Microsoft.Network/virtualNetworks` | GET | VNet configuration |
| `/providers/Microsoft.Network/applicationGateways` | GET | WAF configuration |
| `/providers/Microsoft.Network/networkWatchers` | GET | Network Watcher and flow logs |

#### Key Vault

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/providers/Microsoft.KeyVault/vaults` | GET | Key Vault configuration |
| `/providers/Microsoft.KeyVault/vaults/{name}/keys` | GET | Key inventory and rotation |
| `/providers/Microsoft.KeyVault/vaults/{name}/secrets` | GET | Secret metadata (not values) |

#### Identity & Access

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/providers/Microsoft.Authorization/roleAssignments` | GET | RBAC role assignments |
| `/providers/Microsoft.Authorization/roleDefinitions` | GET | Custom role definitions |
| `/providers/Microsoft.Authorization/policyAssignments` | GET | Azure Policy assignments |
| `/providers/Microsoft.Authorization/policyDefinitions` | GET | Custom policy definitions |

#### Storage & Compute

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/providers/Microsoft.Storage/storageAccounts` | GET | Storage account configuration |
| `/providers/Microsoft.Compute/virtualMachines` | GET | VM configuration, extensions |
| `/providers/Microsoft.Sql/servers` | GET | SQL Server configuration |

#### Monitoring

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/providers/Microsoft.Insights/diagnosticSettings` | GET | Diagnostic logging configuration |
| `/providers/Microsoft.Insights/activityLogAlerts` | GET | Activity log alert rules |
| `/providers/Microsoft.Insights/logProfiles` | GET | Activity log export configuration |

### SDKs and CLIs

- **msgraph-sdk-python** — Microsoft Graph API client
- **azure-identity** — Azure authentication (DefaultAzureCredential, ClientSecretCredential)
- **azure-mgmt-security** — Defender for Cloud management
- **azure-mgmt-authorization** — RBAC and Policy
- **azure-mgmt-network** — NSG, VNet, Network Watcher
- **azure-mgmt-keyvault** — Key Vault management
- **azure-mgmt-storage** — Storage account management
- **azure-mgmt-monitor** — Diagnostic settings, alerts
- **azure-mgmt-resource** — Resource group and subscription management
- **azure-cli** — `az security`, `az ad`, `az policy`, `az network nsg`

## 3. Authentication

### OAuth 2.0 Client Credentials Flow

The tool uses an Entra ID app registration with client credentials:

1. Register an application in Entra ID
2. Grant required Microsoft Graph and ARM API permissions (application permissions)
3. Grant admin consent
4. Authenticate with tenant ID + client ID + client secret (or certificate)

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_TENANT_ID` | Yes | Entra ID tenant ID |
| `AZURE_CLIENT_ID` | Yes | App registration client ID |
| `AZURE_CLIENT_SECRET` | Yes* | Client secret (*or use certificate) |
| `AZURE_CLIENT_CERTIFICATE_PATH` | No | Path to PFX/PEM certificate (alternative to secret) |
| `AZURE_SUBSCRIPTION_ID` | No | Default subscription (auto-detected if omitted) |
| `AZURE_AUTHORITY_HOST` | No | Authority URL (defaults to `login.microsoftonline.com`; use `login.microsoftonline.us` for GCC High) |

### Credential Resolution

The tool uses `azure-identity.DefaultAzureCredential` which attempts, in order:

1. Environment variables (`AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`)
2. Managed Identity (for Azure-hosted execution)
3. Azure CLI (`az login` session)
4. Azure PowerShell session
5. Interactive browser login (optional, disabled by default)

### Required API Permissions

**Microsoft Graph (Application)**:
- `User.Read.All` — user enumeration and properties
- `Directory.Read.All` — roles, groups, policies
- `Policy.Read.All` — conditional access, authentication methods
- `SecurityEvents.Read.All` — security alerts, Secure Score
- `AuditLog.Read.All` — directory audits, sign-in logs
- `IdentityRiskyUser.Read.All` — risky user data
- `DeviceManagementConfiguration.Read.All` — Intune policies
- `DeviceManagementManagedDevices.Read.All` — managed devices
- `InformationProtectionPolicy.Read.All` — sensitivity labels
- `Mail.Read` — mailbox forwarding rules (delegated, optional)
- `Reports.Read.All` — MFA registration reports

**Azure Resource Manager**:
- `Reader` role on target subscriptions
- `Security Reader` role for Defender for Cloud data

### Multi-Tenant / Multi-Subscription

For organizations with multiple tenants or subscriptions:

```
Tenant A
  ├─ Subscription 1 (ARM audit)
  ├─ Subscription 2 (ARM audit)
  └─ Entra ID (Graph audit)

Tenant B (optional)
  ├─ Subscription 3
  └─ Entra ID
```

## 4. Security Controls

| # | Control | API Surface | Description |
|---|---------|------------|-------------|
| 1 | Conditional Access Policies | Graph | Baseline CA policies enforced (require MFA, block legacy auth, require compliant device) |
| 2 | MFA Enforcement | Graph | All users registered for MFA; no exemptions for privileged accounts |
| 3 | Secure Score | Graph | Microsoft Secure Score above threshold; critical controls addressed |
| 4 | Legacy Authentication Blocked | Graph | Legacy authentication protocols disabled via CA policy |
| 5 | Privileged Role Assignments | Graph | Global Admin count minimized; PIM enabled; no permanent assignments |
| 6 | Guest User Access | Graph | Guest user access restricted; external collaboration settings configured |
| 7 | Sign-In Risk Policies | Graph | Identity Protection sign-in risk policy enabled at medium+ risk |
| 8 | User Risk Policies | Graph | Identity Protection user risk policy enabled; self-remediation configured |
| 9 | Device Compliance | Graph (Intune) | Compliance policies defined and enforced; non-compliant devices blocked |
| 10 | DLP Policies | Graph (Purview) | Data Loss Prevention policies active for sensitive data types |
| 11 | Sensitivity Labels | Graph (Purview) | Sensitivity labels published and applied to sensitive content |
| 12 | NSG Rules | ARM | No unrestricted inbound access on admin ports (22, 3389, 3306, 1433) |
| 13 | Key Vault Access | ARM | Key Vault access policies follow least privilege; soft delete and purge protection enabled |
| 14 | Storage Encryption | ARM | Storage accounts enforce HTTPS; encryption at rest with CMK where required |
| 15 | Diagnostic Logging | ARM | Diagnostic settings enabled on all critical resources; logs sent to Log Analytics |
| 16 | Defender for Cloud Enabled | ARM | All Defender plans enabled (Servers, SQL, Storage, App Service, Key Vault, DNS, ARM) |
| 17 | RBAC Least Privilege | ARM | No Owner/Contributor at subscription scope; custom roles scoped appropriately |
| 18 | Subscription Security Contacts | ARM | Security contact email and phone configured; alert notifications enabled |
| 19 | Audit Log Retention | Graph, ARM | Audit logs retained for 90+ days; exported to external SIEM |
| 20 | Mail Forwarding Rules | Graph | No external mail forwarding rules; transport rules reviewed |
| 21 | External Sharing | Graph | SharePoint/OneDrive external sharing restricted; Teams guest access controlled |
| 22 | App Registrations | Graph | No apps with excessive permissions; credentials rotated regularly |
| 23 | Service Principal Security | Graph | No service principals with Owner/Contributor; credentials have expiry |
| 24 | Network Watcher | ARM | Network Watcher enabled in all regions; NSG flow logs active |
| 25 | Azure Policy Compliance | ARM | Mandatory policies assigned (allowed locations, required tags, allowed SKUs) |

## 5. Compliance Framework Mappings

| # | Control | FedRAMP (NIST 800-53) | CMMC 2.0 | SOC 2 | CIS Azure v2.1 | PCI-DSS v4.0 | DISA STIG | IRAP | ISMAP |
|---|---------|----------------------|----------|-------|----------------|-------------|-----------|------|-------|
| 1 | Conditional Access | AC-2, AC-3, AC-7 | AC.L2-3.1.1 | CC6.1, CC6.6 | 1.2.1, 1.2.2 | 7.2.1 | SRG-APP-000033 | ISM-1401 | 7.1.1 |
| 2 | MFA Enforcement | IA-2(1), IA-2(2) | IA.L2-3.5.3 | CC6.1 | 1.1.1, 1.1.2, 1.1.3 | 8.4.2 | SRG-APP-000149 | ISM-1401 | 7.2.1 |
| 3 | Secure Score | CA-7, SI-4 | CA.L2-3.12.3 | CC7.1 | — | 11.5.1 | SRG-APP-000516 | ISM-1228 | 8.2.1 |
| 4 | Legacy Auth Blocked | AC-17, IA-2(6) | AC.L2-3.1.12 | CC6.1, CC6.7 | 1.2.6 | 8.2.1 | SRG-APP-000295 | ISM-1557 | 7.2.2 |
| 5 | Privileged Roles | AC-6(1), AC-6(5) | AC.L2-3.1.5 | CC6.1, CC6.3 | 1.1.4, 1.23 | 7.2.2 | SRG-APP-000340 | ISM-1507 | 7.1.2 |
| 6 | Guest User Access | AC-2, AC-3 | AC.L2-3.1.1 | CC6.1, CC6.2 | 1.14 | 7.2.5 | SRG-APP-000033 | ISM-1380 | 7.1.3 |
| 7 | Sign-In Risk | IA-5(13), SI-4 | IA.L2-3.5.2 | CC6.1, CC6.8 | 1.2.3 | 8.3.1 | SRG-APP-000516 | ISM-0120 | 7.2.3 |
| 8 | User Risk | IA-5(13), SI-4 | IA.L2-3.5.2 | CC6.1, CC6.8 | 1.2.4 | 8.3.1 | SRG-APP-000516 | ISM-0120 | 7.2.4 |
| 9 | Device Compliance | CM-2, CM-6 | CM.L2-3.4.1 | CC6.1, CC6.8 | — | 6.3.1 | SRG-APP-000383 | ISM-1490 | 6.3.1 |
| 10 | DLP Policies | MP-4, SC-28 | SC.L2-3.13.16 | CC6.1, CC6.7 | — | 3.4.1 | SRG-APP-000231 | ISM-0264 | 6.2.1 |
| 11 | Sensitivity Labels | MP-4, SC-16 | SC.L2-3.13.16 | CC6.1, CC6.5 | — | 3.4.1 | SRG-APP-000231 | ISM-0264 | 6.2.2 |
| 12 | NSG Rules | AC-4, SC-7 | SC.L2-3.13.1 | CC6.1, CC6.6 | 6.1, 6.2 | 1.3.1 | SRG-APP-000142 | ISM-1416 | 6.1.1 |
| 13 | Key Vault Access | SC-12, SC-28 | SC.L2-3.13.10 | CC6.1, CC6.7 | 8.1, 8.2, 8.5 | 3.6.4 | SRG-APP-000231 | ISM-0457 | 6.2.3 |
| 14 | Storage Encryption | SC-8, SC-28 | SC.L2-3.13.8 | CC6.1, CC6.7 | 3.1, 3.7 | 3.4.1, 4.1.1 | SRG-APP-000014 | ISM-0457 | 6.2.4 |
| 15 | Diagnostic Logging | AU-2, AU-3, AU-6 | AU.L2-3.3.1 | CC7.2, CC7.3 | 5.1.1, 5.1.2 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 8.1.1 |
| 16 | Defender Enabled | SI-4, IR-4 | SI.L2-3.14.6 | CC7.2, CC7.3 | 2.1.1 through 2.1.15 | 11.5.1 | SRG-APP-000516 | ISM-1228 | 8.2.2 |
| 17 | RBAC Least Privilege | AC-6, AC-6(1) | AC.L2-3.1.5 | CC6.1, CC6.3 | 1.23 | 7.2.2 | SRG-APP-000342 | ISM-1380 | 7.1.4 |
| 18 | Security Contacts | IR-6, PM-2 | IR.L2-3.6.2 | CC7.4 | 2.1.19, 2.1.20 | 12.10.5 | SRG-APP-000516 | ISM-0072 | 9.1.1 |
| 19 | Audit Log Retention | AU-9, AU-11 | AU.L2-3.3.8 | CC7.2 | 5.1.3, 5.2.6 | 10.7.1 | SRG-APP-000125 | ISM-0859 | 8.1.2 |
| 20 | Mail Forwarding | AC-4, SC-7 | SC.L2-3.13.1 | CC6.1 | — | 1.3.4 | SRG-APP-000142 | ISM-1416 | 6.1.2 |
| 21 | External Sharing | AC-3, AC-4 | AC.L2-3.1.3 | CC6.1, CC6.6 | — | 7.2.5 | SRG-APP-000033 | ISM-0263 | 6.1.3 |
| 22 | App Registrations | CM-7, IA-5 | CM.L2-3.4.8 | CC6.1, CC6.2 | 1.11 | 8.6.3 | SRG-APP-000175 | ISM-1590 | 7.2.5 |
| 23 | Service Principals | AC-6, IA-4 | AC.L2-3.1.5 | CC6.1, CC6.3 | — | 8.6.3 | SRG-APP-000340 | ISM-1507 | 7.2.6 |
| 24 | Network Watcher | AU-12, SI-4 | AU.L2-3.3.1 | CC7.2 | 6.4, 6.5 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 8.1.3 |
| 25 | Azure Policy | CM-2, CM-6 | CM.L2-3.4.2 | CC6.1, CC8.1 | — | 6.3.1 | SRG-APP-000383 | ISM-1490 | 6.3.2 |

## 6. Existing Tools

| Tool | Language | Notes |
|------|----------|-------|
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Python | Multi-cloud auditing with Azure support. Reference for check logic. |
| [Azure Policy](https://learn.microsoft.com/en-us/azure/governance/policy/) | Managed Service | Built-in policy definitions for CIS, NIST, PCI-DSS. Inspector reads compliance state. |
| [Microsoft Compliance Manager](https://compliance.microsoft.com) | Managed Service | Microsoft's native compliance assessment. Inspector exports comparable data. |
| [Prowler](https://github.com/prowler-cloud/prowler) | Python | Added Azure support. Reference for check definitions. |
| [Steampipe](https://github.com/turbot/steampipe) | Go | SQL-based queries with Azure plugin. Reference for control queries. |
| [AzureADAssessment](https://github.com/AzureAD/AzureADAssessment) | PowerShell | Microsoft's Entra ID assessment tool. Reference for identity checks. |
| [Monkey365](https://github.com/silverhack/monkey365) | PowerShell | Azure and M365 security auditing. Reference for M365 checks. |
| [Microsoft Secure Score](https://security.microsoft.com/securescore) | Managed Service | Native security posture scoring. Inspector ingests this data. |

## 7. Architecture

### Package Structure

```
azure-sec-inspector/
├── spec.md
├── pyproject.toml
├── src/
│   └── azure_sec_inspector/
│       ├── __init__.py
│       ├── cli.py                  # Click/Typer CLI entry point
│       ├── client.py               # Azure credential management, Graph + ARM clients
│       ├── collector.py            # Data collection orchestrator (Graph + ARM)
│       ├── engine.py               # Analysis engine: runs all analyzers, aggregates results
│       ├── models.py               # Pydantic models: Finding, Control, ComplianceResult
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── base.py             # BaseAnalyzer ABC
│       │   ├── common.py           # Shared analysis utilities
│       │   ├── fedramp.py          # NIST 800-53 control mapping and evaluation
│       │   ├── cmmc.py             # CMMC 2.0 practice mapping and evaluation
│       │   ├── soc2.py             # SOC 2 Trust Services Criteria evaluation
│       │   ├── cis.py              # CIS Azure Foundations Benchmark evaluation
│       │   ├── pci_dss.py          # PCI-DSS v4.0 requirement evaluation
│       │   ├── stig.py             # DISA STIG evaluation
│       │   ├── irap.py             # IRAP (Australian ISM) evaluation
│       │   └── ismap.py            # ISMAP (Japanese cloud security) evaluation
│       └── reporters/
│           ├── __init__.py
│           ├── executive.py        # Executive summary (Secure Score, pass/fail, risk)
│           ├── matrix.py           # Cross-framework compliance matrix
│           ├── fedramp.py          # FedRAMP-formatted report
│           ├── cmmc.py             # CMMC-formatted report
│           ├── soc2.py             # SOC 2 report
│           ├── cis.py              # CIS benchmark report
│           ├── pci_dss.py          # PCI-DSS report
│           ├── stig.py             # STIG checklist (XCCDF/CKL format)
│           ├── irap.py             # IRAP report
│           ├── ismap.py            # ISMAP report
│           └── json_export.py      # Machine-readable JSON/OSCAL export
└── tests/
    ├── conftest.py
    ├── test_models.py
    ├── test_client.py
    ├── test_collector.py
    ├── test_analyzers/
    │   ├── test_common.py
    │   ├── test_fedramp.py
    │   └── ...
    └── test_reporters/
        └── ...
```

### Data Flow

```
CLI (cli.py)
  │
  ├─ Client (client.py)          ← DefaultAzureCredential, Graph + ARM token acquisition
  │
  ├─ Collector (collector.py)     ← Calls Graph API + ARM API, normalizes into models
  │     ├─ EntraIDCollector       ← Users, roles, CA policies, auth methods
  │     ├─ AuditLogCollector      ← Directory audits, sign-in logs
  │     ├─ SecurityCollector      ← Secure Score, alerts, Identity Protection
  │     ├─ IntuneCollector        ← Device compliance, configurations
  │     ├─ PurviewCollector       ← Sensitivity labels, DLP policies
  │     ├─ DefenderCollector      ← Defender plans, assessments, regulatory compliance
  │     ├─ NetworkCollector       ← NSGs, VNets, Network Watcher, flow logs
  │     ├─ KeyVaultCollector      ← Vault config, key rotation, access policies
  │     ├─ RBACCollector          ← Role assignments, custom roles, Azure Policy
  │     ├─ StorageCollector       ← Storage account encryption, access config
  │     └─ MonitoringCollector    ← Diagnostic settings, activity log alerts
  │
  ├─ Engine (engine.py)           ← Runs analyzers against collected data
  │     ├─ FedRAMPAnalyzer
  │     ├─ CMMCAnalyzer
  │     ├─ SOC2Analyzer
  │     ├─ CISAnalyzer
  │     ├─ PCIDSSAnalyzer
  │     ├─ STIGAnalyzer
  │     ├─ IRAPAnalyzer
  │     └─ ISMAPAnalyzer
  │
  └─ Reporters                    ← Generate framework-specific output
        ├─ Markdown reports
        ├─ JSON/OSCAL export
        └─ STIG CKL/XCCDF
```

## 8. CLI Interface

```bash
# Full audit: Entra ID + all subscriptions, all frameworks
azure-sec-inspector audit

# Audit specific frameworks
azure-sec-inspector audit --frameworks fedramp,cmmc,pci-dss

# Audit only Entra ID / Microsoft 365 (no ARM)
azure-sec-inspector audit --scope entra

# Audit only Azure resources (no Graph API)
azure-sec-inspector audit --scope azure

# Specify tenant and subscription
azure-sec-inspector audit --tenant-id <GUID> --subscription-id <GUID>

# Audit multiple subscriptions
azure-sec-inspector audit --subscription-id sub1,sub2,sub3

# Audit all subscriptions the credential has access to
azure-sec-inspector audit --all-subscriptions

# GCC High / government cloud
azure-sec-inspector audit --cloud us-gov

# Output directory and format
azure-sec-inspector audit --output ./reports --format json

# Single control check
azure-sec-inspector check mfa-enforcement

# List all controls
azure-sec-inspector controls list

# List controls for a specific framework
azure-sec-inspector controls list --framework cmmc

# Export OSCAL-formatted results
azure-sec-inspector audit --format oscal --output ./oscal-results

# Dry run: show required permissions and API calls
azure-sec-inspector audit --dry-run

# Verbose output for debugging
azure-sec-inspector audit -v --log-level debug

# Compare two audit snapshots
azure-sec-inspector diff ./reports/2026-03-01 ./reports/2026-03-24
```

## 9. Build Sequence

### Phase 1: Foundation

- Project scaffolding (pyproject.toml, src layout, CI)
- `client.py` — Azure credential management (DefaultAzureCredential, client_secret, certificate)
- `models.py` — Pydantic models for findings, controls, compliance results
- `cli.py` — basic Click/Typer CLI skeleton

### Phase 2: Entra ID & Identity

- EntraIDCollector — users, groups, roles, conditional access, authentication methods
- SecurityCollector — Secure Score, alerts
- AuditLogCollector — directory audits, sign-in logs (30-day window)
- Controls 1-8: CA policies, MFA, Secure Score, legacy auth, privileged roles, guest access, sign-in risk, user risk

### Phase 3: Microsoft 365 & Data Protection

- IntuneCollector — device compliance policies, managed devices
- PurviewCollector — sensitivity labels, DLP policies
- Mail/collaboration settings — forwarding rules, external sharing
- Controls 9-11, 20-23: device compliance, DLP, sensitivity labels, mail forwarding, external sharing, app registrations, service principals

### Phase 4: Azure Infrastructure

- DefenderCollector — Defender plans, assessments, regulatory compliance
- NetworkCollector — NSGs, VNets, Network Watcher, flow logs
- KeyVaultCollector — vault config, key rotation, access policies
- RBACCollector — role assignments, custom roles, Azure Policy
- StorageCollector — encryption, access tier, HTTPS enforcement
- MonitoringCollector — diagnostic settings, activity log alerts
- Controls 12-19, 24-25: NSGs, Key Vault, encryption, logging, Defender, RBAC, security contacts, audit retention, Network Watcher, Azure Policy

### Phase 5: Analyzers

- `base.py` — BaseAnalyzer ABC with common evaluation logic
- Framework-specific analyzers: FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, ISMAP
- Control-to-framework mapping tables
- Scoring logic (pass/fail/not-applicable/manual-review)

### Phase 6: Reporters & Polish

- Executive summary reporter (Secure Score integration, pass/fail breakdown)
- Framework-specific report generators (Markdown, JSON)
- Cross-framework compliance matrix
- STIG CKL/XCCDF export
- OSCAL export format
- Diff tool for comparing audit snapshots
- Multi-subscription aggregation reports

### Phase 7: Hardening

- Comprehensive test suite (unit, integration with mocked Graph/ARM responses)
- Rate limiting and retry logic (Graph API throttling: 429 handling)
- Pagination handling (Graph @odata.nextLink, ARM nextLink)
- Government cloud support (GCC, GCC High, DoD)
- Error handling for missing permissions / unlicensed features
- Documentation and required permissions manifest

## 10. Status

Not yet implemented. Spec only.
