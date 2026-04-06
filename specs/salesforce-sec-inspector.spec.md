---
slug: "salesforce-sec-inspector"
name: "Salesforce Security Inspector"
vendor: "Salesforce"
category: "saas-collaboration"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/salesforce-sec-inspector"
---

# salesforce-sec-inspector

Multi-framework security compliance audit tool for Salesforce.

## Overview

salesforce-sec-inspector is a command-line tool that audits Salesforce org configurations against multiple security compliance frameworks. It queries the REST API, Tooling API, Metadata API, and Shield Platform to evaluate security settings, user permissions, authentication policies, and data protection controls, then maps findings to FedRAMP, CMMC 2.0, SOC 2, CIS Benchmarks, PCI-DSS, DISA STIG, IRAP, and ISMAP controls.

Salesforce orgs accumulate permission sprawl, stale integrations, and misconfigured session policies over time. The built-in Security Health Check provides a 0-100 score but does not map to external compliance frameworks. salesforce-sec-inspector bridges that gap by correlating Health Check findings with granular permission set analysis, connected app inventory, Shield event monitoring, and setup audit trail data to produce actionable, framework-mapped compliance reports.

## APIs & SDKs

### REST API

Standard Salesforce REST API for sObject queries and CRUD operations.

| Endpoint | Purpose |
|----------|---------|
| `GET /services/data/vXX.0/sobjects/SetupAuditTrail` | 180-day admin change history |
| `GET /services/data/vXX.0/sobjects/User` | User records (active, frozen, profile assignments) |
| `GET /services/data/vXX.0/sobjects/Profile` | Profile definitions and settings |
| `GET /services/data/vXX.0/sobjects/LoginHistory` | Login events with source IP, status, client |
| `GET /services/data/vXX.0/sobjects/AuthSession` | Active sessions |
| `GET /services/data/vXX.0/sobjects/TwoFactorInfo` | MFA enrollment status per user |
| `GET /services/data/vXX.0/sobjects/ConnectedApplication` | Connected app inventory |
| `GET /services/data/vXX.0/sobjects/Certificate` | Certificate management |
| `GET /services/data/vXX.0/sobjects/CustomDomain` | My Domain configuration |

### Tooling API

Programmatic access to Salesforce setup and configuration metadata.

| Endpoint | Purpose |
|----------|---------|
| `GET /services/data/vXX.0/tooling/sobjects/SecurityHealthCheck` | Overall 0-100 security score |
| `GET /services/data/vXX.0/tooling/sobjects/SecurityHealthCheckRisks` | Per-setting risk categories (HIGH/MEDIUM/LOW) |
| `GET /services/data/vXX.0/tooling/sobjects/PermissionSet` | Permission set definitions |
| `GET /services/data/vXX.0/tooling/sobjects/PermissionSetAssignment` | Permission set-to-user assignments |
| `GET /services/data/vXX.0/tooling/sobjects/FieldPermissions` | Field-level security per permission set |
| `GET /services/data/vXX.0/tooling/sobjects/ObjectPermissions` | Object-level CRUD per permission set |
| `GET /services/data/vXX.0/tooling/sobjects/SessionPermSetActivation` | Session-based permission set activations |
| `GET /services/data/vXX.0/tooling/sobjects/ProfilePasswordPolicy` | Password policy per profile |

### Metadata API

Declarative configuration retrieval for security-relevant settings.

| Endpoint | Purpose |
|----------|---------|
| `retrieve SecuritySettings` | Session timeout, IP restrictions, password policy, clickjack protection, 2FA, login hours |
| `retrieve SharingRules` | Organization-wide sharing defaults and rules |
| `retrieve RemoteSiteSetting` | Approved remote site URLs |
| `retrieve CspTrustedSite` | Content Security Policy trusted sites |
| `retrieve ExternalDataSource` | External data source configurations |
| `retrieve NamedCredential` | Named credential configurations |
| `retrieve HistoryRetentionPolicy` | Field history retention settings |
| `retrieve NetworkAccess` | Trusted IP ranges |

### Shield Platform (add-on license)

Enhanced security monitoring, encryption, and audit capabilities.

| Endpoint | Purpose |
|----------|---------|
| `GET /services/data/vXX.0/sobjects/EventLogFile` | 50+ event types (Login, API, Report, etc.) -- 24-hour log files |
| `GET /services/data/vXX.0/sobjects/FieldHistoryArchive` | Field Audit Trail -- 60 fields/object, 10-year retention |
| `GET /services/data/vXX.0/sobjects/TenantSecret` | Platform Encryption tenant secrets (AES-256) |
| `GET /services/data/vXX.0/sobjects/EncryptedFieldsInfo` | Fields currently encrypted |
| `GET /services/data/vXX.0/sobjects/EventBusSubscriber` | Platform event subscribers |
| `GET /services/data/vXX.0/sobjects/TransactionSecurityPolicy` | Transaction security policies |

**Note:** Shield Platform Encryption, Event Monitoring, and Field Audit Trail are add-on licenses. The tool detects their availability and adjusts audit scope accordingly.

### Connected Apps & OAuth

OAuth application inventory and scope management.

| Endpoint | Purpose |
|----------|---------|
| `GET /services/data/vXX.0/sobjects/ConnectedApplication` | Connected app definitions |
| `GET /services/data/vXX.0/sobjects/OauthToken` | Active OAuth tokens |
| SOQL: `SELECT ... FROM SetupEntityAccess WHERE SetupEntityType = 'ConnectedApplication'` | App-to-profile/permset assignments |
| Setup API: Connected App policies | Admin pre-authorization, IP relaxation, refresh token policy |

### SOQL Queries

Key queries for security analysis.

```sql
-- Active users with profile and permission sets
SELECT Id, Username, Profile.Name, IsActive, LastLoginDate, UserType
FROM User WHERE IsActive = true

-- Permission set assignments (who has what)
SELECT Assignee.Username, PermissionSet.Name, PermissionSet.IsOwnedByProfile
FROM PermissionSetAssignment

-- Setup audit trail (admin changes)
SELECT CreatedDate, CreatedBy.Username, Action, Section, Display
FROM SetupAuditTrail ORDER BY CreatedDate DESC

-- Login history with failure analysis
SELECT LoginTime, UserId, SourceIp, Status, LoginType, Application, Browser
FROM LoginHistory WHERE LoginTime = LAST_N_DAYS:30

-- Connected apps with scope
SELECT Name, ContactEmail, StartUrl, OptionsAllowAdminApprovedUsersOnly
FROM ConnectedApplication
```

### SDKs and CLI Tools

| Tool | Usage |
|------|-------|
| [simple-salesforce](https://github.com/simple-salesforce/simple-salesforce) | Python SDK for REST, Tooling, Metadata, and Bulk APIs |
| [Salesforce CLI (sf)](https://developer.salesforce.com/tools/salesforcecli) | Official CLI for org management and metadata retrieval |
| `requests` | Direct HTTP for endpoints not covered by simple-salesforce |

## Authentication

### JWT Bearer Flow (recommended for automation)

Server-to-server authentication using a connected app with a digital certificate. No interactive login required.

```bash
export SF_CONSUMER_KEY=3MVG9...
export SF_USERNAME=admin@myorg.example.com
export SF_PRIVATE_KEY_FILE=/path/to/server.key
export SF_INSTANCE_URL=https://myorg.my.salesforce.com
```

### OAuth 2.0 Authorization Code Flow

Interactive browser-based login. Suitable for development and ad-hoc audits.

```bash
export SF_CONSUMER_KEY=3MVG9...
export SF_CONSUMER_SECRET=...
export SF_INSTANCE_URL=https://myorg.my.salesforce.com
```

### Username/Password + Security Token

Legacy authentication. Not recommended for production use.

```bash
export SF_USERNAME=admin@myorg.example.com
export SF_PASSWORD=...
export SF_SECURITY_TOKEN=...
export SF_INSTANCE_URL=https://myorg.my.salesforce.com
```

### Credential File (alternative)

```bash
export SF_CREDENTIALS_FILE=/path/to/salesforce-credentials.json
```

The credentials file supports all three auth methods with a `"grant_type"` field (`jwt-bearer`, `authorization_code`, or `password`).

### Required Permissions

| Permission | Purpose |
|------------|---------|
| `View Setup and Configuration` | Access security settings |
| `View All Users` | User and permission analysis |
| `View Event Log Files` | Shield event monitoring (if licensed) |
| `Manage Encryption Keys` | Shield encryption audit (if licensed) |
| `API Enabled` | API access for all queries |
| `Query All Files` | Full SetupAuditTrail access |
| `Customize Application` | Metadata API access |

## Security Controls

| # | Control | API Source | Description |
|---|---------|-----------|-------------|
| 1 | Health Check Score | Tooling API | Overall security score (0-100) with per-setting risk breakdown |
| 2 | Session Timeout | Metadata API | Session timeout <= 2 hours; force logout on session timeout |
| 3 | Password Policy | Metadata API, Tooling API | Minimum length >= 12, complexity requirements, expiration <= 90 days, history >= 12 |
| 4 | MFA/2FA Enforcement | REST API, Tooling API | MFA required for all UI logins; per-user enrollment verification |
| 5 | IP Range Restrictions | Metadata API | Login IP ranges configured per profile; org-wide trusted IP ranges |
| 6 | Login Hour Restrictions | Metadata API | Login hours restricted for sensitive profiles |
| 7 | API Access Controls | Tooling API | API-only profiles identified; API access limited to required profiles |
| 8 | Field-Level Security | Tooling API | Sensitive fields (SSN, credit card) restricted to minimum profiles |
| 9 | Permission Set Review | Tooling API | Overprivileged permission sets; Modify All Data / View All Data usage |
| 10 | Profile Permissions | Tooling API, REST API | System admin count; profiles with excessive object permissions |
| 11 | Connected App OAuth Scopes | REST API | Connected apps with broad scopes (full, api); unapproved apps |
| 12 | Sharing Settings | Metadata API | Organization-wide defaults not set to Public; sharing rules reviewed |
| 13 | Guest User Access | REST API, Tooling API | Guest user profiles with excessive permissions; public sites exposure |
| 14 | Login Forensics | REST API | Failed login patterns; login from unexpected geolocations/IPs |
| 15 | Setup Change Tracking | REST API | High-risk setup changes (permission changes, new admins, IP changes) |
| 16 | Data Encryption Status | Shield API | Platform Encryption enabled for sensitive fields; tenant secret rotation |
| 17 | Certificate Management | REST API | Certificate expiration; self-signed vs CA-signed |
| 18 | My Domain Enforcement | REST API, Metadata API | Custom domain configured; login policy set to prevent login via login.salesforce.com |
| 19 | Clickjack Protection | Metadata API | Clickjack protection enabled for setup pages, Visualforce, and non-setup pages |
| 20 | CSRF Protection | Metadata API | Cross-Site Request Forgery protection enabled |

## Compliance Framework Mappings

| # | Control | FedRAMP | CMMC 2.0 | SOC 2 | CIS SF | PCI-DSS 4.0 | DISA STIG | IRAP | ISMAP |
|---|---------|---------|----------|-------|--------|-------------|-----------|------|-------|
| 1 | Health Check Score | CA-2 | L2: CA.L2-3.12.1 | CC4.1 | 1.1 | 11.3.1 | SRG-APP-000516 | ISM-1526 | 11.3.1 |
| 2 | Session Timeout | AC-12 | L2: AC.L2-3.1.10 | CC6.1 | 2.1 | 8.2.8 | SRG-APP-000295 | ISM-1164 | 8.2.8 |
| 3 | Password Policy | IA-5(1) | L2: IA.L2-3.5.7 | CC6.1 | 2.2 | 8.3.6 | SRG-APP-000164 | ISM-0421 | 8.3.6 |
| 4 | MFA/2FA Enforcement | IA-2(1) | L2: IA.L2-3.5.3 | CC6.1 | 2.3 | 8.4.1 | SRG-APP-000149 | ISM-1401 | 8.4.1 |
| 5 | IP Range Restrictions | AC-3, SC-7 | L2: SC.L2-3.13.1 | CC6.6 | 2.4 | 1.3.1 | SRG-APP-000142 | ISM-1416 | 1.3.1 |
| 6 | Login Hour Restrictions | AC-2(5) | L2: AC.L2-3.1.8 | CC6.1 | 2.5 | 7.2.1 | SRG-APP-000025 | ISM-0988 | 7.2.1 |
| 7 | API Access Controls | AC-3 | L2: AC.L2-3.1.2 | CC6.3 | 3.1 | 7.2.2 | SRG-APP-000033 | ISM-1508 | 7.2.2 |
| 8 | Field-Level Security | AC-3 | L2: AC.L2-3.1.3 | CC6.1 | 3.2 | 7.2.1 | SRG-APP-000033 | ISM-0405 | 7.2.1 |
| 9 | Permission Set Review | AC-6(1) | L2: AC.L2-3.1.5 | CC6.3 | 3.3 | 7.2.2 | SRG-APP-000340 | ISM-1508 | 7.2.2 |
| 10 | Profile Permissions | AC-6(5) | L2: AC.L2-3.1.6 | CC6.3 | 3.4 | 7.2.1 | SRG-APP-000340 | ISM-1508 | 7.2.1 |
| 11 | Connected App OAuth | AC-3 | L2: AC.L2-3.1.2 | CC6.1 | 4.1 | 6.4.1 | SRG-APP-000033 | ISM-1508 | 6.4.1 |
| 12 | Sharing Settings | AC-4 | L2: AC.L2-3.1.3 | CC6.1 | 3.5 | 7.2.1 | SRG-APP-000038 | ISM-0405 | 7.2.1 |
| 13 | Guest User Access | AC-14 | L2: AC.L2-3.1.1 | CC6.1 | 3.6 | 7.2.5 | SRG-APP-000033 | ISM-1508 | 7.2.5 |
| 14 | Login Forensics | AU-6 | L2: AU.L2-3.3.5 | CC7.2 | 5.1 | 10.6.1 | SRG-APP-000343 | ISM-0580 | 10.6.1 |
| 15 | Setup Change Tracking | AU-2, AU-3 | L2: AU.L2-3.3.1 | CC7.2 | 5.2 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 10.2.1 |
| 16 | Data Encryption | SC-28(1) | L2: SC.L2-3.13.16 | CC6.1 | 6.1 | 3.4.1 | SRG-APP-000231 | ISM-0457 | 3.4.1 |
| 17 | Certificate Mgmt | SC-17 | L2: SC.L2-3.13.10 | CC6.1 | 6.2 | 4.1.1 | SRG-APP-000514 | ISM-1139 | 4.1.1 |
| 18 | My Domain | IA-8 | L2: IA.L2-3.5.2 | CC6.1 | 2.6 | 2.2.1 | SRG-APP-000516 | ISM-1590 | 2.2.1 |
| 19 | Clickjack Protection | SC-18 | L2: SC.L2-3.13.1 | CC6.1 | 7.1 | 6.2.4 | SRG-APP-000516 | ISM-1486 | 6.2.4 |
| 20 | CSRF Protection | SC-18 | L2: SC.L2-3.13.1 | CC6.1 | 7.2 | 6.2.4 | SRG-APP-000516 | ISM-1486 | 6.2.4 |

## Existing Tools

| Tool | Notes |
|------|-------|
| [Salesforce Security Health Check](https://help.salesforce.com/s/articleView?id=sf.security_health_check.htm) | Built-in. 0-100 score with per-setting risk. No external framework mapping. No API automation story until Spring '20. |
| [Varonis for Salesforce](https://www.varonis.com/integrations/salesforce) | Commercial. Permission analysis, data classification, threat detection. No compliance framework mapping. |
| [OwnBackup (now Own)](https://www.owndata.com/) | Commercial. Primarily backup/restore. Some security analytics for permissions. |
| [Sonar](https://www.sonarsource.com/) | Code quality for Apex/LWC. Not configuration security. |
| [Clayton](https://www.yourorg.io/) | Commercial. Org health and technical debt analysis. Some security overlap. |

**Gap:** No open-source tool maps Salesforce security settings to FedRAMP, CMMC 2.0, DISA STIG, IRAP, and ISMAP. The built-in Health Check is a good starting point but provides no compliance framework context. salesforce-sec-inspector extends the Health Check with external framework mapping, permission analysis, and automated evidence collection.

## Architecture

Package structure mirroring the okta-inspector pattern:

```
salesforce-sec-inspector/
├── spec.md
├── pyproject.toml
├── src/
│   └── salesforce_sec_inspector/
│       ├── __init__.py
│       ├── __main__.py          # Entry point
│       ├── cli.py               # Click CLI definition
│       ├── client.py            # Salesforce API client (REST, Tooling, Metadata, Shield)
│       ├── collector.py         # Data collection across all API surfaces
│       ├── engine.py            # Audit engine orchestrating controls
│       ├── models.py            # Pydantic models for findings and controls
│       ├── output.py            # Console output formatting
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── base.py          # Base analyzer interface
│       │   ├── common.py        # Shared analysis utilities
│       │   ├── fedramp.py       # FedRAMP AC/AU/IA/SC family mapping
│       │   ├── cmmc.py          # CMMC 2.0 Level 2 practice mapping
│       │   ├── soc2.py          # SOC 2 Trust Services Criteria mapping
│       │   ├── cis.py           # CIS Salesforce Benchmark checks
│       │   ├── pci_dss.py       # PCI-DSS 4.0 requirement mapping
│       │   ├── stig.py          # DISA STIG SRG mapping
│       │   ├── irap.py          # IRAP ISM control mapping
│       │   └── ismap.py         # ISMAP control mapping
│       └── reporters/
│           ├── __init__.py
│           ├── base.py          # Base reporter interface
│           ├── executive.py     # Executive summary with Health Check score + framework status
│           ├── fedramp.py       # FedRAMP POA&M format
│           ├── cmmc.py          # CMMC assessment report format
│           ├── soc2.py          # SOC 2 evidence format
│           ├── cis.py           # CIS Benchmark scoring
│           ├── pci_dss.py       # PCI-DSS ROC evidence format
│           ├── stig.py          # STIG Checklist (.ckl) format
│           ├── irap.py          # IRAP assessment format
│           ├── ismap.py         # ISMAP assessment format
│           ├── matrix.py        # Cross-framework control matrix
│           └── validation.py    # Finding validation and deduplication
└── tests/
    ├── conftest.py
    ├── test_client.py
    ├── test_collector.py
    ├── test_engine.py
    └── test_analyzers/
        ├── test_fedramp.py
        ├── test_cmmc.py
        └── ...
```

### Key Design Decisions

- **Health Check as baseline:** The Security Health Check score and per-risk breakdown serve as the foundation. Additional controls extend coverage beyond what Health Check measures.
- **Shield detection:** The tool probes for Shield Platform availability at startup. If Event Monitoring, Field Audit Trail, or Platform Encryption are not licensed, those controls report "Not Available (Shield license required)" rather than failing.
- **Multi-API collection:** Data is gathered from REST, Tooling, Metadata, and Shield APIs in a coordinated sweep. The collector deduplicates overlapping data (e.g., password policy appears in both Metadata and Tooling APIs).
- **SOQL-first for bulk data:** User, permission, and login data is collected via SOQL queries for efficiency. API-per-record calls are avoided except where SOQL is not supported.

## CLI Interface

```bash
# Full org audit with all frameworks
salesforce-sec-inspector audit --all-frameworks

# Audit with specific framework
salesforce-sec-inspector audit --framework fedramp

# Audit specific controls only
salesforce-sec-inspector audit --controls 1,3,4,9,11

# Health Check deep-dive with framework mapping
salesforce-sec-inspector health-check --framework cmmc --output health-check.json

# Permission set analysis
salesforce-sec-inspector permissions --report overprivileged --output permissions.csv

# Connected app inventory
salesforce-sec-inspector apps --show-scopes --show-assignments

# Login forensics
salesforce-sec-inspector logins --days 30 --show-failures --geo-analysis

# Setup audit trail analysis
salesforce-sec-inspector audit-trail --days 90 --high-risk-only

# Generate cross-framework compliance matrix
salesforce-sec-inspector matrix --output matrix.html

# Generate CMMC Level 2 assessment report
salesforce-sec-inspector report --framework cmmc --level 2 --output cmmc-report.json

# Check required permissions before running
salesforce-sec-inspector check-permissions

# List available controls
salesforce-sec-inspector controls --framework pci-dss
```

### Output Formats

- `json` -- machine-readable findings with control mappings
- `html` -- interactive dashboard with Health Check gauge and framework drill-down
- `csv` -- spreadsheet-compatible for GRC tools
- `ckl` -- DISA STIG Checklist format
- `oscal` -- NIST OSCAL assessment results

## Build Sequence

### Phase 1: Foundation
- Project scaffolding (pyproject.toml, src layout, CI)
- Salesforce authentication (JWT Bearer, OAuth 2.0, username/password)
- API client supporting REST, Tooling, Metadata, and SOQL
- Pydantic models for findings and controls

### Phase 2: Core Collection
- Security Health Check score and risk retrieval
- User, profile, and permission set enumeration
- Security settings via Metadata API
- Setup audit trail and login history collection

### Phase 3: Security Controls
- Implement controls 1-10 (Health Check, session, passwords, MFA, permissions)
- Implement controls 11-20 (OAuth, sharing, guest users, encryption, web security)
- Shield Platform detection and conditional collection
- Connected app and certificate analysis

### Phase 4: Compliance Mapping
- FedRAMP control family mapping
- CMMC 2.0 practice mapping
- SOC 2, CIS Salesforce, PCI-DSS mapping
- DISA STIG, IRAP, ISMAP mapping
- Cross-framework compliance matrix

### Phase 5: Reporting & Polish
- Executive summary with Health Check score integration
- Framework-specific report formats (POA&M, CKL, OSCAL)
- HTML dashboard with security score gauge
- Permission sprawl visualization
- Test suite with mocked API responses

## Status

Not yet implemented. Spec only.
