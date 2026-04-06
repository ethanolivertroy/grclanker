---
slug: "gcp-sec-inspector"
name: "GCP Security Inspector"
vendor: "Google Cloud"
category: "cloud-infrastructure"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/gcp-sec-inspector"
---

# gcp-sec-inspector

Multi-framework security compliance audit tool for Google Cloud Platform.

## Overview

gcp-sec-inspector is a command-line tool that audits Google Cloud Platform environments against multiple security compliance frameworks. It leverages GCP's security and asset management APIs to evaluate infrastructure configurations, IAM policies, encryption settings, and organizational constraints, then maps findings to FedRAMP, CMMC 2.0, SOC 2, CIS Benchmarks, PCI-DSS, DISA STIG, IRAP, and ISMAP controls.

GCP's security posture is governed by a hierarchy of organization policies, folder-level overrides, and project-level settings. gcp-sec-inspector traverses this hierarchy to identify misconfigurations, policy drift, and compliance gaps that manual reviews miss. SCC Premium provides the compliance manager integration, but the core audit capabilities work with standard APIs and Cloud Asset Inventory as the primary data source.

## APIs & SDKs

### Security Command Center (securitycenter.googleapis.com)

The central hub for security findings and asset visibility across the organization.

| Endpoint | Purpose |
|----------|---------|
| `GET organizations/{org}/sources/-/findings` | List all security findings |
| `GET organizations/{org}/assets` | List all assets with security marks |
| `GET organizations/{org}/sources` | List finding sources (SCC, third-party) |
| `POST organizations/{org}/findings:group` | Group findings by category/severity |
| `GET organizations/{org}/notificationConfigs` | Pub/Sub notification configs |
| `GET organizations/{org}/securityHealthAnalyticsSettings/customModules` | Custom SHA modules |
| `GET organizations/{org}/complianceReports` | Compliance posture reports (Premium) |

**Note:** SCC Premium tier is required for compliance manager, continuous exports, and container threat detection. Standard tier provides Security Health Analytics and Web Security Scanner only.

### Cloud Asset Inventory (cloudasset.googleapis.com)

The workhorse API for IAM analysis and resource discovery across all projects.

| Endpoint | Purpose |
|----------|---------|
| `POST v1/{scope}:searchAllResources` | Search resources across org/folder/project |
| `POST v1/{scope}:searchAllIamPolicies` | Search IAM policy bindings across scope |
| `POST v1/{scope}:analyzeIamPolicy` | Determine who has what access to what |
| `POST v1/{scope}:analyzeIamPolicyLongrunning` | Async IAM analysis for large orgs |
| `POST v1/{scope}:batchGetEffectiveIamPolicies` | Effective policies after inheritance |
| `POST v1/{scope}:exportAssets` | Export asset snapshot to BigQuery/GCS |
| `GET v1/{scope}:queryAssets` | SQL-like asset queries |

### Cloud IAM (iam.googleapis.com)

Service account lifecycle, key management, and custom role definitions.

| Endpoint | Purpose |
|----------|---------|
| `GET v1/projects/{project}/serviceAccounts` | List service accounts |
| `GET v1/projects/{project}/serviceAccounts/{sa}/keys` | List SA keys (check age) |
| `POST v1/projects/{project}/serviceAccounts/{sa}:getIamPolicy` | SA-level IAM bindings |
| `GET v1/projects/{project}/roles` | List custom roles |
| `GET v1/roles` | List predefined roles |
| `GET v1/permissions` | Query permissions metadata |
| `GET v1/projects/{project}/serviceAccounts/{sa}` | SA details (disabled status) |

### Cloud Audit Logs (logging.googleapis.com)

Three log streams: Admin Activity (always on, 400-day retention), Data Access (opt-in, 30-day default), and System Events (always on).

| Endpoint | Purpose |
|----------|---------|
| `POST v2/entries:list` | Query log entries |
| `GET v2/projects/{project}/sinks` | List log sinks (routing) |
| `GET v2/projects/{project}/metrics` | Log-based metrics |
| `GET v2/{resource}/cmekSettings` | CMEK config for log buckets |
| `GET v2/projects/{project}/locations/{loc}/buckets` | Log bucket configs |
| `GET v2/{resource}/settings` | Org/folder/project logging settings |

### Organization Policy (cloudresourcemanager.googleapis.com)

Hierarchical policy constraints that flow from org to folder to project.

| Endpoint | Purpose |
|----------|---------|
| `GET v1/organizations/{org}` | Organization metadata |
| `POST v2/{resource}/policies` | List effective policies |
| `GET v2/{resource}/policies/{constraint}` | Get specific policy |
| `GET v2/organizations/{org}/constraints` | List available constraints |
| `POST v1/projects/{project}:getEffectiveOrgPolicy` | Effective policy after inheritance |
| `GET v1/folders/{folder}` | Folder metadata |

### Cloud KMS (cloudkms.googleapis.com)

Key management, rotation policies, and IAM bindings for encryption keys.

| Endpoint | Purpose |
|----------|---------|
| `GET v1/projects/{project}/locations/{loc}/keyRings` | List key rings |
| `GET v1/{keyRing}/cryptoKeys` | List crypto keys |
| `GET v1/{cryptoKey}/cryptoKeyVersions` | Key version lifecycle |
| `GET v1/{cryptoKey}:getIamPolicy` | Key-level IAM bindings |
| `GET v1/{cryptoKey}` | Key details (rotation period, purpose) |
| `GET v1/{cryptoKey}/cryptoKeyVersions/{version}` | Version state (enabled/disabled/destroyed) |

### Binary Authorization (binaryauthorization.googleapis.com)

Container image verification policies for GKE and Cloud Run.

| Endpoint | Purpose |
|----------|---------|
| `GET v1/projects/{project}/policy` | Get Binary Auth policy |
| `GET v1/projects/{project}/attestors` | List attestors |
| `GET v1/projects/{project}/attestors/{attestor}` | Attestor details |

### SDKs and CLI Tools

| Tool | Usage |
|------|-------|
| `google-cloud-securitycenter` | Python SDK for SCC findings and assets |
| `google-cloud-asset` | Python SDK for Cloud Asset Inventory |
| `google-cloud-iam` | Python SDK for IAM service accounts and roles |
| `google-cloud-logging` | Python SDK for Cloud Audit Logs |
| `google-cloud-kms` | Python SDK for Cloud KMS |
| `google-cloud-resource-manager` | Python SDK for Org Policy |
| `gcloud` | CLI for all GCP services |

## Authentication

### Service Account (recommended for automation)

```bash
export GCP_CREDENTIALS_FILE=/path/to/service-account-key.json
export GCP_PROJECT_ID=my-project-id
export GCP_ORG_ID=123456789012
```

### Application Default Credentials (ADC)

```bash
gcloud auth application-default login
export GCP_PROJECT_ID=my-project-id
export GCP_ORG_ID=123456789012
```

### Required IAM Roles

| Role | Purpose |
|------|---------|
| `roles/securitycenter.findingsViewer` | Read SCC findings |
| `roles/cloudasset.viewer` | Cloud Asset Inventory queries |
| `roles/iam.securityReviewer` | IAM policy and role review |
| `roles/logging.viewer` | Audit log access |
| `roles/orgpolicy.policyViewer` | Organization policy review |
| `roles/cloudkms.viewer` | KMS key and rotation review |
| `roles/binaryauthorization.policyViewer` | Binary Auth policy review |

The tool validates required permissions at startup and reports which audit modules can run based on the authenticated principal's access.

## Security Controls

| # | Control | API Source | Description |
|---|---------|-----------|-------------|
| 1 | Service Account Key Rotation | IAM | SA keys older than 90 days; prefer Workload Identity Federation |
| 2 | Overprivileged IAM Roles | Asset Inventory | Principals with Owner/Editor at org/folder level; unused permissions |
| 3 | Public Resource Exposure | Asset Inventory, SCC | GCS buckets, BigQuery datasets, Compute instances with public access |
| 4 | VPC Firewall Rules | Asset Inventory | Overly permissive ingress rules (0.0.0.0/0), unused rules |
| 5 | Audit Logging Configuration | Logging | Data Access logs enabled per service; log sink destinations |
| 6 | Organization Policy Constraints | Org Policy | Required constraints enforced (e.g., domain-restricted sharing) |
| 7 | KMS Key Rotation | KMS | Key rotation period configured and within policy (<=365 days) |
| 8 | Binary Authorization | Binary Auth | Policy enforcement mode; attestor configuration for GKE/Cloud Run |
| 9 | VPC Flow Logs | Asset Inventory | Flow logs enabled on all subnets with appropriate retention |
| 10 | Cloud NAT Configuration | Asset Inventory | NAT gateways properly configured; no direct public IPs |
| 11 | OS Login Enforcement | Org Policy, Asset Inventory | OS Login required for Compute instances; 2FA enforcement |
| 12 | Serial Port Disabled | Org Policy, Asset Inventory | Serial port access disabled on Compute instances |
| 13 | Default Service Account Usage | IAM, Asset Inventory | Resources using default compute/App Engine SA instead of custom |
| 14 | Cross-Project Access | Asset Inventory | IAM bindings granting access across project boundaries |
| 15 | Uniform Bucket-Level Access | Asset Inventory | GCS buckets using uniform (not fine-grained) access control |
| 16 | Customer-Managed Encryption Keys (CMEK) | KMS, Asset Inventory | CMEK usage for sensitive resources; Google-managed key detection |
| 17 | DNS Security (DNSSEC) | Asset Inventory | DNSSEC enabled on Cloud DNS managed zones |
| 18 | Load Balancer SSL Policies | Asset Inventory | TLS 1.2+ minimum; restricted/modern cipher profiles |
| 19 | Cloud Armor WAF | Asset Inventory | Cloud Armor policies attached to backend services |
| 20 | API Key Restrictions | IAM | API keys with application and API restrictions configured |
| 21 | VPC Service Controls | Asset Inventory | Service perimeters configured for sensitive projects |
| 22 | Private Google Access | Asset Inventory | Subnets configured for Private Google Access |
| 23 | Shielded VM Configuration | Asset Inventory | vTPM, Secure Boot, integrity monitoring enabled |

## Compliance Framework Mappings

| # | Control | FedRAMP | CMMC 2.0 | SOC 2 | CIS GCP | PCI-DSS 4.0 | DISA STIG | IRAP | ISMAP |
|---|---------|---------|----------|-------|---------|-------------|-----------|------|-------|
| 1 | SA Key Rotation | IA-5(1) | L2: IA.L2-3.5.10 | CC6.1 | 1.17 | 8.3.9 | SRG-APP-000516 | ISM-1590 | 8.1.1 |
| 2 | Overprivileged IAM | AC-6(1) | L2: AC.L2-3.1.5 | CC6.3 | 1.1-1.5 | 7.2.1 | SRG-APP-000033 | ISM-1508 | 7.1.1 |
| 3 | Public Resources | AC-3, SC-7 | L2: AC.L2-3.1.3 | CC6.1 | 5.1, 6.2 | 1.3.1 | SRG-APP-000142 | ISM-1037 | 1.3.1 |
| 4 | VPC Firewall Rules | SC-7(5) | L2: SC.L2-3.13.5 | CC6.6 | 3.6-3.9 | 1.3.2 | SRG-APP-000142 | ISM-1416 | 1.3.2 |
| 5 | Audit Logging | AU-2, AU-3 | L2: AU.L2-3.3.1 | CC7.2 | 2.1-2.4 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 10.2.1 |
| 6 | Org Policy Constraints | CM-7 | L2: CM.L2-3.4.7 | CC6.1 | 1.14-1.15 | 2.2.1 | SRG-APP-000141 | ISM-1467 | 2.2.1 |
| 7 | KMS Key Rotation | SC-12(1) | L2: SC.L2-3.13.10 | CC6.1 | 1.18 | 3.6.4 | SRG-APP-000514 | ISM-0457 | 3.6.4 |
| 8 | Binary Authorization | SI-7 | L2: SI.L2-3.14.1 | CC7.1 | 6.13 | 6.3.2 | SRG-APP-000131 | ISM-1657 | 6.3.2 |
| 9 | VPC Flow Logs | AU-12 | L2: AU.L2-3.3.1 | CC7.2 | 3.1 | 10.6.1 | SRG-APP-000089 | ISM-0580 | 10.6.1 |
| 10 | Cloud NAT Config | SC-7 | L2: SC.L2-3.13.1 | CC6.6 | 3.10 | 1.3.4 | SRG-APP-000142 | ISM-1037 | 1.3.4 |
| 11 | OS Login Enforcement | IA-2(1) | L2: IA.L2-3.5.3 | CC6.1 | 4.4 | 8.3.1 | SRG-APP-000149 | ISM-1401 | 8.3.1 |
| 12 | Serial Port Disabled | CM-7 | L2: CM.L2-3.4.7 | CC6.1 | 4.5 | 2.2.2 | SRG-APP-000141 | ISM-1467 | 2.2.2 |
| 13 | Default SA Usage | AC-6(5) | L2: AC.L2-3.1.6 | CC6.3 | 1.6 | 7.2.2 | SRG-APP-000340 | ISM-1508 | 7.2.2 |
| 14 | Cross-Project Access | AC-3 | L2: AC.L2-3.1.3 | CC6.3 | 1.8 | 7.2.1 | SRG-APP-000033 | ISM-1508 | 7.2.1 |
| 15 | Uniform Bucket Access | AC-3 | L2: AC.L2-3.1.2 | CC6.1 | 5.2 | 7.2.1 | SRG-APP-000033 | ISM-0988 | 7.2.1 |
| 16 | CMEK Usage | SC-28(1) | L2: SC.L2-3.13.16 | CC6.1 | 1.18 | 3.4.1 | SRG-APP-000231 | ISM-0457 | 3.4.1 |
| 17 | DNS Security | SC-20 | L2: SC.L2-3.13.15 | CC6.1 | 3.3 | -- | SRG-APP-000516 | ISM-1590 | -- |
| 18 | LB SSL Policies | SC-8 | L2: SC.L2-3.13.8 | CC6.1 | 3.11 | 4.1.1 | SRG-APP-000014 | ISM-1139 | 4.1.1 |
| 19 | Cloud Armor WAF | SC-7(5) | L2: SC.L2-3.13.5 | CC6.6 | 3.12 | 6.6 | SRG-APP-000142 | ISM-1416 | 6.6 |
| 20 | API Key Restrictions | AC-3 | L2: AC.L2-3.1.2 | CC6.1 | 1.12-1.13 | 7.2.1 | SRG-APP-000033 | ISM-0988 | 7.2.1 |
| 21 | VPC Service Controls | AC-4 | L2: AC.L2-3.1.3 | CC6.6 | 3.14 | 1.3.1 | SRG-APP-000038 | ISM-1037 | 1.3.1 |
| 22 | Private Google Access | SC-7 | L2: SC.L2-3.13.1 | CC6.6 | 3.2 | 1.3.4 | SRG-APP-000142 | ISM-1037 | 1.3.4 |
| 23 | Shielded VM Config | SI-7(1) | L2: SI.L2-3.14.1 | CC7.1 | 4.8-4.9 | 2.2.1 | SRG-APP-000131 | ISM-1657 | 2.2.1 |

## Existing Tools

| Tool | Notes |
|------|-------|
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud audit (AWS/GCP/Azure). Python-based. Broad coverage but no compliance framework mapping. |
| [Forseti Security](https://github.com/forseti-security/forseti-security) | Google-maintained GCP scanner. Archived January 2025. Succeeded by SCC Premium. |
| [Steampipe GCP Mod](https://hub.steampipe.io/mods/turbot/gcp_compliance) | SQL-based compliance checks. CIS GCP Benchmark coverage. Requires Steampipe runtime. |
| [Prowler](https://github.com/prowler-cloud/prowler) | Multi-cloud security tool. GCP support added in v3. CIS checks. |
| [CloudSploit](https://github.com/aquasecurity/cloudsploit) | Aqua Security. Open-source cloud scanner with GCP plugins. |

**Gap:** No existing open-source tool maps GCP findings to FedRAMP, CMMC 2.0, DISA STIG, IRAP, and ISMAP simultaneously. gcp-sec-inspector fills this multi-framework mapping gap.

## Architecture

Package structure mirroring the okta-inspector pattern:

```
gcp-sec-inspector/
├── spec.md
├── pyproject.toml
├── src/
│   └── gcp_sec_inspector/
│       ├── __init__.py
│       ├── __main__.py          # Entry point
│       ├── cli.py               # Click CLI definition
│       ├── client.py            # GCP API client wrapper (auth, retry, pagination)
│       ├── collector.py         # Data collection from all 7 API surfaces
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
│       │   ├── cis.py           # CIS GCP Benchmark checks
│       │   ├── pci_dss.py       # PCI-DSS 4.0 requirement mapping
│       │   ├── stig.py          # DISA STIG SRG mapping
│       │   ├── irap.py          # IRAP ISM control mapping
│       │   └── ismap.py         # ISMAP control mapping
│       └── reporters/
│           ├── __init__.py
│           ├── base.py          # Base reporter interface
│           ├── executive.py     # Executive summary with pass/fail/warn counts
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

- **Hierarchical traversal:** Org policies are evaluated at org, folder, and project levels. The collector walks the resource hierarchy and tracks effective policy at each node.
- **Asset Inventory first:** Cloud Asset Inventory is the primary data source. SCC findings supplement but are not required (handles orgs without SCC Premium).
- **Incremental collection:** Resource snapshots can be cached and diffed against previous runs to show compliance drift.
- **Parallel collection:** API calls across independent services run concurrently with configurable rate limiting per API.

## CLI Interface

```bash
# Full org-wide audit with all frameworks
gcp-sec-inspector audit --org-id 123456789012 --all-frameworks

# Audit specific project only
gcp-sec-inspector audit --project-id my-project --framework fedramp

# Audit with specific controls
gcp-sec-inspector audit --org-id 123456789012 --controls 1,2,3,5,7

# Generate CMMC Level 2 assessment report
gcp-sec-inspector report --framework cmmc --level 2 --output cmmc-report.json

# Generate cross-framework compliance matrix
gcp-sec-inspector matrix --org-id 123456789012 --output matrix.html

# Check IAM permissions before running
gcp-sec-inspector check-permissions --org-id 123456789012

# Export findings to SCC (write findings back)
gcp-sec-inspector export --format scc --org-id 123456789012

# List available controls
gcp-sec-inspector controls --framework fedramp

# Diff against previous audit
gcp-sec-inspector diff --baseline baseline.json --current current.json
```

### Output Formats

- `json` -- machine-readable findings with control mappings
- `html` -- interactive dashboard with charts and drill-down
- `csv` -- spreadsheet-compatible for GRC tools
- `ckl` -- DISA STIG Checklist format
- `oscal` -- NIST OSCAL assessment results

## Build Sequence

### Phase 1: Foundation
- Project scaffolding (pyproject.toml, src layout, CI)
- GCP authentication (service account, ADC)
- API client with retry, pagination, and rate limiting
- Pydantic models for findings and controls

### Phase 2: Core Collection
- Cloud Asset Inventory integration (resources, IAM policies)
- IAM service account and key enumeration
- Organization Policy constraint evaluation
- Audit log configuration checks

### Phase 3: Security Controls
- Implement controls 1-12 (IAM, network, logging, org policy)
- Implement controls 13-23 (encryption, DNS, WAF, VM hardening)
- SCC findings integration (optional Premium enrichment)
- KMS and Binary Authorization checks

### Phase 4: Compliance Mapping
- FedRAMP control family mapping
- CMMC 2.0 practice mapping
- SOC 2, CIS, PCI-DSS mapping
- DISA STIG, IRAP, ISMAP mapping
- Cross-framework compliance matrix

### Phase 5: Reporting & Polish
- Executive summary reporter
- Framework-specific report formats (POA&M, CKL, OSCAL)
- HTML dashboard with interactive charts
- Compliance drift detection (baseline diffing)
- Test suite with mocked API responses

## Status

Not yet implemented. Spec only.
