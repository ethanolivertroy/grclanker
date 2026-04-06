---
slug: "aws-sec-inspector"
name: "AWS Security Inspector"
vendor: "Amazon Web Services"
category: "cloud-infrastructure"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/aws-sec-inspector"
---

# aws-sec-inspector

Multi-framework security compliance audit tool for AWS environments.

## 1. Overview

**aws-sec-inspector** is a command-line tool that aggregates security posture data from multiple AWS services into a unified, multi-framework compliance report. AWS already provides compliance scoring through Security Hub and Config conformance packs, but these are siloed by service and standard. This tool pulls findings from Security Hub, Config, IAM, Access Analyzer, CloudTrail, GuardDuty, Organizations, Identity Center, and Audit Manager, correlates them against eight compliance frameworks, and produces actionable reports with pass/fail evidence for each control.

Why it matters: organizations operating in regulated environments (FedRAMP, CMMC, PCI-DSS) need a single view of compliance posture across all AWS accounts. Native AWS tools give pieces of the picture; this tool assembles the full mosaic.

## 2. APIs & SDKs

### AWS Security Hub

| Operation | API | Purpose |
|-----------|-----|---------|
| `GetFindings` | `securityhub:GetFindings` | Retrieve security findings with filters |
| `GetComplianceSummary` | `securityhub:GetComplianceSummary` | Compliance status by standard |
| `DescribeHub` | `securityhub:DescribeHub` | Hub enablement and configuration |
| `DescribeStandards` | `securityhub:DescribeStandards` | List enabled security standards |
| `DescribeStandardsControls` | `securityhub:DescribeStandardsControls` | Control-level compliance detail |
| `GetEnabledStandards` | `securityhub:GetEnabledStandards` | Which standards are active |

### AWS Config

| Operation | API | Purpose |
|-----------|-----|---------|
| `DescribeComplianceByConfigRule` | `config:DescribeComplianceByConfigRule` | Rule-level compliance status |
| `ListConformancePackComplianceScores` | `config:ListConformancePackComplianceScores` | Conformance pack scores |
| `GetConformancePackComplianceDetails` | `config:GetConformancePackComplianceDetails` | Per-resource compliance in a pack |
| `DescribeConfigRules` | `config:DescribeConfigRules` | List all config rules |
| `GetComplianceDetailsByConfigRule` | `config:GetComplianceDetailsByConfigRule` | Per-resource evaluation results |
| `DescribeConformancePacks` | `config:DescribeConformancePacks` | List conformance packs (NIST, CIS, PCI, SOC2) |

### IAM

| Operation | API | Purpose |
|-----------|-----|---------|
| `GenerateCredentialReport` | `iam:GenerateCredentialReport` | Trigger credential report generation |
| `GetCredentialReport` | `iam:GetCredentialReport` | Download CSV of all users, MFA, access keys |
| `GetAccountPasswordPolicy` | `iam:GetAccountPasswordPolicy` | Password complexity, rotation, reuse policy |
| `ListUsers` | `iam:ListUsers` | Enumerate IAM users |
| `ListMFADevices` | `iam:ListMFADevices` | MFA devices per user |
| `ListAccessKeys` | `iam:ListAccessKeys` | Access key metadata per user |
| `GetAccessKeyLastUsed` | `iam:GetAccessKeyLastUsed` | Last usage timestamp per key |
| `GetAccountAuthorizationDetails` | `iam:GetAccountAuthorizationDetails` | Full IAM policy dump |
| `ListVirtualMFADevices` | `iam:ListVirtualMFADevices` | Virtual MFA device inventory |
| `GetAccountSummary` | `iam:GetAccountSummary` | Account-level IAM statistics |

### IAM Access Analyzer

| Operation | API | Purpose |
|-----------|-----|---------|
| `ListAnalyzers` | `access-analyzer:ListAnalyzers` | Enumerate active analyzers |
| `ListFindings` | `access-analyzer:ListFindings` | External access findings |
| `ListFindingsV2` | `access-analyzer:ListFindingsV2` | Enhanced findings with unused access |
| `GetFinding` | `access-analyzer:GetFinding` | Detailed finding information |

### CloudTrail

| Operation | API | Purpose |
|-----------|-----|---------|
| `DescribeTrails` | `cloudtrail:DescribeTrails` | List all trails |
| `GetTrailStatus` | `cloudtrail:GetTrailStatus` | Trail logging status |
| `GetEventSelectors` | `cloudtrail:GetEventSelectors` | Management/data event config |
| `GetInsightSelectors` | `cloudtrail:GetInsightSelectors` | CloudTrail Insights config |
| `GetTrail` | `cloudtrail:GetTrail` | Trail configuration details |

### GuardDuty

| Operation | API | Purpose |
|-----------|-----|---------|
| `ListDetectors` | `guardduty:ListDetectors` | Enumerate detectors |
| `GetDetector` | `guardduty:GetDetector` | Detector configuration |
| `ListFindings` | `guardduty:ListFindings` | Finding IDs with filters |
| `GetFindings` | `guardduty:GetFindings` | Full finding details |
| `GetFindingsStatistics` | `guardduty:GetFindingsStatistics` | Finding count by severity |
| `ListMembers` | `guardduty:ListMembers` | Multi-account member status |

### Organizations

| Operation | API | Purpose |
|-----------|-----|---------|
| `DescribeOrganization` | `organizations:DescribeOrganization` | Org configuration |
| `ListAccounts` | `organizations:ListAccounts` | All member accounts |
| `ListPolicies` | `organizations:ListPolicies` | SCPs, tag policies, backup policies |
| `DescribePolicy` | `organizations:DescribePolicy` | Policy document content |
| `ListOrganizationalUnits...` | `organizations:ListOrganizationalUnitsForParent` | OU hierarchy |
| `ListTargetsForPolicy` | `organizations:ListTargetsForPolicy` | Where SCPs are attached |

### IAM Identity Center (SSO)

| Operation | API | Purpose |
|-----------|-----|---------|
| `ListInstances` | `sso-admin:ListInstances` | Identity Center instance |
| `ListPermissionSets` | `sso-admin:ListPermissionSets` | All permission sets |
| `DescribePermissionSet` | `sso-admin:DescribePermissionSet` | Permission set details |
| `ListAccountAssignments` | `sso-admin:ListAccountAssignments` | Who has access to what |
| `GetInlinePolicyForPermissionSet` | `sso-admin:GetInlinePolicyForPermissionSet` | Inline policies |
| `ListManagedPoliciesInPermissionSet` | `sso-admin:ListManagedPoliciesInPermissionSet` | Attached managed policies |

### Audit Manager

| Operation | API | Purpose |
|-----------|-----|---------|
| `ListAssessmentFrameworks` | `auditmanager:ListAssessmentFrameworks` | Available frameworks |
| `ListAssessments` | `auditmanager:ListAssessments` | Active assessments |
| `GetAssessment` | `auditmanager:GetAssessment` | Assessment details and evidence |
| `ListControls` | `auditmanager:ListControls` | Control catalog |

### SDKs and CLIs

- **boto3** (Python) — primary SDK for all service calls
- **aws-cli** — `aws securityhub get-findings`, `aws configservice`, `aws iam`, etc.
- **botocore** — low-level session/credential management

## 3. Authentication

### Credential Chain

AWS SDK credential resolution order:

1. Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. Shared credentials file: `~/.aws/credentials`
3. AWS config file: `~/.aws/config` (with profile)
4. Container credentials (ECS)
5. Instance profile credentials (EC2)
6. SSO token cache

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_PROFILE` | No | Named profile from `~/.aws/config` |
| `AWS_ACCESS_KEY_ID` | Yes* | Access key ID (*unless using profile/role) |
| `AWS_SECRET_ACCESS_KEY` | Yes* | Secret access key |
| `AWS_SESSION_TOKEN` | No | Session token for temporary credentials |
| `AWS_DEFAULT_REGION` | No | Default region (falls back to `us-east-1`) |
| `AWS_ROLE_ARN` | No | Role ARN for cross-account assume-role |
| `AWS_EXTERNAL_ID` | No | External ID for assume-role |

### Multi-Account Strategy

For Organizations-wide audits, the tool assumes a hub role in the management account, then uses `sts:AssumeRole` to audit each member account:

```
Management Account (hub)
  └─ AssumeRole → Member Account A
  └─ AssumeRole → Member Account B
  └─ AssumeRole → Member Account N
```

Required IAM permissions are documented in a minimal policy JSON shipped with the tool.

## 4. Security Controls

| # | Control | AWS Services | Description |
|---|---------|-------------|-------------|
| 1 | MFA Enforcement | IAM | All IAM users have MFA enabled; root account has hardware MFA |
| 2 | Password Policy | IAM | Minimum length, complexity, rotation, reuse prevention |
| 3 | Access Key Rotation | IAM | Access keys rotated within 90 days; inactive keys disabled |
| 4 | Root Account Usage | IAM, CloudTrail | Root account has no access keys; no recent root sign-ins |
| 5 | Unused Credentials | IAM, Access Analyzer | Credentials unused for 90+ days are disabled or removed |
| 6 | CloudTrail Enabled | CloudTrail | Multi-region trail with log file validation; organization trail |
| 7 | CloudTrail Log Integrity | CloudTrail | Log file validation enabled; S3 bucket not publicly accessible |
| 8 | Security Hub Enabled | Security Hub | Security Hub active with CIS, PCI, NIST standards enabled |
| 9 | GuardDuty Enabled | GuardDuty | GuardDuty active in all regions; S3/EKS/Malware protection |
| 10 | Config Enabled | Config | AWS Config recording all resource types in all regions |
| 11 | S3 Public Access | Config, Security Hub | Account-level S3 Block Public Access enabled |
| 12 | Encryption at Rest | Config, Security Hub | EBS, RDS, S3, EFS default encryption enabled |
| 13 | Encryption in Transit | Config, Security Hub | TLS 1.2+ enforced on load balancers, API endpoints |
| 14 | VPC Flow Logs | Config, Security Hub | Flow logs enabled on all VPCs |
| 15 | Cross-Account Access | Access Analyzer | No unintended cross-account resource sharing |
| 16 | SCP Enforcement | Organizations | Deny policies for critical guardrails (region lock, service deny) |
| 17 | Permission Boundaries | IAM | Permission boundaries applied to delegated admin roles |
| 18 | Least Privilege | Access Analyzer, IAM | No wildcard actions/resources in IAM policies |
| 19 | Logging Configuration | CloudTrail, Config | Management and data events captured; Config delivery channel active |
| 20 | Network ACLs | Config, Security Hub | No overly permissive NACLs (0.0.0.0/0 ingress) |
| 21 | Security Group Rules | Config, Security Hub | No unrestricted ingress on admin ports (22, 3389) |
| 22 | KMS Key Rotation | Config, Security Hub | Customer-managed KMS keys have automatic rotation enabled |
| 23 | Identity Center Configuration | Identity Center | Centralized SSO with MFA; no direct IAM user access |
| 24 | Audit Manager Evidence | Audit Manager | Active assessments collecting automated evidence |
| 25 | Account Contacts | Organizations, IAM | Security and billing contacts configured |

## 5. Compliance Framework Mappings

| # | Control | FedRAMP (NIST 800-53) | CMMC 2.0 | SOC 2 | CIS AWS v3.0 | PCI-DSS v4.0 | DISA STIG | IRAP | ISMAP |
|---|---------|----------------------|----------|-------|--------------|-------------|-----------|------|-------|
| 1 | MFA Enforcement | IA-2(1), IA-2(2) | AC.L2-3.1.1 | CC6.1, CC6.6 | 1.5, 1.6, 1.10 | 8.4.2 | SRG-APP-000149 | ISM-1401 | 7.2.1 |
| 2 | Password Policy | IA-5(1) | IA.L2-3.5.7 | CC6.1 | 1.8, 1.9 | 8.3.6 | SRG-APP-000166 | ISM-0421 | 7.2.2 |
| 3 | Access Key Rotation | IA-5(1) | IA.L2-3.5.8 | CC6.1, CC6.2 | 1.12, 1.14 | 8.6.3 | SRG-APP-000175 | ISM-1590 | 7.2.3 |
| 4 | Root Account Usage | AC-6(1), AC-6(5) | AC.L2-3.1.5 | CC6.1, CC6.3 | 1.4, 1.7 | 8.6.1 | SRG-APP-000340 | ISM-1507 | 7.1.1 |
| 5 | Unused Credentials | AC-2(3) | AC.L2-3.1.12 | CC6.2 | 1.12 | 8.1.4 | SRG-APP-000163 | ISM-1404 | 7.2.4 |
| 6 | CloudTrail Enabled | AU-2, AU-3, AU-12 | AU.L2-3.3.1 | CC7.2, CC7.3 | 3.1, 3.2 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 8.1.1 |
| 7 | CloudTrail Log Integrity | AU-9, AU-10 | AU.L2-3.3.8 | CC7.2 | 3.4, 3.7 | 10.3.2 | SRG-APP-000125 | ISM-0859 | 8.1.2 |
| 8 | Security Hub Enabled | CA-7, SI-4 | CA.L2-3.12.3 | CC7.1, CC7.2 | — | 11.5.1 | SRG-APP-000516 | ISM-1228 | 8.2.1 |
| 9 | GuardDuty Enabled | SI-4, IR-4 | SI.L2-3.14.6 | CC7.2, CC7.3 | — | 11.5.1 | SRG-APP-000516 | ISM-1228 | 8.2.2 |
| 10 | Config Enabled | CM-2, CM-6, CM-8 | CM.L2-3.4.1 | CC7.1 | 3.5 | 10.2.1 | SRG-APP-000516 | ISM-1228 | 8.2.3 |
| 11 | S3 Public Access | AC-3, AC-4 | AC.L2-3.1.3 | CC6.1, CC6.6 | 2.1.4 | 1.3.1 | SRG-APP-000516 | ISM-0263 | 6.1.1 |
| 12 | Encryption at Rest | SC-28 | SC.L2-3.13.16 | CC6.1, CC6.7 | 2.2.1 | 3.4.1 | SRG-APP-000231 | ISM-0457 | 6.2.1 |
| 13 | Encryption in Transit | SC-8, SC-23 | SC.L2-3.13.8 | CC6.1, CC6.7 | — | 4.1.1 | SRG-APP-000014 | ISM-0469 | 6.2.2 |
| 14 | VPC Flow Logs | AU-12, SI-4 | AU.L2-3.3.1 | CC7.2 | 3.9 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 8.1.3 |
| 15 | Cross-Account Access | AC-3, AC-6 | AC.L2-3.1.2 | CC6.1, CC6.3 | 1.16 | 7.2.1 | SRG-APP-000033 | ISM-1380 | 7.1.2 |
| 16 | SCP Enforcement | AC-3, CM-7 | AC.L2-3.1.7 | CC6.1, CC6.8 | — | 7.2.1 | SRG-APP-000246 | ISM-1380 | 7.1.3 |
| 17 | Permission Boundaries | AC-6(1), AC-6(2) | AC.L2-3.1.5 | CC6.3 | — | 7.2.2 | SRG-APP-000340 | ISM-1380 | 7.1.4 |
| 18 | Least Privilege | AC-6 | AC.L2-3.1.5 | CC6.1, CC6.3 | 1.16 | 7.2.2 | SRG-APP-000342 | ISM-1380 | 7.1.5 |
| 19 | Logging Configuration | AU-2, AU-3, AU-6 | AU.L2-3.3.1 | CC7.2, CC7.3 | 3.1, 3.3, 3.5 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 8.1.4 |
| 20 | Network ACLs | AC-4, SC-7 | SC.L2-3.13.1 | CC6.1, CC6.6 | 5.1 | 1.3.1 | SRG-APP-000142 | ISM-1416 | 6.1.2 |
| 21 | Security Group Rules | AC-4, SC-7 | SC.L2-3.13.1 | CC6.1, CC6.6 | 5.2, 5.3 | 1.3.2 | SRG-APP-000142 | ISM-1416 | 6.1.3 |
| 22 | KMS Key Rotation | SC-12, SC-28 | SC.L2-3.13.10 | CC6.1, CC6.7 | 3.8 | 3.6.4 | SRG-APP-000231 | ISM-0457 | 6.2.3 |
| 23 | Identity Center Config | AC-2, IA-2 | AC.L2-3.1.1 | CC6.1, CC6.2 | — | 8.4.2 | SRG-APP-000149 | ISM-1401 | 7.2.5 |
| 24 | Audit Manager Evidence | CA-2, CA-7 | CA.L2-3.12.1 | CC4.1 | — | 12.4.1 | SRG-APP-000516 | ISM-1228 | 8.3.1 |
| 25 | Account Contacts | IR-6, PM-2 | IR.L2-3.6.2 | CC7.4 | 1.1, 1.2 | 12.10.5 | SRG-APP-000516 | ISM-0072 | 9.1.1 |

## 6. Existing Tools

| Tool | Language | Notes |
|------|----------|-------|
| [Prowler](https://github.com/prowler-cloud/prowler) | Python | 900+ checks, CIS/PCI/NIST/SOC2. Industry standard. Reference for check logic, not a dependency. |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Python | Multi-cloud security auditing. Good for cross-cloud comparison logic. |
| [AWS Audit Manager](https://aws.amazon.com/audit-manager/) | Managed Service | Native AWS evidence collection. Inspector reads its data, does not replace it. |
| [CloudSploit](https://github.com/aquasecurity/cloudsploit) | JavaScript | Open-source cloud security scanner by Aqua Security. |
| [Steampipe](https://github.com/turbot/steampipe) | Go | SQL-based cloud security queries. Reference for check definitions. |
| [Parliament](https://github.com/duo-labs/parliament) | Python | IAM policy linting. Reference for least-privilege analysis. |

## 7. Architecture

### Package Structure

```
aws-sec-inspector/
├── spec.md
├── pyproject.toml
├── src/
│   └── aws_sec_inspector/
│       ├── __init__.py
│       ├── cli.py                  # Click/Typer CLI entry point
│       ├── client.py               # boto3 session management, credential handling
│       ├── collector.py            # Data collection orchestrator (all 9 services)
│       ├── engine.py               # Analysis engine: runs all analyzers, aggregates results
│       ├── models.py               # Pydantic models: Finding, Control, ComplianceResult
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── base.py             # BaseAnalyzer ABC
│       │   ├── common.py           # Shared analysis utilities
│       │   ├── fedramp.py          # NIST 800-53 control mapping and evaluation
│       │   ├── cmmc.py             # CMMC 2.0 practice mapping and evaluation
│       │   ├── soc2.py             # SOC 2 Trust Services Criteria evaluation
│       │   ├── cis.py              # CIS AWS Foundations Benchmark evaluation
│       │   ├── pci_dss.py          # PCI-DSS v4.0 requirement evaluation
│       │   ├── stig.py             # DISA STIG evaluation
│       │   ├── irap.py             # IRAP (Australian ISM) evaluation
│       │   └── ismap.py            # ISMAP (Japanese cloud security) evaluation
│       └── reporters/
│           ├── __init__.py
│           ├── executive.py        # Executive summary (pass/fail counts, risk score)
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
  ├─ Client (client.py)        ← boto3 session, STS AssumeRole, credential chain
  │
  ├─ Collector (collector.py)   ← Calls 9 AWS service APIs, normalizes into models
  │     ├─ SecurityHubCollector
  │     ├─ ConfigCollector
  │     ├─ IAMCollector
  │     ├─ AccessAnalyzerCollector
  │     ├─ CloudTrailCollector
  │     ├─ GuardDutyCollector
  │     ├─ OrganizationsCollector
  │     ├─ IdentityCenterCollector
  │     └─ AuditManagerCollector
  │
  ├─ Engine (engine.py)         ← Runs analyzers against collected data
  │     ├─ FedRAMPAnalyzer
  │     ├─ CMMCAnalyzer
  │     ├─ SOC2Analyzer
  │     ├─ CISAnalyzer
  │     ├─ PCIDSSAnalyzer
  │     ├─ STIGAnalyzer
  │     ├─ IRAPAnalyzer
  │     └─ ISMAPAnalyzer
  │
  └─ Reporters                  ← Generate framework-specific output
        ├─ Markdown reports
        ├─ JSON/OSCAL export
        └─ STIG CKL/XCCDF
```

## 8. CLI Interface

```bash
# Full audit with all frameworks (default: current AWS profile)
aws-sec-inspector audit

# Audit specific frameworks
aws-sec-inspector audit --frameworks fedramp,cmmc,pci-dss

# Use a named AWS profile
aws-sec-inspector audit --profile production

# Cross-account audit via Organizations
aws-sec-inspector audit --org-wide --role-name SecurityAuditRole

# Audit specific accounts
aws-sec-inspector audit --accounts 123456789012,987654321098

# Specify output directory and format
aws-sec-inspector audit --output ./reports --format json

# Single control check
aws-sec-inspector check mfa-enforcement

# List all controls
aws-sec-inspector controls list

# List controls for a specific framework
aws-sec-inspector controls list --framework fedramp

# Export OSCAL-formatted results
aws-sec-inspector audit --format oscal --output ./oscal-results

# Dry run: show what would be audited without making API calls
aws-sec-inspector audit --dry-run

# Verbose output for debugging
aws-sec-inspector audit -v --log-level debug

# Compare two audit snapshots
aws-sec-inspector diff ./reports/2026-03-01 ./reports/2026-03-24
```

## 9. Build Sequence

### Phase 1: Foundation

- Project scaffolding (pyproject.toml, src layout, CI)
- `client.py` — boto3 session management, credential chain, STS AssumeRole
- `models.py` — Pydantic models for findings, controls, compliance results
- `collector.py` — IAM data collection (credential report, password policy, MFA)
- `cli.py` — basic Click/Typer CLI skeleton
- Controls 1-5 (IAM-focused): MFA, password policy, access key rotation, root account, unused credentials

### Phase 2: Logging & Detection

- CloudTrail collector (trail status, event selectors, log validation)
- GuardDuty collector (detector status, findings, member accounts)
- Security Hub collector (findings, standards, controls)
- Config collector (rules, conformance packs, compliance scores)
- Controls 6-14: CloudTrail, Security Hub, GuardDuty, Config, S3, encryption, VPC flow logs

### Phase 3: Organization & Access

- Organizations collector (accounts, SCPs, OUs)
- Identity Center collector (permission sets, assignments)
- Access Analyzer collector (external access, unused permissions)
- Audit Manager collector (frameworks, assessments)
- Controls 15-25: cross-account, SCPs, permission boundaries, least privilege, network, KMS

### Phase 4: Analyzers

- `base.py` — BaseAnalyzer ABC with common evaluation logic
- Framework-specific analyzers: FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, ISMAP
- Control-to-framework mapping tables
- Scoring logic (pass/fail/not-applicable/manual-review)

### Phase 5: Reporters & Polish

- Executive summary reporter (risk score, pass/fail breakdown)
- Framework-specific report generators (Markdown, JSON)
- Cross-framework compliance matrix
- STIG CKL/XCCDF export
- OSCAL export format
- Diff tool for comparing audit snapshots
- Multi-account aggregation reports

### Phase 6: Hardening

- Comprehensive test suite (unit, integration with moto)
- Rate limiting and retry logic for AWS API calls
- Pagination handling for all List/Describe operations
- Error handling for missing permissions / disabled services
- Documentation and minimal IAM policy generator

## 10. Status

Not yet implemented. Spec only.
