---
slug: "aws-sec-inspector"
name: "AWS Security Inspector"
vendor: "Amazon Web Services"
category: "cloud-infrastructure"
language: "language-neutral"
status: "generated"
version: "2.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
implementation_kind: "security-inspector"
---

<!-- generated integration spec -->
> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.

# AWS Security Inspector

Read-only AWS posture inspection across identity, logging, detection, organization guardrails, data protection, and network security.

## Purpose

AWS Security Inspector gives auditors a read-only, multi-framework view of one AWS account across identity, logging, threat detection, organization guardrails, data protection, and network security. It gathers evidence directly from the services that own each setting and produces findings that remain traceable to the operation, region, and resource population assessed.

## Rationale

AWS security posture is distributed across global and regional services. A complete assessment must distinguish account-wide IAM and Organizations evidence from per-region EC2, RDS, KMS, Config, GuardDuty, and Security Hub evidence. It must also distinguish a genuinely empty account from a denied operation, an incomplete response, or a collection stopped by a configured cap.

The contract reads direct resource settings where an aggregate service cannot prove the control. Examples include account and bucket public-access blocks, default encryption, TLS-only bucket policies, VPC flow-log coverage, network access rules, and key rotation. This keeps each verdict tied to evidence that another implementation can collect independently.

## Non-goals

- Changing AWS resources, policies, standards, detectors, recorders, or contacts
- Assuming roles into additional accounts or aggregating an organization-wide report
- Treating Security Hub or Config scores as substitutes for direct resource checks
- Claiming complete regional coverage when region discovery fails or a region cap is reached
- Reproducing a particular programming language, software development kit, package layout, or command-line framework

## Portable implementation guidance

Keep service calls behind a read-only client boundary and attach the service action and region to every failed collection. Discover enabled regions unless the caller explicitly supplies a region list. Collect regional evidence independently so one denied region does not erase readable evidence from another. Validate successful responses against the documented output shape before treating an absent list as empty. Preserve the global handling required for root-account activity.

## Shared integration contract

This specification requires [shared integration contract version 1.1](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Tools

| Tool | Purpose | Finding IDs | Result shape |
|---|---|---|---|
| `aws_check_access` | Validate read-only AWS audit access across IAM, CloudTrail, Security Hub, Config, GuardDuty, Access Analyzer, Organizations, Identity Center, EC2, S3, KMS, RDS, Audit Manager, and Account surfaces. | None | Text table plus structured fields {tool, status, accountId?, arn?, surfaces, notes, recommendedNextStep}. |
| `aws_assess_identity` | Assess AWS IAM hygiene, including root-account protection, IAM user MFA, password policy, access key rotation, dormant users, and privileged roles without permission boundaries. | `AWS-IAM-01`, `AWS-IAM-02`, `AWS-IAM-03`, `AWS-IAM-04`, `AWS-IAM-05`, `AWS-IAM-06`, `AWS-IAM-07`, `AWS-IAM-08` | Text summary/table plus structured fields {tool, title, summary, findings, errors?}. |
| `aws_assess_logging_detection` | Assess AWS CloudTrail, Security Hub, GuardDuty, and Config posture, including multi-region trail coverage, log validation, data events, standards enablement, and active recording. | `AWS-LOG-01`, `AWS-LOG-02`, `AWS-LOG-03`, `AWS-LOG-04`, `AWS-LOG-05` | Text summary/table plus structured fields {tool, title, summary, findings, errors?}. |
| `aws_assess_org_guardrails` | Assess AWS Organizations visibility, service control policies, Access Analyzer coverage, active external-access findings, and IAM Identity Center visibility. | `AWS-ORG-01`, `AWS-ORG-02`, `AWS-ORG-03`, `AWS-ORG-04`, `AWS-ORG-05`, `AWS-ORG-06`, `AWS-ORG-07` | Text summary/table plus structured fields {tool, title, summary, findings, errors?}. |
| `aws_assess_data_protection` | Assess AWS data protection posture: account and bucket S3 Block Public Access, EBS default encryption per region, S3 default encryption, RDS storage encryption, TLS-only bucket policies (aws:SecureTransport), and customer-managed KMS key rotation. | `AWS-DATA-11`, `AWS-DATA-12`, `AWS-DATA-13`, `AWS-DATA-22` | Text summary/table plus structured fields {tool, title, summary, findings, errors?}. |
| `aws_assess_network_security` | Assess AWS network security posture per region: VPC Flow Logs coverage (DescribeFlowLogs versus DescribeVpcs), network ACL inbound rules open to 0.0.0.0/0 or ::/0 on sensitive ports, and security group inbound rules open to the world on sensitive ports. | `AWS-NET-14`, `AWS-NET-20`, `AWS-NET-21` | Text summary/table plus structured fields {tool, title, summary, findings, errors?}. |
| `aws_export_audit_bundle` | Export an AWS audit package with the access check, identity, logging and detection, organization guardrail, data protection, and network security findings, an executive summary, a unified compliance matrix, per-framework reports, JSON analysis, an error log when collection was partial, and a zip archive named after the bundle directory. | `AWS-IAM-01`, `AWS-IAM-02`, `AWS-IAM-03`, `AWS-IAM-04`, `AWS-IAM-05`, `AWS-IAM-06`, `AWS-IAM-07`, `AWS-IAM-08`, `AWS-LOG-01`, `AWS-LOG-02`, `AWS-LOG-03`, `AWS-LOG-04`, `AWS-LOG-05`, `AWS-ORG-01`, `AWS-ORG-02`, `AWS-ORG-03`, `AWS-ORG-04`, `AWS-ORG-05`, `AWS-ORG-06`, `AWS-ORG-07`, `AWS-DATA-11`, `AWS-DATA-12`, `AWS-DATA-13`, `AWS-DATA-22`, `AWS-NET-14`, `AWS-NET-20`, `AWS-NET-21` | Text export receipt plus structured fields {tool, output_dir, zip_path, finding_count, file_count, error_count}. |

### Parameters

#### `aws_check_access`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `region` | string | no | AWS region. Defaults to AWS_REGION, AWS_DEFAULT_REGION, or us-east-1. |
| `profile` | string | no | AWS shared-config profile to use. Defaults to AWS_PROFILE or the default SDK chain. |
| `account_id` | string | no | Optional expected AWS account ID hint for operator context. |

#### `aws_assess_identity`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `region` | string | no | AWS region. Defaults to AWS_REGION, AWS_DEFAULT_REGION, or us-east-1. |
| `profile` | string | no | AWS shared-config profile to use. Defaults to AWS_PROFILE or the default SDK chain. |
| `account_id` | string | no | Optional expected AWS account ID hint for operator context. |
| `user_limit` | number | no | Maximum IAM users to sample. Defaults to 500. |
| `stale_days` | number | no | Staleness threshold in days for keys and dormant users. Defaults to 90. |
| `role_limit` | number | no | Maximum IAM roles to inspect. Defaults to 500. |
| `max_privileged_roles` | number | no | Maximum tolerated privileged roles without permission boundaries before failing. Defaults to 5. |
| `lookback_days` | number | no | Days of CloudTrail history to search for root activity (LookupEvents keeps 90 days). Defaults to 90. |
| `policy_limit` | number | no | Maximum customer-managed IAM policies to inspect before flagging truncation. Defaults to 1000. |

#### `aws_assess_logging_detection`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `region` | string | no | AWS region. Defaults to AWS_REGION, AWS_DEFAULT_REGION, or us-east-1. |
| `profile` | string | no | AWS shared-config profile to use. Defaults to AWS_PROFILE or the default SDK chain. |
| `account_id` | string | no | Optional expected AWS account ID hint for operator context. |

#### `aws_assess_org_guardrails`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `region` | string | no | AWS region. Defaults to AWS_REGION, AWS_DEFAULT_REGION, or us-east-1. |
| `profile` | string | no | AWS shared-config profile to use. Defaults to AWS_PROFILE or the default SDK chain. |
| `account_id` | string | no | Optional expected AWS account ID hint for operator context. |
| `max_findings` | number | no | Maximum Access Analyzer findings to sample. Defaults to 200. |

#### `aws_assess_data_protection`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `region` | string | no | AWS region. Defaults to AWS_REGION, AWS_DEFAULT_REGION, or us-east-1. |
| `profile` | string | no | AWS shared-config profile to use. Defaults to AWS_PROFILE or the default SDK chain. |
| `account_id` | string | no | Optional expected AWS account ID hint for operator context. |
| `regions` | string | no | Comma-separated regions to assess. Defaults to every enabled region from EC2 DescribeRegions, falling back to the configured region. |
| `region_limit` | number | no | Maximum regions to assess before flagging a partial scope. Defaults to 30. |
| `bucket_limit` | number | no | Maximum S3 buckets to inspect before flagging truncation. Defaults to 1000. |
| `key_limit` | number | no | Maximum KMS keys per region before flagging truncation. Defaults to 1000. |
| `instance_limit` | number | no | Maximum RDS instances per region before flagging truncation. Defaults to 500. |

#### `aws_assess_network_security`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `region` | string | no | AWS region. Defaults to AWS_REGION, AWS_DEFAULT_REGION, or us-east-1. |
| `profile` | string | no | AWS shared-config profile to use. Defaults to AWS_PROFILE or the default SDK chain. |
| `account_id` | string | no | Optional expected AWS account ID hint for operator context. |
| `regions` | string | no | Comma-separated regions to assess. Defaults to every enabled region from EC2 DescribeRegions, falling back to the configured region. |
| `region_limit` | number | no | Maximum regions to assess before flagging a partial scope. Defaults to 30. |
| `resource_limit` | number | no | Maximum VPCs, flow logs, NACLs, or security groups per region before flagging truncation. Defaults to 2000. |
| `sensitive_ports` | string | no | Comma-separated ports treated as sensitive. Defaults to 21,22,23,445,1433,1521,3306,3389,5432,5900,6379,9200,27017. |

#### `aws_export_audit_bundle`

| Parameter | Kind | Required | Meaning |
|---|---|---|---|
| `region` | string | no | AWS region. Defaults to AWS_REGION, AWS_DEFAULT_REGION, or us-east-1. |
| `profile` | string | no | AWS shared-config profile to use. Defaults to AWS_PROFILE or the default SDK chain. |
| `account_id` | string | no | Optional expected AWS account ID hint for operator context. |
| `output_dir` | string | no | Output root. Defaults to ./export/aws. |
| `user_limit` | number | no | Maximum IAM users to sample. Defaults to 500. |
| `stale_days` | number | no | Staleness threshold in days for keys and dormant users. Defaults to 90. |
| `role_limit` | number | no | Maximum IAM roles to inspect. Defaults to 500. |
| `max_privileged_roles` | number | no | Maximum tolerated privileged roles without permission boundaries before failing. Defaults to 5. |
| `lookback_days` | number | no | Days of CloudTrail history to search for root activity (LookupEvents keeps 90 days). Defaults to 90. |
| `policy_limit` | number | no | Maximum customer-managed IAM policies to inspect before flagging truncation. Defaults to 1000. |
| `max_findings` | number | no | Maximum Access Analyzer findings to sample. Defaults to 200. |
| `regions` | string | no | Comma-separated regions to assess. Defaults to every enabled region from EC2 DescribeRegions, falling back to the configured region. |
| `region_limit` | number | no | Maximum regions to assess before flagging a partial scope. Defaults to 30. |
| `bucket_limit` | number | no | Maximum S3 buckets to inspect before flagging truncation. Defaults to 1000. |
| `key_limit` | number | no | Maximum KMS keys per region before flagging truncation. Defaults to 1000. |
| `instance_limit` | number | no | Maximum RDS instances per region before flagging truncation. Defaults to 500. |
| `resource_limit` | number | no | Maximum VPCs, flow logs, NACLs, or security groups per region before flagging truncation. Defaults to 2000. |
| `sensitive_ports` | string | no | Comma-separated ports treated as sensitive. Defaults to 21,22,23,445,1433,1521,3306,3389,5432,5900,6379,9200,27017. |


## Authentication

Supported modes:

- AWS default credential provider chain
- Named shared-configuration profile

Credential precedence, highest first:

1. Named profile argument or AWS_PROFILE
2. Environment credentials
3. Shared credentials and configuration files
4. Container credentials
5. Instance role credentials

Environment variables: `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_DEFAULT_REGION`, `AWS_ACCOUNT_ID`

Configuration locations: ~/.aws/credentials, ~/.aws/config

Credential and deployment variants: Long-lived access keys, Temporary session credentials, Identity Center cached session, Container role, Instance role

Configuration fields: `region`, `profile`, `account_id`

Malformed configuration: Credential-provider errors are replaced with a fixed provider name and sanitized code/status; raw provider and shared-file parser messages are never emitted.

## Permissions

| Kind | Permission, role, or plan | Unlocks | Notes |
|---|---|---|---|
| iam-action | `sts:GetCallerIdentity` | `sts-get-caller-identity` |  |
| iam-action | `iam:GetAccountSummary` | `iam-get-account-summary` |  |
| iam-action | `iam:GetAccountPasswordPolicy` | `iam-get-account-password-policy` |  |
| iam-action | `iam:ListUsers` | `iam-list-users` |  |
| iam-action | `iam:ListMFADevices` | `iam-list-mfa-devices` |  |
| iam-action | `iam:ListAccessKeys` | `iam-list-access-keys` |  |
| iam-action | `iam:GetAccessKeyLastUsed` | `iam-get-access-key-last-used` |  |
| iam-action | `iam:GetAccountAuthorizationDetails` | `iam-get-account-authorization-details` |  |
| iam-action | `iam:ListPolicies` | `iam-list-policies` |  |
| iam-action | `iam:GetPolicyVersion` | `iam-get-policy-version` |  |
| iam-action | `cloudtrail:LookupEvents` | `cloudtrail-lookup-events` |  |
| iam-action | `cloudtrail:DescribeTrails` | `cloudtrail-describe-trails` |  |
| iam-action | `cloudtrail:GetTrailStatus` | `cloudtrail-get-trail-status` |  |
| iam-action | `cloudtrail:GetEventSelectors` | `cloudtrail-get-event-selectors` |  |
| iam-action | `securityhub:DescribeHub` | `securityhub-describe-hub` |  |
| iam-action | `securityhub:GetEnabledStandards` | `securityhub-get-enabled-standards` |  |
| iam-action | `config:DescribeConfigurationRecorders` | `config-describe-configuration-recorders` |  |
| iam-action | `config:DescribeConfigurationRecorderStatus` | `config-describe-configuration-recorder-status` |  |
| iam-action | `guardduty:ListDetectors` | `guardduty-list-detectors` |  |
| iam-action | `guardduty:GetDetector` | `guardduty-get-detector` |  |
| iam-action | `organizations:DescribeOrganization` | `organizations-describe-organization` |  |
| iam-action | `organizations:ListAccounts` | `organizations-list-accounts` |  |
| iam-action | `organizations:ListPolicies` | `organizations-list-policies` |  |
| iam-action | `organizations:ListTargetsForPolicy` | `organizations-list-targets-for-policy` |  |
| iam-action | `access-analyzer:ListAnalyzers` | `access-analyzer-list-analyzers` |  |
| iam-action | `access-analyzer:ListFindings` | `access-analyzer-list-findings` |  |
| iam-action | `sso:ListInstances` | `sso-admin-list-instances` |  |
| iam-action | `auditmanager:ListAssessments` | `auditmanager-list-assessments` |  |
| iam-action | `account:GetAlternateContact` | `account-get-alternate-contact` |  |
| iam-action | `ec2:DescribeRegions` | `ec2-describe-regions` |  |
| iam-action | `s3:GetAccountPublicAccessBlock` | `s3-get-account-public-access-block` |  |
| iam-action | `s3:ListBuckets` | `s3-list-buckets` |  |
| iam-action | `s3:GetPublicAccessBlock` | `s3-get-public-access-block` |  |
| iam-action | `s3:GetBucketPolicyStatus` | `s3-get-bucket-policy-status` |  |
| iam-action | `s3:GetBucketEncryption` | `s3-get-bucket-encryption` |  |
| iam-action | `s3:GetBucketPolicy` | `s3-get-bucket-policy` |  |
| iam-action | `ec2:GetEbsEncryptionByDefault` | `ec2-get-ebs-encryption-by-default` |  |
| iam-action | `ec2:DescribeVpcs` | `ec2-describe-vpcs` |  |
| iam-action | `ec2:DescribeFlowLogs` | `ec2-describe-flow-logs` |  |
| iam-action | `ec2:DescribeNetworkAcls` | `ec2-describe-network-acls` |  |
| iam-action | `ec2:DescribeSecurityGroups` | `ec2-describe-security-groups` |  |
| iam-action | `rds:DescribeDBInstances` | `rds-describe-db-instances` |  |
| iam-action | `kms:ListKeys` | `kms-list-keys` |  |
| iam-action | `kms:DescribeKey` | `kms-describe-key` |  |
| iam-action | `kms:GetKeyRotationStatus` | `kms-get-key-rotation-status` |  |

## API surfaces

| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |
|---|---|---|---|---|---|---|---|---|
| `sts-get-caller-identity` | service operation | `GetCallerIdentity` | sts | `sts:GetCallerIdentity` | auth-only | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Account`, `Arn`, `UserId` | [Official documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) |
| `iam-get-account-summary` | service operation | `GetAccountSummary` | iam | `iam:GetAccountSummary` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `SummaryMap` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html) |
| `iam-get-account-password-policy` | service operation | `GetAccountPasswordPolicy` | iam | `iam:GetAccountPasswordPolicy` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `PasswordPolicy` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountPasswordPolicy.html) |
| `iam-list-users` | service operation | `ListUsers` | iam | `iam:ListUsers` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Users.UserName`, `Users.Arn`, `Users.CreateDate`, `Users.PasswordLastUsed` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html) |
| `iam-list-mfa-devices` | service operation | `ListMFADevices` | iam | `iam:ListMFADevices` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `MFADevices.SerialNumber`, `MFADevices.EnableDate` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListMFADevices.html) |
| `iam-list-access-keys` | service operation | `ListAccessKeys` | iam | `iam:ListAccessKeys` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `AccessKeyMetadata.UserName`, `AccessKeyMetadata.AccessKeyId`, `AccessKeyMetadata.Status`, `AccessKeyMetadata.CreateDate` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html) |
| `iam-get-access-key-last-used` | service operation | `GetAccessKeyLastUsed` | iam | `iam:GetAccessKeyLastUsed` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `AccessKeyLastUsed.LastUsedDate`, `AccessKeyLastUsed.ServiceName`, `AccessKeyLastUsed.Region` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html) |
| `iam-get-account-authorization-details` | service operation | `GetAccountAuthorizationDetails` | iam | `iam:GetAccountAuthorizationDetails` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `RoleDetailList`, `UserDetailList`, `GroupDetailList`, `Policies` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html) |
| `iam-list-policies` | service operation | `ListPolicies` | iam | `iam:ListPolicies` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Policies.PolicyName`, `Policies.Arn`, `Policies.DefaultVersionId`, `Policies.AttachmentCount`, `Policies.PermissionsBoundaryUsageCount` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html) |
| `iam-get-policy-version` | service operation | `GetPolicyVersion` | iam | `iam:GetPolicyVersion` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `PolicyVersion.Document` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html) |
| `cloudtrail-lookup-events` | service operation | `LookupEvents` | cloudtrail | `cloudtrail:LookupEvents` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Events.EventId`, `Events.EventName`, `Events.EventSource`, `Events.EventTime`, `Events.Username`, `Events.ReadOnly` | [Official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html) |
| `cloudtrail-describe-trails` | service operation | `DescribeTrails` | cloudtrail | `cloudtrail:DescribeTrails` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `trailList.Name`, `trailList.TrailARN`, `trailList.IsMultiRegionTrail`, `trailList.LogFileValidationEnabled` | [Official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeTrails.html) |
| `cloudtrail-get-trail-status` | service operation | `GetTrailStatus` | cloudtrail | `cloudtrail:GetTrailStatus` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `IsLogging` | [Official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html) |
| `cloudtrail-get-event-selectors` | service operation | `GetEventSelectors` | cloudtrail | `cloudtrail:GetEventSelectors` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `EventSelectors`, `AdvancedEventSelectors` | [Official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html) |
| `securityhub-describe-hub` | service operation | `DescribeHub` | securityhub | `securityhub:DescribeHub` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `HubArn` | [Official documentation](https://docs.aws.amazon.com/securityhub/latest/APIReference/API_DescribeHub.html) |
| `securityhub-get-enabled-standards` | service operation | `GetEnabledStandards` | securityhub | `securityhub:GetEnabledStandards` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `StandardsSubscriptions` | [Official documentation](https://docs.aws.amazon.com/securityhub/latest/APIReference/API_GetEnabledStandards.html) |
| `config-describe-configuration-recorders` | service operation | `DescribeConfigurationRecorders` | config | `config:DescribeConfigurationRecorders` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `ConfigurationRecorders` | [Official documentation](https://docs.aws.amazon.com/config/latest/APIReference/API_DescribeConfigurationRecorders.html) |
| `config-describe-configuration-recorder-status` | service operation | `DescribeConfigurationRecorderStatus` | config | `config:DescribeConfigurationRecorderStatus` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `ConfigurationRecordersStatus` | [Official documentation](https://docs.aws.amazon.com/config/latest/APIReference/API_DescribeConfigurationRecorderStatus.html) |
| `guardduty-list-detectors` | service operation | `ListDetectors` | guardduty | `guardduty:ListDetectors` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `DetectorIds` | [Official documentation](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html) |
| `guardduty-get-detector` | service operation | `GetDetector` | guardduty | `guardduty:GetDetector` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Status`, `ServiceRole` | [Official documentation](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetDetector.html) |
| `organizations-describe-organization` | service operation | `DescribeOrganization` | organizations | `organizations:DescribeOrganization` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Organization.Id`, `Organization.Arn`, `Organization.FeatureSet` | [Official documentation](https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeOrganization.html) |
| `organizations-list-accounts` | service operation | `ListAccounts` | organizations | `organizations:ListAccounts` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Accounts.Id`, `Accounts.Name`, `Accounts.Email`, `Accounts.Status` | [Official documentation](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html) |
| `organizations-list-policies` | service operation | `ListPolicies` | organizations | `organizations:ListPolicies` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Policies.Id`, `Policies.Name`, `Policies.Arn`, `Policies.Type`, `Policies.AwsManaged` | [Official documentation](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPolicies.html) |
| `organizations-list-targets-for-policy` | service operation | `ListTargetsForPolicy` | organizations | `organizations:ListTargetsForPolicy` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Targets.TargetId`, `Targets.Name`, `Targets.Type` | [Official documentation](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListTargetsForPolicy.html) |
| `access-analyzer-list-analyzers` | service operation | `ListAnalyzers` | access-analyzer | `access-analyzer:ListAnalyzers` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `analyzers.arn`, `analyzers.name`, `analyzers.status`, `analyzers.type` | [Official documentation](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ListAnalyzers.html) |
| `access-analyzer-list-findings` | service operation | `ListFindings` | access-analyzer | `access-analyzer:ListFindings` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `findings.id`, `findings.resource`, `findings.resourceType`, `findings.status`, `findings.createdAt`, `findings.updatedAt` | [Official documentation](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ListFindings.html) |
| `sso-admin-list-instances` | service operation | `ListInstances` | sso-admin | `sso:ListInstances` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Instances.InstanceArn`, `Instances.IdentityStoreId`, `Instances.Name`, `Instances.Status` | [Official documentation](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListInstances.html) |
| `auditmanager-list-assessments` | service operation | `ListAssessments` | auditmanager | `auditmanager:ListAssessments` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `assessmentMetadata.id`, `assessmentMetadata.name`, `assessmentMetadata.status` | [Official documentation](https://docs.aws.amazon.com/auditmanager/latest/APIReference/API_ListAssessments.html) |
| `account-get-alternate-contact` | service operation | `GetAlternateContact` | account | `account:GetAlternateContact` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `AlternateContact.Name`, `AlternateContact.Title`, `AlternateContact.EmailAddress`, `AlternateContact.PhoneNumber` | [Official documentation](https://docs.aws.amazon.com/accounts/latest/APIReference/API_GetAlternateContact.html) |
| `ec2-describe-regions` | service operation | `DescribeRegions` | ec2 | `ec2:DescribeRegions` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Regions.RegionName`, `Regions.OptInStatus` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html) |
| `s3-get-account-public-access-block` | service operation | `GetPublicAccessBlock` | s3-control | `s3:GetAccountPublicAccessBlock` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `PublicAccessBlockConfiguration` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_GetPublicAccessBlock.html) |
| `s3-list-buckets` | service operation | `ListBuckets` | s3 | `s3:ListBuckets` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Buckets.Name`, `Buckets.CreationDate`, `ContinuationToken` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/APIReference/API_ListBuckets.html) |
| `s3-get-public-access-block` | service operation | `GetPublicAccessBlock` | s3 | `s3:GetPublicAccessBlock` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `PublicAccessBlockConfiguration` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/APIReference/API_GetPublicAccessBlock.html) |
| `s3-get-bucket-policy-status` | service operation | `GetBucketPolicyStatus` | s3 | `s3:GetBucketPolicyStatus` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `PolicyStatus.IsPublic` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/APIReference/API_GetBucketPolicyStatus.html) |
| `s3-get-bucket-encryption` | service operation | `GetBucketEncryption` | s3 | `s3:GetBucketEncryption` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `ServerSideEncryptionConfiguration.Rules` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/APIReference/API_GetBucketEncryption.html) |
| `s3-get-bucket-policy` | service operation | `GetBucketPolicy` | s3 | `s3:GetBucketPolicy` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Policy` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/APIReference/API_GetBucketPolicy.html) |
| `ec2-get-ebs-encryption-by-default` | service operation | `GetEbsEncryptionByDefault` | ec2 | `ec2:GetEbsEncryptionByDefault` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `EbsEncryptionByDefault`, `SseType` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetEbsEncryptionByDefault.html) |
| `ec2-describe-vpcs` | service operation | `DescribeVpcs` | ec2 | `ec2:DescribeVpcs` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Vpcs.VpcId`, `Vpcs.IsDefault`, `Vpcs.CidrBlock`, `Vpcs.State` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcs.html) |
| `ec2-describe-flow-logs` | service operation | `DescribeFlowLogs` | ec2 | `ec2:DescribeFlowLogs` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `FlowLogs.FlowLogId`, `FlowLogs.ResourceId`, `FlowLogs.FlowLogStatus` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeFlowLogs.html) |
| `ec2-describe-network-acls` | service operation | `DescribeNetworkAcls` | ec2 | `ec2:DescribeNetworkAcls` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `NetworkAcls.NetworkAclId`, `NetworkAcls.VpcId`, `NetworkAcls.Entries` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeNetworkAcls.html) |
| `ec2-describe-security-groups` | service operation | `DescribeSecurityGroups` | ec2 | `ec2:DescribeSecurityGroups` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `SecurityGroups.GroupId`, `SecurityGroups.GroupName`, `SecurityGroups.VpcId`, `SecurityGroups.IpPermissions` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html) |
| `rds-describe-db-instances` | service operation | `DescribeDBInstances` | rds | `rds:DescribeDBInstances` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `DBInstances.DBInstanceIdentifier`, `DBInstances.StorageEncrypted`, `DBInstances.Engine`, `DBInstances.KmsKeyId` | [Official documentation](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html) |
| `kms-list-keys` | service operation | `ListKeys` | kms | `kms:ListKeys` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `Keys.KeyId`, `Keys.KeyArn` | [Official documentation](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html) |
| `kms-describe-key` | service operation | `DescribeKey` | kms | `kms:DescribeKey` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `KeyMetadata.KeyId`, `KeyMetadata.Arn`, `KeyMetadata.KeyManager`, `KeyMetadata.KeyState`, `KeyMetadata.KeySpec`, `KeyMetadata.Origin` | [Official documentation](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html) |
| `kms-get-key-rotation-status` | service operation | `GetKeyRotationStatus` | kms | `kms:GetKeyRotationStatus` | read | Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported. | `KeyRotationEnabled`, `RotationPeriodInDays`, `NextRotationDate` | [Official documentation](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html) |

### Request construction

| Surface | Input | Exact value or rule | Required |
|---|---|---|---|
| `sts-get-caller-identity` | client | The configured home region. | yes |
| `sts-get-caller-identity` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `sts-get-caller-identity` | response | Account: string | yes |
| `iam-get-account-summary` | client | The configured home region. | yes |
| `iam-get-account-summary` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `iam-get-account-summary` | response | SummaryMap: map | yes |
| `iam-get-account-password-policy` | client | The configured home region. | yes |
| `iam-get-account-password-policy` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `iam-get-account-password-policy` | response | PasswordPolicy: structure | yes |
| `iam-list-users` | client | The configured home region. | yes |
| `iam-list-users` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `iam-list-users` | response | Users: list | yes |
| `iam-list-users` | operation-input:Marker | Previous page marker | no |
| `iam-list-users` | operation-input:MaxItems | min(100, remaining item budget) | yes |
| `iam-list-mfa-devices` | client | The configured home region. | yes |
| `iam-list-mfa-devices` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `iam-list-mfa-devices` | response | MFADevices: list | yes |
| `iam-list-mfa-devices` | operation-input:UserName | Current IAM user name | yes |
| `iam-list-access-keys` | client | The configured home region. | yes |
| `iam-list-access-keys` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `iam-list-access-keys` | response | AccessKeyMetadata: list | yes |
| `iam-list-access-keys` | operation-input:UserName | Current IAM user name | yes |
| `iam-get-access-key-last-used` | client | The configured home region. | yes |
| `iam-get-access-key-last-used` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `iam-get-access-key-last-used` | response | AccessKeyLastUsed: structure | yes |
| `iam-get-access-key-last-used` | operation-input:AccessKeyId | Current access key identifier | yes |
| `iam-get-account-authorization-details` | client | The configured home region. | yes |
| `iam-get-account-authorization-details` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `iam-get-account-authorization-details` | response | RoleDetailList: list, UserDetailList: list, GroupDetailList: list, Policies: list | yes |
| `iam-get-account-authorization-details` | operation-input:Filter | ['Role'] | yes |
| `iam-get-account-authorization-details` | operation-input:Marker | Previous page marker | no |
| `iam-get-account-authorization-details` | operation-input:MaxItems | min(100, remaining item budget) | yes |
| `iam-list-policies` | client | The configured home region. | yes |
| `iam-list-policies` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `iam-list-policies` | response | Policies: list | yes |
| `iam-list-policies` | operation-input:Scope | Local | yes |
| `iam-list-policies` | operation-input:OnlyAttached | false | yes |
| `iam-list-policies` | operation-input:Marker | Previous page marker | no |
| `iam-list-policies` | operation-input:MaxItems | 100 | yes |
| `iam-get-policy-version` | client | The configured home region. | yes |
| `iam-get-policy-version` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `iam-get-policy-version` | response | PolicyVersion: structure | yes |
| `iam-get-policy-version` | operation-input:PolicyArn | ARN from ListPolicies | yes |
| `iam-get-policy-version` | operation-input:VersionId | DefaultVersionId from ListPolicies, falling back to v1 only when absent | yes |
| `cloudtrail-lookup-events` | client | us-east-1 for global root activity, then the configured region only as a fallback when the global lookup fails and differs. | yes |
| `cloudtrail-lookup-events` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `cloudtrail-lookup-events` | response | Events: list | yes |
| `cloudtrail-lookup-events` | operation-input:LookupAttributes | [{AttributeKey: Username, AttributeValue: root}] | yes |
| `cloudtrail-lookup-events` | operation-input:StartTime | Current time minus lookback_days, clamped to the 90-day service history | yes |
| `cloudtrail-lookup-events` | operation-input:EndTime | Current time | yes |
| `cloudtrail-lookup-events` | operation-input:MaxResults | 50 | yes |
| `cloudtrail-lookup-events` | operation-input:NextToken | Previous page token | no |
| `cloudtrail-describe-trails` | client | The configured home region. | yes |
| `cloudtrail-describe-trails` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `cloudtrail-describe-trails` | response | trailList: list | yes |
| `cloudtrail-describe-trails` | operation-input:includeShadowTrails | false | yes |
| `cloudtrail-get-trail-status` | client | The configured home region. | yes |
| `cloudtrail-get-trail-status` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `cloudtrail-get-trail-status` | response | IsLogging: boolean | yes |
| `cloudtrail-get-trail-status` | operation-input:Name | TrailARN, falling back to Name | yes |
| `cloudtrail-get-event-selectors` | client | The configured home region. | yes |
| `cloudtrail-get-event-selectors` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `cloudtrail-get-event-selectors` | response | TrailARN: string, EventSelectors: list, AdvancedEventSelectors: list | yes |
| `cloudtrail-get-event-selectors` | operation-input:TrailName | TrailARN, falling back to Name | yes |
| `securityhub-describe-hub` | client | The configured home region. | yes |
| `securityhub-describe-hub` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `securityhub-describe-hub` | response | HubArn: string | yes |
| `securityhub-get-enabled-standards` | client | The configured home region. | yes |
| `securityhub-get-enabled-standards` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `securityhub-get-enabled-standards` | response | StandardsSubscriptions: list | yes |
| `securityhub-get-enabled-standards` | operation-input:MaxResults | 100 | yes |
| `securityhub-get-enabled-standards` | operation-input:NextToken | Previous page token | no |
| `config-describe-configuration-recorders` | client | The configured home region. | yes |
| `config-describe-configuration-recorders` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `config-describe-configuration-recorders` | response | ConfigurationRecorders: list | yes |
| `config-describe-configuration-recorder-status` | client | The configured home region. | yes |
| `config-describe-configuration-recorder-status` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `config-describe-configuration-recorder-status` | response | ConfigurationRecordersStatus: list | yes |
| `guardduty-list-detectors` | client | The configured home region. | yes |
| `guardduty-list-detectors` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `guardduty-list-detectors` | response | DetectorIds: list | yes |
| `guardduty-list-detectors` | operation-input:MaxResults | 50 | yes |
| `guardduty-list-detectors` | operation-input:NextToken | Previous page token | no |
| `guardduty-get-detector` | client | The configured home region. | yes |
| `guardduty-get-detector` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `guardduty-get-detector` | response | Status: string, ServiceRole: string | yes |
| `guardduty-get-detector` | operation-input:DetectorId | Identifier from ListDetectors | yes |
| `organizations-describe-organization` | client | The configured home region. | yes |
| `organizations-describe-organization` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `organizations-describe-organization` | response | Organization: structure | yes |
| `organizations-list-accounts` | client | The configured home region. | yes |
| `organizations-list-accounts` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `organizations-list-accounts` | response | Accounts: list | yes |
| `organizations-list-accounts` | operation-input:NextToken | Previous page token | no |
| `organizations-list-accounts` | operation-input:MaxResults | min(20, remaining item budget) | yes |
| `organizations-list-policies` | client | The configured home region. | yes |
| `organizations-list-policies` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `organizations-list-policies` | response | Policies: list | yes |
| `organizations-list-policies` | operation-input:Filter | SERVICE_CONTROL_POLICY | yes |
| `organizations-list-policies` | operation-input:NextToken | Previous page token | no |
| `organizations-list-policies` | operation-input:MaxResults | 20 | yes |
| `organizations-list-targets-for-policy` | client | The configured home region. | yes |
| `organizations-list-targets-for-policy` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `organizations-list-targets-for-policy` | response | Targets: list | yes |
| `organizations-list-targets-for-policy` | operation-input:PolicyId | Identifier from ListPolicies | yes |
| `organizations-list-targets-for-policy` | operation-input:NextToken | Previous page token | no |
| `access-analyzer-list-analyzers` | client | The configured home region. | yes |
| `access-analyzer-list-analyzers` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `access-analyzer-list-analyzers` | response | analyzers: list | yes |
| `access-analyzer-list-analyzers` | operation-input:nextToken | Previous page token | no |
| `access-analyzer-list-analyzers` | operation-input:maxResults | 100 | yes |
| `access-analyzer-list-findings` | client | The configured home region. | yes |
| `access-analyzer-list-findings` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `access-analyzer-list-findings` | response | findings: list | yes |
| `access-analyzer-list-findings` | operation-input:analyzerArn | ARN of each ACTIVE analyzer | yes |
| `access-analyzer-list-findings` | operation-input:maxResults | min(100, remaining finding budget) | yes |
| `access-analyzer-list-findings` | operation-input:nextToken | Previous page token | no |
| `sso-admin-list-instances` | client | The configured home region. | yes |
| `sso-admin-list-instances` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `sso-admin-list-instances` | response | Instances: list | yes |
| `sso-admin-list-instances` | operation-input:MaxResults | 100 | yes |
| `sso-admin-list-instances` | operation-input:NextToken | Previous page token | no |
| `auditmanager-list-assessments` | client | The configured home region. | yes |
| `auditmanager-list-assessments` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `auditmanager-list-assessments` | response | assessmentMetadata: list | yes |
| `auditmanager-list-assessments` | operation-input:status | ACTIVE | yes |
| `auditmanager-list-assessments` | operation-input:maxResults | 100 | yes |
| `auditmanager-list-assessments` | operation-input:nextToken | Previous page token | no |
| `account-get-alternate-contact` | client | The configured home region. | yes |
| `account-get-alternate-contact` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `account-get-alternate-contact` | response | AlternateContact: structure | yes |
| `account-get-alternate-contact` | operation-input:AlternateContactType | SECURITY | yes |
| `ec2-describe-regions` | client | Each assessed region; DescribeRegions itself uses the configured region. | yes |
| `ec2-describe-regions` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `ec2-describe-regions` | response | Regions: list | yes |
| `ec2-describe-regions` | operation-input:Filters | opt-in-status in [opt-in-not-required, opted-in] | yes |
| `s3-get-account-public-access-block` | client | The configured home region. | yes |
| `s3-get-account-public-access-block` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `s3-get-account-public-access-block` | response | PublicAccessBlockConfiguration: structure | yes |
| `s3-get-account-public-access-block` | operation-input:AccountId | Account from GetCallerIdentity, falling back to account_id configuration | yes |
| `s3-list-buckets` | client | The configured home region. | yes |
| `s3-list-buckets` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `s3-list-buckets` | response | Buckets: list | yes |
| `s3-list-buckets` | operation-input:ContinuationToken | Previous page token | no |
| `s3-list-buckets` | operation-input:MaxBuckets | min(1000, remaining item budget) | yes |
| `s3-get-public-access-block` | client | The configured home region. | yes |
| `s3-get-public-access-block` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `s3-get-public-access-block` | response | PublicAccessBlockConfiguration: structure | yes |
| `s3-get-public-access-block` | operation-input:Bucket | Bucket name from ListBuckets | yes |
| `s3-get-bucket-policy-status` | client | The configured home region. | yes |
| `s3-get-bucket-policy-status` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `s3-get-bucket-policy-status` | response | PolicyStatus: structure | yes |
| `s3-get-bucket-policy-status` | operation-input:Bucket | Bucket name from ListBuckets | yes |
| `s3-get-bucket-encryption` | client | The configured home region. | yes |
| `s3-get-bucket-encryption` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `s3-get-bucket-encryption` | response | ServerSideEncryptionConfiguration: structure | yes |
| `s3-get-bucket-encryption` | operation-input:Bucket | Bucket name from ListBuckets | yes |
| `s3-get-bucket-policy` | client | The configured home region. | yes |
| `s3-get-bucket-policy` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `s3-get-bucket-policy` | response | Policy: policyDocument | yes |
| `s3-get-bucket-policy` | operation-input:Bucket | Bucket name from ListBuckets | yes |
| `ec2-get-ebs-encryption-by-default` | client | Each assessed region; DescribeRegions itself uses the configured region. | yes |
| `ec2-get-ebs-encryption-by-default` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `ec2-get-ebs-encryption-by-default` | response | EbsEncryptionByDefault: boolean | yes |
| `ec2-describe-vpcs` | client | Each assessed region; DescribeRegions itself uses the configured region. | yes |
| `ec2-describe-vpcs` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `ec2-describe-vpcs` | response | Vpcs: list | yes |
| `ec2-describe-vpcs` | operation-input:NextToken | Previous page token | no |
| `ec2-describe-vpcs` | operation-input:MaxResults | 1000 | yes |
| `ec2-describe-flow-logs` | client | Each assessed region; DescribeRegions itself uses the configured region. | yes |
| `ec2-describe-flow-logs` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `ec2-describe-flow-logs` | response | FlowLogs: list | yes |
| `ec2-describe-flow-logs` | operation-input:NextToken | Previous page token | no |
| `ec2-describe-flow-logs` | operation-input:MaxResults | 1000 | yes |
| `ec2-describe-network-acls` | client | Each assessed region; DescribeRegions itself uses the configured region. | yes |
| `ec2-describe-network-acls` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `ec2-describe-network-acls` | response | NetworkAcls: list | yes |
| `ec2-describe-network-acls` | operation-input:NextToken | Previous page token | no |
| `ec2-describe-network-acls` | operation-input:MaxResults | 1000 | yes |
| `ec2-describe-security-groups` | client | Each assessed region; DescribeRegions itself uses the configured region. | yes |
| `ec2-describe-security-groups` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `ec2-describe-security-groups` | response | SecurityGroups: list | yes |
| `ec2-describe-security-groups` | operation-input:NextToken | Previous page token | no |
| `ec2-describe-security-groups` | operation-input:MaxResults | 1000 | yes |
| `rds-describe-db-instances` | client | Each assessed region; DescribeRegions itself uses the configured region. | yes |
| `rds-describe-db-instances` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `rds-describe-db-instances` | response | DBInstances: list | yes |
| `rds-describe-db-instances` | operation-input:Marker | Previous page marker | no |
| `rds-describe-db-instances` | operation-input:MaxRecords | 100 | yes |
| `kms-list-keys` | client | Each assessed region; DescribeRegions itself uses the configured region. | yes |
| `kms-list-keys` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `kms-list-keys` | response | Keys: list | yes |
| `kms-list-keys` | operation-input:Marker | Previous page marker | no |
| `kms-list-keys` | operation-input:Limit | 1000 | yes |
| `kms-describe-key` | client | Each assessed region; DescribeRegions itself uses the configured region. | yes |
| `kms-describe-key` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `kms-describe-key` | response | KeyMetadata: structure | yes |
| `kms-describe-key` | operation-input:KeyId | KeyId from ListKeys | yes |
| `kms-get-key-rotation-status` | client | Each assessed region; DescribeRegions itself uses the configured region. | yes |
| `kms-get-key-rotation-status` | headers | Service request signed with AWS Signature Version 4 by the resolved credential provider. | yes |
| `kms-get-key-rotation-status` | response | KeyRotationEnabled: boolean | yes |
| `kms-get-key-rotation-status` | operation-input:KeyId | Eligible KeyId from DescribeKey | yes |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `iam-list-users`, `iam-list-policies`, `iam-get-account-authorization-details` | `Marker`, `IsTruncated` | 100 | caller limit | 1000 | IAM does not return a stable population total; report items seen and truncation. | IsTruncated is false; Configured item cap; Page cap; Missing or repeated marker |
| `cloudtrail-lookup-events`, `securityhub-get-enabled-standards`, `guardduty-list-detectors`, `organizations-list-accounts`, `organizations-list-policies`, `organizations-list-targets-for-policy`, `access-analyzer-list-analyzers`, `access-analyzer-list-findings`, `sso-admin-list-instances`, `auditmanager-list-assessments`, `ec2-describe-vpcs`, `ec2-describe-flow-logs`, `ec2-describe-network-acls`, `ec2-describe-security-groups` | `NextToken`, `nextToken` | service default | caller limit | 1000 | The service does not provide a dependable total; report items seen and truncation. | No next token; Configured item cap; Page cap; Missing or repeated token |
| `s3-list-buckets` | `ContinuationToken` | 1000 | 1000 | 1000 | No total is returned; only exhaustion proves completeness. | No continuation token; Bucket cap; Page cap; Missing or repeated token |
| `rds-describe-db-instances` | `Marker` | 100 | caller limit | 1000 | No total is returned; only exhaustion proves completeness. | No marker; Configured item cap; Page cap; Missing or repeated marker |
| `kms-list-keys` | `Marker request`, `NextMarker response when Truncated=true` | 1000 | 1000 | 1000 | KMS returns no total; only Truncated=false proves exhaustion. | Truncated is false; Configured key cap; Page cap; Missing or repeated NextMarker |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| AWS service APIs | Not published | None | 429, 500, 502, 503, 504 | Use the service client's bounded retry behavior. If retries are exhausted, mark the surface unreadable and demote dependent findings. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | MFA Enforcement | AWS-IAM-01, AWS-IAM-02 | GetAccountSummary is unreadable; verify root MFA and absence of root access keys in IAM. ListUsers is unreadable, or every sampled user's MFA-device list is unreadable. |
| 2 | Password Policy | AWS-IAM-03 | GetAccountPasswordPolicy is unreadable. |
| 3 | Access Key Rotation | AWS-IAM-04 | ListUsers is unreadable, every user's key list is unreadable, or every sampled key's last-use read is unreadable. |
| 4 | Root Account Usage | AWS-IAM-01, AWS-IAM-07 | GetAccountSummary is unreadable; verify root MFA and absence of root access keys in IAM. Root LookupEvents is unreadable. |
| 5 | Unused Credentials | AWS-IAM-06 | ListUsers is unreadable. |
| 6 | CloudTrail Enabled | AWS-LOG-01 | DescribeTrails is unreadable, or a qualifying trail exists but every qualifying logging state is unreadable. |
| 7 | CloudTrail Log Integrity | AWS-LOG-01 | DescribeTrails is unreadable, or a qualifying trail exists but every qualifying logging state is unreadable. |
| 8 | Security Hub Enabled | AWS-LOG-03 | DescribeHub is unreadable. |
| 9 | GuardDuty Enabled | AWS-LOG-04 | ListDetectors is unreadable, or detector IDs exist but enablement is unreadable. |
| 10 | Config Enabled | AWS-LOG-05 | Recorder listing or recorder-status listing is unreadable. |
| 11 | S3 Public Access | AWS-DATA-11 | Account-level S3 Control GetPublicAccessBlock or ListBuckets is unreadable. |
| 12 | Encryption at Rest | AWS-DATA-12 | EBS default encryption is unreadable in every assessed region or ListBuckets is unreadable. |
| 13 | Encryption in Transit | AWS-DATA-13 | ListBuckets is unreadable or returns zero buckets; load-balancer and endpoint TLS remain manual. |
| 14 | VPC Flow Logs | AWS-NET-14 | VPCs are unreadable in every region, no VPC exists, or every VPC's flow-log state is unreadable or missing. |
| 15 | Cross-Account Access | AWS-ORG-03, AWS-ORG-04 | ListAnalyzers is unreadable. Analyzers are unreadable, no ACTIVE analyzer exists, or no ACTIVE analyzer has a readable findings list. |
| 16 | SCP Enforcement | AWS-ORG-01, AWS-ORG-02 | DescribeOrganization is unreadable. ListPolicies is unreadable, or SCPs exist but target lists needed to settle attachment are unreadable. |
| 17 | Permission Boundaries | AWS-IAM-05 | GetAccountAuthorizationDetails for roles is unreadable. |
| 18 | Least Privilege | AWS-IAM-08 | ListPolicies is unreadable or returns zero customer-managed policies; inline policies remain manual. |
| 19 | Logging Configuration | AWS-LOG-02 | DescribeTrails is unreadable or any required GetEventSelectors read is unreadable. |
| 20 | Network ACLs | AWS-NET-20 | NACLs are unreadable in every region or no NACL is returned. |
| 21 | Security Group Rules | AWS-NET-21 | Security groups are unreadable in every region or no security group is returned. |
| 22 | KMS Key Rotation | AWS-DATA-22 | KMS lists fail in every region, no customer key exists, or no customer key can be confirmed because every KeyManager is unreadable. |
| 23 | Identity Center Configuration | AWS-ORG-05 | ListInstances is unreadable. |
| 24 | Audit Manager Evidence | AWS-ORG-06 | ListAssessments is unreadable; verify applicability in Audit Manager or the alternate evidence process. |
| 25 | Account Contacts | AWS-ORG-07 | GetAlternateContact is unreadable. |

### Finding criteria

| Finding | Severity | Owning tool | Sources | Pass | Warn | Fail | Manual |
|---|---|---|---|---|---|---|---|
| `AWS-IAM-01` | critical | `aws_assess_identity` | `iam-get-account-summary` | GetAccountSummary is readable, AccountMFAEnabled equals 1, and AccountAccessKeysPresent is absent or equals 0. | No warn verdict is emitted directly. | AccountMFAEnabled is not 1 or AccountAccessKeysPresent is greater than 0. | GetAccountSummary is unreadable; verify root MFA and absence of root access keys in IAM. |
| `AWS-IAM-02` | high | `aws_assess_identity` | `iam-list-users`, `iam-list-mfa-devices` | ListUsers is readable and every sampled user whose ListMFADevices call is readable has at least one MFA device. | The pass result is demoted when the user inventory is truncated or one or more user MFA-device lists is unreadable. | At least one sampled IAM user has a readable empty MFA-device list. | ListUsers is unreadable, or every sampled user's MFA-device list is unreadable. |
| `AWS-IAM-03` | high | `aws_assess_identity` | `iam-get-account-password-policy` | A password policy exists, MinimumPasswordLength is at least 14, and RequireSymbols, RequireNumbers, RequireUppercaseCharacters, and RequireLowercaseCharacters are all true. | No warn verdict is emitted directly. | No password policy exists, minimum length is below 14, or any required complexity flag is not true. | GetAccountPasswordPolicy is unreadable. |
| `AWS-IAM-04` | high | `aws_assess_identity` | `iam-list-users`, `iam-list-access-keys`, `iam-get-access-key-last-used` | ListUsers is readable and no judged access key is older than stale_days since LastUsedDate, or since CreateDate when never used; stale_days defaults to 90. | The pass result is demoted when users are truncated or any user's key list or any sampled key's last-use read is unreadable. | At least one judged key exceeds stale_days. | ListUsers is unreadable, every user's key list is unreadable, or every sampled key's last-use read is unreadable. |
| `AWS-IAM-05` | medium | `aws_assess_identity` | `iam-get-account-authorization-details` | The role inventory is readable and no role with AdministratorAccess or an inline Allow Action='*' Resource='*' policy lacks PermissionsBoundary. | One to max_privileged_roles privileged roles lack boundaries, or an otherwise-passing role inventory is truncated; max_privileged_roles defaults to 5. | More than max_privileged_roles privileged roles lack permission boundaries. | GetAccountAuthorizationDetails for roles is unreadable. |
| `AWS-IAM-06` | low | `aws_assess_identity` | `iam-list-users`, `iam-list-access-keys`, `iam-get-access-key-last-used` | ListUsers is readable and no user has PasswordLastUsed older than stale_days and no user with no password activity is proven to have zero access keys. | At least one user appears dormant, or an otherwise-passing user/key inventory is partial; stale_days defaults to 90. | No fail verdict is emitted; dormant users require review. | ListUsers is unreadable. |
| `AWS-IAM-07` | high | `aws_assess_identity` | `cloudtrail-lookup-events` | No CloudTrail event attributed to username root is found in the lookback window, first queried in us-east-1. | No root ConsoleLogin exists but another root API event exists, or an otherwise-passing lookup is truncated, contains undated events, or falls back after the us-east-1 lookup fails. | At least one root ConsoleLogin event exists. | Root LookupEvents is unreadable. |
| `AWS-IAM-08` | high | `aws_assess_identity` | `iam-list-policies`, `iam-get-policy-version` | At least one customer-managed policy is readable and none has an Allow statement with wildcard Action and wildcard Resource. | An unattached policy grants Action='*' and Resource='*', a policy grants a service-wide action such as service:* on Resource='*', or an otherwise-passing inventory is partial. | An attached policy or permission-boundary policy has an Allow statement with Action='*' and Resource='*'. | ListPolicies is unreadable or returns zero customer-managed policies; inline policies remain manual. |
| `AWS-LOG-01` | critical | `aws_assess_logging_detection` | `cloudtrail-describe-trails`, `cloudtrail-get-trail-status` | At least one trail has IsMultiRegionTrail=true, LogFileValidationEnabled=true and GetTrailStatus.IsLogging=true. | A pass is demoted when GetTrailStatus is unreadable for any trail. | Trails are readable but no trail satisfies all three required values. | DescribeTrails is unreadable, or a qualifying trail exists but every qualifying logging state is unreadable. |
| `AWS-LOG-02` | medium | `aws_assess_logging_detection` | `cloudtrail-describe-trails`, `cloudtrail-get-event-selectors` | At least one readable trail has a nonempty EventSelectors.DataResources list or any AdvancedEventSelectors entry. | Trails and selectors are readable but no data-event selector exists. | No fail verdict is emitted; absent data events are a review condition. | DescribeTrails is unreadable or any required GetEventSelectors read is unreadable. |
| `AWS-LOG-03` | high | `aws_assess_logging_detection` | `securityhub-describe-hub`, `securityhub-get-enabled-standards` | DescribeHub confirms a hub and GetEnabledStandards returns at least one standards subscription. | The hub exists but standards are unreadable, empty, or truncated. | DescribeHub reports that the hub is not subscribed. | DescribeHub is unreadable. |
| `AWS-LOG-04` | high | `aws_assess_logging_detection` | `guardduty-list-detectors`, `guardduty-get-detector` | At least one listed detector has GetDetector.Status equal to ENABLED. | A pass is demoted when detector listing is truncated or any detector detail is unreadable. | No detector exists, or all readable detectors have a status other than ENABLED. | ListDetectors is unreadable, or detector IDs exist but enablement is unreadable. |
| `AWS-LOG-05` | high | `aws_assess_logging_detection` | `config-describe-configuration-recorders`, `config-describe-configuration-recorder-status` | At least one configuration recorder has a same-name status with recording=true. | No warn verdict is emitted directly. | No configuration recorder exists, or recorders exist but none reports recording=true. | Recorder listing or recorder-status listing is unreadable. |
| `AWS-ORG-01` | medium | `aws_assess_org_guardrails` | `organizations-describe-organization`, `organizations-list-accounts` | DescribeOrganization returns an organization; account listing may be readable or unreadable, but a pass is demoted if accounts are unreadable or truncated. | The account is standalone, or organization visibility passes while member accounts are unreadable or truncated. | No fail verdict is emitted directly. | DescribeOrganization is unreadable. |
| `AWS-ORG-02` | high | `aws_assess_org_guardrails` | `organizations-list-policies`, `organizations-list-targets-for-policy` | At least one SERVICE_CONTROL_POLICY exists and at least one policy has one or more targets. | The account is standalone, no SCP exists, or a pass is demoted by unreadable/truncated policy or target lists. | SCPs exist, every target list is readable, and no SCP has a root, OU, or account target. | ListPolicies is unreadable, or SCPs exist but target lists needed to settle attachment are unreadable. |
| `AWS-ORG-03` | high | `aws_assess_org_guardrails` | `access-analyzer-list-analyzers` | At least one analyzer has status ACTIVE. | A pass is demoted when the analyzer listing is truncated. | The analyzer listing is readable and contains no ACTIVE analyzer. | ListAnalyzers is unreadable. |
| `AWS-ORG-04` | dynamic | `aws_assess_org_guardrails` | `access-analyzer-list-analyzers`, `access-analyzer-list-findings` | At least one ACTIVE analyzer has a readable, complete findings list and no returned finding has missing status or status ACTIVE; severity is low. | At least one active external finding is returned; severity is high. A pass is also demoted by unreadable or truncated findings from another ACTIVE analyzer. | No fail verdict is emitted; active external access is a review condition. | Analyzers are unreadable, no ACTIVE analyzer exists, or no ACTIVE analyzer has a readable findings list. |
| `AWS-ORG-05` | low | `aws_assess_org_guardrails` | `sso-admin-list-instances` | ListInstances returns at least one IAM Identity Center instance. | No instance is visible, or an otherwise-passing list is truncated. | No fail verdict is emitted. | ListInstances is unreadable. |
| `AWS-ORG-06` | medium | `aws_assess_org_guardrails` | `auditmanager-list-assessments` | ListAssessments(status=ACTIVE) returns at least one assessment with a creation or update timestamp and the list is complete. | A pass is demoted when any assessment lacks both timestamps or the list is truncated. | The read is successful but returns zero ACTIVE assessments. | ListAssessments is unreadable; verify applicability in Audit Manager or the alternate evidence process. |
| `AWS-ORG-07` | medium | `aws_assess_org_guardrails` | `account-get-alternate-contact` | GetAlternateContact(SECURITY) returns a contact with nonempty EmailAddress and PhoneNumber. | A SECURITY contact exists but email or phone is missing. | GetAlternateContact reports ResourceNotFoundException, meaning no SECURITY contact exists. | GetAlternateContact is unreadable. |
| `AWS-DATA-11` | critical | `aws_assess_data_protection` | `s3-get-account-public-access-block`, `s3-list-buckets`, `s3-get-public-access-block`, `s3-get-bucket-policy-status` | All four account Block Public Access flags are true, no readable bucket policy evaluates public, all bucket reads are complete, and no bucket public-access detail is unreadable. | The account block is incomplete but every bucket has all four bucket flags and no public policy, or the account block is complete but a policy evaluates public; a pass is also demoted by partial bucket evidence. | The account block is absent, or incomplete while any bucket lacks a full bucket block or has a public policy. | Account-level S3 Control GetPublicAccessBlock or ListBuckets is unreadable. |
| `AWS-DATA-12` | high | `aws_assess_data_protection` | `ec2-get-ebs-encryption-by-default`, `s3-get-bucket-encryption`, `rds-describe-db-instances` | Every readable assessed region has EbsEncryptionByDefault=true, every bucket has at least one default SSEAlgorithm, and every RDS instance with a readable StorageEncrypted field reports true. | The base pass is demoted by partial region scope, unreadable regional/bucket sources, truncated inventories, or any RDS instance missing StorageEncrypted. | Any readable region reports EbsEncryptionByDefault=false, any bucket lacks default encryption, or any RDS instance reports StorageEncrypted=false. | EBS default encryption is unreadable in every assessed region or ListBuckets is unreadable. |
| `AWS-DATA-13` | high | `aws_assess_data_protection` | `s3-list-buckets`, `s3-get-bucket-policy` | Every listed bucket has a Deny statement whose condition requires aws:SecureTransport=false; bucket and policy reads are complete. | The pass is demoted when any bucket policy is unreadable or the bucket list is truncated. | At least one readable bucket lacks the required Deny statement. | ListBuckets is unreadable or returns zero buckets; load-balancer and endpoint TLS remain manual. |
| `AWS-DATA-22` | medium | `aws_assess_data_protection` | `kms-list-keys`, `kms-describe-key`, `kms-get-key-rotation-status` | Every eligible key reports KeyRotationEnabled=true. Eligibility requires KeyManager=CUSTOMER, KeyState=Enabled, KeySpec=SYMMETRIC_DEFAULT and Origin=AWS_KMS. | Customer keys exist but none is eligible for automatic rotation, or a pass is demoted by unreadable/truncated regional scope, key metadata, or rotation status. | At least one eligible key reports KeyRotationEnabled=false. | KMS lists fail in every region, no customer key exists, or no customer key can be confirmed because every KeyManager is unreadable. |
| `AWS-NET-14` | medium | `aws_assess_network_security` | `ec2-describe-vpcs`, `ec2-describe-flow-logs` | Every readable VPC has at least one matching flow log whose FlowLogStatus is ACTIVE. | The base pass is demoted by partial region scope, unreadable/truncated VPC or flow-log inventories, or missing FlowLogStatus on some logs. | At least one readable VPC has no ACTIVE flow log. | VPCs are unreadable in every region, no VPC exists, or every VPC's flow-log state is unreadable or missing. |
| `AWS-NET-20` | medium | `aws_assess_network_security` | `ec2-describe-network-acls` | At least one network ACL is readable and none has an inbound allow entry from 0.0.0.0/0 or ::/0 whose protocol/range covers any configured sensitive port or all ports. | A pass is demoted by partial region scope or unreadable/truncated NACL inventories. | At least one NACL has a matching permissive inbound entry. | NACLs are unreadable in every region or no NACL is returned. |
| `AWS-NET-21` | high | `aws_assess_network_security` | `ec2-describe-security-groups` | At least one security group is readable and none has an inbound IPv4 or IPv6 world source whose protocol/range covers any configured sensitive port or all ports. | A pass is demoted by partial region scope or unreadable/truncated security-group inventories. | At least one security group has a matching unrestricted inbound permission. | Security groups are unreadable in every region or no security group is returned. |

### Criterion constants

| Finding | Name | Value |
|---|---|---|
| `AWS-IAM-01` | `mfaEnabled` | 1 |
| `AWS-IAM-01` | `accessKeysPresent` | 0 |
| `AWS-IAM-03` | `minimumLength` | 14 |
| `AWS-IAM-03` | `requiredComplexityFields` | RequireSymbols, RequireNumbers, RequireUppercaseCharacters, RequireLowercaseCharacters |
| `AWS-IAM-04` | `defaultStaleDays` | 90 |
| `AWS-IAM-05` | `administratorPolicyName` | AdministratorAccess |
| `AWS-IAM-05` | `defaultMaximum` | 5 |
| `AWS-IAM-06` | `defaultStaleDays` | 90 |
| `AWS-IAM-07` | `consoleLoginEventName` | ConsoleLogin |
| `AWS-IAM-07` | `defaultLookbackDays` | 90 |
| `AWS-IAM-07` | `globalRegion` | us-east-1 |
| `AWS-IAM-08` | `wildcard` | * |
| `AWS-LOG-04` | `enabledStatus` | ENABLED |
| `AWS-ORG-02` | `filter` | SERVICE_CONTROL_POLICY |
| `AWS-ORG-03` | `activeStatus` | ACTIVE |
| `AWS-ORG-04` | `activeAnalyzerStatus` | ACTIVE |
| `AWS-ORG-04` | `activeFindingStatus` | ACTIVE |
| `AWS-ORG-06` | `requestedStatus` | ACTIVE |
| `AWS-ORG-07` | `contactType` | SECURITY |
| `AWS-DATA-11` | `requiredFlags` | BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets |
| `AWS-DATA-13` | `conditionKey` | aws:SecureTransport |
| `AWS-DATA-13` | `deniedValue` | false |
| `AWS-DATA-22` | `keyManager` | CUSTOMER |
| `AWS-DATA-22` | `keyState` | Enabled |
| `AWS-DATA-22` | `keySpec` | SYMMETRIC_DEFAULT |
| `AWS-DATA-22` | `keyOrigin` | AWS_KMS |
| `AWS-NET-14` | `activeStatus` | ACTIVE |
| `AWS-NET-20` | `publicIpv4` | 0.0.0.0/0 |
| `AWS-NET-20` | `publicIpv6` | ::/0 |
| `AWS-NET-20` | `defaultSensitivePorts` | 21, 22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017 |
| `AWS-NET-21` | `publicIpv4` | 0.0.0.0/0 |
| `AWS-NET-21` | `publicIpv6` | ::/0 |
| `AWS-NET-21` | `defaultSensitivePorts` | 21, 22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017 |

### Criterion examples

| Finding | Case | Input condition | Expected | Reason |
|---|---|---|---|---|
| `AWS-IAM-01` | compliant | GetAccountSummary is readable, AccountMFAEnabled equals 1, and AccountAccessKeysPresent is absent or equals 0. | pass | The compliant predicate emits pass. |
| `AWS-IAM-01` | noncompliant | AccountMFAEnabled is not 1 or AccountAccessKeysPresent is greater than 0. | fail | The noncompliant predicate emits fail. |
| `AWS-IAM-01` | partial | No warn verdict is emitted directly. | warn | The partial predicate emits warn. |
| `AWS-IAM-01` | unreadable | GetAccountSummary is unreadable; verify root MFA and absence of root access keys in IAM. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-IAM-02` | compliant | ListUsers is readable and every sampled user whose ListMFADevices call is readable has at least one MFA device. | pass | The compliant predicate emits pass. |
| `AWS-IAM-02` | noncompliant | At least one sampled IAM user has a readable empty MFA-device list. | fail | The noncompliant predicate emits fail. |
| `AWS-IAM-02` | partial | The pass result is demoted when the user inventory is truncated or one or more user MFA-device lists is unreadable. | warn | The partial predicate emits warn. |
| `AWS-IAM-02` | unreadable | ListUsers is unreadable, or every sampled user's MFA-device list is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-IAM-03` | compliant | A password policy exists, MinimumPasswordLength is at least 14, and RequireSymbols, RequireNumbers, RequireUppercaseCharacters, and RequireLowercaseCharacters are all true. | pass | The compliant predicate emits pass. |
| `AWS-IAM-03` | noncompliant | No password policy exists, minimum length is below 14, or any required complexity flag is not true. | fail | The noncompliant predicate emits fail. |
| `AWS-IAM-03` | partial | No warn verdict is emitted directly. | warn | The partial predicate emits warn. |
| `AWS-IAM-03` | unreadable | GetAccountPasswordPolicy is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-IAM-04` | compliant | ListUsers is readable and no judged access key is older than stale_days since LastUsedDate, or since CreateDate when never used; stale_days defaults to 90. | pass | The compliant predicate emits pass. |
| `AWS-IAM-04` | noncompliant | At least one judged key exceeds stale_days. | fail | The noncompliant predicate emits fail. |
| `AWS-IAM-04` | partial | The pass result is demoted when users are truncated or any user's key list or any sampled key's last-use read is unreadable. | warn | The partial predicate emits warn. |
| `AWS-IAM-04` | unreadable | ListUsers is unreadable, every user's key list is unreadable, or every sampled key's last-use read is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-IAM-05` | compliant | The role inventory is readable and no role with AdministratorAccess or an inline Allow Action='*' Resource='*' policy lacks PermissionsBoundary. | pass | The compliant predicate emits pass. |
| `AWS-IAM-05` | noncompliant | More than max_privileged_roles privileged roles lack permission boundaries. | fail | The noncompliant predicate emits fail. |
| `AWS-IAM-05` | partial | One to max_privileged_roles privileged roles lack boundaries, or an otherwise-passing role inventory is truncated; max_privileged_roles defaults to 5. | warn | The partial predicate emits warn. |
| `AWS-IAM-05` | unreadable | GetAccountAuthorizationDetails for roles is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-IAM-06` | compliant | ListUsers is readable and no user has PasswordLastUsed older than stale_days and no user with no password activity is proven to have zero access keys. | pass | The compliant predicate emits pass. |
| `AWS-IAM-06` | noncompliant | No fail verdict is emitted; dormant users require review. | warn | The noncompliant predicate emits warn. |
| `AWS-IAM-06` | partial | At least one user appears dormant, or an otherwise-passing user/key inventory is partial; stale_days defaults to 90. | warn | The partial predicate emits warn. |
| `AWS-IAM-06` | unreadable | ListUsers is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-IAM-07` | compliant | No CloudTrail event attributed to username root is found in the lookback window, first queried in us-east-1. | pass | The compliant predicate emits pass. |
| `AWS-IAM-07` | noncompliant | At least one root ConsoleLogin event exists. | fail | The noncompliant predicate emits fail. |
| `AWS-IAM-07` | partial | No root ConsoleLogin exists but another root API event exists, or an otherwise-passing lookup is truncated, contains undated events, or falls back after the us-east-1 lookup fails. | warn | The partial predicate emits warn. |
| `AWS-IAM-07` | unreadable | Root LookupEvents is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-IAM-08` | compliant | At least one customer-managed policy is readable and none has an Allow statement with wildcard Action and wildcard Resource. | pass | The compliant predicate emits pass. |
| `AWS-IAM-08` | noncompliant | An attached policy or permission-boundary policy has an Allow statement with Action='*' and Resource='*'. | fail | The noncompliant predicate emits fail. |
| `AWS-IAM-08` | partial | An unattached policy grants Action='*' and Resource='*', a policy grants a service-wide action such as service:* on Resource='*', or an otherwise-passing inventory is partial. | warn | The partial predicate emits warn. |
| `AWS-IAM-08` | unreadable | ListPolicies is unreadable or returns zero customer-managed policies; inline policies remain manual. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-LOG-01` | compliant | At least one trail has IsMultiRegionTrail=true, LogFileValidationEnabled=true and GetTrailStatus.IsLogging=true. | pass | The compliant predicate emits pass. |
| `AWS-LOG-01` | noncompliant | Trails are readable but no trail satisfies all three required values. | fail | The noncompliant predicate emits fail. |
| `AWS-LOG-01` | partial | A pass is demoted when GetTrailStatus is unreadable for any trail. | warn | The partial predicate emits warn. |
| `AWS-LOG-01` | unreadable | DescribeTrails is unreadable, or a qualifying trail exists but every qualifying logging state is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-LOG-02` | compliant | At least one readable trail has a nonempty EventSelectors.DataResources list or any AdvancedEventSelectors entry. | pass | The compliant predicate emits pass. |
| `AWS-LOG-02` | noncompliant | No fail verdict is emitted; absent data events are a review condition. | warn | The noncompliant predicate emits warn. |
| `AWS-LOG-02` | partial | Trails and selectors are readable but no data-event selector exists. | manual | The partial predicate emits manual. |
| `AWS-LOG-02` | unreadable | DescribeTrails is unreadable or any required GetEventSelectors read is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-LOG-03` | compliant | DescribeHub confirms a hub and GetEnabledStandards returns at least one standards subscription. | pass | The compliant predicate emits pass. |
| `AWS-LOG-03` | noncompliant | DescribeHub reports that the hub is not subscribed. | fail | The noncompliant predicate emits fail. |
| `AWS-LOG-03` | partial | The hub exists but standards are unreadable, empty, or truncated. | warn | The partial predicate emits warn. |
| `AWS-LOG-03` | unreadable | DescribeHub is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-LOG-04` | compliant | At least one listed detector has GetDetector.Status equal to ENABLED. | pass | The compliant predicate emits pass. |
| `AWS-LOG-04` | noncompliant | No detector exists, or all readable detectors have a status other than ENABLED. | fail | The noncompliant predicate emits fail. |
| `AWS-LOG-04` | partial | A pass is demoted when detector listing is truncated or any detector detail is unreadable. | warn | The partial predicate emits warn. |
| `AWS-LOG-04` | unreadable | ListDetectors is unreadable, or detector IDs exist but enablement is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-LOG-05` | compliant | At least one configuration recorder has a same-name status with recording=true. | pass | The compliant predicate emits pass. |
| `AWS-LOG-05` | noncompliant | No configuration recorder exists, or recorders exist but none reports recording=true. | fail | The noncompliant predicate emits fail. |
| `AWS-LOG-05` | partial | No warn verdict is emitted directly. | warn | The partial predicate emits warn. |
| `AWS-LOG-05` | unreadable | Recorder listing or recorder-status listing is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-ORG-01` | compliant | DescribeOrganization returns an organization; account listing may be readable or unreadable, but a pass is demoted if accounts are unreadable or truncated. | pass | The compliant predicate emits pass. |
| `AWS-ORG-01` | noncompliant | No fail verdict is emitted directly. | warn | The noncompliant predicate emits warn. |
| `AWS-ORG-01` | partial | The account is standalone, or organization visibility passes while member accounts are unreadable or truncated. | warn | The partial predicate emits warn. |
| `AWS-ORG-01` | unreadable | DescribeOrganization is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-ORG-02` | compliant | At least one SERVICE_CONTROL_POLICY exists and at least one policy has one or more targets. | pass | The compliant predicate emits pass. |
| `AWS-ORG-02` | noncompliant | SCPs exist, every target list is readable, and no SCP has a root, OU, or account target. | fail | The noncompliant predicate emits fail. |
| `AWS-ORG-02` | partial | The account is standalone, no SCP exists, or a pass is demoted by unreadable/truncated policy or target lists. | warn | The partial predicate emits warn. |
| `AWS-ORG-02` | unreadable | ListPolicies is unreadable, or SCPs exist but target lists needed to settle attachment are unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-ORG-03` | compliant | At least one analyzer has status ACTIVE. | pass | The compliant predicate emits pass. |
| `AWS-ORG-03` | noncompliant | The analyzer listing is readable and contains no ACTIVE analyzer. | fail | The noncompliant predicate emits fail. |
| `AWS-ORG-03` | partial | A pass is demoted when the analyzer listing is truncated. | warn | The partial predicate emits warn. |
| `AWS-ORG-03` | unreadable | ListAnalyzers is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-ORG-04` | compliant | At least one ACTIVE analyzer has a readable, complete findings list and no returned finding has missing status or status ACTIVE; severity is low. | pass | The compliant predicate emits pass. |
| `AWS-ORG-04` | noncompliant | No fail verdict is emitted; active external access is a review condition. | warn | The noncompliant predicate emits warn. |
| `AWS-ORG-04` | partial | At least one active external finding is returned; severity is high. A pass is also demoted by unreadable or truncated findings from another ACTIVE analyzer. | warn | The partial predicate emits warn. |
| `AWS-ORG-04` | unreadable | Analyzers are unreadable, no ACTIVE analyzer exists, or no ACTIVE analyzer has a readable findings list. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-ORG-05` | compliant | ListInstances returns at least one IAM Identity Center instance. | pass | The compliant predicate emits pass. |
| `AWS-ORG-05` | noncompliant | No fail verdict is emitted. | warn | The noncompliant predicate emits warn. |
| `AWS-ORG-05` | partial | No instance is visible, or an otherwise-passing list is truncated. | warn | The partial predicate emits warn. |
| `AWS-ORG-05` | unreadable | ListInstances is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-ORG-06` | compliant | ListAssessments(status=ACTIVE) returns at least one assessment with a creation or update timestamp and the list is complete. | pass | The compliant predicate emits pass. |
| `AWS-ORG-06` | noncompliant | The read is successful but returns zero ACTIVE assessments. | fail | The noncompliant predicate emits fail. |
| `AWS-ORG-06` | partial | A pass is demoted when any assessment lacks both timestamps or the list is truncated. | warn | The partial predicate emits warn. |
| `AWS-ORG-06` | unreadable | ListAssessments is unreadable; verify applicability in Audit Manager or the alternate evidence process. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-ORG-07` | compliant | GetAlternateContact(SECURITY) returns a contact with nonempty EmailAddress and PhoneNumber. | pass | The compliant predicate emits pass. |
| `AWS-ORG-07` | noncompliant | GetAlternateContact reports ResourceNotFoundException, meaning no SECURITY contact exists. | fail | The noncompliant predicate emits fail. |
| `AWS-ORG-07` | partial | A SECURITY contact exists but email or phone is missing. | warn | The partial predicate emits warn. |
| `AWS-ORG-07` | unreadable | GetAlternateContact is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-DATA-11` | compliant | All four account Block Public Access flags are true, no readable bucket policy evaluates public, all bucket reads are complete, and no bucket public-access detail is unreadable. | pass | The compliant predicate emits pass. |
| `AWS-DATA-11` | noncompliant | The account block is absent, or incomplete while any bucket lacks a full bucket block or has a public policy. | fail | The noncompliant predicate emits fail. |
| `AWS-DATA-11` | partial | The account block is incomplete but every bucket has all four bucket flags and no public policy, or the account block is complete but a policy evaluates public; a pass is also demoted by partial bucket evidence. | warn | The partial predicate emits warn. |
| `AWS-DATA-11` | unreadable | Account-level S3 Control GetPublicAccessBlock or ListBuckets is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-DATA-12` | compliant | Every readable assessed region has EbsEncryptionByDefault=true, every bucket has at least one default SSEAlgorithm, and every RDS instance with a readable StorageEncrypted field reports true. | pass | The compliant predicate emits pass. |
| `AWS-DATA-12` | noncompliant | Any readable region reports EbsEncryptionByDefault=false, any bucket lacks default encryption, or any RDS instance reports StorageEncrypted=false. | fail | The noncompliant predicate emits fail. |
| `AWS-DATA-12` | partial | The base pass is demoted by partial region scope, unreadable regional/bucket sources, truncated inventories, or any RDS instance missing StorageEncrypted. | warn | The partial predicate emits warn. |
| `AWS-DATA-12` | unreadable | EBS default encryption is unreadable in every assessed region or ListBuckets is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-DATA-13` | compliant | Every listed bucket has a Deny statement whose condition requires aws:SecureTransport=false; bucket and policy reads are complete. | pass | The compliant predicate emits pass. |
| `AWS-DATA-13` | noncompliant | At least one readable bucket lacks the required Deny statement. | fail | The noncompliant predicate emits fail. |
| `AWS-DATA-13` | partial | The pass is demoted when any bucket policy is unreadable or the bucket list is truncated. | warn | The partial predicate emits warn. |
| `AWS-DATA-13` | unreadable | ListBuckets is unreadable or returns zero buckets; load-balancer and endpoint TLS remain manual. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-DATA-22` | compliant | Every eligible key reports KeyRotationEnabled=true. Eligibility requires KeyManager=CUSTOMER, KeyState=Enabled, KeySpec=SYMMETRIC_DEFAULT and Origin=AWS_KMS. | pass | The compliant predicate emits pass. |
| `AWS-DATA-22` | noncompliant | At least one eligible key reports KeyRotationEnabled=false. | fail | The noncompliant predicate emits fail. |
| `AWS-DATA-22` | partial | Customer keys exist but none is eligible for automatic rotation, or a pass is demoted by unreadable/truncated regional scope, key metadata, or rotation status. | warn | The partial predicate emits warn. |
| `AWS-DATA-22` | unreadable | KMS lists fail in every region, no customer key exists, or no customer key can be confirmed because every KeyManager is unreadable. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-NET-14` | compliant | Every readable VPC has at least one matching flow log whose FlowLogStatus is ACTIVE. | pass | The compliant predicate emits pass. |
| `AWS-NET-14` | noncompliant | At least one readable VPC has no ACTIVE flow log. | fail | The noncompliant predicate emits fail. |
| `AWS-NET-14` | partial | The base pass is demoted by partial region scope, unreadable/truncated VPC or flow-log inventories, or missing FlowLogStatus on some logs. | warn | The partial predicate emits warn. |
| `AWS-NET-14` | unreadable | VPCs are unreadable in every region, no VPC exists, or every VPC's flow-log state is unreadable or missing. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-NET-20` | compliant | At least one network ACL is readable and none has an inbound allow entry from 0.0.0.0/0 or ::/0 whose protocol/range covers any configured sensitive port or all ports. | pass | The compliant predicate emits pass. |
| `AWS-NET-20` | noncompliant | At least one NACL has a matching permissive inbound entry. | fail | The noncompliant predicate emits fail. |
| `AWS-NET-20` | partial | A pass is demoted by partial region scope or unreadable/truncated NACL inventories. | warn | The partial predicate emits warn. |
| `AWS-NET-20` | unreadable | NACLs are unreadable in every region or no NACL is returned. | manual | The required evidence cannot be evaluated automatically. |
| `AWS-NET-21` | compliant | At least one security group is readable and none has an inbound IPv4 or IPv6 world source whose protocol/range covers any configured sensitive port or all ports. | pass | The compliant predicate emits pass. |
| `AWS-NET-21` | noncompliant | At least one security group has a matching unrestricted inbound permission. | fail | The noncompliant predicate emits fail. |
| `AWS-NET-21` | partial | A pass is demoted by partial region scope or unreadable/truncated security-group inventories. | warn | The partial predicate emits warn. |
| `AWS-NET-21` | unreadable | Security groups are unreadable in every region or no security group is returned. | manual | The required evidence cannot be evaluated automatically. |

### Compliance framework mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|---|
| 1 | MFA Enforcement | IA-2(1), IA-2(2) | AC.L2-3.1.1 | CC6.1, CC6.6 | 1.5, 1.6, 1.10 | 8.4.2 | SRG-APP-000149 | ISM-1401 | 7.2.1 |
| 2 | Password Policy | IA-5(1) | IA.L2-3.5.7 | CC6.1 | 1.8, 1.9 | 8.3.6 | SRG-APP-000166 | ISM-0421 | 7.2.2 |
| 3 | Access Key Rotation | IA-5(1) | IA.L2-3.5.8 | CC6.1, CC6.2 | 1.12, 1.14 | 8.6.3 | SRG-APP-000175 | ISM-1590 | 7.2.3 |
| 4 | Root Account Usage | AC-6(1), AC-6(5) | AC.L2-3.1.5 | CC6.1, CC6.3 | 1.4, 1.7 | 8.6.1 | SRG-APP-000340 | ISM-1507 | 7.1.1 |
| 5 | Unused Credentials | AC-2(3) | AC.L2-3.1.12 | CC6.2 | 1.12 | 8.1.4 | SRG-APP-000163 | ISM-1404 | 7.2.4 |
| 6 | CloudTrail Enabled | AU-2, AU-3, AU-12 | AU.L2-3.3.1 | CC7.2, CC7.3 | 3.1, 3.2 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 8.1.1 |
| 7 | CloudTrail Log Integrity | AU-9, AU-10 | AU.L2-3.3.8 | CC7.2 | 3.4, 3.7 | 10.3.2 | SRG-APP-000125 | ISM-0859 | 8.1.2 |
| 8 | Security Hub Enabled | CA-7, SI-4 | CA.L2-3.12.3 | CC7.1, CC7.2 | - | 11.5.1 | SRG-APP-000516 | ISM-1228 | 8.2.1 |
| 9 | GuardDuty Enabled | SI-4, IR-4 | SI.L2-3.14.6 | CC7.2, CC7.3 | - | 11.5.1 | SRG-APP-000516 | ISM-1228 | 8.2.2 |
| 10 | Config Enabled | CM-2, CM-6, CM-8 | CM.L2-3.4.1 | CC7.1 | 3.5 | 10.2.1 | SRG-APP-000516 | ISM-1228 | 8.2.3 |
| 11 | S3 Public Access | AC-3, AC-4 | AC.L2-3.1.3 | CC6.1, CC6.6 | 2.1.4 | 1.3.1 | SRG-APP-000516 | ISM-0263 | 6.1.1 |
| 12 | Encryption at Rest | SC-28 | SC.L2-3.13.16 | CC6.1, CC6.7 | 2.2.1 | 3.4.1 | SRG-APP-000231 | ISM-0457 | 6.2.1 |
| 13 | Encryption in Transit | SC-8, SC-23 | SC.L2-3.13.8 | CC6.1, CC6.7 | - | 4.1.1 | SRG-APP-000014 | ISM-0469 | 6.2.2 |
| 14 | VPC Flow Logs | AU-12, SI-4 | AU.L2-3.3.1 | CC7.2 | 3.9 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 8.1.3 |
| 15 | Cross-Account Access | AC-3, AC-6 | AC.L2-3.1.2 | CC6.1, CC6.3 | 1.16 | 7.2.1 | SRG-APP-000033 | ISM-1380 | 7.1.2 |
| 16 | SCP Enforcement | AC-3, CM-7 | AC.L2-3.1.7 | CC6.1, CC6.8 | - | 7.2.1 | SRG-APP-000246 | ISM-1380 | 7.1.3 |
| 17 | Permission Boundaries | AC-6(1), AC-6(2) | AC.L2-3.1.5 | CC6.3 | - | 7.2.2 | SRG-APP-000340 | ISM-1380 | 7.1.4 |
| 18 | Least Privilege | AC-6 | AC.L2-3.1.5 | CC6.1, CC6.3 | 1.16 | 7.2.2 | SRG-APP-000342 | ISM-1380 | 7.1.5 |
| 19 | Logging Configuration | AU-2, AU-3, AU-6 | AU.L2-3.3.1 | CC7.2, CC7.3 | 3.1, 3.3, 3.5 | 10.2.1 | SRG-APP-000089 | ISM-0580 | 8.1.4 |
| 20 | Network ACLs | AC-4, SC-7 | SC.L2-3.13.1 | CC6.1, CC6.6 | 5.1 | 1.3.1 | SRG-APP-000142 | ISM-1416 | 6.1.2 |
| 21 | Security Group Rules | AC-4, SC-7 | SC.L2-3.13.1 | CC6.1, CC6.6 | 5.2, 5.3 | 1.3.2 | SRG-APP-000142 | ISM-1416 | 6.1.3 |
| 22 | KMS Key Rotation | SC-12, SC-28 | SC.L2-3.13.10 | CC6.1, CC6.7 | 3.8 | 3.6.4 | SRG-APP-000231 | ISM-0457 | 6.2.3 |
| 23 | Identity Center Configuration | AC-2, IA-2 | AC.L2-3.1.1 | CC6.1, CC6.2 | - | 8.4.2 | SRG-APP-000149 | ISM-1401 | 7.2.5 |
| 24 | Audit Manager Evidence | CA-2, CA-7 | CA.L2-3.12.1 | CC4.1 | - | 12.4.1 | SRG-APP-000516 | ISM-1228 | 8.3.1 |
| 25 | Account Contacts | IR-6, PM-2 | IR.L2-3.6.2 | CC7.4 | 1.1, 1.2 | 12.10.5 | SRG-APP-000516 | ISM-0072 | 9.1.1 |

## Collection states

| State | Required rendering |
|---|---|
| complete | The requested operation completed and every page was read. |
| truncated | The operation returned data, but a configured item or region cap, page cap, or token anomaly prevented proven exhaustion. |
| unreadable | The operation failed or returned a response that did not contain the documented output member and shape. |
| denied | AWS refused the operation; record the action, region, error code, and observed status without treating the inventory as empty. |
| not requested | A child operation was never issued because its parent inventory was unreadable; name the parent and invent no status. |
| not configured | A service or regional surface was outside the explicitly configured assessment scope. |

## Integration-specific scrubbing

Shared contract version: 1.1.

Projection stage: Each service response is normalized to the listed members before assessment. Findings and summaries contain only normalized evidence. Every JSON artifact is recursively snapshot-scrubbed again at the write sink.

Sensitive fields and values: AccessKeyId, SecretAccessKey, SessionToken, Authorization, Cookie, Policy credentials, AlternateContact.EmailAddress, AlternateContact.PhoneNumber

Credential formats: AWS access key identifiers, AWS secret access keys, Session tokens, Signature Version 4 authorization values, Shared-configuration credential values, Private key material

Reviewed benign exceptions: Masked access key identifiers, Resource ARNs, Account identifiers, Region names, Policy names

Integration-specific rules:

- Register AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN from the environment at client construction, then register SecretAccessKey and SessionToken returned by the resolved credential provider before a signed request.
- Replace AWS access-key identifiers shaped like AKIA or ASIA plus 16 uppercase letters/digits, 40-character secret keys, Signature Version 4 Signature/Credential proofs, session tokens, authorization values, cookies, private-key material and credential assignments.
- Under snapshot keys ending in token, secret, password, credential, authorization, private key, secret key, session token, or bearer-id variants, replace every nonempty value or subtree with [REDACTED]. Keep null, undefined and the empty string to preserve absence.
- Snapshot recursion keeps scalar values through depth 32; a container deeper than 32 is replaced whole with [REDACTED].
- Mask access-key identifiers in findings as first four characters + **** + last four; identifiers of eight characters or fewer become ****.
- Preserve resource ARNs, account and region identifiers, policy names, status/code tokens, setting booleans and numeric limits unless they contain a registered configured secret.
- Never copy an HTTP response body into an error. Record fixed operation, region, sanitized error code, HTTP status, content type and byte length only.

Projected fields by surface:

| Surface | Allowed fields |
|---|---|
| `sts-get-caller-identity` | `Account`, `Arn`, `UserId` |
| `iam-get-account-summary` | `SummaryMap` |
| `iam-get-account-password-policy` | `PasswordPolicy` |
| `iam-list-users` | `Users.UserName`, `Users.Arn`, `Users.CreateDate`, `Users.PasswordLastUsed` |
| `iam-list-mfa-devices` | `MFADevices.SerialNumber`, `MFADevices.EnableDate` |
| `iam-list-access-keys` | `AccessKeyMetadata.UserName`, `AccessKeyMetadata.AccessKeyId`, `AccessKeyMetadata.Status`, `AccessKeyMetadata.CreateDate` |
| `iam-get-access-key-last-used` | `AccessKeyLastUsed.LastUsedDate`, `AccessKeyLastUsed.ServiceName`, `AccessKeyLastUsed.Region` |
| `iam-get-account-authorization-details` | `RoleDetailList`, `UserDetailList`, `GroupDetailList`, `Policies` |
| `iam-list-policies` | `Policies.PolicyName`, `Policies.Arn`, `Policies.DefaultVersionId`, `Policies.AttachmentCount`, `Policies.PermissionsBoundaryUsageCount` |
| `iam-get-policy-version` | `PolicyVersion.Document` |
| `cloudtrail-lookup-events` | `Events.EventId`, `Events.EventName`, `Events.EventSource`, `Events.EventTime`, `Events.Username`, `Events.ReadOnly` |
| `cloudtrail-describe-trails` | `trailList.Name`, `trailList.TrailARN`, `trailList.IsMultiRegionTrail`, `trailList.LogFileValidationEnabled` |
| `cloudtrail-get-trail-status` | `IsLogging` |
| `cloudtrail-get-event-selectors` | `EventSelectors`, `AdvancedEventSelectors` |
| `securityhub-describe-hub` | `HubArn` |
| `securityhub-get-enabled-standards` | `StandardsSubscriptions` |
| `config-describe-configuration-recorders` | `ConfigurationRecorders` |
| `config-describe-configuration-recorder-status` | `ConfigurationRecordersStatus` |
| `guardduty-list-detectors` | `DetectorIds` |
| `guardduty-get-detector` | `Status`, `ServiceRole` |
| `organizations-describe-organization` | `Organization.Id`, `Organization.Arn`, `Organization.FeatureSet` |
| `organizations-list-accounts` | `Accounts.Id`, `Accounts.Name`, `Accounts.Email`, `Accounts.Status` |
| `organizations-list-policies` | `Policies.Id`, `Policies.Name`, `Policies.Arn`, `Policies.Type`, `Policies.AwsManaged` |
| `organizations-list-targets-for-policy` | `Targets.TargetId`, `Targets.Name`, `Targets.Type` |
| `access-analyzer-list-analyzers` | `analyzers.arn`, `analyzers.name`, `analyzers.status`, `analyzers.type` |
| `access-analyzer-list-findings` | `findings.id`, `findings.resource`, `findings.resourceType`, `findings.status`, `findings.createdAt`, `findings.updatedAt` |
| `sso-admin-list-instances` | `Instances.InstanceArn`, `Instances.IdentityStoreId`, `Instances.Name`, `Instances.Status` |
| `auditmanager-list-assessments` | `assessmentMetadata.id`, `assessmentMetadata.name`, `assessmentMetadata.status` |
| `account-get-alternate-contact` | `AlternateContact.Name`, `AlternateContact.Title`, `AlternateContact.EmailAddress`, `AlternateContact.PhoneNumber` |
| `ec2-describe-regions` | `Regions.RegionName`, `Regions.OptInStatus` |
| `s3-get-account-public-access-block` | `PublicAccessBlockConfiguration` |
| `s3-list-buckets` | `Buckets.Name`, `Buckets.CreationDate`, `ContinuationToken` |
| `s3-get-public-access-block` | `PublicAccessBlockConfiguration` |
| `s3-get-bucket-policy-status` | `PolicyStatus.IsPublic` |
| `s3-get-bucket-encryption` | `ServerSideEncryptionConfiguration.Rules` |
| `s3-get-bucket-policy` | `Policy` |
| `ec2-get-ebs-encryption-by-default` | `EbsEncryptionByDefault`, `SseType` |
| `ec2-describe-vpcs` | `Vpcs.VpcId`, `Vpcs.IsDefault`, `Vpcs.CidrBlock`, `Vpcs.State` |
| `ec2-describe-flow-logs` | `FlowLogs.FlowLogId`, `FlowLogs.ResourceId`, `FlowLogs.FlowLogStatus` |
| `ec2-describe-network-acls` | `NetworkAcls.NetworkAclId`, `NetworkAcls.VpcId`, `NetworkAcls.Entries` |
| `ec2-describe-security-groups` | `SecurityGroups.GroupId`, `SecurityGroups.GroupName`, `SecurityGroups.VpcId`, `SecurityGroups.IpPermissions` |
| `rds-describe-db-instances` | `DBInstances.DBInstanceIdentifier`, `DBInstances.StorageEncrypted`, `DBInstances.Engine`, `DBInstances.KmsKeyId` |
| `kms-list-keys` | `Keys.KeyId`, `Keys.KeyArn` |
| `kms-describe-key` | `KeyMetadata.KeyId`, `KeyMetadata.Arn`, `KeyMetadata.KeyManager`, `KeyMetadata.KeyState`, `KeyMetadata.KeySpec`, `KeyMetadata.Origin` |
| `kms-get-key-rotation-status` | `KeyRotationEnabled`, `RotationPeriodInDays`, `NextRotationDate` |

## Export layout

Required paths:

- `README.md`
- `QUICK_REFERENCE.md`
- `metadata.json`
- `core_data/access.json`
- `analysis/findings.json`
- `analysis/identity.json`
- `analysis/logging-detection.json`
- `analysis/org-guardrails.json`
- `analysis/data-protection.json`
- `analysis/network-security.json`
- `analysis/summary.json`
- `compliance/executive_summary.md`
- `compliance/unified_compliance_matrix.md`
- `compliance/frameworks/{framework}.md`

Conditional paths:

- `_errors.log`

### Artifact schemas

| Path | Format | Required when | Schema | Serialization |
|---|---|---|---|---|
| `README.md` | markdown | Always | Evidence-bundle heading, Contents list, and credential-resolution notice. | UTF-8 with a trailing newline. |
| `QUICK_REFERENCE.md` | markdown | Always | Access summary, finding counts, Where to look, and every finding ID/title/status. | UTF-8 with a trailing newline. |
| `metadata.json` | json | Always | Object: region, profile\|null, account_id\|null, account_id_hint\|null, source_chain string[], generated_at ISO string, finding/control counts, pass/warn/fail/manual counts, options object with effective limits and regions. | Snapshot scrub, two-space JSON, insertion-order keys, one trailing newline. |
| `core_data/access.json` | json | Always | AwsAccessCheckResult record described below. | Snapshot scrub, two-space JSON, insertion-order keys, one trailing newline. |
| `analysis/findings.json` | json | Always | Array of AwsFinding records in category order: identity, logging-detection, org-guardrails, data-protection, network-security. | Snapshot scrub, two-space JSON, one trailing newline. |
| `analysis/{category}.json` | json | One each for identity, logging-detection, org-guardrails, data-protection and network-security | AwsAssessmentResult: title, summary, findings, optional errors. | Snapshot scrub, two-space JSON, insertion-order keys, one trailing newline. |
| `analysis/summary.json` | json | Always | Object: findings, controls_covered, pass, warn, fail, manual, categories[{category,pass,warn,fail,manual}]. | Snapshot scrub, two-space JSON, one trailing newline. |
| `compliance/executive_summary.md` | markdown | Always | Run metadata; Result Counts; up to 10 fail/warn findings ordered by status then severity; Manual Evidence Required; optional Collection Warnings. | UTF-8 Markdown with one trailing newline. |
| `compliance/unified_compliance_matrix.md` | markdown | Always | Finding, Controls, Title, Status, Severity and eight framework columns; pipe/newline escaped. | UTF-8 Markdown table with one trailing newline. |
| `compliance/frameworks/{framework}.md` | markdown | One file for every configured framework | Framework heading, mapped finding/status counts, then Finding, Title, Status, Severity, Mapping, Summary table. | UTF-8 Markdown with one trailing newline. |
| `_errors.log` | text | At least one collection error or truncation warning exists | Deduplicated sanitized collection messages, one per line. | UTF-8 text with one final newline. |
| `{allocated-bundle-name}.zip` | zip | Always after directory files are complete | Archive contains every bundle file under relative paths with no enclosing bundle directory. | Zip archive paired to the exact allocated directory basename; only already-scrubbed files enter the archive. |

### Record schemas

#### AwsFinding

- `id:string`
- `title:string`
- `severity:critical|high|medium|low|info`
- `status:pass|warn|fail|manual`
- `summary:string`
- `evidence?:object`
- `mappings:string[]`

#### AwsAssessmentResult

- `title:string`
- `summary:object`
- `findings:AwsFinding[]`
- `errors?:string[]`

#### AwsAccessCheckResult

- `status:healthy|limited`
- `accountId?:string`
- `arn?:string`
- `surfaces:AwsAccessSurface[]`
- `notes:string[]`
- `recommendedNextStep:string`

#### AwsAccessSurface

- `name:string`
- `service:string`
- `command:IAM action string`
- `region:string`
- `status:readable|not_readable`
- `count:number|null`
- `truncated:boolean|null`
- `error?:string`
- `error_code?:string|null`
- `http_status?:number|null`

#### NotCollectedMarker

- `collected:false`
- `command:string`
- `error:string|null`
- `error_code:string|null`
- `http_status:number|null`

#### RegionScope

- `regions:string[]`
- `regionsTotal:number|null`
- `regionsSeen:number`
- `partial:boolean`
- `source:arguments|describe-regions|configured-region-fallback`
- `error?:string`

JSON formatting: Before every JSON write, recursively scrub the complete value. Serialize with two-space indentation, preserve object insertion order, encode Date values as ISO strings through normal JSON conversion, and append exactly one newline.

Overwrite policy: Allocate a new suffixed bundle directory on every rerun; never replace an earlier bundle.

Path safety: Reject traversal, output roots outside the configured parent, symlink roots, and symlinked parent directories.

Archive pairing: Write a zip archive beside the bundle directory using the exact allocated directory name plus .zip.
