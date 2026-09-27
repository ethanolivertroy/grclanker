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
> Generated from `cli/extensions/grc-tools/aws.spec.ts` and registered tool definitions by `npm --prefix cli run sync:integration-specs`. Edit the metadata or narrative source, not this file.

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

This specification requires [shared integration contract version 1.0](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.

## Tools

| Tool | Purpose | Finding IDs |
|---|---|---|
| `aws_check_access` | Validate read-only AWS audit access across IAM, CloudTrail, Security Hub, Config, GuardDuty, Access Analyzer, Organizations, Identity Center, EC2, S3, KMS, RDS, Audit Manager, and Account surfaces. | None |
| `aws_assess_identity` | Assess AWS IAM hygiene, including root-account protection, IAM user MFA, password policy, access key rotation, dormant users, and privileged roles without permission boundaries. | `AWS-IAM-01`, `AWS-IAM-02`, `AWS-IAM-03`, `AWS-IAM-04`, `AWS-IAM-05`, `AWS-IAM-06`, `AWS-IAM-07`, `AWS-IAM-08` |
| `aws_assess_logging_detection` | Assess AWS CloudTrail, Security Hub, GuardDuty, and Config posture, including multi-region trail coverage, log validation, data events, standards enablement, and active recording. | `AWS-LOG-01`, `AWS-LOG-02`, `AWS-LOG-03`, `AWS-LOG-04`, `AWS-LOG-05` |
| `aws_assess_org_guardrails` | Assess AWS Organizations visibility, service control policies, Access Analyzer coverage, active external-access findings, and IAM Identity Center visibility. | `AWS-ORG-01`, `AWS-ORG-02`, `AWS-ORG-03`, `AWS-ORG-04`, `AWS-ORG-05`, `AWS-ORG-06`, `AWS-ORG-07` |
| `aws_assess_data_protection` | Assess AWS data protection posture: account and bucket S3 Block Public Access, EBS default encryption per region, S3 default encryption, RDS storage encryption, TLS-only bucket policies (aws:SecureTransport), and customer-managed KMS key rotation. | `AWS-DATA-11`, `AWS-DATA-12`, `AWS-DATA-13`, `AWS-DATA-22` |
| `aws_assess_network_security` | Assess AWS network security posture per region: VPC Flow Logs coverage (DescribeFlowLogs versus DescribeVpcs), network ACL inbound rules open to 0.0.0.0/0 or ::/0 on sensitive ports, and security group inbound rules open to the world on sensitive ports. | `AWS-NET-14`, `AWS-NET-20`, `AWS-NET-21` |
| `aws_export_audit_bundle` | Export an AWS audit package with the access check, identity, logging and detection, organization guardrail, data protection, and network security findings, an executive summary, a unified compliance matrix, per-framework reports, JSON analysis, an error log when collection was partial, and a zip archive named after the bundle directory. | `AWS-IAM-01`, `AWS-IAM-02`, `AWS-IAM-03`, `AWS-IAM-04`, `AWS-IAM-05`, `AWS-IAM-06`, `AWS-IAM-07`, `AWS-IAM-08`, `AWS-LOG-01`, `AWS-LOG-02`, `AWS-LOG-03`, `AWS-LOG-04`, `AWS-LOG-05`, `AWS-ORG-01`, `AWS-ORG-02`, `AWS-ORG-03`, `AWS-ORG-04`, `AWS-ORG-05`, `AWS-ORG-06`, `AWS-ORG-07`, `AWS-DATA-11`, `AWS-DATA-12`, `AWS-DATA-13`, `AWS-DATA-22`, `AWS-NET-14`, `AWS-NET-20`, `AWS-NET-21` |

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

Environment variables: `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_DEFAULT_REGION`

Configuration locations: ~/.aws/credentials, ~/.aws/config

Credential and deployment variants: Long-lived access keys, Temporary session credentials, Identity Center cached session, Container role, Instance role

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

| ID | Interface | Read operation | Service | Intent | Fields consumed | Reference |
|---|---|---|---|---|---|---|
| `sts-get-caller-identity` | service operation | `GetCallerIdentity` | sts | auth-only | `Account`, `Arn`, `UserId` | [Official documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) |
| `iam-get-account-summary` | service operation | `GetAccountSummary` | iam | read | `SummaryMap` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html) |
| `iam-get-account-password-policy` | service operation | `GetAccountPasswordPolicy` | iam | read | `PasswordPolicy` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountPasswordPolicy.html) |
| `iam-list-users` | service operation | `ListUsers` | iam | read | `Users.UserName`, `Users.Arn`, `Users.CreateDate`, `Users.PasswordLastUsed` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html) |
| `iam-list-mfa-devices` | service operation | `ListMFADevices` | iam | read | `MFADevices.SerialNumber`, `MFADevices.EnableDate` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListMFADevices.html) |
| `iam-list-access-keys` | service operation | `ListAccessKeys` | iam | read | `AccessKeyMetadata.UserName`, `AccessKeyMetadata.AccessKeyId`, `AccessKeyMetadata.Status`, `AccessKeyMetadata.CreateDate` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html) |
| `iam-get-access-key-last-used` | service operation | `GetAccessKeyLastUsed` | iam | read | `AccessKeyLastUsed.LastUsedDate`, `AccessKeyLastUsed.ServiceName`, `AccessKeyLastUsed.Region` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html) |
| `iam-get-account-authorization-details` | service operation | `GetAccountAuthorizationDetails` | iam | read | `RoleDetailList`, `UserDetailList`, `GroupDetailList`, `Policies` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html) |
| `iam-list-policies` | service operation | `ListPolicies` | iam | read | `Policies.PolicyName`, `Policies.Arn`, `Policies.DefaultVersionId`, `Policies.AttachmentCount`, `Policies.PermissionsBoundaryUsageCount` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html) |
| `iam-get-policy-version` | service operation | `GetPolicyVersion` | iam | read | `PolicyVersion.Document` | [Official documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html) |
| `cloudtrail-lookup-events` | service operation | `LookupEvents` | cloudtrail | read | `Events.EventId`, `Events.EventName`, `Events.EventSource`, `Events.EventTime`, `Events.Username`, `Events.ReadOnly` | [Official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html) |
| `cloudtrail-describe-trails` | service operation | `DescribeTrails` | cloudtrail | read | `trailList.Name`, `trailList.TrailARN`, `trailList.IsMultiRegionTrail`, `trailList.LogFileValidationEnabled` | [Official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeTrails.html) |
| `cloudtrail-get-trail-status` | service operation | `GetTrailStatus` | cloudtrail | read | `IsLogging` | [Official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html) |
| `cloudtrail-get-event-selectors` | service operation | `GetEventSelectors` | cloudtrail | read | `EventSelectors`, `AdvancedEventSelectors` | [Official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html) |
| `securityhub-describe-hub` | service operation | `DescribeHub` | securityhub | read | `HubArn` | [Official documentation](https://docs.aws.amazon.com/securityhub/latest/APIReference/API_DescribeHub.html) |
| `securityhub-get-enabled-standards` | service operation | `GetEnabledStandards` | securityhub | read | `StandardsSubscriptions` | [Official documentation](https://docs.aws.amazon.com/securityhub/latest/APIReference/API_GetEnabledStandards.html) |
| `config-describe-configuration-recorders` | service operation | `DescribeConfigurationRecorders` | config | read | `ConfigurationRecorders` | [Official documentation](https://docs.aws.amazon.com/config/latest/APIReference/API_DescribeConfigurationRecorders.html) |
| `config-describe-configuration-recorder-status` | service operation | `DescribeConfigurationRecorderStatus` | config | read | `ConfigurationRecordersStatus` | [Official documentation](https://docs.aws.amazon.com/config/latest/APIReference/API_DescribeConfigurationRecorderStatus.html) |
| `guardduty-list-detectors` | service operation | `ListDetectors` | guardduty | read | `DetectorIds` | [Official documentation](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html) |
| `guardduty-get-detector` | service operation | `GetDetector` | guardduty | read | `Status`, `ServiceRole` | [Official documentation](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetDetector.html) |
| `organizations-describe-organization` | service operation | `DescribeOrganization` | organizations | read | `Organization.Id`, `Organization.Arn`, `Organization.FeatureSet` | [Official documentation](https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeOrganization.html) |
| `organizations-list-accounts` | service operation | `ListAccounts` | organizations | read | `Accounts.Id`, `Accounts.Name`, `Accounts.Email`, `Accounts.Status` | [Official documentation](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html) |
| `organizations-list-policies` | service operation | `ListPolicies` | organizations | read | `Policies.Id`, `Policies.Name`, `Policies.Arn`, `Policies.Type`, `Policies.AwsManaged` | [Official documentation](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPolicies.html) |
| `organizations-list-targets-for-policy` | service operation | `ListTargetsForPolicy` | organizations | read | `Targets.TargetId`, `Targets.Name`, `Targets.Type` | [Official documentation](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListTargetsForPolicy.html) |
| `access-analyzer-list-analyzers` | service operation | `ListAnalyzers` | access-analyzer | read | `analyzers.arn`, `analyzers.name`, `analyzers.status`, `analyzers.type` | [Official documentation](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ListAnalyzers.html) |
| `access-analyzer-list-findings` | service operation | `ListFindings` | access-analyzer | read | `findings.id`, `findings.resource`, `findings.resourceType`, `findings.status`, `findings.createdAt`, `findings.updatedAt` | [Official documentation](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ListFindings.html) |
| `sso-admin-list-instances` | service operation | `ListInstances` | sso-admin | read | `Instances.InstanceArn`, `Instances.IdentityStoreId`, `Instances.Name`, `Instances.Status` | [Official documentation](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListInstances.html) |
| `auditmanager-list-assessments` | service operation | `ListAssessments` | auditmanager | read | `assessmentMetadata.id`, `assessmentMetadata.name`, `assessmentMetadata.status` | [Official documentation](https://docs.aws.amazon.com/auditmanager/latest/APIReference/API_ListAssessments.html) |
| `account-get-alternate-contact` | service operation | `GetAlternateContact` | account | read | `AlternateContact.Name`, `AlternateContact.Title`, `AlternateContact.EmailAddress`, `AlternateContact.PhoneNumber` | [Official documentation](https://docs.aws.amazon.com/accounts/latest/APIReference/API_GetAlternateContact.html) |
| `ec2-describe-regions` | service operation | `DescribeRegions` | ec2 | read | `Regions.RegionName`, `Regions.OptInStatus` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html) |
| `s3-get-account-public-access-block` | service operation | `GetAccountPublicAccessBlock` | s3 | read | `PublicAccessBlockConfiguration` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/APIReference/API_GetAccountPublicAccessBlock.html) |
| `s3-list-buckets` | service operation | `ListBuckets` | s3 | read | `Buckets.Name`, `Buckets.CreationDate`, `ContinuationToken` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/APIReference/API_ListBuckets.html) |
| `s3-get-public-access-block` | service operation | `GetPublicAccessBlock` | s3 | read | `PublicAccessBlockConfiguration` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/APIReference/API_GetPublicAccessBlock.html) |
| `s3-get-bucket-policy-status` | service operation | `GetBucketPolicyStatus` | s3 | read | `PolicyStatus.IsPublic` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/APIReference/API_GetBucketPolicyStatus.html) |
| `s3-get-bucket-encryption` | service operation | `GetBucketEncryption` | s3 | read | `ServerSideEncryptionConfiguration.Rules` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/APIReference/API_GetBucketEncryption.html) |
| `s3-get-bucket-policy` | service operation | `GetBucketPolicy` | s3 | read | `Policy` | [Official documentation](https://docs.aws.amazon.com/AmazonS3/latest/APIReference/API_GetBucketPolicy.html) |
| `ec2-get-ebs-encryption-by-default` | service operation | `GetEbsEncryptionByDefault` | ec2 | read | `EbsEncryptionByDefault`, `SseType` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetEbsEncryptionByDefault.html) |
| `ec2-describe-vpcs` | service operation | `DescribeVpcs` | ec2 | read | `Vpcs.VpcId`, `Vpcs.IsDefault`, `Vpcs.CidrBlock`, `Vpcs.State` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcs.html) |
| `ec2-describe-flow-logs` | service operation | `DescribeFlowLogs` | ec2 | read | `FlowLogs.FlowLogId`, `FlowLogs.ResourceId`, `FlowLogs.FlowLogStatus` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeFlowLogs.html) |
| `ec2-describe-network-acls` | service operation | `DescribeNetworkAcls` | ec2 | read | `NetworkAcls.NetworkAclId`, `NetworkAcls.VpcId`, `NetworkAcls.Entries` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeNetworkAcls.html) |
| `ec2-describe-security-groups` | service operation | `DescribeSecurityGroups` | ec2 | read | `SecurityGroups.GroupId`, `SecurityGroups.GroupName`, `SecurityGroups.VpcId`, `SecurityGroups.IpPermissions` | [Official documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html) |
| `rds-describe-db-instances` | service operation | `DescribeDBInstances` | rds | read | `DBInstances.DBInstanceIdentifier`, `DBInstances.StorageEncrypted`, `DBInstances.Engine`, `DBInstances.KmsKeyId` | [Official documentation](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html) |
| `kms-list-keys` | service operation | `ListKeys` | kms | read | `Keys.KeyId`, `Keys.KeyArn` | [Official documentation](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html) |
| `kms-describe-key` | service operation | `DescribeKey` | kms | read | `KeyMetadata.KeyId`, `KeyMetadata.Arn`, `KeyMetadata.KeyManager`, `KeyMetadata.KeyState`, `KeyMetadata.KeySpec`, `KeyMetadata.Origin` | [Official documentation](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html) |
| `kms-get-key-rotation-status` | service operation | `GetKeyRotationStatus` | kms | read | `KeyRotationEnabled`, `RotationPeriodInDays`, `NextRotationDate` | [Official documentation](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html) |

## Pagination

| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |
|---|---|---|---|---|---|---|
| `iam-list-users`, `iam-get-account-authorization-details`, `iam-list-policies`, `organizations-list-policies` | `Marker`, `IsTruncated` | 100 | caller limit | 1000 | IAM does not return a stable population total; report items seen and truncation. | IsTruncated is false; Configured item cap; Page cap; Missing or repeated marker |
| `cloudtrail-lookup-events`, `securityhub-get-enabled-standards`, `guardduty-list-detectors`, `organizations-list-accounts`, `organizations-list-targets-for-policy`, `access-analyzer-list-analyzers`, `access-analyzer-list-findings`, `sso-admin-list-instances`, `auditmanager-list-assessments`, `ec2-describe-vpcs`, `ec2-describe-flow-logs`, `ec2-describe-network-acls`, `ec2-describe-security-groups` | `NextToken`, `nextToken` | service default | caller limit | 1000 | The service does not provide a dependable total; report items seen and truncation. | No next token; Configured item cap; Page cap; Missing or repeated token |
| `s3-list-buckets` | `ContinuationToken` | 1000 | 1000 | 1000 | No total is returned; only exhaustion proves completeness. | No continuation token; Bucket cap; Page cap; Missing or repeated token |
| `rds-describe-db-instances`, `kms-list-keys` | `Marker`, `NextMarker`, `Truncated` | 100 | caller limit | 1000 | No total is returned; only exhaustion proves completeness. | No marker; Configured item cap; Page cap; Missing or repeated marker |

## Rate limits

| Scope | Documented limit | Retry headers | Retryable statuses | Policy |
|---|---|---|---|---|
| AWS service APIs | Not published | None | 429, 500, 502, 503, 504 | Use the service client's bounded retry behavior. If retries are exhausted, mark the surface unreadable and demote dependent findings. |

## Checks

### Control coverage

| # | Control | Finding | Verdict semantics |
|---|---|---|---|
| 1 | MFA Enforcement | AWS-IAM-01, AWS-IAM-02 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 2 | Password Policy | AWS-IAM-03 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 3 | Access Key Rotation | AWS-IAM-04 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 4 | Root Account Usage | AWS-IAM-01, AWS-IAM-07 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 5 | Unused Credentials | AWS-IAM-06 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 6 | CloudTrail Enabled | AWS-LOG-01 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 7 | CloudTrail Log Integrity | AWS-LOG-01 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 8 | Security Hub Enabled | AWS-LOG-03 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 9 | GuardDuty Enabled | AWS-LOG-04 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 10 | Config Enabled | AWS-LOG-05 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 11 | S3 Public Access | AWS-DATA-11 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 12 | Encryption at Rest | AWS-DATA-12 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 13 | Encryption in Transit | AWS-DATA-13 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 14 | VPC Flow Logs | AWS-NET-14 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 15 | Cross-Account Access | AWS-ORG-03, AWS-ORG-04 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 16 | SCP Enforcement | AWS-ORG-01, AWS-ORG-02 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 17 | Permission Boundaries | AWS-IAM-05 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 18 | Least Privilege | AWS-IAM-08 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 19 | Logging Configuration | AWS-LOG-02 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 20 | Network ACLs | AWS-NET-20 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 21 | Security Group Rules | AWS-NET-21 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 22 | KMS Key Rotation | AWS-DATA-22 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 23 | Identity Center Configuration | AWS-ORG-05 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 24 | Audit Manager Evidence | AWS-ORG-06 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| 25 | Account Contacts | AWS-ORG-07 | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |

### Finding criteria

| Finding | Severity | Owning tool | Sources | Pass | Warn | Fail | Manual |
|---|---|---|---|---|---|---|---|
| `AWS-IAM-01` | critical | `aws_assess_identity` | `iam-get-account-summary` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-IAM-02` | high | `aws_assess_identity` | `iam-list-users`, `iam-list-mfa-devices` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-IAM-03` | high | `aws_assess_identity` | `iam-get-account-password-policy` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-IAM-04` | high | `aws_assess_identity` | `iam-list-users`, `iam-list-access-keys`, `iam-get-access-key-last-used` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-IAM-05` | medium | `aws_assess_identity` | `iam-get-account-authorization-details` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-IAM-06` | low | `aws_assess_identity` | `iam-list-users`, `iam-list-access-keys`, `iam-get-access-key-last-used` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-IAM-07` | high | `aws_assess_identity` | `cloudtrail-lookup-events` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-IAM-08` | high | `aws_assess_identity` | `iam-list-policies`, `iam-get-policy-version` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-LOG-01` | critical | `aws_assess_logging_detection` | `cloudtrail-describe-trails`, `cloudtrail-get-trail-status` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-LOG-02` | high | `aws_assess_logging_detection` | `cloudtrail-get-event-selectors` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-LOG-03` | high | `aws_assess_logging_detection` | `securityhub-describe-hub`, `securityhub-get-enabled-standards` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-LOG-04` | high | `aws_assess_logging_detection` | `guardduty-list-detectors`, `guardduty-get-detector` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-LOG-05` | high | `aws_assess_logging_detection` | `config-describe-configuration-recorders`, `config-describe-configuration-recorder-status` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-ORG-01` | medium | `aws_assess_org_guardrails` | `organizations-describe-organization`, `organizations-list-accounts` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-ORG-02` | high | `aws_assess_org_guardrails` | `organizations-list-policies`, `organizations-list-targets-for-policy` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-ORG-03` | high | `aws_assess_org_guardrails` | `access-analyzer-list-analyzers` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-ORG-04` | high | `aws_assess_org_guardrails` | `access-analyzer-list-findings` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-ORG-05` | medium | `aws_assess_org_guardrails` | `sso-admin-list-instances` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-ORG-06` | medium | `aws_assess_org_guardrails` | `auditmanager-list-assessments` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-ORG-07` | medium | `aws_assess_org_guardrails` | `account-get-alternate-contact` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-DATA-11` | critical | `aws_assess_data_protection` | `s3-get-account-public-access-block`, `s3-list-buckets`, `s3-get-public-access-block`, `s3-get-bucket-policy-status` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-DATA-12` | high | `aws_assess_data_protection` | `ec2-get-ebs-encryption-by-default`, `s3-get-bucket-encryption`, `rds-describe-db-instances` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-DATA-13` | high | `aws_assess_data_protection` | `s3-get-bucket-policy` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-DATA-22` | high | `aws_assess_data_protection` | `kms-list-keys`, `kms-describe-key`, `kms-get-key-rotation-status` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-NET-14` | high | `aws_assess_network_security` | `ec2-describe-vpcs`, `ec2-describe-flow-logs` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-NET-20` | high | `aws_assess_network_security` | `ec2-describe-network-acls` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |
| `AWS-NET-21` | high | `aws_assess_network_security` | `ec2-describe-security-groups` | Every required source is complete and the observed configuration satisfies the check. | The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance. | Complete readable evidence proves that the required configuration is absent or noncompliant. | A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict. |

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

Shared contract version: 1.0.

Sensitive fields and values: AccessKeyId, SecretAccessKey, SessionToken, Authorization, Cookie, Policy credentials, AlternateContact.EmailAddress, AlternateContact.PhoneNumber

Credential formats: AWS access key identifiers, AWS secret access keys, Session tokens, Signature Version 4 authorization values, Shared-configuration credential values, Private key material

Reviewed benign exceptions: Masked access key identifiers, Resource ARNs, Account identifiers, Region names, Policy names

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

Overwrite policy: Allocate a new suffixed bundle directory on every rerun; never replace an earlier bundle.

Path safety: Reject traversal, output roots outside the configured parent, symlink roots, and symlinked parent directories.

Archive pairing: Write a zip archive beside the bundle directory using the exact allocated directory name plus .zip.
