import type {
  CheckContract,
  ControlContract,
  FrameworkKey,
  IntegrationSpecContract,
  VerdictCriteria,
} from "./spec-model.js";

export type AwsFrameworkKey = FrameworkKey;

export interface AwsFrameworkDescriptor {
  key: AwsFrameworkKey;
  label: string;
  file: string;
}

export interface AwsControlDescriptor {
  title: string;
  frameworks: Record<AwsFrameworkKey, string[]>;
}

export type AwsOutputMemberKind = "list" | "map" | "structure" | "string" | "boolean" | "policyDocument";

export const AWS_DEFAULTS = {
  region: "us-east-1",
  outputDir: "./export/aws",
  userLimit: 500,
  roleLimit: 500,
  staleDays: 90,
  maxPrivilegedRoles: 5,
  maxFindings: 200,
  regionLimit: 30,
  bucketLimit: 1000,
  keyLimit: 1000,
  instanceLimit: 500,
  resourceLimit: 2000,
  policyLimit: 1000,
  eventLimit: 500,
  accountLimit: 1000,
  targetLimit: 1000,
  analyzerLimit: 100,
  standardLimit: 100,
  detectorLimit: 50,
  maxPagesPerList: 1000,
  rootLookbackDays: 90,
  rootEventRegion: "us-east-1",
  concurrency: 8,
  sensitivePorts: [21, 22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017],
} as const;

export const AWS_REQUIRED_PUBLIC_ACCESS_FLAGS = [
  "BlockPublicAcls",
  "IgnorePublicAcls",
  "BlockPublicPolicy",
  "RestrictPublicBuckets",
] as const;

export const AWS_FRAMEWORKS: ReadonlyArray<AwsFrameworkDescriptor> = [
  { key: "fedramp", label: "FedRAMP", file: "fedramp" },
  { key: "cmmc", label: "CMMC", file: "cmmc" },
  { key: "soc2", label: "SOC 2", file: "soc2" },
  { key: "cis", label: "CIS AWS", file: "cis" },
  { key: "pci_dss", label: "PCI-DSS", file: "pci-dss" },
  { key: "disa_stig", label: "DISA STIG", file: "disa-stig" },
  { key: "irap", label: "IRAP", file: "irap" },
  { key: "ismap", label: "ISMAP", file: "ismap" },
];

function control(
  title: string,
  fedramp: string[],
  cmmc: string[],
  soc2: string[],
  cis: string[],
  pciDss: string[],
  disaStig: string[],
  irap: string[],
  ismap: string[],
): AwsControlDescriptor {
  return { title, frameworks: { fedramp, cmmc, soc2, cis, pci_dss: pciDss, disa_stig: disaStig, irap, ismap } };
}

export const AWS_CONTROL_CATALOG: Record<number, AwsControlDescriptor> = {
  1: control("MFA Enforcement", ["IA-2(1)", "IA-2(2)"], ["AC.L2-3.1.1"], ["CC6.1", "CC6.6"], ["1.5", "1.6", "1.10"], ["8.4.2"], ["SRG-APP-000149"], ["ISM-1401"], ["7.2.1"]),
  2: control("Password Policy", ["IA-5(1)"], ["IA.L2-3.5.7"], ["CC6.1"], ["1.8", "1.9"], ["8.3.6"], ["SRG-APP-000166"], ["ISM-0421"], ["7.2.2"]),
  3: control("Access Key Rotation", ["IA-5(1)"], ["IA.L2-3.5.8"], ["CC6.1", "CC6.2"], ["1.12", "1.14"], ["8.6.3"], ["SRG-APP-000175"], ["ISM-1590"], ["7.2.3"]),
  4: control("Root Account Usage", ["AC-6(1)", "AC-6(5)"], ["AC.L2-3.1.5"], ["CC6.1", "CC6.3"], ["1.4", "1.7"], ["8.6.1"], ["SRG-APP-000340"], ["ISM-1507"], ["7.1.1"]),
  5: control("Unused Credentials", ["AC-2(3)"], ["AC.L2-3.1.12"], ["CC6.2"], ["1.12"], ["8.1.4"], ["SRG-APP-000163"], ["ISM-1404"], ["7.2.4"]),
  6: control("CloudTrail Enabled", ["AU-2", "AU-3", "AU-12"], ["AU.L2-3.3.1"], ["CC7.2", "CC7.3"], ["3.1", "3.2"], ["10.2.1"], ["SRG-APP-000089"], ["ISM-0580"], ["8.1.1"]),
  7: control("CloudTrail Log Integrity", ["AU-9", "AU-10"], ["AU.L2-3.3.8"], ["CC7.2"], ["3.4", "3.7"], ["10.3.2"], ["SRG-APP-000125"], ["ISM-0859"], ["8.1.2"]),
  8: control("Security Hub Enabled", ["CA-7", "SI-4"], ["CA.L2-3.12.3"], ["CC7.1", "CC7.2"], [], ["11.5.1"], ["SRG-APP-000516"], ["ISM-1228"], ["8.2.1"]),
  9: control("GuardDuty Enabled", ["SI-4", "IR-4"], ["SI.L2-3.14.6"], ["CC7.2", "CC7.3"], [], ["11.5.1"], ["SRG-APP-000516"], ["ISM-1228"], ["8.2.2"]),
  10: control("Config Enabled", ["CM-2", "CM-6", "CM-8"], ["CM.L2-3.4.1"], ["CC7.1"], ["3.5"], ["10.2.1"], ["SRG-APP-000516"], ["ISM-1228"], ["8.2.3"]),
  11: control("S3 Public Access", ["AC-3", "AC-4"], ["AC.L2-3.1.3"], ["CC6.1", "CC6.6"], ["2.1.4"], ["1.3.1"], ["SRG-APP-000516"], ["ISM-0263"], ["6.1.1"]),
  12: control("Encryption at Rest", ["SC-28"], ["SC.L2-3.13.16"], ["CC6.1", "CC6.7"], ["2.2.1"], ["3.4.1"], ["SRG-APP-000231"], ["ISM-0457"], ["6.2.1"]),
  13: control("Encryption in Transit", ["SC-8", "SC-23"], ["SC.L2-3.13.8"], ["CC6.1", "CC6.7"], [], ["4.1.1"], ["SRG-APP-000014"], ["ISM-0469"], ["6.2.2"]),
  14: control("VPC Flow Logs", ["AU-12", "SI-4"], ["AU.L2-3.3.1"], ["CC7.2"], ["3.9"], ["10.2.1"], ["SRG-APP-000089"], ["ISM-0580"], ["8.1.3"]),
  15: control("Cross-Account Access", ["AC-3", "AC-6"], ["AC.L2-3.1.2"], ["CC6.1", "CC6.3"], ["1.16"], ["7.2.1"], ["SRG-APP-000033"], ["ISM-1380"], ["7.1.2"]),
  16: control("SCP Enforcement", ["AC-3", "CM-7"], ["AC.L2-3.1.7"], ["CC6.1", "CC6.8"], [], ["7.2.1"], ["SRG-APP-000246"], ["ISM-1380"], ["7.1.3"]),
  17: control("Permission Boundaries", ["AC-6(1)", "AC-6(2)"], ["AC.L2-3.1.5"], ["CC6.3"], [], ["7.2.2"], ["SRG-APP-000340"], ["ISM-1380"], ["7.1.4"]),
  18: control("Least Privilege", ["AC-6"], ["AC.L2-3.1.5"], ["CC6.1", "CC6.3"], ["1.16"], ["7.2.2"], ["SRG-APP-000342"], ["ISM-1380"], ["7.1.5"]),
  19: control("Logging Configuration", ["AU-2", "AU-3", "AU-6"], ["AU.L2-3.3.1"], ["CC7.2", "CC7.3"], ["3.1", "3.3", "3.5"], ["10.2.1"], ["SRG-APP-000089"], ["ISM-0580"], ["8.1.4"]),
  20: control("Network ACLs", ["AC-4", "SC-7"], ["SC.L2-3.13.1"], ["CC6.1", "CC6.6"], ["5.1"], ["1.3.1"], ["SRG-APP-000142"], ["ISM-1416"], ["6.1.2"]),
  21: control("Security Group Rules", ["AC-4", "SC-7"], ["SC.L2-3.13.1"], ["CC6.1", "CC6.6"], ["5.2", "5.3"], ["1.3.2"], ["SRG-APP-000142"], ["ISM-1416"], ["6.1.3"]),
  22: control("KMS Key Rotation", ["SC-12", "SC-28"], ["SC.L2-3.13.10"], ["CC6.1", "CC6.7"], ["3.8"], ["3.6.4"], ["SRG-APP-000231"], ["ISM-0457"], ["6.2.3"]),
  23: control("Identity Center Configuration", ["AC-2", "IA-2"], ["AC.L2-3.1.1"], ["CC6.1", "CC6.2"], [], ["8.4.2"], ["SRG-APP-000149"], ["ISM-1401"], ["7.2.5"]),
  24: control("Audit Manager Evidence", ["CA-2", "CA-7"], ["CA.L2-3.12.1"], ["CC4.1"], [], ["12.4.1"], ["SRG-APP-000516"], ["ISM-1228"], ["8.3.1"]),
  25: control("Account Contacts", ["IR-6", "PM-2"], ["IR.L2-3.6.2"], ["CC7.4"], ["1.1", "1.2"], ["12.10.5"], ["SRG-APP-000516"], ["ISM-0072"], ["9.1.1"]),
};

export const AWS_FINDING_CONTROLS: Record<string, number[]> = {
  "AWS-IAM-01": [1, 4],
  "AWS-IAM-02": [1],
  "AWS-IAM-03": [2],
  "AWS-IAM-04": [3],
  "AWS-IAM-05": [17],
  "AWS-IAM-06": [5],
  "AWS-IAM-07": [4],
  "AWS-IAM-08": [18],
  "AWS-LOG-01": [6, 7],
  "AWS-LOG-02": [19],
  "AWS-LOG-03": [8],
  "AWS-LOG-04": [9],
  "AWS-LOG-05": [10],
  "AWS-ORG-01": [16],
  "AWS-ORG-02": [16],
  "AWS-ORG-03": [15],
  "AWS-ORG-04": [15],
  "AWS-ORG-05": [23],
  "AWS-ORG-06": [24],
  "AWS-ORG-07": [25],
  "AWS-DATA-11": [11],
  "AWS-DATA-12": [12],
  "AWS-DATA-13": [13],
  "AWS-DATA-22": [22],
  "AWS-NET-14": [14],
  "AWS-NET-20": [20],
  "AWS-NET-21": [21],
};

export const AWS_REQUIRED_OUTPUT_MEMBERS: Readonly<Record<string, Readonly<Record<string, AwsOutputMemberKind>>>> = Object.freeze({
  GetCallerIdentity: { Account: "string" },
  GetAccountSummary: { SummaryMap: "map" },
  GetAccountPasswordPolicy: { PasswordPolicy: "structure" },
  ListUsers: { Users: "list" },
  ListMFADevices: { MFADevices: "list" },
  ListAccessKeys: { AccessKeyMetadata: "list" },
  GetAccessKeyLastUsed: { AccessKeyLastUsed: "structure" },
  GetAccountAuthorizationDetails: { RoleDetailList: "list", UserDetailList: "list", GroupDetailList: "list", Policies: "list" },
  ListPolicies: { Policies: "list" },
  GetPolicyVersion: { PolicyVersion: "structure" },
  LookupEvents: { Events: "list" },
  DescribeTrails: { trailList: "list" },
  GetTrailStatus: { IsLogging: "boolean" },
  GetEventSelectors: { TrailARN: "string", EventSelectors: "list", AdvancedEventSelectors: "list" },
  DescribeHub: { HubArn: "string" },
  GetEnabledStandards: { StandardsSubscriptions: "list" },
  DescribeConfigurationRecorders: { ConfigurationRecorders: "list" },
  DescribeConfigurationRecorderStatus: { ConfigurationRecordersStatus: "list" },
  ListDetectors: { DetectorIds: "list" },
  GetDetector: { Status: "string", ServiceRole: "string" },
  DescribeOrganization: { Organization: "structure" },
  ListAccounts: { Accounts: "list" },
  ListTargetsForPolicy: { Targets: "list" },
  ListAnalyzers: { analyzers: "list" },
  ListFindings: { findings: "list" },
  ListInstances: { Instances: "list" },
  ListAssessments: { assessmentMetadata: "list" },
  GetAlternateContact: { AlternateContact: "structure" },
  DescribeRegions: { Regions: "list" },
  GetPublicAccessBlock: { PublicAccessBlockConfiguration: "structure" },
  ListBuckets: { Buckets: "list" },
  GetBucketPolicyStatus: { PolicyStatus: "structure" },
  GetBucketEncryption: { ServerSideEncryptionConfiguration: "structure" },
  GetBucketPolicy: { Policy: "policyDocument" },
  GetEbsEncryptionByDefault: { EbsEncryptionByDefault: "boolean" },
  DescribeVpcs: { Vpcs: "list" },
  DescribeFlowLogs: { FlowLogs: "list" },
  DescribeNetworkAcls: { NetworkAcls: "list" },
  DescribeSecurityGroups: { SecurityGroups: "list" },
  DescribeDBInstances: { DBInstances: "list" },
  ListKeys: { Keys: "list" },
  DescribeKey: { KeyMetadata: "structure" },
  GetKeyRotationStatus: { KeyRotationEnabled: "boolean" },
});

interface AwsOperationContract {
  id: string;
  service: string;
  operation: string;
  action: string;
  fields: readonly string[];
}

function operation(service: string, operationName: string, fields: readonly string[], actionPrefix = service): AwsOperationContract {
  const stableOperationId = operationName
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1-$2")
    .replace(/([a-z0-9])([A-Z])/g, "$1-$2")
    .toLowerCase();
  return {
    id: `${service}-${stableOperationId}`,
    service,
    operation: operationName,
    action: `${actionPrefix}:${operationName}`,
    fields,
  };
}

export const AWS_OPERATIONS: readonly AwsOperationContract[] = [
  operation("sts", "GetCallerIdentity", ["Account", "Arn", "UserId"]),
  operation("iam", "GetAccountSummary", ["SummaryMap"]),
  operation("iam", "GetAccountPasswordPolicy", ["PasswordPolicy"]),
  operation("iam", "ListUsers", ["Users.UserName", "Users.Arn", "Users.CreateDate", "Users.PasswordLastUsed"]),
  operation("iam", "ListMFADevices", ["MFADevices.SerialNumber", "MFADevices.EnableDate"]),
  operation("iam", "ListAccessKeys", ["AccessKeyMetadata.UserName", "AccessKeyMetadata.AccessKeyId", "AccessKeyMetadata.Status", "AccessKeyMetadata.CreateDate"]),
  operation("iam", "GetAccessKeyLastUsed", ["AccessKeyLastUsed.LastUsedDate", "AccessKeyLastUsed.ServiceName", "AccessKeyLastUsed.Region"]),
  operation("iam", "GetAccountAuthorizationDetails", ["RoleDetailList", "UserDetailList", "GroupDetailList", "Policies"]),
  operation("iam", "ListPolicies", ["Policies.PolicyName", "Policies.Arn", "Policies.DefaultVersionId", "Policies.AttachmentCount", "Policies.PermissionsBoundaryUsageCount"]),
  operation("iam", "GetPolicyVersion", ["PolicyVersion.Document"]),
  operation("cloudtrail", "LookupEvents", ["Events.EventId", "Events.EventName", "Events.EventSource", "Events.EventTime", "Events.Username", "Events.ReadOnly"]),
  operation("cloudtrail", "DescribeTrails", ["trailList.Name", "trailList.TrailARN", "trailList.IsMultiRegionTrail", "trailList.LogFileValidationEnabled"]),
  operation("cloudtrail", "GetTrailStatus", ["IsLogging"]),
  operation("cloudtrail", "GetEventSelectors", ["EventSelectors", "AdvancedEventSelectors"]),
  operation("securityhub", "DescribeHub", ["HubArn"]),
  operation("securityhub", "GetEnabledStandards", ["StandardsSubscriptions"]),
  operation("config", "DescribeConfigurationRecorders", ["ConfigurationRecorders"]),
  operation("config", "DescribeConfigurationRecorderStatus", ["ConfigurationRecordersStatus"]),
  operation("guardduty", "ListDetectors", ["DetectorIds"]),
  operation("guardduty", "GetDetector", ["Status", "ServiceRole"]),
  operation("organizations", "DescribeOrganization", ["Organization.Id", "Organization.Arn", "Organization.FeatureSet"]),
  operation("organizations", "ListAccounts", ["Accounts.Id", "Accounts.Name", "Accounts.Email", "Accounts.Status"]),
  operation("organizations", "ListPolicies", ["Policies.Id", "Policies.Name", "Policies.Arn", "Policies.Type", "Policies.AwsManaged"]),
  operation("organizations", "ListTargetsForPolicy", ["Targets.TargetId", "Targets.Name", "Targets.Type"]),
  operation("access-analyzer", "ListAnalyzers", ["analyzers.arn", "analyzers.name", "analyzers.status", "analyzers.type"]),
  operation("access-analyzer", "ListFindings", ["findings.id", "findings.resource", "findings.resourceType", "findings.status", "findings.createdAt", "findings.updatedAt"]),
  operation("sso-admin", "ListInstances", ["Instances.InstanceArn", "Instances.IdentityStoreId", "Instances.Name", "Instances.Status"], "sso"),
  operation("auditmanager", "ListAssessments", ["assessmentMetadata.id", "assessmentMetadata.name", "assessmentMetadata.status"]),
  operation("account", "GetAlternateContact", ["AlternateContact.Name", "AlternateContact.Title", "AlternateContact.EmailAddress", "AlternateContact.PhoneNumber"]),
  operation("ec2", "DescribeRegions", ["Regions.RegionName", "Regions.OptInStatus"]),
  operation("s3", "GetAccountPublicAccessBlock", ["PublicAccessBlockConfiguration"], "s3"),
  operation("s3", "ListBuckets", ["Buckets.Name", "Buckets.CreationDate", "ContinuationToken"]),
  operation("s3", "GetPublicAccessBlock", ["PublicAccessBlockConfiguration"]),
  operation("s3", "GetBucketPolicyStatus", ["PolicyStatus.IsPublic"]),
  operation("s3", "GetBucketEncryption", ["ServerSideEncryptionConfiguration.Rules"]),
  operation("s3", "GetBucketPolicy", ["Policy"]),
  operation("ec2", "GetEbsEncryptionByDefault", ["EbsEncryptionByDefault", "SseType"]),
  operation("ec2", "DescribeVpcs", ["Vpcs.VpcId", "Vpcs.IsDefault", "Vpcs.CidrBlock", "Vpcs.State"]),
  operation("ec2", "DescribeFlowLogs", ["FlowLogs.FlowLogId", "FlowLogs.ResourceId", "FlowLogs.FlowLogStatus"]),
  operation("ec2", "DescribeNetworkAcls", ["NetworkAcls.NetworkAclId", "NetworkAcls.VpcId", "NetworkAcls.Entries"]),
  operation("ec2", "DescribeSecurityGroups", ["SecurityGroups.GroupId", "SecurityGroups.GroupName", "SecurityGroups.VpcId", "SecurityGroups.IpPermissions"]),
  operation("rds", "DescribeDBInstances", ["DBInstances.DBInstanceIdentifier", "DBInstances.StorageEncrypted", "DBInstances.Engine", "DBInstances.KmsKeyId"]),
  operation("kms", "ListKeys", ["Keys.KeyId", "Keys.KeyArn"]),
  operation("kms", "DescribeKey", ["KeyMetadata.KeyId", "KeyMetadata.Arn", "KeyMetadata.KeyManager", "KeyMetadata.KeyState", "KeyMetadata.KeySpec", "KeyMetadata.Origin"]),
  operation("kms", "GetKeyRotationStatus", ["KeyRotationEnabled", "RotationPeriodInDays", "NextRotationDate"]),
];

function docsUrl(entry: AwsOperationContract): string {
  const serviceDocs: Record<string, string> = {
    "access-analyzer": "access-analyzer",
    account: "accounts",
    auditmanager: "auditmanager",
    cloudtrail: "awscloudtrail",
    config: "config",
    ec2: "AWSEC2",
    guardduty: "guardduty",
    iam: "IAM",
    kms: "kms",
    organizations: "organizations",
    rds: "AmazonRDS",
    s3: "AmazonS3",
    securityhub: "securityhub",
    "sso-admin": "singlesignon",
    sts: "STS",
  };
  return `https://docs.aws.amazon.com/${serviceDocs[entry.service]}/latest/APIReference/API_${entry.operation}.html`;
}

const AWS_CONTROLS: ControlContract[] = Object.entries(AWS_CONTROL_CATALOG).map(([number, descriptor]) => ({
  number: Number(number),
  title: descriptor.title,
  frameworks: descriptor.frameworks,
}));

const CRITERIA: VerdictCriteria = {
  pass: "Every required source is complete and the observed configuration satisfies the check.",
  warn: "The evidence is partial, scope-limited, or contains a condition that needs review without proving noncompliance.",
  fail: "Complete readable evidence proves that the required configuration is absent or noncompliant.",
  manual: "A required operation is unreadable, denied, not requested, or does not expose enough evidence for an automated verdict.",
};

const CHECK_INPUTS = [
  ["AWS-IAM-01", "Root account MFA and access keys", "critical", "aws_assess_identity", ["iam-get-account-summary"]],
  ["AWS-IAM-02", "IAM user MFA coverage", "high", "aws_assess_identity", ["iam-list-users", "iam-list-mfa-devices"]],
  ["AWS-IAM-03", "Password policy strength", "high", "aws_assess_identity", ["iam-get-account-password-policy"]],
  ["AWS-IAM-04", "Access key rotation", "high", "aws_assess_identity", ["iam-list-users", "iam-list-access-keys", "iam-get-access-key-last-used"]],
  ["AWS-IAM-05", "Privileged role boundaries", "medium", "aws_assess_identity", ["iam-get-account-authorization-details"]],
  ["AWS-IAM-06", "Dormant IAM users", "low", "aws_assess_identity", ["iam-list-users", "iam-list-access-keys", "iam-get-access-key-last-used"]],
  ["AWS-IAM-07", "Root account activity", "high", "aws_assess_identity", ["cloudtrail-lookup-events"]],
  ["AWS-IAM-08", "Customer-managed policy wildcards", "high", "aws_assess_identity", ["iam-list-policies", "iam-get-policy-version"]],
  ["AWS-LOG-01", "Multi-region CloudTrail with validation", "critical", "aws_assess_logging_detection", ["cloudtrail-describe-trails", "cloudtrail-get-trail-status"]],
  ["AWS-LOG-02", "CloudTrail data events", "high", "aws_assess_logging_detection", ["cloudtrail-get-event-selectors"]],
  ["AWS-LOG-03", "Security Hub enablement", "high", "aws_assess_logging_detection", ["securityhub-describe-hub", "securityhub-get-enabled-standards"]],
  ["AWS-LOG-04", "GuardDuty detectors", "high", "aws_assess_logging_detection", ["guardduty-list-detectors", "guardduty-get-detector"]],
  ["AWS-LOG-05", "AWS Config recording", "high", "aws_assess_logging_detection", ["config-describe-configuration-recorders", "config-describe-configuration-recorder-status"]],
  ["AWS-ORG-01", "Organizations visibility", "medium", "aws_assess_org_guardrails", ["organizations-describe-organization", "organizations-list-accounts"]],
  ["AWS-ORG-02", "Service control policies", "high", "aws_assess_org_guardrails", ["organizations-list-policies", "organizations-list-targets-for-policy"]],
  ["AWS-ORG-03", "Access Analyzer enablement", "high", "aws_assess_org_guardrails", ["access-analyzer-list-analyzers"]],
  ["AWS-ORG-04", "External access findings", "high", "aws_assess_org_guardrails", ["access-analyzer-list-findings"]],
  ["AWS-ORG-05", "Identity Center visibility", "medium", "aws_assess_org_guardrails", ["sso-admin-list-instances"]],
  ["AWS-ORG-06", "Audit Manager active assessments", "medium", "aws_assess_org_guardrails", ["auditmanager-list-assessments"]],
  ["AWS-ORG-07", "Account security contact", "medium", "aws_assess_org_guardrails", ["account-get-alternate-contact"]],
  ["AWS-DATA-11", "S3 Block Public Access", "critical", "aws_assess_data_protection", ["s3-get-account-public-access-block", "s3-list-buckets", "s3-get-public-access-block", "s3-get-bucket-policy-status"]],
  ["AWS-DATA-12", "Encryption at rest defaults", "high", "aws_assess_data_protection", ["ec2-get-ebs-encryption-by-default", "s3-get-bucket-encryption", "rds-describe-db-instances"]],
  ["AWS-DATA-13", "S3 TLS-only bucket policies", "high", "aws_assess_data_protection", ["s3-get-bucket-policy"]],
  ["AWS-DATA-22", "KMS customer-managed key rotation", "high", "aws_assess_data_protection", ["kms-list-keys", "kms-describe-key", "kms-get-key-rotation-status"]],
  ["AWS-NET-14", "VPC Flow Logs coverage", "high", "aws_assess_network_security", ["ec2-describe-vpcs", "ec2-describe-flow-logs"]],
  ["AWS-NET-20", "Network ACL inbound exposure", "high", "aws_assess_network_security", ["ec2-describe-network-acls"]],
  ["AWS-NET-21", "Security group inbound exposure", "high", "aws_assess_network_security", ["ec2-describe-security-groups"]],
] as const;

export const AWS_CHECKS: readonly CheckContract[] = CHECK_INPUTS.map(([id, title, severity, owningTool, sourceSurfaceIds]) => ({
  id,
  controlNumbers: AWS_FINDING_CONTROLS[id],
  title,
  severity,
  owningTool,
  sourceSurfaceIds,
  criteria: CRITERIA,
}));

const AWS_EXPORT = {
  files: [
    "README.md",
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access.json",
    "analysis/findings.json",
    "analysis/identity.json",
    "analysis/logging-detection.json",
    "analysis/org-guardrails.json",
    "analysis/data-protection.json",
    "analysis/network-security.json",
    "analysis/summary.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/frameworks/{framework}.md",
  ],
  conditionalFiles: ["_errors.log"],
  overwritePolicy: "Allocate a new suffixed bundle directory on every rerun; never replace an earlier bundle.",
  pathSafetyPolicy: "Reject traversal, output roots outside the configured parent, symlink roots, and symlinked parent directories.",
  archivePairing: "Write a zip archive beside the bundle directory using the exact allocated directory name plus .zip.",
} as const;

export const AWS_SPEC: IntegrationSpecContract = {
  identity: {
    slug: "aws-sec-inspector",
    displayName: "AWS Security Inspector",
    vendor: "Amazon Web Services",
    category: "cloud-infrastructure",
    kind: "security-inspector",
    version: "2.0",
    lastUpdated: "2026-09-27",
    summary: "Read-only AWS posture inspection across identity, logging, detection, organization guardrails, data protection, and network security.",
  },
  sourceModule: "cli/extensions/grc-tools/aws.spec.ts",
  baseServices: ["AWS regional and global service endpoints selected by the credential and region configuration"],
  apiSurfaces: AWS_OPERATIONS.map((entry) => ({
    id: entry.id,
    kind: "sdk",
    operation: entry.operation,
    baseService: entry.service,
    documentationUrl: docsUrl(entry),
    fieldsConsumed: entry.fields,
    intent: entry.operation === "GetCallerIdentity" ? "auth-only" : "read",
  })),
  authentication: {
    modes: ["AWS default credential provider chain", "Named shared-configuration profile"],
    credentialPrecedence: ["Named profile argument or AWS_PROFILE", "Environment credentials", "Shared credentials and configuration files", "Container credentials", "Instance role credentials"],
    environmentVariables: ["AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION"],
    configLocations: ["~/.aws/credentials", "~/.aws/config"],
    variants: ["Long-lived access keys", "Temporary session credentials", "Identity Center cached session", "Container role", "Instance role"],
  },
  permissions: AWS_OPERATIONS.map((entry) => ({ id: entry.id, kind: "iam-action", value: entry.action, unlocks: [entry.id] })),
  pagination: [
    {
      surfaceIds: AWS_OPERATIONS.filter((entry) => ["ListUsers", "ListPolicies", "GetAccountAuthorizationDetails"].includes(entry.operation)).map((entry) => entry.id),
      cursorFields: ["Marker", "IsTruncated"],
      pageSize: 100,
      itemCap: null,
      pageCap: AWS_DEFAULTS.maxPagesPerList,
      totalSemantics: "IAM does not return a stable population total; report items seen and truncation.",
      stopConditions: ["IsTruncated is false", "Configured item cap", "Page cap", "Missing or repeated marker"],
    },
    {
      surfaceIds: AWS_OPERATIONS.filter((entry) => ["LookupEvents", "GetEnabledStandards", "ListDetectors", "ListAccounts", "ListTargetsForPolicy", "ListAnalyzers", "ListFindings", "ListInstances", "ListAssessments", "DescribeVpcs", "DescribeFlowLogs", "DescribeNetworkAcls", "DescribeSecurityGroups"].includes(entry.operation)).map((entry) => entry.id),
      cursorFields: ["NextToken", "nextToken"],
      pageSize: null,
      itemCap: null,
      pageCap: AWS_DEFAULTS.maxPagesPerList,
      totalSemantics: "The service does not provide a dependable total; report items seen and truncation.",
      stopConditions: ["No next token", "Configured item cap", "Page cap", "Missing or repeated token"],
    },
    {
      surfaceIds: ["s3-list-buckets"],
      cursorFields: ["ContinuationToken"],
      pageSize: 1000,
      itemCap: AWS_DEFAULTS.bucketLimit,
      pageCap: AWS_DEFAULTS.maxPagesPerList,
      totalSemantics: "No total is returned; only exhaustion proves completeness.",
      stopConditions: ["No continuation token", "Bucket cap", "Page cap", "Missing or repeated token"],
    },
    {
      surfaceIds: ["rds-describe-db-instances", "kms-list-keys"],
      cursorFields: ["Marker", "NextMarker", "Truncated"],
      pageSize: 100,
      itemCap: null,
      pageCap: AWS_DEFAULTS.maxPagesPerList,
      totalSemantics: "No total is returned; only exhaustion proves completeness.",
      stopConditions: ["No marker", "Configured item cap", "Page cap", "Missing or repeated marker"],
    },
  ],
  rateLimits: [{
    scope: "AWS service APIs",
    documentedLimit: null,
    retryHeaders: [],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Use the service client's bounded retry behavior. If retries are exhausted, mark the surface unreadable and demote dependent findings.",
  }],
  controls: AWS_CONTROLS,
  checks: AWS_CHECKS,
  collectionStates: {
    complete: "The requested operation completed and every page was read.",
    truncated: "The operation returned data, but a configured item or region cap, page cap, or token anomaly prevented proven exhaustion.",
    unreadable: "The operation failed or returned a response that did not contain the documented output member and shape.",
    denied: "AWS refused the operation; record the action, region, error code, and observed status without treating the inventory as empty.",
    notRequested: "A child operation was never issued because its parent inventory was unreadable; name the parent and invent no status.",
    notConfigured: "A service or regional surface was outside the explicitly configured assessment scope.",
  },
  redaction: {
    sharedContractVersion: "1.0",
    projections: Object.fromEntries(AWS_OPERATIONS.map((entry) => [entry.id, entry.fields])),
    sensitiveFields: ["AccessKeyId", "SecretAccessKey", "SessionToken", "Authorization", "Cookie", "Policy credentials", "AlternateContact.EmailAddress", "AlternateContact.PhoneNumber"],
    benignExceptions: ["Masked access key identifiers", "Resource ARNs", "Account identifiers", "Region names", "Policy names"],
    credentialFormats: ["AWS access key identifiers", "AWS secret access keys", "Session tokens", "Signature Version 4 authorization values", "Shared-configuration credential values", "Private key material"],
  },
  output: AWS_EXPORT,
  tools: [
    { name: "aws_check_access", checkIds: [] },
    ...["aws_assess_identity", "aws_assess_logging_detection", "aws_assess_org_guardrails", "aws_assess_data_protection", "aws_assess_network_security"].map((name) => ({
      name,
      checkIds: AWS_CHECKS.filter((item) => item.owningTool === name).map((item) => item.id),
    })),
    { name: "aws_export_audit_bundle", checkIds: AWS_CHECKS.map((item) => item.id), output: AWS_EXPORT },
  ],
};
