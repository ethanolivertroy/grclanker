import type {
  CheckContract,
  ControlContract,
  FrameworkKey,
  IntegrationSpecContract,
  PortableValue,
  RequestContract,
  VerdictCriteria,
  VerdictCondition,
  VerdictOperand,
  VerdictRule,
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

export const AWS_VERDICT_VALUES = {
  minimumPasswordLength: 14,
  passwordComplexityFields: ["RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", "RequireLowercaseCharacters"],
  accountMfaEnabled: 1,
  accountAccessKeysPresent: 0,
  administratorPolicyName: "AdministratorAccess",
  rootConsoleLoginEvent: "ConsoleLogin",
  enabledGuardDutyStatus: "ENABLED",
  activeAnalyzerStatus: "ACTIVE",
  activeFindingStatus: "ACTIVE",
  activeAssessmentStatus: "ACTIVE",
  activeFlowLogStatus: "ACTIVE",
  customerKeyManager: "CUSTOMER",
  eligibleKeyState: "Enabled",
  eligibleKeySpec: "SYMMETRIC_DEFAULT",
  eligibleKeyOrigin: "AWS_KMS",
  publicIpv4Cidr: "0.0.0.0/0",
  publicIpv6Cidr: "::/0",
  allowedNetworkAction: "allow",
  secureTransportConditionKey: "aws:SecureTransport",
  secureTransportDeniedValue: "false",
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
  documentationNamespace: string;
  documentationUrl?: string;
  fields: readonly string[];
}

interface AwsOperationOptions {
  id?: string;
  action?: string;
  documentationNamespace?: string;
  documentationUrl?: string;
}

function operation(
  service: string,
  operationName: string,
  fields: readonly string[],
  options: AwsOperationOptions = {},
): AwsOperationContract {
  const stableOperationId = operationName
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1-$2")
    .replace(/([a-z0-9])([A-Z])/g, "$1-$2")
    .toLowerCase();
  return {
    id: options.id ?? `${service}-${stableOperationId}`,
    service,
    operation: operationName,
    action: options.action ?? `${service}:${operationName}`,
    documentationNamespace: options.documentationNamespace ?? service,
    documentationUrl: options.documentationUrl,
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
  operation("sso-admin", "ListInstances", ["Instances.InstanceArn", "Instances.IdentityStoreId", "Instances.Name", "Instances.Status"], { action: "sso:ListInstances" }),
  operation("auditmanager", "ListAssessments", ["assessmentMetadata.id", "assessmentMetadata.name", "assessmentMetadata.status", "assessmentMetadata.complianceType", "assessmentMetadata.creationTime", "assessmentMetadata.lastUpdated"]),
  operation("account", "GetAlternateContact", ["AlternateContact.Name", "AlternateContact.Title", "AlternateContact.EmailAddress", "AlternateContact.PhoneNumber"]),
  operation("ec2", "DescribeRegions", ["Regions.RegionName", "Regions.OptInStatus"]),
  operation("s3-control", "GetPublicAccessBlock", ["PublicAccessBlockConfiguration"], {
    id: "s3-get-account-public-access-block",
    action: "s3:GetAccountPublicAccessBlock",
    documentationNamespace: "s3-control",
    documentationUrl: "https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_GetPublicAccessBlock.html",
  }),
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

export const AWS_IAM_ACTIONS: Readonly<Record<string, string>> = Object.freeze(
  Object.fromEntries(AWS_OPERATIONS.map((entry) => [entry.id, entry.action])),
);

const requestParameter = (
  name: string,
  required: boolean,
  value: string,
  when?: string,
): RequestContract["parameters"][number] => ({
  name,
  location: "operation-input",
  required,
  value,
  ...(when ? { when } : {}),
});

const AWS_REQUEST_PARAMETERS: Readonly<Record<string, RequestContract["parameters"]>> = {
  "iam-list-users": [requestParameter("Marker", false, "Previous page marker"), requestParameter("MaxItems", true, "min(100, remaining item budget)")],
  "iam-list-mfa-devices": [requestParameter("UserName", true, "Current IAM user name")],
  "iam-list-access-keys": [requestParameter("UserName", true, "Current IAM user name")],
  "iam-get-access-key-last-used": [requestParameter("AccessKeyId", true, "Current access key identifier")],
  "iam-get-account-authorization-details": [
    requestParameter("Filter", true, "['Role']"),
    requestParameter("Marker", false, "Previous page marker"),
    requestParameter("MaxItems", true, "min(100, remaining item budget)"),
  ],
  "iam-list-policies": [
    requestParameter("Scope", true, "Local"),
    requestParameter("OnlyAttached", true, "false"),
    requestParameter("Marker", false, "Previous page marker"),
    requestParameter("MaxItems", true, "100"),
  ],
  "iam-get-policy-version": [
    requestParameter("PolicyArn", true, "ARN from ListPolicies"),
    requestParameter("VersionId", true, "DefaultVersionId from ListPolicies, falling back to v1 only when absent"),
  ],
  "cloudtrail-lookup-events": [
    requestParameter("LookupAttributes", true, "[{AttributeKey: Username, AttributeValue: root}]"),
    requestParameter("StartTime", true, "Current time minus lookback_days, clamped to the 90-day service history"),
    requestParameter("EndTime", true, "Current time"),
    requestParameter("MaxResults", true, "50"),
    requestParameter("NextToken", false, "Previous page token"),
  ],
  "cloudtrail-describe-trails": [requestParameter("includeShadowTrails", true, "false")],
  "cloudtrail-get-trail-status": [requestParameter("Name", true, "TrailARN, falling back to Name")],
  "cloudtrail-get-event-selectors": [requestParameter("TrailName", true, "TrailARN, falling back to Name")],
  "securityhub-get-enabled-standards": [requestParameter("MaxResults", true, "100"), requestParameter("NextToken", false, "Previous page token")],
  "guardduty-list-detectors": [requestParameter("MaxResults", true, "50"), requestParameter("NextToken", false, "Previous page token")],
  "guardduty-get-detector": [requestParameter("DetectorId", true, "Identifier from ListDetectors")],
  "organizations-list-accounts": [requestParameter("NextToken", false, "Previous page token"), requestParameter("MaxResults", true, "min(20, remaining item budget)")],
  "organizations-list-policies": [
    requestParameter("Filter", true, "SERVICE_CONTROL_POLICY"),
    requestParameter("NextToken", false, "Previous page token"),
    requestParameter("MaxResults", true, "20"),
  ],
  "organizations-list-targets-for-policy": [
    requestParameter("PolicyId", true, "Identifier from ListPolicies"),
    requestParameter("NextToken", false, "Previous page token"),
  ],
  "access-analyzer-list-analyzers": [requestParameter("nextToken", false, "Previous page token"), requestParameter("maxResults", true, "100")],
  "access-analyzer-list-findings": [
    requestParameter("analyzerArn", true, "ARN of each ACTIVE analyzer"),
    requestParameter("maxResults", true, "min(100, remaining finding budget)"),
    requestParameter("nextToken", false, "Previous page token"),
  ],
  "sso-admin-list-instances": [requestParameter("MaxResults", true, "100"), requestParameter("NextToken", false, "Previous page token")],
  "auditmanager-list-assessments": [
    requestParameter("status", true, AWS_VERDICT_VALUES.activeAssessmentStatus),
    requestParameter("maxResults", true, "100"),
    requestParameter("nextToken", false, "Previous page token"),
  ],
  "account-get-alternate-contact": [requestParameter("AlternateContactType", true, "SECURITY")],
  "ec2-describe-regions": [requestParameter("Filters", true, "opt-in-status in [opt-in-not-required, opted-in]")],
  "s3-get-account-public-access-block": [requestParameter("AccountId", true, "Account from GetCallerIdentity, falling back to account_id configuration")],
  "s3-list-buckets": [requestParameter("ContinuationToken", false, "Previous page token"), requestParameter("MaxBuckets", true, "min(1000, remaining item budget)")],
  "s3-get-public-access-block": [requestParameter("Bucket", true, "Bucket name from ListBuckets")],
  "s3-get-bucket-policy-status": [requestParameter("Bucket", true, "Bucket name from ListBuckets")],
  "s3-get-bucket-encryption": [requestParameter("Bucket", true, "Bucket name from ListBuckets")],
  "s3-get-bucket-policy": [requestParameter("Bucket", true, "Bucket name from ListBuckets")],
  "ec2-describe-vpcs": [requestParameter("NextToken", false, "Previous page token"), requestParameter("MaxResults", true, "1000")],
  "ec2-describe-flow-logs": [requestParameter("NextToken", false, "Previous page token"), requestParameter("MaxResults", true, "1000")],
  "ec2-describe-network-acls": [requestParameter("NextToken", false, "Previous page token"), requestParameter("MaxResults", true, "1000")],
  "ec2-describe-security-groups": [requestParameter("NextToken", false, "Previous page token"), requestParameter("MaxResults", true, "1000")],
  "rds-describe-db-instances": [requestParameter("Marker", false, "Previous page marker"), requestParameter("MaxRecords", true, "100")],
  "kms-list-keys": [requestParameter("Marker", false, "Previous page marker"), requestParameter("Limit", true, "1000")],
  "kms-describe-key": [requestParameter("KeyId", true, "KeyId from ListKeys")],
  "kms-get-key-rotation-status": [requestParameter("KeyId", true, "Eligible KeyId from DescribeKey")],
};

function awsClientRegion(surfaceId: string): string {
  if (surfaceId === "cloudtrail-lookup-events") {
    return `${AWS_DEFAULTS.rootEventRegion} for global root activity, then the configured region only as a fallback when the global lookup fails and differs.`;
  }
  if (/^(?:ec2|rds|kms)-/.test(surfaceId)) return "Each assessed region; DescribeRegions itself uses the configured region.";
  return "The configured home region.";
}

export const AWS_REQUESTS: Readonly<Record<string, RequestContract>> = Object.freeze(Object.fromEntries(
  AWS_OPERATIONS.map((entry) => [
    entry.id,
    {
      clientRegion: awsClientRegion(entry.id),
      headers: ["Service request signed with AWS Signature Version 4 by the resolved credential provider."],
      parameters: AWS_REQUEST_PARAMETERS[entry.id] ?? [],
      responseShape: Object.entries(AWS_REQUIRED_OUTPUT_MEMBERS[entry.operation] ?? {})
        .map(([name, kind]) => `${name}: ${kind}`)
        .join(", ") || "The documented service response shape.",
    },
  ]),
));

function docsUrl(entry: AwsOperationContract): string {
  if (entry.documentationUrl) return entry.documentationUrl;
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
  return `https://docs.aws.amazon.com/${serviceDocs[entry.documentationNamespace]}/latest/APIReference/API_${entry.operation}.html`;
}

const AWS_CONTROLS: ControlContract[] = Object.entries(AWS_CONTROL_CATALOG).map(([number, descriptor]) => ({
  number: Number(number),
  title: descriptor.title,
  frameworks: descriptor.frameworks,
}));

function criteria(
  pass: string,
  warn: string,
  fail: string,
  manual: string,
  constants: VerdictCriteria["constants"] = {},
  emitted: { compliant?: "pass" | "manual"; noncompliant?: "fail" | "warn" | "manual"; partial?: "warn" | "manual" } = {},
): VerdictCriteria {
  const compliant = emitted.compliant ?? "pass";
  const noncompliant = emitted.noncompliant ?? "fail";
  const partial = emitted.partial ?? "warn";
  return {
    pass,
    warn,
    fail,
    manual,
    constants,
    examples: [
      { kind: "compliant", input: pass, expected: compliant, reason: `The compliant predicate emits ${compliant}.` },
      { kind: "noncompliant", input: fail, expected: noncompliant, reason: `The noncompliant predicate emits ${noncompliant}.` },
      { kind: "partial", input: warn, expected: partial, reason: `The partial predicate emits ${partial}.` },
      { kind: "unreadable", input: manual, expected: "manual", reason: "The required evidence cannot be evaluated automatically." },
    ],
    rules: [],
  };
}

function awsCheck(
  id: string,
  title: string,
  severity: CheckContract["severity"],
  owningTool: string,
  sourceSurfaceIds: readonly string[],
  verdictCriteria: VerdictCriteria,
): CheckContract {
  const evidenceFields = AWS_EVIDENCE_FIELDS[id];
  if (!evidenceFields) throw new Error(`No evidence schema exists for ${id}`);
  const derivedFacts = AWS_DERIVED_FACTS[id] ?? {};
  const rules = AWS_VERDICT_RULES[id];
  if (!rules) throw new Error(`No runtime verdict rules exist for ${id}`);
  return {
    id,
    controlNumbers: AWS_FINDING_CONTROLS[id],
    title,
    severity,
    owningTool,
    sourceSurfaceIds,
    evidenceFields,
    derivedFacts,
    criteria: {
      ...verdictCriteria,
      rules,
    },
  };
}

const IDENTITY_TOOL = "aws_assess_identity";
const LOGGING_TOOL = "aws_assess_logging_detection";
const ORG_TOOL = "aws_assess_org_guardrails";
const DATA_TOOL = "aws_assess_data_protection";
const NETWORK_TOOL = "aws_assess_network_security";

export const AWS_EVIDENCE_FIELDS: Readonly<Record<string, readonly string[]>> = {
  "AWS-IAM-01": ["summary_readable", "account_mfa_enabled", "account_access_keys_present"],
  "AWS-IAM-02": ["users_readable", "user_count", "users_mfa_judged", "users_without_mfa", "users_mfa_unreadable", "user_inventory_truncated"],
  "AWS-IAM-03": ["password_policy_readable", "password_policy_configured", "password_policy"],
  "AWS-IAM-04": ["users_readable", "keys_sampled", "keys_judged", "stale_access_keys", "users_keys_unreadable", "keys_last_used_unreadable", "user_inventory_truncated"],
  "AWS-IAM-05": ["roles_readable", "roles_read", "privileged_roles", "roles_without_boundaries", "max_privileged_roles", "role_inventory_truncated"],
  "AWS-IAM-06": ["users_readable", "dormant_users", "users_keys_unreadable", "user_inventory_truncated"],
  "AWS-IAM-07": ["region", "lookup_region", "global_event_region", "global_lookup_error", "lookback_days", "window_start", "events_readable", "root_events", "root_console_logins", "root_other_events", "lookup_truncated"],
  "AWS-IAM-08": ["policies_readable", "customer_managed_policies", "full_admin_attached", "full_admin_unattached", "service_wildcard_policies", "policies_unreadable", "policy_inventory_truncated", "inline_policies"],
  "AWS-LOG-01": ["trails_readable", "trails"],
  "AWS-LOG-02": ["trails_readable", "data_event_trails", "selectors_unreadable"],
  "AWS-LOG-03": ["hub_readable", "hub_enabled", "standards_readable", "standard_count", "standards_truncated"],
  "AWS-LOG-04": ["detectors_readable", "detector_count", "enabled_detectors", "detectors_unreadable", "detector_list_truncated"],
  "AWS-LOG-05": ["recorders_readable", "recorder_status_readable", "recorders", "recorder_statuses"],
  "AWS-ORG-01": ["organization_readable", "standalone", "organization", "accounts_readable", "accounts", "account_list_truncated"],
  "AWS-ORG-02": ["scps_readable", "scp_count", "attached_scp_count", "scps_targets_unreadable", "scp_list_truncated", "sample"],
  "AWS-ORG-03": ["analyzers_readable", "analyzers", "analyzer_list_truncated"],
  "AWS-ORG-04": ["analyzers_readable", "analyzers_sampled", "analyzers_findings_unreadable", "analyzers_findings_truncated", "active_finding_count", "sample"],
  "AWS-ORG-05": ["instances_readable", "identity_center_instances", "instance_list_truncated"],
  "AWS-ORG-06": ["assessments_readable", "active_assessments", "assessments", "list_truncated"],
  "AWS-ORG-07": ["contact_readable", "security_contact_configured", "has_name", "has_title", "email_domain", "has_phone", "billing_and_operations_contacts"],
  "AWS-DATA-11": ["account_id", "account_block_readable", "account_block_configured", "account_flags", "buckets_readable", "buckets", "buckets_without_full_block", "buckets_without_bucket_level_block", "buckets_with_public_policy", "buckets_unreadable", "bucket_inventory_truncated"],
  "AWS-DATA-12": ["regions_seen", "regions_total", "regions", "partial", "source", "scope_error", "ebs_by_region", "rds_instances", "rds_unencrypted", "rds_without_flag", "regions_with_rds_errors", "buckets_readable", "buckets", "buckets_without_default_encryption", "buckets_encryption_unreadable", "bucket_inventory_truncated", "efs"],
  "AWS-DATA-13": ["buckets_readable", "buckets", "buckets_without_tls_deny", "buckets_policy_unreadable", "bucket_inventory_truncated", "load_balancer_tls"],
  "AWS-DATA-22": ["regions_seen", "regions_total", "regions", "partial", "source", "scope_error", "keys", "customer_managed_keys", "eligible_keys", "keys_not_rotating", "keys_rotation_unreadable", "keys_manager_unreadable", "ineligible_customer_keys", "key_inventory_truncated", "regions_with_list_errors"],
  "AWS-NET-14": ["regions_seen", "regions_total", "regions", "partial", "source", "scope_error", "vpcs", "vpcs_without_active_flow_logs", "vpcs_unverified", "inventory_truncated", "regions_with_vpc_errors", "regions_with_flow_log_errors"],
  "AWS-NET-20": ["regions_seen", "regions_total", "regions", "partial", "source", "scope_error", "sensitive_ports", "network_acls", "permissive_network_acls", "inventory_truncated", "regions_with_errors"],
  "AWS-NET-21": ["regions_seen", "regions_total", "regions", "partial", "source", "scope_error", "sensitive_ports", "security_groups", "unrestricted_security_groups", "inventory_truncated", "regions_with_errors"],
};

export const AWS_DERIVED_FACTS: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  "AWS-IAM-04": {
    keys_last_used_unreadable_count: "Count every sampled access key whose GetAccessKeyLastUsed read is unavailable, before the evidence list is capped at 25.",
  },
  "AWS-IAM-05": {
    roles_without_boundaries_count: "Count every privileged role without PermissionsBoundary, before the evidence list is capped at 25.",
  },
  "AWS-IAM-07": {
    undated_root_events: "Count entries returned by LookupEvents whose EventTime is absent or cannot be parsed as a date.",
  },
  "AWS-ORG-06": {
    undated_assessments: "Count ACTIVE assessment records for which both lastUpdated and creationTime are absent or cannot be parsed as dates.",
  },
  "AWS-NET-14": {
    vpcs_unverified_count: "Count every VPC whose flow-log inventory is unreadable or whose matching flow logs have no ACTIVE status and at least one missing FlowLogStatus, before the evidence list is capped at 25.",
  },
};

const awsPath = (name: string, fallback?: PortableValue): VerdictOperand =>
  fallback === undefined ? { kind: "path", path: name } : { kind: "path", path: name, fallback };
const awsValue = (entry: PortableValue): VerdictOperand => ({ kind: "value", value: entry });
const awsLength = (name: string): VerdictOperand => ({ kind: "length", path: name });
const awsCompare = (op: Extract<VerdictCondition["op"], "eq" | "ne" | "gt" | "gte" | "lt" | "lte">, left: VerdictOperand, right: VerdictOperand): VerdictCondition => ({ op, left, right });
const awsEq = (name: string, entry: PortableValue): VerdictCondition => awsCompare("eq", awsPath(name), awsValue(entry));
const awsDefined = (name: string): VerdictCondition => ({ op: "defined", operand: awsPath(name) });
const awsNull = (name: string): VerdictCondition => ({ op: "null", operand: awsPath(name) });
const awsAnd = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const awsOr = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const awsNot = (condition: VerdictCondition): VerdictCondition => ({ op: "not", condition });
const awsSome = (name: string, condition: VerdictCondition): VerdictCondition => ({ op: "some", path: name, condition });
const awsEvery = (name: string, condition: VerdictCondition): VerdictCondition => ({ op: "every", path: name, condition });
const awsRule = (status: VerdictRule["status"], condition: VerdictCondition, note?: string): VerdictRule => ({ status, condition, ...(note ? { note } : {}) });
const awsNonempty = (name: string): VerdictCondition => awsCompare("gt", awsLength(name), awsValue(0));
const awsEmpty = (name: string): VerdictCondition => awsCompare("eq", awsLength(name), awsValue(0));
const awsMissingOrZero = (name: string): VerdictCondition => awsOr(awsNot(awsDefined(name)), awsEq(name, 0));

export const AWS_VERDICT_RULES: Readonly<Record<string, readonly VerdictRule[]>> = {
  "AWS-IAM-01": [
    awsRule("manual", awsEq("summary_readable", false)),
    awsRule("fail", awsOr(awsCompare("ne", awsPath("account_mfa_enabled"), awsValue(AWS_VERDICT_VALUES.accountMfaEnabled)), awsCompare("gt", awsPath("account_access_keys_present", 0), awsValue(0)))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-IAM-02": [
    awsRule("manual", awsOr(awsEq("users_readable", false), awsNull("users_mfa_judged"))),
    awsRule("fail", awsNonempty("users_without_mfa")),
    awsRule("warn", awsOr(awsEq("user_inventory_truncated", true), awsNonempty("users_mfa_unreadable"))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-IAM-03": [
    awsRule("manual", awsEq("password_policy_readable", false)),
    awsRule("fail", awsOr(
      awsEq("password_policy_configured", false),
      awsCompare("lt", awsPath("password_policy.MinimumPasswordLength", 0), awsValue(AWS_VERDICT_VALUES.minimumPasswordLength)),
      ...AWS_VERDICT_VALUES.passwordComplexityFields.map((field) => awsCompare("ne", awsPath(`password_policy.${field}`), awsValue(true))),
    )),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-IAM-04": [
    awsRule("manual", awsOr(
      awsEq("users_readable", false),
      awsNull("keys_sampled"),
      awsAnd(awsCompare("gt", awsPath("keys_sampled", 0), awsValue(0)), awsCompare("eq", awsPath("keys_last_used_unreadable_count", 0), awsPath("keys_sampled", 0))),
    )),
    awsRule("fail", awsNonempty("stale_access_keys")),
    awsRule("warn", awsOr(awsEq("user_inventory_truncated", true), awsNonempty("users_keys_unreadable"), awsNonempty("keys_last_used_unreadable"))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-IAM-05": [
    awsRule("manual", awsEq("roles_readable", false)),
    awsRule("fail", awsCompare("gt", awsPath("roles_without_boundaries_count", 0), awsPath("max_privileged_roles", AWS_DEFAULTS.maxPrivilegedRoles))),
    awsRule("warn", awsOr(awsCompare("gt", awsPath("roles_without_boundaries_count", 0), awsValue(0)), awsEq("role_inventory_truncated", true))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-IAM-06": [
    awsRule("manual", awsEq("users_readable", false)),
    awsRule("warn", awsOr(awsNonempty("dormant_users"), awsEq("user_inventory_truncated", true), awsNonempty("users_keys_unreadable"))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-IAM-07": [
    awsRule("manual", awsEq("events_readable", false)),
    awsRule("fail", awsNonempty("root_console_logins")),
    awsRule("warn", awsOr(
      awsNonempty("root_other_events"),
      awsAnd(awsDefined("global_lookup_error"), awsCompare("ne", awsPath("global_lookup_error"), awsValue(null))),
      awsEq("lookup_truncated", true),
      awsCompare("gt", awsPath("undated_root_events", 0), awsValue(0)),
    )),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-IAM-08": [
    awsRule("manual", awsOr(awsEq("policies_readable", false), awsEq("customer_managed_policies", 0))),
    awsRule("fail", awsNonempty("full_admin_attached")),
    awsRule("warn", awsOr(awsNonempty("full_admin_unattached"), awsNonempty("service_wildcard_policies"), awsNonempty("policies_unreadable"), awsEq("policy_inventory_truncated", true))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-LOG-01": [
    awsRule("manual", awsOr(
      awsEq("trails_readable", false),
      awsAnd(
        awsNot(awsSome("trails", awsAnd(awsEq("$.is_multi_region", true), awsEq("$.validation", true), awsEq("$.is_logging", true)))),
        awsSome("trails", awsAnd(awsEq("$.is_multi_region", true), awsEq("$.validation", true), awsNull("$.is_logging"))),
      ),
    )),
    awsRule("fail", awsNot(awsSome("trails", awsAnd(awsEq("$.is_multi_region", true), awsEq("$.validation", true), awsEq("$.is_logging", true))))),
    awsRule("warn", awsSome("trails", awsAnd(awsDefined("$.status_error"), awsCompare("ne", awsPath("$.status_error"), awsValue(null))))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-LOG-02": [
    awsRule("manual", awsOr(awsEq("trails_readable", false), awsNull("data_event_trails"), awsAnd(awsEmpty("data_event_trails"), awsNonempty("selectors_unreadable")))),
    awsRule("warn", awsOr(awsEmpty("data_event_trails"), awsNonempty("selectors_unreadable"))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-LOG-03": [
    awsRule("manual", awsEq("hub_readable", false)),
    awsRule("fail", awsEq("hub_enabled", false)),
    awsRule("warn", awsOr(awsEq("standards_readable", false), awsEq("standard_count", 0), awsEq("standards_truncated", true))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-LOG-04": [
    awsRule("manual", awsOr(awsEq("detectors_readable", false), awsNull("enabled_detectors"), awsAnd(awsEq("enabled_detectors", 0), awsNonempty("detectors_unreadable")))),
    awsRule("fail", awsEq("enabled_detectors", 0)),
    awsRule("warn", awsOr(awsNonempty("detectors_unreadable"), awsEq("detector_list_truncated", true))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-LOG-05": [
    awsRule("manual", awsOr(awsEq("recorders_readable", false), awsAnd(awsNonempty("recorders"), awsEq("recorder_status_readable", false)))),
    awsRule("fail", awsOr(awsEmpty("recorders"), awsNot(awsSome("recorder_statuses", awsEq("$.recording", true))))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-ORG-01": [
    awsRule("manual", awsEq("organization_readable", false)),
    awsRule("warn", awsOr(awsEq("standalone", true), awsEq("accounts_readable", false), awsEq("account_list_truncated", true))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-ORG-02": [
    awsRule("warn", awsNull("scps_readable")),
    awsRule("manual", awsOr(awsEq("scps_readable", false), awsNull("attached_scp_count"))),
    awsRule("warn", awsEq("scp_count", 0)),
    awsRule("fail", awsAnd(awsEq("attached_scp_count", 0), awsEmpty("scps_targets_unreadable"))),
    awsRule("warn", awsOr(awsNonempty("scps_targets_unreadable"), awsEq("scp_list_truncated", true))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-ORG-03": [
    awsRule("manual", awsEq("analyzers_readable", false)),
    awsRule("fail", awsNot(awsSome("analyzers", awsEq("$.status", AWS_VERDICT_VALUES.activeAnalyzerStatus)))),
    awsRule("warn", awsEq("analyzer_list_truncated", true)),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-ORG-04": [
    awsRule("manual", awsOr(awsEq("analyzers_readable", false), awsNull("analyzers_sampled"), awsNull("active_finding_count"))),
    awsRule("warn", awsOr(awsCompare("gt", awsPath("active_finding_count", 0), awsValue(0)), awsNonempty("analyzers_findings_unreadable"), awsNonempty("analyzers_findings_truncated"))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-ORG-05": [
    awsRule("manual", awsEq("instances_readable", false)),
    awsRule("warn", awsOr(awsEq("identity_center_instances", 0), awsEq("instance_list_truncated", true))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-ORG-06": [
    awsRule("manual", awsEq("assessments_readable", false)),
    awsRule("fail", awsEq("active_assessments", 0)),
    awsRule("warn", awsOr(awsCompare("gt", awsPath("undated_assessments", 0), awsValue(0)), awsEq("list_truncated", true))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-ORG-07": [
    awsRule("manual", awsEq("contact_readable", false)),
    awsRule("fail", awsEq("security_contact_configured", false)),
    awsRule("warn", awsOr(awsNull("email_domain"), awsCompare("ne", awsPath("has_phone"), awsValue(true)))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-DATA-11": [
    awsRule("manual", awsOr(awsEq("account_block_readable", false), awsEq("buckets_readable", false))),
    awsRule("fail", awsOr(
      awsEq("account_block_configured", false),
      awsAnd(
        awsNot(awsAnd(...AWS_REQUIRED_PUBLIC_ACCESS_FLAGS.map((name) => awsEq(`account_flags.${name}`, true)))),
        awsOr(awsNonempty("buckets_without_full_block"), awsNonempty("buckets_with_public_policy")),
      ),
    )),
    awsRule("warn", awsOr(
      awsNot(awsAnd(...AWS_REQUIRED_PUBLIC_ACCESS_FLAGS.map((name) => awsEq(`account_flags.${name}`, true)))),
      awsNonempty("buckets_with_public_policy"),
      awsNonempty("buckets_unreadable"),
      awsEq("bucket_inventory_truncated", true),
    )),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-DATA-12": [
    awsRule("manual", awsOr(awsEq("buckets_readable", false), awsAnd(awsNonempty("ebs_by_region"), awsEvery("ebs_by_region", awsNull("$.EbsEncryptionByDefault"))))),
    awsRule("fail", awsOr(awsSome("ebs_by_region", awsEq("$.EbsEncryptionByDefault", false)), awsNonempty("rds_unencrypted"), awsNonempty("buckets_without_default_encryption"))),
    awsRule("warn", awsOr(awsEq("partial", true), awsSome("ebs_by_region", awsNull("$.EbsEncryptionByDefault")), awsNonempty("regions_with_rds_errors"), awsNonempty("rds_without_flag"), awsNonempty("buckets_encryption_unreadable"), awsEq("bucket_inventory_truncated", true))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-DATA-13": [
    awsRule("manual", awsOr(awsEq("buckets_readable", false), awsEq("buckets", 0))),
    awsRule("fail", awsNonempty("buckets_without_tls_deny")),
    awsRule("warn", awsOr(awsNonempty("buckets_policy_unreadable"), awsEq("bucket_inventory_truncated", true))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-DATA-22": [
    awsRule("manual", awsOr(awsNull("keys"), awsNull("customer_managed_keys"), awsEq("customer_managed_keys", 0))),
    awsRule("fail", awsNonempty("keys_not_rotating")),
    awsRule("warn", awsOr(awsEq("eligible_keys", 0), awsEq("partial", true), awsNonempty("keys_rotation_unreadable"), awsNonempty("keys_manager_unreadable"), awsEq("key_inventory_truncated", true), awsNonempty("regions_with_list_errors"))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-NET-14": [
    awsRule("manual", awsOr(
      awsNot(awsDefined("vpcs")),
      awsEq("vpcs", 0),
      awsNull("vpcs_without_active_flow_logs"),
      awsCompare("eq", awsPath("vpcs_unverified_count", 0), awsPath("vpcs", 0)),
    )),
    awsRule("fail", awsNonempty("vpcs_without_active_flow_logs")),
    awsRule("warn", awsOr(awsEq("partial", true), awsNonempty("vpcs_unverified"), awsEq("inventory_truncated", true), awsNonempty("regions_with_vpc_errors"), awsNonempty("regions_with_flow_log_errors"))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-NET-20": [
    awsRule("manual", awsOr(awsNot(awsDefined("network_acls")), awsNull("network_acls"), awsEq("network_acls", 0))),
    awsRule("fail", awsNonempty("permissive_network_acls")),
    awsRule("warn", awsOr(awsEq("partial", true), awsEq("inventory_truncated", true), awsNonempty("regions_with_errors"))),
    awsRule("pass", { op: "always" }),
  ],
  "AWS-NET-21": [
    awsRule("manual", awsOr(awsNot(awsDefined("security_groups")), awsNull("security_groups"), awsEq("security_groups", 0))),
    awsRule("fail", awsNonempty("unrestricted_security_groups")),
    awsRule("warn", awsOr(awsEq("partial", true), awsEq("inventory_truncated", true), awsNonempty("regions_with_errors"))),
    awsRule("pass", { op: "always" }),
  ],
};

export const AWS_CHECKS: readonly CheckContract[] = [
  awsCheck("AWS-IAM-01", "Root account MFA and access keys", "critical", IDENTITY_TOOL, ["iam-get-account-summary"], criteria(
    "GetAccountSummary is readable, AccountMFAEnabled equals 1, and AccountAccessKeysPresent is absent or equals 0.",
    "No warn verdict is emitted directly.",
    "AccountMFAEnabled is not 1 or AccountAccessKeysPresent is greater than 0.",
    "GetAccountSummary is unreadable; verify root MFA and absence of root access keys in IAM.",
    { mfaEnabled: AWS_VERDICT_VALUES.accountMfaEnabled, accessKeysPresent: AWS_VERDICT_VALUES.accountAccessKeysPresent },
  )),
  awsCheck("AWS-IAM-02", "IAM user MFA coverage", "high", IDENTITY_TOOL, ["iam-list-users", "iam-list-mfa-devices"], criteria(
    "ListUsers is readable and every sampled user whose ListMFADevices call is readable has at least one MFA device.",
    "The pass result is demoted when the user inventory is truncated or one or more user MFA-device lists is unreadable.",
    "At least one sampled IAM user has a readable empty MFA-device list.",
    "ListUsers is unreadable, or every sampled user's MFA-device list is unreadable.",
  )),
  awsCheck("AWS-IAM-03", "Password policy strength", "high", IDENTITY_TOOL, ["iam-get-account-password-policy"], criteria(
    "A password policy exists, MinimumPasswordLength is at least 14, and RequireSymbols, RequireNumbers, RequireUppercaseCharacters, and RequireLowercaseCharacters are all true.",
    "No warn verdict is emitted directly.",
    "No password policy exists, minimum length is below 14, or any required complexity flag is not true.",
    "GetAccountPasswordPolicy is unreadable.",
    { minimumLength: AWS_VERDICT_VALUES.minimumPasswordLength, requiredComplexityFields: AWS_VERDICT_VALUES.passwordComplexityFields },
  )),
  awsCheck("AWS-IAM-04", "Access key rotation", "high", IDENTITY_TOOL, ["iam-list-users", "iam-list-access-keys", "iam-get-access-key-last-used"], criteria(
    "ListUsers is readable and no judged access key is older than stale_days since LastUsedDate, or since CreateDate when never used; stale_days defaults to 90.",
    "The pass result is demoted when users are truncated or any user's key list or any sampled key's last-use read is unreadable.",
    "At least one judged key exceeds stale_days.",
    "ListUsers is unreadable, every user's key list is unreadable, or every sampled key's last-use read is unreadable.",
    { defaultStaleDays: AWS_DEFAULTS.staleDays },
  )),
  awsCheck("AWS-IAM-05", "Privileged role boundaries", "medium", IDENTITY_TOOL, ["iam-get-account-authorization-details"], criteria(
    "The role inventory is readable and no role with AdministratorAccess or an inline Allow Action='*' Resource='*' policy lacks PermissionsBoundary.",
    "One to max_privileged_roles privileged roles lack boundaries, or an otherwise-passing role inventory is truncated; max_privileged_roles defaults to 5.",
    "More than max_privileged_roles privileged roles lack permission boundaries.",
    "GetAccountAuthorizationDetails for roles is unreadable.",
    { administratorPolicyName: AWS_VERDICT_VALUES.administratorPolicyName, defaultMaximum: AWS_DEFAULTS.maxPrivilegedRoles },
  )),
  awsCheck("AWS-IAM-06", "Dormant IAM users", "low", IDENTITY_TOOL, ["iam-list-users", "iam-list-access-keys", "iam-get-access-key-last-used"], criteria(
    "ListUsers is readable and no user has PasswordLastUsed older than stale_days and no user with no password activity is proven to have zero access keys.",
    "At least one user appears dormant, or an otherwise-passing user/key inventory is partial; stale_days defaults to 90.",
    "No fail verdict is emitted; dormant users require review.",
    "ListUsers is unreadable.",
    { defaultStaleDays: AWS_DEFAULTS.staleDays },
    { noncompliant: "warn" },
  )),
  awsCheck("AWS-IAM-07", "Root account activity", "high", IDENTITY_TOOL, ["cloudtrail-lookup-events"], criteria(
    "No CloudTrail event attributed to username root is found in the lookback window, first queried in us-east-1.",
    "No root ConsoleLogin exists but another root API event exists, or an otherwise-passing lookup is truncated, contains undated events, or falls back after the us-east-1 lookup fails.",
    "At least one root ConsoleLogin event exists.",
    "Root LookupEvents is unreadable.",
    { consoleLoginEventName: AWS_VERDICT_VALUES.rootConsoleLoginEvent, defaultLookbackDays: AWS_DEFAULTS.rootLookbackDays, globalRegion: AWS_DEFAULTS.rootEventRegion },
  )),
  awsCheck("AWS-IAM-08", "Customer-managed policy wildcards", "high", IDENTITY_TOOL, ["iam-list-policies", "iam-get-policy-version"], criteria(
    "At least one customer-managed policy is readable and none has an Allow statement with wildcard Action and wildcard Resource.",
    "An unattached policy grants Action='*' and Resource='*', a policy grants a service-wide action such as service:* on Resource='*', or an otherwise-passing inventory is partial.",
    "An attached policy or permission-boundary policy has an Allow statement with Action='*' and Resource='*'.",
    "ListPolicies is unreadable or returns zero customer-managed policies; inline policies remain manual.",
    { wildcard: "*" },
  )),
  awsCheck("AWS-LOG-01", "Multi-region CloudTrail with validation", "critical", LOGGING_TOOL, ["cloudtrail-describe-trails", "cloudtrail-get-trail-status"], criteria(
    "At least one trail has IsMultiRegionTrail=true, LogFileValidationEnabled=true and GetTrailStatus.IsLogging=true.",
    "A pass is demoted when GetTrailStatus is unreadable for any trail.",
    "Trails are readable but no trail satisfies all three required values.",
    "DescribeTrails is unreadable, or a qualifying trail exists but every qualifying logging state is unreadable.",
  )),
  awsCheck("AWS-LOG-02", "CloudTrail data events", "medium", LOGGING_TOOL, ["cloudtrail-describe-trails", "cloudtrail-get-event-selectors"], criteria(
    "At least one readable trail has a nonempty EventSelectors.DataResources list or any AdvancedEventSelectors entry.",
    "Trails and selectors are readable but no data-event selector exists.",
    "No fail verdict is emitted; absent data events are a review condition.",
    "DescribeTrails is unreadable or any required GetEventSelectors read is unreadable.",
    {},
    { noncompliant: "warn", partial: "manual" },
  )),
  awsCheck("AWS-LOG-03", "Security Hub enablement", "high", LOGGING_TOOL, ["securityhub-describe-hub", "securityhub-get-enabled-standards"], criteria(
    "DescribeHub confirms a hub and GetEnabledStandards returns at least one standards subscription.",
    "The hub exists but standards are unreadable, empty, or truncated.",
    "DescribeHub reports that the hub is not subscribed.",
    "DescribeHub is unreadable.",
  )),
  awsCheck("AWS-LOG-04", "GuardDuty detectors", "high", LOGGING_TOOL, ["guardduty-list-detectors", "guardduty-get-detector"], criteria(
    "At least one listed detector has GetDetector.Status equal to ENABLED.",
    "A pass is demoted when detector listing is truncated or any detector detail is unreadable.",
    "No detector exists, or all readable detectors have a status other than ENABLED.",
    "ListDetectors is unreadable, or detector IDs exist but enablement is unreadable.",
    { enabledStatus: AWS_VERDICT_VALUES.enabledGuardDutyStatus },
  )),
  awsCheck("AWS-LOG-05", "AWS Config recording", "high", LOGGING_TOOL, ["config-describe-configuration-recorders", "config-describe-configuration-recorder-status"], criteria(
    "At least one configuration recorder has a same-name status with recording=true.",
    "No warn verdict is emitted directly.",
    "No configuration recorder exists, or recorders exist but none reports recording=true.",
    "Recorder listing or recorder-status listing is unreadable.",
  )),
  awsCheck("AWS-ORG-01", "Organizations visibility", "medium", ORG_TOOL, ["organizations-describe-organization", "organizations-list-accounts"], criteria(
    "DescribeOrganization returns an organization; account listing may be readable or unreadable, but a pass is demoted if accounts are unreadable or truncated.",
    "The account is standalone, or organization visibility passes while member accounts are unreadable or truncated.",
    "No fail verdict is emitted directly.",
    "DescribeOrganization is unreadable.",
    {},
    { noncompliant: "warn" },
  )),
  awsCheck("AWS-ORG-02", "Service control policies", "high", ORG_TOOL, ["organizations-list-policies", "organizations-list-targets-for-policy"], criteria(
    "At least one SERVICE_CONTROL_POLICY exists and at least one policy has one or more targets.",
    "The account is standalone, no SCP exists, or a pass is demoted by unreadable/truncated policy or target lists.",
    "SCPs exist, every target list is readable, and no SCP has a root, OU, or account target.",
    "ListPolicies is unreadable, or SCPs exist but target lists needed to settle attachment are unreadable.",
    { filter: "SERVICE_CONTROL_POLICY" },
  )),
  awsCheck("AWS-ORG-03", "Access Analyzer enablement", "high", ORG_TOOL, ["access-analyzer-list-analyzers"], criteria(
    "At least one analyzer has status ACTIVE.",
    "A pass is demoted when the analyzer listing is truncated.",
    "The analyzer listing is readable and contains no ACTIVE analyzer.",
    "ListAnalyzers is unreadable.",
    { activeStatus: AWS_VERDICT_VALUES.activeAnalyzerStatus },
  )),
  awsCheck("AWS-ORG-04", "External access findings", "dynamic", ORG_TOOL, ["access-analyzer-list-analyzers", "access-analyzer-list-findings"], criteria(
    "At least one ACTIVE analyzer has a readable, complete findings list and no returned finding has missing status or status ACTIVE; severity is low.",
    "At least one active external finding is returned; severity is high. A pass is also demoted by unreadable or truncated findings from another ACTIVE analyzer.",
    "No fail verdict is emitted; active external access is a review condition.",
    "Analyzers are unreadable, no ACTIVE analyzer exists, or no ACTIVE analyzer has a readable findings list.",
    { activeAnalyzerStatus: AWS_VERDICT_VALUES.activeAnalyzerStatus, activeFindingStatus: AWS_VERDICT_VALUES.activeFindingStatus },
    { noncompliant: "warn" },
  )),
  awsCheck("AWS-ORG-05", "Identity Center visibility", "low", ORG_TOOL, ["sso-admin-list-instances"], criteria(
    "ListInstances returns at least one IAM Identity Center instance.",
    "No instance is visible, or an otherwise-passing list is truncated.",
    "No fail verdict is emitted.",
    "ListInstances is unreadable.",
    {},
    { noncompliant: "warn" },
  )),
  awsCheck("AWS-ORG-06", "Audit Manager active assessments", "medium", ORG_TOOL, ["auditmanager-list-assessments"], criteria(
    "ListAssessments(status=ACTIVE) returns at least one assessment with a creation or update timestamp and the list is complete.",
    "A pass is demoted when any assessment lacks both timestamps or the list is truncated.",
    "The read is successful but returns zero ACTIVE assessments.",
    "ListAssessments is unreadable; verify applicability in Audit Manager or the alternate evidence process.",
    { requestedStatus: AWS_VERDICT_VALUES.activeAssessmentStatus },
  )),
  awsCheck("AWS-ORG-07", "Account security contact", "medium", ORG_TOOL, ["account-get-alternate-contact"], criteria(
    "GetAlternateContact(SECURITY) returns a contact with nonempty EmailAddress and PhoneNumber.",
    "A SECURITY contact exists but email or phone is missing.",
    "GetAlternateContact reports ResourceNotFoundException, meaning no SECURITY contact exists.",
    "GetAlternateContact is unreadable.",
    { contactType: "SECURITY" },
  )),
  awsCheck("AWS-DATA-11", "S3 Block Public Access", "critical", DATA_TOOL, ["s3-get-account-public-access-block", "s3-list-buckets", "s3-get-public-access-block", "s3-get-bucket-policy-status"], criteria(
    "All four account Block Public Access flags are true, no readable bucket policy evaluates public, all bucket reads are complete, and no bucket public-access detail is unreadable.",
    "The account block is incomplete but every bucket has all four bucket flags and no public policy, or the account block is complete but a policy evaluates public; a pass is also demoted by partial bucket evidence.",
    "The account block is absent, or incomplete while any bucket lacks a full bucket block or has a public policy.",
    "Account-level S3 Control GetPublicAccessBlock or ListBuckets is unreadable.",
    { requiredFlags: AWS_REQUIRED_PUBLIC_ACCESS_FLAGS },
  )),
  awsCheck("AWS-DATA-12", "Encryption at rest defaults", "high", DATA_TOOL, ["ec2-get-ebs-encryption-by-default", "s3-get-bucket-encryption", "rds-describe-db-instances"], criteria(
    "Every readable assessed region has EbsEncryptionByDefault=true, every bucket has at least one default SSEAlgorithm, and every RDS instance with a readable StorageEncrypted field reports true.",
    "The base pass is demoted by partial region scope, unreadable regional/bucket sources, truncated inventories, or any RDS instance missing StorageEncrypted.",
    "Any readable region reports EbsEncryptionByDefault=false, any bucket lacks default encryption, or any RDS instance reports StorageEncrypted=false.",
    "EBS default encryption is unreadable in every assessed region or ListBuckets is unreadable.",
  )),
  awsCheck("AWS-DATA-13", "S3 TLS-only bucket policies", "high", DATA_TOOL, ["s3-list-buckets", "s3-get-bucket-policy"], criteria(
    "Every listed bucket has a Deny statement whose condition requires aws:SecureTransport=false; bucket and policy reads are complete.",
    "The pass is demoted when any bucket policy is unreadable or the bucket list is truncated.",
    "At least one readable bucket lacks the required Deny statement.",
    "ListBuckets is unreadable or returns zero buckets; load-balancer and endpoint TLS remain manual.",
    { conditionKey: AWS_VERDICT_VALUES.secureTransportConditionKey, deniedValue: AWS_VERDICT_VALUES.secureTransportDeniedValue },
  )),
  awsCheck("AWS-DATA-22", "KMS customer-managed key rotation", "medium", DATA_TOOL, ["kms-list-keys", "kms-describe-key", "kms-get-key-rotation-status"], criteria(
    "Every eligible key reports KeyRotationEnabled=true. Eligibility requires KeyManager=CUSTOMER, KeyState=Enabled, KeySpec=SYMMETRIC_DEFAULT and Origin=AWS_KMS.",
    "Customer keys exist but none is eligible for automatic rotation, or a pass is demoted by unreadable/truncated regional scope, key metadata, or rotation status.",
    "At least one eligible key reports KeyRotationEnabled=false.",
    "KMS lists fail in every region, no customer key exists, or no customer key can be confirmed because every KeyManager is unreadable.",
    {
      keyManager: AWS_VERDICT_VALUES.customerKeyManager,
      keyState: AWS_VERDICT_VALUES.eligibleKeyState,
      keySpec: AWS_VERDICT_VALUES.eligibleKeySpec,
      keyOrigin: AWS_VERDICT_VALUES.eligibleKeyOrigin,
    },
  )),
  awsCheck("AWS-NET-14", "VPC Flow Logs coverage", "medium", NETWORK_TOOL, ["ec2-describe-vpcs", "ec2-describe-flow-logs"], criteria(
    "Every readable VPC has at least one matching flow log whose FlowLogStatus is ACTIVE.",
    "The base pass is demoted by partial region scope, unreadable/truncated VPC or flow-log inventories, or missing FlowLogStatus on some logs.",
    "At least one readable VPC has no ACTIVE flow log.",
    "VPCs are unreadable in every region, no VPC exists, or every VPC's flow-log state is unreadable or missing.",
    { activeStatus: AWS_VERDICT_VALUES.activeFlowLogStatus },
  )),
  awsCheck("AWS-NET-20", "Network ACL inbound exposure", "medium", NETWORK_TOOL, ["ec2-describe-network-acls"], criteria(
    "At least one network ACL is readable and none has an inbound allow entry from 0.0.0.0/0 or ::/0 whose protocol/range covers any configured sensitive port or all ports.",
    "A pass is demoted by partial region scope or unreadable/truncated NACL inventories.",
    "At least one NACL has a matching permissive inbound entry.",
    "NACLs are unreadable in every region or no NACL is returned.",
    { publicIpv4: AWS_VERDICT_VALUES.publicIpv4Cidr, publicIpv6: AWS_VERDICT_VALUES.publicIpv6Cidr, defaultSensitivePorts: AWS_DEFAULTS.sensitivePorts },
  )),
  awsCheck("AWS-NET-21", "Security group inbound exposure", "high", NETWORK_TOOL, ["ec2-describe-security-groups"], criteria(
    "At least one security group is readable and none has an inbound IPv4 or IPv6 world source whose protocol/range covers any configured sensitive port or all ports.",
    "A pass is demoted by partial region scope or unreadable/truncated security-group inventories.",
    "At least one security group has a matching unrestricted inbound permission.",
    "Security groups are unreadable in every region or no security group is returned.",
    { publicIpv4: AWS_VERDICT_VALUES.publicIpv4Cidr, publicIpv6: AWS_VERDICT_VALUES.publicIpv6Cidr, defaultSensitivePorts: AWS_DEFAULTS.sensitivePorts },
  )),
];

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
  artifacts: [
    { path: "README.md", format: "markdown", requiredWhen: "Always", schema: "Evidence-bundle heading, Contents list, and credential-resolution notice.", serialization: "UTF-8 with a trailing newline." },
    { path: "QUICK_REFERENCE.md", format: "markdown", requiredWhen: "Always", schema: "Access summary, finding counts, Where to look, and every finding ID/title/status.", serialization: "UTF-8 with a trailing newline." },
    { path: "metadata.json", format: "json", requiredWhen: "Always", schema: "Object: region, profile|null, account_id|null, account_id_hint|null, source_chain string[], generated_at ISO string, finding/control counts, pass/warn/fail/manual counts, options object with effective limits and regions.", serialization: "Snapshot scrub, two-space JSON, insertion-order keys, one trailing newline." },
    { path: "core_data/access.json", format: "json", requiredWhen: "Always", schema: "AwsAccessCheckResult record described below.", serialization: "Snapshot scrub, two-space JSON, insertion-order keys, one trailing newline." },
    { path: "analysis/findings.json", format: "json", requiredWhen: "Always", schema: "Array of AwsFinding records in category order: identity, logging-detection, org-guardrails, data-protection, network-security.", serialization: "Snapshot scrub, two-space JSON, one trailing newline." },
    { path: "analysis/{category}.json", format: "json", requiredWhen: "One each for identity, logging-detection, org-guardrails, data-protection and network-security", schema: "AwsAssessmentResult: title, summary, findings, optional errors.", serialization: "Snapshot scrub, two-space JSON, insertion-order keys, one trailing newline." },
    { path: "analysis/summary.json", format: "json", requiredWhen: "Always", schema: "Object: findings, controls_covered, pass, warn, fail, manual, categories[{category,pass,warn,fail,manual}].", serialization: "Snapshot scrub, two-space JSON, one trailing newline." },
    { path: "compliance/executive_summary.md", format: "markdown", requiredWhen: "Always", schema: "Run metadata; Result Counts; up to 10 fail/warn findings ordered by status then severity; Manual Evidence Required; optional Collection Warnings.", serialization: "UTF-8 Markdown with one trailing newline." },
    { path: "compliance/unified_compliance_matrix.md", format: "markdown", requiredWhen: "Always", schema: "Finding, Controls, Title, Status, Severity and eight framework columns; pipe/newline escaped.", serialization: "UTF-8 Markdown table with one trailing newline." },
    { path: "compliance/frameworks/{framework}.md", format: "markdown", requiredWhen: "One file for every configured framework", schema: "Framework heading, mapped finding/status counts, then Finding, Title, Status, Severity, Mapping, Summary table.", serialization: "UTF-8 Markdown with one trailing newline." },
    { path: "_errors.log", format: "text", requiredWhen: "At least one collection error or truncation warning exists", schema: "Deduplicated sanitized collection messages, one per line.", serialization: "UTF-8 text with one final newline." },
    { path: "{allocated-bundle-name}.zip", format: "zip", requiredWhen: "Always after directory files are complete", schema: "Archive contains every bundle file under relative paths with no enclosing bundle directory.", serialization: "Zip archive paired to the exact allocated directory basename; only already-scrubbed files enter the archive." },
  ],
  overwritePolicy: "Allocate a new suffixed bundle directory on every rerun; never replace an earlier bundle.",
  pathSafetyPolicy: "Reject traversal, output roots outside the configured parent, symlink roots, and symlinked parent directories.",
  archivePairing: "Write a zip archive beside the bundle directory using the exact allocated directory name plus .zip.",
  recordSchemas: {
    AwsFinding: ["id:string", "title:string", "severity:critical|high|medium|low|info", "status:pass|warn|fail|manual", "summary:string", "evidence?:object", "mappings:string[]"],
    AwsAssessmentResult: ["title:string", "summary:object", "findings:AwsFinding[]", "errors?:string[]"],
    AwsAccessCheckResult: ["status:healthy|limited", "accountId?:string", "arn?:string", "surfaces:AwsAccessSurface[]", "notes:string[]", "recommendedNextStep:string"],
    AwsAccessSurface: ["name:string", "service:string", "command:IAM action string", "region:string", "status:readable|not_readable", "count:number|null", "truncated:boolean|null", "error?:string", "error_code?:string|null", "http_status?:number|null"],
    NotCollectedMarker: ["collected:false", "command:string", "error:string|null", "error_code:string|null", "http_status:number|null"],
    RegionScope: ["regions:string[]", "regionsTotal:number|null", "regionsSeen:number", "partial:boolean", "source:arguments|describe-regions|configured-region-fallback", "error?:string"],
    IdentitySummary: ["users", "user_inventory_truncated", "users_mfa_judged", "users_without_mfa", "keys_judged", "stale_access_keys", "keys_last_used_unreadable", "roles", "role_inventory_truncated", "privileged_roles", "roles_without_boundaries", "dormant_users", "root_console_logins", "customer_managed_policies", "full_admin_policies_attached", "collection_errors"],
    LoggingDetectionSummary: ["trails", "compliant_trails", "security_hub_enabled", "security_hub_standards", "guardduty_detectors", "enabled_guardduty_detectors", "config_recorders", "recording_config_recorders", "collection_errors"],
    OrgGuardrailsSummary: ["organization_visible", "accounts", "scps", "attached_scps", "analyzers", "active_analyzers", "active_external_findings", "identity_center_instances", "audit_manager_active_assessments", "security_contact_configured", "collection_errors"],
    DataProtectionSummary: ["account_id", "regions_seen", "regions_total", "buckets", "buckets_without_full_block", "buckets_without_bucket_level_block", "buckets_with_public_policy", "buckets_without_default_encryption", "buckets_without_tls_deny", "ebs_regions_without_default_encryption", "rds_instances", "rds_unencrypted", "customer_managed_keys", "keys_not_rotating", "collection_errors"],
    NetworkSecuritySummary: ["regions_seen", "regions_total", "vpcs", "vpcs_without_active_flow_logs", "network_acls", "permissive_network_acls", "security_groups", "unrestricted_security_groups", "collection_errors"],
  },
  jsonFormatting: "Before every JSON write, recursively scrub the complete value. Serialize with two-space indentation, preserve object insertion order, encode Date values as ISO strings through normal JSON conversion, and append exactly one newline.",
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
    sdkService: entry.service,
    iamAction: entry.action,
    documentationNamespace: entry.documentationNamespace,
    baseService: entry.service,
    documentationUrl: docsUrl(entry),
    fieldsConsumed: entry.fields,
    projectionStage: "Fields name the normalized record returned by the read client and then used in finding evidence. Raw service responses are never exported.",
    request: AWS_REQUESTS[entry.id],
    intent: entry.operation === "GetCallerIdentity" ? "auth-only" : "read",
  })),
  authentication: {
    modes: ["AWS default credential provider chain", "Named shared-configuration profile"],
    credentialPrecedence: ["Named profile argument or AWS_PROFILE", "Environment credentials", "Shared credentials and configuration files", "Container credentials", "Instance role credentials"],
    environmentVariables: ["AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCOUNT_ID"],
    configLocations: ["~/.aws/credentials", "~/.aws/config"],
    variants: ["Long-lived access keys", "Temporary session credentials", "Identity Center cached session", "Container role", "Instance role"],
    configFields: ["region", "profile", "account_id"],
    malformedConfigBehavior: "Credential-provider errors are replaced with a fixed provider name and sanitized code/status; raw provider and shared-file parser messages are never emitted.",
  },
  permissions: AWS_OPERATIONS.map((entry) => ({ id: entry.id, kind: "iam-action", value: entry.action, unlocks: [entry.id] })),
  pagination: [
    {
      surfaceIds: ["iam-list-users", "iam-list-policies", "iam-get-account-authorization-details"],
      cursorFields: ["Marker", "IsTruncated"],
      pageSize: 100,
      itemCap: null,
      pageCap: AWS_DEFAULTS.maxPagesPerList,
      totalSemantics: "IAM does not return a stable population total; report items seen and truncation.",
      stopConditions: ["IsTruncated is false", "Configured item cap", "Page cap", "Missing or repeated marker"],
    },
    {
      surfaceIds: ["cloudtrail-lookup-events", "securityhub-get-enabled-standards", "guardduty-list-detectors", "organizations-list-accounts", "organizations-list-policies", "organizations-list-targets-for-policy", "access-analyzer-list-analyzers", "access-analyzer-list-findings", "sso-admin-list-instances", "auditmanager-list-assessments", "ec2-describe-vpcs", "ec2-describe-flow-logs", "ec2-describe-network-acls", "ec2-describe-security-groups"],
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
      surfaceIds: ["rds-describe-db-instances"],
      cursorFields: ["Marker"],
      pageSize: 100,
      itemCap: null,
      pageCap: AWS_DEFAULTS.maxPagesPerList,
      totalSemantics: "No total is returned; only exhaustion proves completeness.",
      stopConditions: ["No marker", "Configured item cap", "Page cap", "Missing or repeated marker"],
    },
    {
      surfaceIds: ["kms-list-keys"],
      cursorFields: ["Marker request", "NextMarker response when Truncated=true"],
      pageSize: 1000,
      itemCap: AWS_DEFAULTS.keyLimit,
      pageCap: AWS_DEFAULTS.maxPagesPerList,
      totalSemantics: "KMS returns no total; only Truncated=false proves exhaustion.",
      stopConditions: ["Truncated is false", "Configured key cap", "Page cap", "Missing or repeated NextMarker"],
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
  knownGaps: [],
  redaction: {
    sharedContractVersion: "1.1",
    projections: Object.fromEntries(AWS_OPERATIONS.map((entry) => [entry.id, entry.fields])),
    projectionStage: "Each service response is normalized to the listed members before assessment. Findings and summaries contain only normalized evidence. Every JSON artifact is recursively snapshot-scrubbed again at the write sink.",
    sensitiveFields: ["AccessKeyId", "SecretAccessKey", "SessionToken", "Authorization", "Cookie", "Policy credentials", "AlternateContact.EmailAddress", "AlternateContact.PhoneNumber"],
    benignExceptions: ["Masked access key identifiers", "Resource ARNs", "Account identifiers", "Region names", "Policy names"],
    credentialFormats: ["AWS access key identifiers", "AWS secret access keys", "Session tokens", "Signature Version 4 authorization values", "Shared-configuration credential values", "Private key material"],
    integrationRules: [
      "Register AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN from the environment at client construction, then register SecretAccessKey and SessionToken returned by the resolved credential provider before a signed request.",
      "Replace AWS access-key identifiers shaped like AKIA or ASIA plus 16 uppercase letters/digits, 40-character secret keys, Signature Version 4 Signature/Credential proofs, session tokens, authorization values, cookies, private-key material and credential assignments.",
      "Under snapshot keys ending in token, secret, password, credential, authorization, private key, secret key, session token, or bearer-id variants, replace every nonempty value or subtree with [REDACTED]. Keep null, undefined and the empty string to preserve absence.",
      "Snapshot recursion keeps scalar values through depth 32; a container deeper than 32 is replaced whole with [REDACTED].",
      "Mask access-key identifiers in findings as first four characters + **** + last four; identifiers of eight characters or fewer become ****.",
      "Preserve resource ARNs, account and region identifiers, policy names, status/code tokens, setting booleans and numeric limits unless they contain a registered configured secret.",
      "Never copy an HTTP response body into an error. Record fixed operation, region, sanitized error code, HTTP status, content type and byte length only.",
    ],
  },
  output: AWS_EXPORT,
  tools: [
    { name: "aws_check_access", checkIds: [], resultSchema: "Text table plus structured fields {tool, status, accountId?, arn?, surfaces, notes, recommendedNextStep}." },
    ...["aws_assess_identity", "aws_assess_logging_detection", "aws_assess_org_guardrails", "aws_assess_data_protection", "aws_assess_network_security"].map((name) => ({
      name,
      checkIds: AWS_CHECKS.filter((item) => item.owningTool === name).map((item) => item.id),
      resultSchema: "Text summary/table plus structured fields {tool, title, summary, findings, errors?}.",
    })),
    { name: "aws_export_audit_bundle", checkIds: AWS_CHECKS.map((item) => item.id), resultSchema: "Text export receipt plus structured fields {tool, output_dir, zip_path, finding_count, file_count, error_count}.", output: AWS_EXPORT },
  ],
};
