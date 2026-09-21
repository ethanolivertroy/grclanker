import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AWS_CONTROL_CATALOG,
  AWS_FINDING_CONTROLS,
  assessAwsDataProtection,
  assessAwsIdentity,
  assessAwsLoggingDetection,
  assessAwsNetworkSecurity,
  assessAwsOrgGuardrails,
  buildAwsMappings,
  checkAwsAccess,
  exportAwsAuditBundle,
  isAwsAccessDenied,
  permissiveNaclEntries,
  resolveAwsConfiguration,
  resolveRegionScope,
  resolveSecureOutputPath,
  statementDeniesInsecureTransport,
  unrestrictedSecurityGroupRules,
} from "../dist/extensions/grc-tools/aws.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function accessDenied(code = "AccessDeniedException") {
  const error = new Error(`User is not authorized to perform this operation (${code})`);
  error.name = code;
  error.$metadata = { httpStatusCode: 403 };
  return error;
}

function findingById(result, id) {
  return result.findings.find((item) => item.id === id);
}

function statusMap(result) {
  return Object.fromEntries(result.findings.map((item) => [item.id, item.status]));
}

const TLS_ONLY_POLICY = JSON.stringify({
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "DenyInsecureTransport",
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"],
      Condition: { Bool: { "aws:SecureTransport": "false" } },
    },
  ],
});

const FULL_BLOCK = {
  BlockPublicAcls: true,
  IgnorePublicAcls: true,
  BlockPublicPolicy: true,
  RestrictPublicBuckets: true,
};

/** Fixture (d): a compliant account where every automatable data protection control reaches pass. */
function compliantDataProtectionClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getCallerIdentity() {
      return { Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/auditor" };
    },
    async describeRegions() {
      return ["us-east-1", "us-west-2"];
    },
    async getAccountPublicAccessBlock() {
      return { ...FULL_BLOCK };
    },
    async listBuckets() {
      return { items: [{ Name: "audit-logs", BucketRegion: "us-east-1" }, { Name: "app-data", BucketRegion: "us-west-2" }], truncated: false };
    },
    async getBucketPublicAccessBlock() {
      return { ...FULL_BLOCK };
    },
    async getBucketPolicyStatus() {
      return { IsPublic: false };
    },
    async getBucketEncryption() {
      return { Rules: [{ SSEAlgorithm: "aws:kms", KMSMasterKeyID: "arn:aws:kms:us-east-1:123456789012:key/k1", BucketKeyEnabled: true }] };
    },
    async getBucketPolicy() {
      return TLS_ONLY_POLICY;
    },
    async getEbsEncryptionByDefault() {
      return { EbsEncryptionByDefault: true };
    },
    async describeDbInstances(region) {
      return {
        items: region === "us-east-1" ? [{ DBInstanceIdentifier: "orders-db", Engine: "postgres", StorageEncrypted: true }] : [],
        truncated: false,
      };
    },
    async listKmsKeys(region) {
      return {
        items: region === "us-east-1" ? [{ KeyId: "k-customer" }, { KeyId: "k-aws" }] : [{ KeyId: "k-west" }],
        truncated: false,
      };
    },
    async describeKmsKey(_region, keyId) {
      if (keyId === "k-aws") {
        return { KeyId: keyId, KeyManager: "AWS", KeyState: "Enabled", KeySpec: "SYMMETRIC_DEFAULT", Origin: "AWS_KMS" };
      }
      return { KeyId: keyId, KeyManager: "CUSTOMER", KeyState: "Enabled", KeySpec: "SYMMETRIC_DEFAULT", Origin: "AWS_KMS" };
    },
    async getKeyRotationStatus() {
      return { KeyRotationEnabled: true, RotationPeriodInDays: 365 };
    },
    ...overrides,
  };
}

/** Fixture (d) for network security: locked-down NACLs and security groups with flow logs on every VPC. */
function compliantNetworkClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async describeRegions() {
      return ["us-east-1", "us-west-2"];
    },
    async describeVpcs(region) {
      return { items: [{ VpcId: `vpc-${region}`, IsDefault: false, CidrBlock: "10.0.0.0/16" }], truncated: false };
    },
    async describeFlowLogs(region) {
      return { items: [{ FlowLogId: `fl-${region}`, ResourceId: `vpc-${region}`, FlowLogStatus: "ACTIVE", TrafficType: "ALL", LogDestinationType: "s3" }], truncated: false };
    },
    async describeNetworkAcls(region) {
      return {
        items: [{
          NetworkAclId: `acl-${region}`,
          VpcId: `vpc-${region}`,
          IsDefault: true,
          Entries: [
            { RuleNumber: 100, Protocol: "6", RuleAction: "allow", Egress: false, CidrBlock: "10.0.0.0/8", PortRange: { From: 22, To: 22 } },
            { RuleNumber: 110, Protocol: "6", RuleAction: "allow", Egress: false, CidrBlock: "0.0.0.0/0", PortRange: { From: 443, To: 443 } },
            { RuleNumber: 120, Protocol: "6", RuleAction: "deny", Egress: false, CidrBlock: "0.0.0.0/0", PortRange: { From: 22, To: 22 } },
            { RuleNumber: 100, Protocol: "-1", RuleAction: "allow", Egress: true, CidrBlock: "0.0.0.0/0" },
            { RuleNumber: 32767, Protocol: "-1", RuleAction: "deny", Egress: false, CidrBlock: "0.0.0.0/0" },
          ],
        }],
        truncated: false,
      };
    },
    async describeSecurityGroups(region) {
      return {
        items: [{
          GroupId: `sg-${region}`,
          GroupName: "web",
          VpcId: `vpc-${region}`,
          IpPermissions: [
            { IpProtocol: "tcp", FromPort: 443, ToPort: 443, IpRanges: [{ CidrIp: "0.0.0.0/0" }], Ipv6Ranges: [{ CidrIpv6: "::/0" }] },
            { IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "203.0.113.0/24" }], Ipv6Ranges: [] },
          ],
        }],
        truncated: false,
      };
    },
    ...overrides,
  };
}

function deniedDataProtectionClient() {
  const deny = async () => {
    throw accessDenied();
  };
  return {
    getResolvedConfig: () => sampleConfig(),
    async getCallerIdentity() {
      return { Account: "123456789012" };
    },
    describeRegions: async () => {
      throw accessDenied("UnauthorizedOperation");
    },
    getAccountPublicAccessBlock: deny,
    listBuckets: deny,
    getBucketPublicAccessBlock: deny,
    getBucketPolicyStatus: deny,
    getBucketEncryption: deny,
    getBucketPolicy: deny,
    getEbsEncryptionByDefault: async () => {
      throw accessDenied("UnauthorizedOperation");
    },
    describeDbInstances: deny,
    listKmsKeys: deny,
    describeKmsKey: deny,
    getKeyRotationStatus: deny,
  };
}

function sampleConfig(overrides = {}) {
  return {
    region: "us-east-1",
    profile: "prod-audit",
    accountId: "123456789012",
    sourceChain: ["tests"],
    ...overrides,
  };
}

test("resolveAwsConfiguration prefers explicit args over environment defaults", () => {
  const resolved = resolveAwsConfiguration(
    { region: "us-west-2", profile: "audit", account_id: "111122223333" },
    { AWS_REGION: "eu-west-1", AWS_PROFILE: "env-profile" },
  );

  assert.equal(resolved.region, "us-west-2");
  assert.equal(resolved.profile, "audit");
  assert.equal(resolved.accountId, "111122223333");
  assert.ok(resolved.sourceChain.includes("arguments-region"));
  assert.ok(resolved.sourceChain.includes("arguments-profile"));
});

test("checkAwsAccess reports readable AWS audit surfaces", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getCallerIdentity() {
      return { Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/auditor" };
    },
    async getAccountSummary() {
      return { SummaryMap: { Users: 3 } };
    },
    async describeTrails() {
      return [{ Name: "org-trail" }];
    },
    async getEnabledSecurityHubStandards() {
      return [{ StandardsArn: "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0" }];
    },
    async describeConfigurationRecorders() {
      return [{ name: "default" }];
    },
    async listDetectors() {
      return ["detector-1"];
    },
    async listAnalyzers() {
      return [{ arn: "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/org", status: "ACTIVE" }];
    },
    async describeOrganization() {
      return { Id: "o-example" };
    },
    async listIdentityCenterInstances() {
      return [{ InstanceArn: "arn:aws:sso:::instance/ssoins-1" }];
    },
  };

  const result = await checkAwsAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 8);
  assert.match(result.recommendedNextStep, /aws_assess_identity/);
});

test("assessAwsIdentity flags root, MFA, password, key, and boundary issues", async () => {
  const client = {
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    async getAccountSummary() {
      return { SummaryMap: { AccountMFAEnabled: 0, AccountAccessKeysPresent: 1 } };
    },
    async getPasswordPolicy() {
      return {
        MinimumPasswordLength: 12,
        RequireSymbols: true,
        RequireNumbers: false,
        RequireUppercaseCharacters: true,
        RequireLowercaseCharacters: true,
      };
    },
    async listIamUsers() {
      return [
        { UserName: "alice", PasswordLastUsed: "2026-04-14T00:00:00Z" },
        { UserName: "bob", PasswordLastUsed: "2025-12-01T00:00:00Z" },
        { UserName: "carol" },
      ];
    },
    async listMfaDevices(userName) {
      return userName === "alice" ? [] : [{ SerialNumber: `mfa-${userName}` }];
    },
    async listAccessKeys(userName) {
      if (userName === "bob") {
        return [{ AccessKeyId: "AKIABOB", CreateDate: "2025-01-01T00:00:00Z" }];
      }
      return [];
    },
    async getAccessKeyLastUsed() {
      return { LastUsedDate: "2025-01-02T00:00:00Z" };
    },
    async getAccountAuthorizationDetails() {
      return [
        {
          RoleName: "AdminRole",
          AttachedManagedPolicies: [{ PolicyName: "AdministratorAccess" }],
        },
      ];
    },
  };

  const result = await assessAwsIdentity(client, { staleDays: 90, maxPrivilegedRoles: 5 });
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-04")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-05")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-06")?.status, "warn");
});

test("assessAwsLoggingDetection classifies trail, Security Hub, GuardDuty, and Config posture", async () => {
  const client = {
    async describeTrails() {
      return [
        {
          Name: "org-trail",
          TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail",
          IsMultiRegionTrail: true,
          LogFileValidationEnabled: true,
        },
      ];
    },
    async getTrailStatus() {
      return { IsLogging: true };
    },
    async getEventSelectors() {
      return { EventSelectors: [] };
    },
    async describeSecurityHub() {
      return { HubArn: "arn:aws:securityhub:us-east-1:123456789012:hub/default" };
    },
    async getEnabledSecurityHubStandards() {
      return [{ StandardsArn: "cis" }];
    },
    async describeConfigurationRecorders() {
      return [{ name: "default", recordingGroup: { allSupported: true } }];
    },
    async describeConfigurationRecorderStatus() {
      return [{ name: "default", recording: true }];
    },
    async listDetectors() {
      return ["detector-1"];
    },
    async getDetector() {
      return { Status: "ENABLED" };
    },
  };

  const result = await assessAwsLoggingDetection(client);
  assert.equal(result.findings.find((item) => item.id === "AWS-LOG-01")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-LOG-02")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AWS-LOG-03")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-LOG-04")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-LOG-05")?.status, "pass");
});

test("assessAwsOrgGuardrails flags external access and missing Identity Center", async () => {
  const client = {
    async describeOrganization() {
      return { Id: "o-example", FeatureSet: "ALL" };
    },
    async listAccounts() {
      return [{ Id: "1111" }, { Id: "2222" }, { Id: "3333" }];
    },
    async listScps() {
      return [{ Id: "p-1", Name: "DenyRegions" }];
    },
    async listPolicyTargets() {
      return [{ TargetId: "ou-1", Name: "Prod", Type: "ORGANIZATIONAL_UNIT" }];
    },
    async listAnalyzers() {
      return [{ arn: "arn:analyzer", status: "ACTIVE" }];
    },
    async listAccessAnalyzerFindings() {
      return [{ id: "f-1", status: "ACTIVE", resource: "arn:aws:s3:::public-bucket" }];
    },
    async listIdentityCenterInstances() {
      return [];
    },
  };

  const result = await assessAwsOrgGuardrails(client, { maxFindings: 50 });
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-01")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-02")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-03")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-05")?.status, "warn");
});

test("exportAwsAuditBundle writes reports, analysis, and archive", async () => {
  const base = createTempBase("grclanker-aws-export-");
  const client = {
    getResolvedConfig: () => sampleConfig(),
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    async getCallerIdentity() {
      return { Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/auditor" };
    },
    async getAccountSummary() {
      return { SummaryMap: { AccountMFAEnabled: 1, AccountAccessKeysPresent: 0 } };
    },
    async getPasswordPolicy() {
      return {
        MinimumPasswordLength: 16,
        RequireSymbols: true,
        RequireNumbers: true,
        RequireUppercaseCharacters: true,
        RequireLowercaseCharacters: true,
      };
    },
    async listIamUsers() {
      return [{ UserName: "alice", PasswordLastUsed: "2026-04-14T00:00:00Z" }];
    },
    async listMfaDevices() {
      return [{ SerialNumber: "mfa-alice" }];
    },
    async listAccessKeys() {
      return [];
    },
    async getAccessKeyLastUsed() {
      return null;
    },
    async getAccountAuthorizationDetails() {
      return [];
    },
    async describeTrails() {
      return [{ Name: "org-trail", TrailARN: "arn:trail", IsMultiRegionTrail: true, LogFileValidationEnabled: true }];
    },
    async getTrailStatus() {
      return { IsLogging: true };
    },
    async getEventSelectors() {
      return { AdvancedEventSelectors: [{ Name: "data-events" }] };
    },
    async describeSecurityHub() {
      return { HubArn: "arn:hub" };
    },
    async getEnabledSecurityHubStandards() {
      return [{ StandardsArn: "cis" }];
    },
    async describeConfigurationRecorders() {
      return [{ name: "default" }];
    },
    async describeConfigurationRecorderStatus() {
      return [{ name: "default", recording: true }];
    },
    async listDetectors() {
      return ["detector-1"];
    },
    async getDetector() {
      return { Status: "ENABLED" };
    },
    async describeOrganization() {
      return { Id: "o-example" };
    },
    async listAccounts() {
      return [{ Id: "123456789012" }];
    },
    async listScps() {
      return [{ Id: "p-1", Name: "DenyRegions" }];
    },
    async listPolicyTargets() {
      return [{ TargetId: "r-root", Type: "ROOT" }];
    },
    async listAnalyzers() {
      return [{ arn: "arn:analyzer", status: "ACTIVE" }];
    },
    async listAccessAnalyzerFindings() {
      return [];
    },
    async listIdentityCenterInstances() {
      return [{ InstanceArn: "arn:sso" }];
    },
    async lookupRootEvents() {
      return { items: [], truncated: false };
    },
    async listCustomerManagedPolicies() {
      return { items: [{ PolicyName: "ReadOnlyAudit", Arn: "arn:aws:iam::123456789012:policy/ReadOnlyAudit", DefaultVersionId: "v2", AttachmentCount: 1 }], truncated: false };
    },
    async getPolicyVersionDocument() {
      return { Statement: [{ Effect: "Allow", Action: ["s3:GetObject"], Resource: "arn:aws:s3:::audit/*" }] };
    },
    async listActiveAuditManagerAssessments() {
      return { items: [{ id: "a-1", name: "FedRAMP Moderate", status: "ACTIVE", complianceType: "FedRAMP", lastUpdated: "2026-04-01T00:00:00Z" }], truncated: false };
    },
    async getSecurityAlternateContact() {
      return { Name: "Security Team", Title: "CISO", EmailAddress: "security@example.com", PhoneNumber: "+1 555 0100" };
    },
  };

  const result = await exportAwsAuditBundle(client, sampleConfig(), base);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.ok(result.fileCount >= 12);
  assert.equal(result.findingCount, 20);

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.region, "us-east-1");
  assert.equal(metadata.profile, "prod-audit");
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-aws-path-");
  const outside = createTempBase("grclanker-aws-outside-");
  const nested = join(base, "nested");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);
  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
  assert.ok(!existsSync(nested));
});

test("control catalog covers all 25 spec controls and mappings carry framework prefixes", () => {
  assert.equal(Object.keys(AWS_CONTROL_CATALOG).length, 25);
  const mappings = buildAwsMappings(11);
  assert.ok(mappings.includes("FedRAMP AC-3"));
  assert.ok(mappings.includes("CMMC AC.L2-3.1.3"));
  assert.ok(mappings.includes("SOC 2 CC6.1"));
  assert.ok(mappings.includes("CIS AWS 2.1.4"));
  assert.ok(mappings.includes("PCI-DSS 1.3.1"));
  assert.ok(mappings.includes("DISA STIG SRG-APP-000516"));
  assert.ok(mappings.includes("IRAP ISM-0263"));
  assert.ok(mappings.includes("ISMAP 6.1.1"));
  assert.deepEqual(buildAwsMappings(99), []);
  for (const controls of Object.values(AWS_FINDING_CONTROLS)) {
    for (const controlNumber of controls) {
      assert.ok(AWS_CONTROL_CATALOG[controlNumber], `control ${controlNumber} must exist in the catalog`);
    }
  }
});

test("isAwsAccessDenied recognizes SDK denial codes and 403 metadata", () => {
  assert.ok(isAwsAccessDenied(accessDenied("AccessDenied")));
  assert.ok(isAwsAccessDenied(accessDenied("UnauthorizedOperation")));
  assert.ok(isAwsAccessDenied(Object.assign(new Error("nope"), { name: "Other", $metadata: { httpStatusCode: 403 } })));
  assert.ok(!isAwsAccessDenied(Object.assign(new Error("missing"), { name: "NoSuchBucketPolicy", $metadata: { httpStatusCode: 404 } })));
});

test("statementDeniesInsecureTransport matches Deny statements on aws:SecureTransport=false only", () => {
  assert.ok(statementDeniesInsecureTransport({ Effect: "Deny", Condition: { Bool: { "aws:SecureTransport": "false" } } }));
  assert.ok(statementDeniesInsecureTransport({ Effect: "Deny", Condition: { Bool: { "AWS:SecureTransport": false } } }));
  assert.ok(!statementDeniesInsecureTransport({ Effect: "Allow", Condition: { Bool: { "aws:SecureTransport": "true" } } }));
  assert.ok(!statementDeniesInsecureTransport({ Effect: "Deny", Condition: { Bool: { "aws:SecureTransport": "true" } } }));
  assert.ok(!statementDeniesInsecureTransport({ Effect: "Deny" }));
});

test("resolveRegionScope prefers arguments, then DescribeRegions, then the configured region", () => {
  const fromArgs = resolveRegionScope(["eu-west-1", "us-east-1", "ap-south-1"], {}, "us-east-1", 2);
  assert.deepEqual(fromArgs.regions, ["eu-west-1", "us-east-1"]);
  assert.equal(fromArgs.partial, true);
  assert.equal(fromArgs.regionsTotal, 3);
  assert.equal(fromArgs.source, "arguments");

  const described = resolveRegionScope(undefined, { value: ["us-east-1", "us-west-2"] }, "us-east-1", 30);
  assert.equal(described.partial, false);
  assert.equal(described.regionsSeen, 2);
  assert.equal(described.source, "describe-regions");

  const fallback = resolveRegionScope(undefined, { error: "ec2:DescribeRegions: AccessDenied", denied: true }, "us-east-1", 30);
  assert.deepEqual(fallback.regions, ["us-east-1"]);
  assert.equal(fallback.partial, true);
  assert.equal(fallback.source, "configured-region-fallback");
});

test("assessAwsDataProtection fixture (d): compliant account passes every data protection control", async () => {
  const result = await assessAwsDataProtection(compliantDataProtectionClient());
  assert.deepEqual(statusMap(result), {
    "AWS-DATA-11": "pass",
    "AWS-DATA-12": "pass",
    "AWS-DATA-13": "pass",
    "AWS-DATA-22": "pass",
  });
  assert.deepEqual(result.errors, []);
  assert.equal(result.summary.regions_seen, 2);
  assert.equal(result.summary.customer_managed_keys, 2);
  const publicAccess = findingById(result, "AWS-DATA-11");
  assert.deepEqual(publicAccess.evidence.account_flags, FULL_BLOCK);
  assert.ok(publicAccess.mappings.includes("CIS AWS 2.1.4"));
  const encryption = findingById(result, "AWS-DATA-12");
  assert.equal(encryption.evidence.ebs_by_region.length, 2);
  assert.equal(encryption.evidence.ebs_by_region[0].EbsEncryptionByDefault, true);
  assert.equal(encryption.evidence.efs, "not assessed");
  assert.equal(findingById(result, "AWS-DATA-22").evidence.eligible_keys, 2);
});

test("assessAwsDataProtection fails on public buckets, disabled encryption defaults, missing TLS policies, and unrotated keys", async () => {
  const client = compliantDataProtectionClient({
    async getAccountPublicAccessBlock() {
      return { ...FULL_BLOCK, BlockPublicPolicy: false };
    },
    async getBucketPublicAccessBlock(bucket) {
      return bucket === "app-data" ? { ...FULL_BLOCK, RestrictPublicBuckets: false } : { ...FULL_BLOCK };
    },
    async getBucketPolicyStatus(bucket) {
      return { IsPublic: bucket === "app-data" };
    },
    async getBucketEncryption(bucket) {
      return bucket === "app-data" ? null : { Rules: [{ SSEAlgorithm: "AES256" }] };
    },
    async getBucketPolicy(bucket) {
      return bucket === "app-data" ? null : JSON.stringify({ Statement: [{ Effect: "Allow", Action: "s3:GetObject" }] });
    },
    async getEbsEncryptionByDefault(region) {
      return { EbsEncryptionByDefault: region === "us-east-1" };
    },
    async describeDbInstances(region) {
      return { items: region === "us-west-2" ? [{ DBInstanceIdentifier: "legacy", Engine: "mysql", StorageEncrypted: false }] : [], truncated: false };
    },
    async getKeyRotationStatus(_region, keyId) {
      return { KeyRotationEnabled: keyId !== "k-west" };
    },
  });

  const result = await assessAwsDataProtection(client);
  assert.deepEqual(statusMap(result), {
    "AWS-DATA-11": "fail",
    "AWS-DATA-12": "fail",
    "AWS-DATA-13": "fail",
    "AWS-DATA-22": "fail",
  });
  const publicAccess = findingById(result, "AWS-DATA-11");
  assert.match(publicAccess.summary, /BlockPublicPolicy=false/);
  assert.deepEqual(publicAccess.evidence.buckets_with_public_policy, ["app-data"]);
  assert.equal(publicAccess.evidence.buckets_without_full_block[0].name, "app-data");
  const encryption = findingById(result, "AWS-DATA-12");
  assert.deepEqual(encryption.evidence.buckets_without_default_encryption, ["app-data"]);
  assert.equal(encryption.evidence.rds_unencrypted[0].id, "legacy");
  assert.match(encryption.summary, /disabled in 1\/2 region/);
  const transit = findingById(result, "AWS-DATA-13");
  assert.equal(transit.evidence.buckets_without_tls_deny.length, 2);
  assert.deepEqual(findingById(result, "AWS-DATA-22").evidence.keys_not_rotating, [{ region: "us-west-2", key_id: "k-west" }]);
});

test("assessAwsDataProtection never passes when every surface is AccessDenied", async () => {
  const result = await assessAwsDataProtection(deniedDataProtectionClient());
  for (const item of result.findings) {
    assert.equal(item.status, "manual", `${item.id} must be manual, saw ${item.status}: ${item.summary}`);
    assert.match(item.summary, /could not be read|AccessDenied/);
  }
  assert.ok(result.errors.some((line) => line.startsWith("ec2:DescribeRegions: AccessDenied")));
  assert.ok(result.errors.some((line) => line.startsWith("s3control:GetPublicAccessBlock: AccessDenied")));
  assert.ok(result.errors.some((line) => line.startsWith("s3:ListBuckets: AccessDenied")));
  assert.ok(result.errors.some((line) => line.startsWith("kms:ListKeys us-east-1: AccessDenied")));
  assert.equal(result.summary.regions_seen, 1);
  assert.equal(findingById(result, "AWS-DATA-12").evidence.source, "configured-region-fallback");
});

test("assessAwsDataProtection fails when account-level Block Public Access is unset and treats missing configurations honestly", async () => {
  const client = compliantDataProtectionClient({
    async getAccountPublicAccessBlock() {
      return null;
    },
    async getBucketPublicAccessBlock() {
      return null;
    },
    async getBucketPolicyStatus() {
      return null;
    },
  });
  const result = await assessAwsDataProtection(client);
  const publicAccess = findingById(result, "AWS-DATA-11");
  assert.equal(publicAccess.status, "fail");
  assert.match(publicAccess.summary, /not configured/);
  assert.equal(publicAccess.evidence.account_block_configured, false);
  assert.equal(publicAccess.evidence.buckets_without_full_block.length, 2);
});

test("assessAwsDataProtection warns when account-level block is partial but every bucket blocks public access", async () => {
  const client = compliantDataProtectionClient({
    async getAccountPublicAccessBlock() {
      return { ...FULL_BLOCK, IgnorePublicAcls: false };
    },
  });
  const result = await assessAwsDataProtection(client);
  const publicAccess = findingById(result, "AWS-DATA-11");
  assert.equal(publicAccess.status, "warn");
  assert.match(publicAccess.summary, /IgnorePublicAcls=false/);
});

test("assessAwsDataProtection empty inventories: settings still decide, item-less controls go manual", async () => {
  const client = compliantDataProtectionClient({
    async listBuckets() {
      return { items: [], truncated: false };
    },
    async describeDbInstances() {
      return { items: [], truncated: false };
    },
    async listKmsKeys() {
      return { items: [{ KeyId: "k-aws" }], truncated: false };
    },
  });
  const result = await assessAwsDataProtection(client);
  const statuses = statusMap(result);
  assert.equal(statuses["AWS-DATA-11"], "pass", "account-level flags were read and are all true");
  assert.equal(statuses["AWS-DATA-12"], "pass", "EBS default encryption flag was read true in every region");
  assert.equal(statuses["AWS-DATA-13"], "manual");
  assert.match(findingById(result, "AWS-DATA-13").summary, /No S3 buckets exist/);
  assert.equal(statuses["AWS-DATA-22"], "manual");
  assert.match(findingById(result, "AWS-DATA-22").summary, /No customer-managed KMS keys/);
});

test("assessAwsDataProtection caps partial reads and truncation at warn", async () => {
  const client = compliantDataProtectionClient({
    async listBuckets() {
      return { items: [{ Name: "audit-logs" }, { Name: "app-data" }], truncated: true };
    },
    async getBucketPublicAccessBlock(bucket) {
      if (bucket === "app-data") throw accessDenied("AccessDenied");
      return { ...FULL_BLOCK };
    },
    async describeDbInstances(region) {
      if (region === "us-west-2") throw accessDenied();
      return { items: [{ DBInstanceIdentifier: "orders-db", StorageEncrypted: true }], truncated: false };
    },
    async getKeyRotationStatus(region) {
      if (region === "us-west-2") throw accessDenied();
      return { KeyRotationEnabled: true };
    },
  });
  const result = await assessAwsDataProtection(client, { regionLimit: 1 });
  assert.deepEqual(statusMap(result), {
    "AWS-DATA-11": "warn",
    "AWS-DATA-12": "warn",
    "AWS-DATA-13": "warn",
    "AWS-DATA-22": "warn",
  });
  assert.match(findingById(result, "AWS-DATA-11").summary, /Downgraded to warn: 1 bucket\(s\) could not be read; bucket inventory truncated at 1000/);
  assert.match(findingById(result, "AWS-DATA-12").summary, /only 1 of 2 regions assessed/);
  assert.match(findingById(result, "AWS-DATA-13").summary, /bucket inventory truncated/);
  assert.match(findingById(result, "AWS-DATA-22").summary, /only 1 of 2 regions assessed/);
  assert.equal(result.summary.regions_seen, 1);
  assert.equal(result.summary.regions_total, 2);
  assert.ok(result.errors.some((line) => /Region scope truncated to 1 of 2/.test(line)));
  assert.ok(result.errors.some((line) => /s3:ListBuckets: inventory truncated/.test(line)));
});

test("assessAwsDataProtection warns when customer keys exist but none can auto-rotate, and fails on public policies only with restrict", async () => {
  const client = compliantDataProtectionClient({
    async describeKmsKey(_region, keyId) {
      return { KeyId: keyId, KeyManager: "CUSTOMER", KeyState: "Enabled", KeySpec: "RSA_2048", Origin: "AWS_KMS" };
    },
    async getBucketPolicyStatus(bucket) {
      return { IsPublic: bucket === "audit-logs" };
    },
  });
  const result = await assessAwsDataProtection(client, { regions: ["us-east-1"] });
  const kms = findingById(result, "AWS-DATA-22");
  assert.equal(kms.status, "warn");
  assert.match(kms.summary, /automatic rotation cannot apply/);
  assert.equal(kms.evidence.ineligible_customer_keys.length, 2);
  const publicAccess = findingById(result, "AWS-DATA-11");
  assert.equal(publicAccess.status, "warn");
  assert.match(publicAccess.summary, /restricted by RestrictPublicBuckets/);
  assert.equal(result.summary.regions_total, 1);
});

test("permissiveNaclEntries and unrestrictedSecurityGroupRules read protocol, ports, and world sources", () => {
  const ports = [22, 3389];
  const acl = {
    Entries: [
      { RuleNumber: 100, Protocol: "-1", RuleAction: "allow", Egress: false, CidrBlock: "0.0.0.0/0" },
      { RuleNumber: 110, Protocol: "6", RuleAction: "allow", Egress: false, Ipv6CidrBlock: "::/0", PortRange: { From: 3000, To: 4000 } },
      { RuleNumber: 120, Protocol: "17", RuleAction: "allow", Egress: false, CidrBlock: "0.0.0.0/0" },
      { RuleNumber: 130, Protocol: "6", RuleAction: "allow", Egress: false, CidrBlock: "0.0.0.0/0", PortRange: { From: 80, To: 80 } },
      { RuleNumber: 140, Protocol: "6", RuleAction: "allow", Egress: true, CidrBlock: "0.0.0.0/0", PortRange: { From: 22, To: 22 } },
      { RuleNumber: 150, Protocol: "1", RuleAction: "allow", Egress: false, CidrBlock: "0.0.0.0/0" },
    ],
  };
  const permissive = permissiveNaclEntries(acl, ports);
  assert.deepEqual(permissive.map((entry) => entry.RuleNumber), [100, 110, 120]);
  assert.equal(permissive[0].exposed_ports, "all");
  assert.deepEqual(permissive[1].exposed_ports, [3389]);
  assert.deepEqual(permissive[2].exposed_ports, [22, 3389]);

  const group = {
    IpPermissions: [
      { IpProtocol: "-1", IpRanges: [{ CidrIp: "0.0.0.0/0" }], Ipv6Ranges: [] },
      { IpProtocol: "tcp", FromPort: 3389, ToPort: 3389, IpRanges: [], Ipv6Ranges: [{ CidrIpv6: "::/0" }] },
      { IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "10.0.0.0/8" }], Ipv6Ranges: [] },
      { IpProtocol: "tcp", FromPort: 443, ToPort: 443, IpRanges: [{ CidrIp: "0.0.0.0/0" }], Ipv6Ranges: [] },
      { IpProtocol: "icmp", FromPort: -1, ToPort: -1, IpRanges: [{ CidrIp: "0.0.0.0/0" }], Ipv6Ranges: [] },
    ],
  };
  const unrestricted = unrestrictedSecurityGroupRules(group, ports);
  assert.equal(unrestricted.length, 2);
  assert.deepEqual(unrestricted[0].sources, ["0.0.0.0/0"]);
  assert.equal(unrestricted[0].exposed_ports, "all");
  assert.deepEqual(unrestricted[1].sources, ["::/0"]);
  assert.deepEqual(unrestricted[1].exposed_ports, [3389]);
});

test("assessAwsNetworkSecurity fixture (d): compliant account passes every network control", async () => {
  const result = await assessAwsNetworkSecurity(compliantNetworkClient());
  assert.deepEqual(statusMap(result), {
    "AWS-NET-14": "pass",
    "AWS-NET-20": "pass",
    "AWS-NET-21": "pass",
  });
  assert.deepEqual(result.errors, []);
  assert.equal(result.summary.vpcs, 2);
  assert.equal(result.summary.network_acls, 2);
  assert.equal(result.summary.security_groups, 2);
  assert.ok(findingById(result, "AWS-NET-21").mappings.includes("CIS AWS 5.2"));
  assert.ok(findingById(result, "AWS-NET-14").mappings.includes("FedRAMP AU-12"));
});

test("assessAwsNetworkSecurity fails on missing flow logs, open NACLs, and open security groups", async () => {
  const client = compliantNetworkClient({
    async describeVpcs(region) {
      return { items: [{ VpcId: `vpc-${region}`, IsDefault: true }, { VpcId: `vpc-${region}-b`, IsDefault: false }], truncated: false };
    },
    async describeFlowLogs(region) {
      return {
        items: [
          { FlowLogId: "fl-1", ResourceId: `vpc-${region}`, FlowLogStatus: "ACTIVE" },
          { FlowLogId: "fl-2", ResourceId: `vpc-${region}-b`, FlowLogStatus: "INACTIVE" },
        ],
        truncated: false,
      };
    },
    async describeNetworkAcls(region) {
      return {
        items: [{
          NetworkAclId: `acl-${region}`,
          VpcId: `vpc-${region}`,
          IsDefault: true,
          Entries: [{ RuleNumber: 100, Protocol: "-1", RuleAction: "allow", Egress: false, CidrBlock: "0.0.0.0/0" }],
        }],
        truncated: false,
      };
    },
    async describeSecurityGroups(region) {
      return {
        items: [{
          GroupId: `sg-${region}`,
          GroupName: "bastion",
          IpPermissions: [{ IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "0.0.0.0/0" }], Ipv6Ranges: [] }],
        }],
        truncated: false,
      };
    },
  });
  const result = await assessAwsNetworkSecurity(client, { sensitivePorts: [22, 3389] });
  assert.deepEqual(statusMap(result), {
    "AWS-NET-14": "fail",
    "AWS-NET-20": "fail",
    "AWS-NET-21": "fail",
  });
  const flowLogs = findingById(result, "AWS-NET-14");
  assert.match(flowLogs.summary, /2\/4 VPCs/);
  assert.deepEqual(flowLogs.evidence.vpcs_without_active_flow_logs.map((row) => row.vpc_id), ["vpc-us-east-1-b", "vpc-us-west-2-b"]);
  const acls = findingById(result, "AWS-NET-20");
  assert.match(acls.summary, /2 of them are default NACLs/);
  assert.equal(acls.evidence.permissive_network_acls[0].entries[0].exposed_ports, "all");
  const groups = findingById(result, "AWS-NET-21");
  assert.deepEqual(groups.evidence.sensitive_ports, [22, 3389]);
  assert.deepEqual(groups.evidence.unrestricted_security_groups[0].rules[0].exposed_ports, [22]);
});

test("assessAwsNetworkSecurity never passes when every surface is AccessDenied", async () => {
  const deny = async () => {
    throw accessDenied("UnauthorizedOperation");
  };
  const result = await assessAwsNetworkSecurity({
    getResolvedConfig: () => sampleConfig(),
    describeRegions: deny,
    describeVpcs: deny,
    describeFlowLogs: deny,
    describeNetworkAcls: deny,
    describeSecurityGroups: deny,
  });
  for (const item of result.findings) {
    assert.equal(item.status, "manual", `${item.id} must be manual, saw ${item.status}`);
    assert.match(item.summary, /could not be listed/);
  }
  assert.equal(result.summary.regions_seen, 1);
  assert.ok(result.errors.some((line) => line.startsWith("ec2:DescribeVpcs us-east-1: AccessDenied")));
  assert.ok(result.errors.some((line) => line.startsWith("ec2:DescribeSecurityGroups us-east-1: AccessDenied")));
});

test("assessAwsNetworkSecurity treats empty inventories as manual with the reason stated", async () => {
  const empty = async () => ({ items: [], truncated: false });
  const result = await assessAwsNetworkSecurity(compliantNetworkClient({
    describeVpcs: empty,
    describeFlowLogs: empty,
    describeNetworkAcls: empty,
    describeSecurityGroups: empty,
  }));
  assert.deepEqual(statusMap(result), {
    "AWS-NET-14": "manual",
    "AWS-NET-20": "manual",
    "AWS-NET-21": "manual",
  });
  assert.match(findingById(result, "AWS-NET-14").summary, /No VPCs were found in 2 region/);
  assert.match(findingById(result, "AWS-NET-20").summary, /Every VPC has a default NACL/);
  assert.match(findingById(result, "AWS-NET-21").summary, /Every VPC has a default security group/);
});

test("assessAwsNetworkSecurity caps partial regions, unreadable flow logs, and truncation at warn", async () => {
  const client = compliantNetworkClient({
    async describeRegions() {
      return ["us-east-1", "us-west-2", "eu-west-1"];
    },
    async describeVpcs(region) {
      return {
        items: [{ VpcId: `vpc-${region}` }, { VpcId: `vpc-${region}-b` }],
        truncated: region === "us-west-2",
      };
    },
    async describeFlowLogs(region) {
      if (region === "us-west-2") throw accessDenied("UnauthorizedOperation");
      return {
        items: [
          { ResourceId: `vpc-${region}`, FlowLogStatus: "ACTIVE" },
          { ResourceId: `vpc-${region}-b`, FlowLogStatus: "ACTIVE" },
        ],
        truncated: false,
      };
    },
    async describeNetworkAcls(region) {
      if (region === "us-west-2") throw accessDenied("UnauthorizedOperation");
      return { items: [{ NetworkAclId: `acl-${region}`, Entries: [] }], truncated: false };
    },
    async describeSecurityGroups(region) {
      return { items: [{ GroupId: `sg-${region}`, IpPermissions: [] }], truncated: region === "us-east-1" };
    },
  });
  const result = await assessAwsNetworkSecurity(client, { regionLimit: 2 });
  assert.deepEqual(statusMap(result), {
    "AWS-NET-14": "warn",
    "AWS-NET-20": "warn",
    "AWS-NET-21": "warn",
  });
  assert.match(findingById(result, "AWS-NET-14").summary, /2 VPC\(s\) could not be verified/);
  assert.match(findingById(result, "AWS-NET-14").summary, /only 2 of 3 regions assessed/);
  assert.match(findingById(result, "AWS-NET-20").summary, /DescribeNetworkAcls unreadable in 1 region/);
  assert.match(findingById(result, "AWS-NET-21").summary, /security group inventory truncated in 1 region/);
  assert.equal(result.summary.regions_seen, 2);
  assert.equal(result.summary.regions_total, 3);
  assert.ok(result.errors.some((line) => /ec2:DescribeVpcs us-west-2: inventory truncated/.test(line)));
});

function compliantIdentityClient(overrides = {}) {
  return {
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    getResolvedConfig: () => sampleConfig(),
    async getAccountSummary() {
      return { SummaryMap: { AccountMFAEnabled: 1, AccountAccessKeysPresent: 0 } };
    },
    async getPasswordPolicy() {
      return { MinimumPasswordLength: 16, RequireSymbols: true, RequireNumbers: true, RequireUppercaseCharacters: true, RequireLowercaseCharacters: true };
    },
    async listIamUsers() {
      return [{ UserName: "alice", PasswordLastUsed: "2026-04-14T00:00:00Z" }];
    },
    async listMfaDevices() {
      return [{ SerialNumber: "mfa-alice" }];
    },
    async listAccessKeys() {
      return [];
    },
    async getAccessKeyLastUsed() {
      return null;
    },
    async getAccountAuthorizationDetails() {
      return [];
    },
    async lookupRootEvents() {
      return { items: [], truncated: false };
    },
    async listCustomerManagedPolicies() {
      return {
        items: [
          { PolicyName: "ReadOnlyAudit", Arn: "arn:aws:iam::123456789012:policy/ReadOnlyAudit", DefaultVersionId: "v2", AttachmentCount: 1 },
          { PolicyName: "Deploy", Arn: "arn:aws:iam::123456789012:policy/Deploy", DefaultVersionId: "v1", AttachmentCount: 0, PermissionsBoundaryUsageCount: 0 },
        ],
        truncated: false,
      };
    },
    async getPolicyVersionDocument() {
      return { Statement: [{ Effect: "Allow", Action: ["s3:GetObject", "s3:ListBucket"], Resource: ["arn:aws:s3:::audit", "arn:aws:s3:::audit/*"] }] };
    },
    ...overrides,
  };
}

test("assessAwsIdentity fixture (d): compliant account passes root activity and policy wildcard checks", async () => {
  const result = await assessAwsIdentity(compliantIdentityClient());
  const statuses = statusMap(result);
  for (const id of ["AWS-IAM-01", "AWS-IAM-02", "AWS-IAM-03", "AWS-IAM-04", "AWS-IAM-05", "AWS-IAM-06", "AWS-IAM-07", "AWS-IAM-08"]) {
    assert.equal(statuses[id], "pass", `${id} should pass, saw ${statuses[id]}`);
  }
  assert.deepEqual(result.errors, []);
  const root = findingById(result, "AWS-IAM-07");
  assert.equal(root.evidence.lookback_days, 90);
  assert.equal(root.evidence.window_start, "2026-01-16T00:00:00.000Z");
  assert.ok(root.mappings.includes("CIS AWS 1.7"));
  assert.equal(findingById(result, "AWS-IAM-08").evidence.customer_managed_policies, 2);
  assert.ok(findingById(result, "AWS-IAM-08").mappings.includes("CIS AWS 1.16"));
});

test("assessAwsIdentity fails on root console logins and attached full-admin customer policies", async () => {
  const result = await assessAwsIdentity(compliantIdentityClient({
    async lookupRootEvents() {
      return {
        items: [
          { EventId: "e1", EventName: "ConsoleLogin", EventTime: "2026-04-10T08:00:00Z", EventSource: "signin.amazonaws.com", Username: "root" },
          { EventId: "e2", EventName: "GetAccountSummary", EventTime: "2026-04-10T08:05:00Z", EventSource: "iam.amazonaws.com", Username: "root" },
        ],
        truncated: false,
      };
    },
    async getPolicyVersionDocument(arn) {
      if (arn.endsWith("/Deploy")) {
        return encodeURIComponent(JSON.stringify({ Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] }));
      }
      return { Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] };
    },
  }), { lookbackDays: 30 });
  const root = findingById(result, "AWS-IAM-07");
  assert.equal(root.status, "fail");
  assert.match(root.summary, /1 root ConsoleLogin event/);
  assert.equal(root.evidence.lookback_days, 30);
  const policies = findingById(result, "AWS-IAM-08");
  assert.equal(policies.status, "fail");
  assert.deepEqual(policies.evidence.full_admin_attached, [{ name: "ReadOnlyAudit", attachment_count: 1 }]);
  assert.deepEqual(policies.evidence.full_admin_unattached, ["Deploy"]);
});

test("assessAwsIdentity warns on non-console root activity, unattached wildcards, and unreadable policy versions", async () => {
  const result = await assessAwsIdentity(compliantIdentityClient({
    async lookupRootEvents() {
      return { items: [{ EventId: "e2", EventName: "CreateAccessKey", EventTime: "2026-04-10T08:05:00Z", Username: "root" }], truncated: false };
    },
    async getPolicyVersionDocument(arn) {
      if (arn.endsWith("/Deploy")) throw accessDenied();
      return { Statement: [{ Effect: "Allow", Action: "ec2:*", Resource: "*" }] };
    },
  }));
  assert.equal(findingById(result, "AWS-IAM-07").status, "warn");
  const policies = findingById(result, "AWS-IAM-08");
  assert.equal(policies.status, "warn");
  assert.deepEqual(policies.evidence.service_wildcard_policies, ["ReadOnlyAudit"]);
  assert.deepEqual(policies.evidence.policies_unreadable, ["Deploy"]);
  assert.ok(result.errors.some((line) => line.startsWith("iam:GetPolicyVersion arn:aws:iam::123456789012:policy/Deploy: AccessDenied")));
});

test("assessAwsIdentity new findings never pass on AccessDenied, empty policies go manual, truncation caps at warn", async () => {
  const denied = await assessAwsIdentity(compliantIdentityClient({
    async lookupRootEvents() {
      throw accessDenied();
    },
    async listCustomerManagedPolicies() {
      throw accessDenied();
    },
  }));
  assert.equal(findingById(denied, "AWS-IAM-07").status, "manual");
  assert.equal(findingById(denied, "AWS-IAM-08").status, "manual");
  assert.equal(denied.errors.length, 2);

  const empty = await assessAwsIdentity(compliantIdentityClient({
    async listCustomerManagedPolicies() {
      return { items: [], truncated: false };
    },
  }));
  assert.equal(findingById(empty, "AWS-IAM-08").status, "manual");
  assert.match(findingById(empty, "AWS-IAM-08").summary, /No customer-managed IAM policies exist/);

  const truncated = await assessAwsIdentity(compliantIdentityClient({
    async lookupRootEvents() {
      return { items: [], truncated: true };
    },
    async listCustomerManagedPolicies() {
      return { items: [{ PolicyName: "P", Arn: "arn:p", DefaultVersionId: "v1", AttachmentCount: 1 }], truncated: true };
    },
  }));
  assert.equal(findingById(truncated, "AWS-IAM-07").status, "warn");
  assert.match(findingById(truncated, "AWS-IAM-07").summary, /event lookup truncated/);
  assert.equal(findingById(truncated, "AWS-IAM-08").status, "warn");
  assert.match(findingById(truncated, "AWS-IAM-08").summary, /policy inventory truncated at 1000/);
});

function compliantOrgClient(overrides = {}) {
  return {
    async describeOrganization() {
      return { Id: "o-example", FeatureSet: "ALL" };
    },
    async listAccounts() {
      return [{ Id: "123456789012" }];
    },
    async listScps() {
      return [{ Id: "p-1", Name: "DenyRegions" }];
    },
    async listPolicyTargets() {
      return [{ TargetId: "r-root", Type: "ROOT" }];
    },
    async listAnalyzers() {
      return [{ arn: "arn:analyzer", status: "ACTIVE" }];
    },
    async listAccessAnalyzerFindings() {
      return [];
    },
    async listIdentityCenterInstances() {
      return [{ InstanceArn: "arn:sso" }];
    },
    async listActiveAuditManagerAssessments() {
      return { items: [{ id: "a-1", name: "FedRAMP Moderate", status: "ACTIVE", complianceType: "FedRAMP", lastUpdated: "2026-04-01T00:00:00Z" }], truncated: false };
    },
    async getSecurityAlternateContact() {
      return { AlternateContactType: "SECURITY", Name: "Security Team", Title: "CISO", EmailAddress: "security@example.com", PhoneNumber: "+1 555 0100" };
    },
    ...overrides,
  };
}

test("assessAwsOrgGuardrails fixture (d): compliant account passes Audit Manager and security contact checks", async () => {
  const result = await assessAwsOrgGuardrails(compliantOrgClient());
  const statuses = statusMap(result);
  for (const id of ["AWS-ORG-01", "AWS-ORG-02", "AWS-ORG-03", "AWS-ORG-04", "AWS-ORG-05", "AWS-ORG-06", "AWS-ORG-07"]) {
    assert.equal(statuses[id], "pass", `${id} should pass, saw ${statuses[id]}`);
  }
  const contact = findingById(result, "AWS-ORG-07");
  assert.equal(contact.evidence.email_domain, "@example.com");
  assert.match(contact.summary, /\*\*\*@example\.com/);
  assert.ok(!JSON.stringify(contact.evidence).includes("security@example.com"), "evidence must not carry the raw email");
  assert.ok(findingById(result, "AWS-ORG-06").mappings.includes("FedRAMP CA-7"));
  assert.ok(contact.mappings.includes("CIS AWS 1.2"));
});

test("assessAwsOrgGuardrails fails on missing Audit Manager assessments and missing security contact", async () => {
  const result = await assessAwsOrgGuardrails(compliantOrgClient({
    async listActiveAuditManagerAssessments() {
      return { items: [], truncated: false };
    },
    async getSecurityAlternateContact() {
      return null;
    },
  }));
  assert.equal(findingById(result, "AWS-ORG-06").status, "fail");
  assert.match(findingById(result, "AWS-ORG-06").summary, /no ACTIVE assessments/);
  assert.equal(findingById(result, "AWS-ORG-07").status, "fail");
  assert.match(findingById(result, "AWS-ORG-07").summary, /ResourceNotFoundException/);
});

test("assessAwsOrgGuardrails goes manual on AccessDenied and warns on incomplete contacts or undated assessments", async () => {
  const denied = await assessAwsOrgGuardrails(compliantOrgClient({
    async listActiveAuditManagerAssessments() {
      throw accessDenied();
    },
    async getSecurityAlternateContact() {
      throw accessDenied();
    },
  }));
  assert.equal(findingById(denied, "AWS-ORG-06").status, "manual");
  assert.match(findingById(denied, "AWS-ORG-06").summary, /Audit Manager may not be set up/);
  assert.equal(findingById(denied, "AWS-ORG-07").status, "manual");
  assert.equal(denied.errors.length, 2);

  const partial = await assessAwsOrgGuardrails(compliantOrgClient({
    async listActiveAuditManagerAssessments() {
      return { items: [{ id: "a-1", name: "Undated", status: "ACTIVE" }], truncated: false };
    },
    async getSecurityAlternateContact() {
      return { Name: "Security Team", EmailAddress: "security@example.com" };
    },
  }));
  assert.equal(findingById(partial, "AWS-ORG-06").status, "warn");
  assert.match(findingById(partial, "AWS-ORG-06").summary, /without creation or update timestamps/);
  assert.equal(findingById(partial, "AWS-ORG-07").status, "warn");
  assert.match(findingById(partial, "AWS-ORG-07").summary, /missing a phone number/);
});
