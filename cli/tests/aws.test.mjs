import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  AWS_CONTROL_CATALOG,
  AWS_FINDING_CONTROLS,
  AWS_FRAMEWORKS,
  assessAwsDataProtection,
  assessAwsIdentity,
  assessAwsLoggingDetection,
  assessAwsNetworkSecurity,
  assessAwsOrgGuardrails,
  buildAwsMappings,
  checkAwsAccess,
  exportAwsAuditBundle,
  isAwsAccessDenied,
  maskAccessKeyId,
  normalizePolicyDocument,
  paginateAwsList,
  permissiveNaclEntries,
  resolveAwsConfiguration,
  resolveRegionScope,
  resolveSecureOutputPath,
  statementDeniesInsecureTransport,
  unrestrictedSecurityGroupRules,
} from "../dist/extensions/grc-tools/aws.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

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

/** Shape returned by every paginated client list: the items seen plus whether the walk stopped early. */
function paged(items, truncated = false) {
  return { items, truncated };
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
    async listIamUsers(limit) {
      return paged([{ UserName: "alice" }], limit === 1);
    },
    async describeTrails() {
      return [{ Name: "org-trail" }];
    },
    async getEnabledSecurityHubStandards() {
      return paged([{ StandardsArn: "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0" }]);
    },
    async describeConfigurationRecorders() {
      return [{ name: "default" }];
    },
    async listDetectors() {
      return paged(["detector-1"]);
    },
    async listAnalyzers() {
      return paged([{ arn: "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/org", status: "ACTIVE" }]);
    },
    async describeOrganization() {
      return { Id: "o-example" };
    },
    async listIdentityCenterInstances() {
      return paged([{ InstanceArn: "arn:aws:sso:::instance/ssoins-1" }]);
    },
  };

  const result = await checkAwsAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 9);
  const counts = Object.fromEntries(result.surfaces.map((surface) => [surface.name, surface.count]));
  assert.equal(counts.security_hub, 1, "paged lists report the items seen as the surface count");
  assert.equal(counts.guardduty, 1);
  assert.equal(counts.access_analyzer, 1);
  assert.equal(counts.identity_center, 1);
  assert.equal(counts.organizations, 1);
  assert.equal(counts.iam_users, 1, "IAM.ListUsers is probed so a denial of the user inventory is visible in the access check");
  const users = result.surfaces.find((surface) => surface.name === "iam_users");
  assert.deepEqual(
    { command: users.command, region: users.region, truncated: users.truncated },
    { command: "iam:ListUsers", region: "us-east-1", truncated: true },
    "a probe capped at its page limit carries truncated: true beside the command and region it issued",
  );
  for (const surface of result.surfaces) {
    assert.match(surface.command, /^[a-z0-9-]+:[A-Z][A-Za-z]+$/, `${surface.name} names the IAM action it issued`);
    assert.equal(surface.region, "us-east-1");
    assert.equal(typeof surface.count, "number", `${surface.name}: a completed probe carries a numeric count`);
  }
  assert.match(result.recommendedNextStep, /aws_assess_identity/);
});

test("checkAwsAccess probes EC2, S3, KMS, RDS, Audit Manager, and Account surfaces and reports limited when any is denied", async () => {
  const healthy = await checkAwsAccess(compliantBundleClient());
  assert.equal(healthy.status, "healthy");
  assert.equal(healthy.surfaces.length, 15);
  for (const name of ["ec2_regions", "s3_buckets", "kms_keys", "rds_instances", "audit_manager", "account_contacts", "iam_users"]) {
    const probe = healthy.surfaces.find((surface) => surface.name === name);
    assert.equal(probe?.status, "readable", `${name} should be readable`);
  }
  assert.match(healthy.recommendedNextStep, /aws_assess_data_protection/);
  assert.match(healthy.recommendedNextStep, /aws_assess_network_security/);

  const limited = await checkAwsAccess(compliantBundleClient({
    async listKmsKeys() {
      throw accessDenied();
    },
    async getSecurityAlternateContact() {
      return null;
    },
  }));
  assert.equal(limited.status, "limited");
  const kms = limited.surfaces.find((surface) => surface.name === "kms_keys");
  assert.equal(kms?.status, "not_readable");
  assert.deepEqual(
    { count: kms.count, truncated: kms.truncated, command: kms.command, region: kms.region, error_code: kms.error_code, http_status: kms.http_status },
    { count: null, truncated: null, command: "kms:ListKeys", region: "us-east-1", error_code: "AccessDeniedException", http_status: 403 },
    "a denied probe keeps count and truncated null and names the command, region, SDK error code, and HTTP status that failed",
  );
  assert.match(kms.error, /AccessDeniedException/);
  assert.equal(limited.surfaces.find((surface) => surface.name === "account_contacts")?.status, "readable", "a missing contact is readable evidence, not a denial");
  assert.equal(limited.surfaces.find((surface) => surface.name === "account_contacts")?.count, 0);
  assert.match(limited.recommendedNextStep, /kms/);
  assert.match(limited.recommendedNextStep, /never pass/);

  const usersDenied = await checkAwsAccess(compliantBundleClient({
    async listIamUsers() {
      throw accessDenied();
    },
  }));
  assert.equal(usersDenied.status, "limited", "a denied IAM.ListUsers is visible in the access check instead of leaving it healthy");
  assert.equal(usersDenied.surfaces.find((surface) => surface.name === "iam_users")?.status, "not_readable");
  assert.equal(usersDenied.surfaces.find((surface) => surface.name === "iam_users")?.count, null);
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
      return paged([
        { UserName: "alice", PasswordLastUsed: "2026-04-14T00:00:00Z" },
        { UserName: "bob", PasswordLastUsed: "2025-12-01T00:00:00Z" },
        { UserName: "carol" },
      ]);
    },
    async listMfaDevices(userName) {
      return userName === "alice" ? [] : [{ SerialNumber: `mfa-${userName}` }];
    },
    async listAccessKeys(userName) {
      if (userName === "bob") {
        return [{ AccessKeyId: "AKIAIOSFODNN7EXAMPLE", CreateDate: "2025-01-01T00:00:00Z" }];
      }
      return [];
    },
    async getAccessKeyLastUsed() {
      return { LastUsedDate: "2025-01-02T00:00:00Z" };
    },
    async getAccountAuthorizationDetails() {
      return paged([
        {
          RoleName: "AdminRole",
          AttachedManagedPolicies: [{ PolicyName: "AdministratorAccess" }],
        },
      ]);
    },
  };

  const result = await assessAwsIdentity(client, { staleDays: 90, maxPrivilegedRoles: 5 });
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-04")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-05")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-06")?.status, "warn");
  const staleKeys = findingById(result, "AWS-IAM-04").evidence.stale_access_keys;
  assert.deepEqual(staleKeys.map((key) => key.accessKeyId), ["AKIA****MPLE"], "access key ids are masked in evidence");
  assert.ok(!JSON.stringify(result).includes("AKIAIOSFODNN7EXAMPLE"), "the raw access key id never reaches the assessment output");
});

test("paginateAwsList stops at the limit, on a repeated token, and on the page budget, reporting each as truncated", async () => {
  const pages = { undefined: { items: [1, 2], nextToken: "t1" }, t1: { items: [3, 4], nextToken: "t2" }, t2: { items: [5] } };
  const complete = await paginateAwsList(10, async (token) => pages[String(token)]);
  assert.deepEqual(complete, { items: [1, 2, 3, 4, 5], truncated: false });

  const capped = await paginateAwsList(3, async (token) => pages[String(token)]);
  assert.deepEqual(capped, { items: [1, 2, 3], truncated: true });

  const stalled = await paginateAwsList(10, async (token) => (token ? { items: [2], nextToken: token } : { items: [1], nextToken: "same" }));
  assert.deepEqual(stalled, { items: [1, 2], truncated: true }, "a token that never advances ends the walk as truncated instead of looping");

  let calls = 0;
  const endless = await paginateAwsList(10_000, async () => {
    calls += 1;
    return { items: [], nextToken: `t${calls}` };
  });
  assert.equal(endless.truncated, true, "a walk that exhausts the page budget is truncated");
  assert.equal(calls, 1000);
});

test("maskAccessKeyId keeps only the prefix and suffix of a key id", () => {
  assert.equal(maskAccessKeyId("AKIAIOSFODNN7EXAMPLE"), "AKIA****MPLE");
  assert.equal(maskAccessKeyId("short"), "****");
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
      return paged([{ StandardsArn: "cis" }]);
    },
    async describeConfigurationRecorders() {
      return [{ name: "default", recordingGroup: { allSupported: true } }];
    },
    async describeConfigurationRecorderStatus() {
      return [{ name: "default", recording: true }];
    },
    async listDetectors() {
      return paged(["detector-1"]);
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
  assert.deepEqual(result.errors, []);
  assert.equal(result.summary.collection_errors, 0);
});

/** Fixture (d) for logging: two trails and two detectors so a single per-item denial leaves a healthy sibling. */
function compliantLoggingClient(overrides = {}) {
  return {
    async describeTrails() {
      return [
        { Name: "org-trail", TrailARN: "arn:trail/org", IsMultiRegionTrail: true, LogFileValidationEnabled: true },
        { Name: "regional-trail", TrailARN: "arn:trail/regional", IsMultiRegionTrail: false, LogFileValidationEnabled: true },
      ];
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
      return paged([{ StandardsArn: "cis" }]);
    },
    async describeConfigurationRecorders() {
      return [{ name: "default" }];
    },
    async describeConfigurationRecorderStatus() {
      return [{ name: "default", recording: true }];
    },
    async listDetectors() {
      return paged(["detector-1", "detector-2"]);
    },
    async getDetector() {
      return { Status: "ENABLED" };
    },
    ...overrides,
  };
}

const LOGGING_IDS = ["AWS-LOG-01", "AWS-LOG-02", "AWS-LOG-03", "AWS-LOG-04", "AWS-LOG-05"];

/** Asserts that exactly the listed findings left pass and every other finding in the assessment still passes. */
function assertOnlyDemoted(result, expected, label) {
  const statuses = statusMap(result);
  for (const [id, status] of Object.entries(statuses)) {
    if (id in expected) assert.equal(status, expected[id], `${label}: ${id} should be ${expected[id]}, saw ${status}`);
    else assert.equal(status, "pass", `${label}: ${id} must stay pass while only ${Object.keys(expected).join(", ")} is affected, saw ${status}`);
  }
}

test("rule 1 corollary: assessAwsLoggingDetection never passes a control whose per-item read was denied, one secondary at a time", async () => {
  const healthy = await assessAwsLoggingDetection(compliantLoggingClient());
  assertOnlyDemoted(healthy, {}, "healthy fixture");
  assert.deepEqual(Object.keys(statusMap(healthy)).sort(), LOGGING_IDS);

  const trailStatusOne = await assessAwsLoggingDetection(compliantLoggingClient({
    async getTrailStatus(nameOrArn) {
      if (nameOrArn === "arn:trail/regional") throw accessDenied();
      return { IsLogging: true };
    },
  }));
  assertOnlyDemoted(trailStatusOne, { "AWS-LOG-01": "warn" }, "GetTrailStatus denied for one trail");
  assert.match(findingById(trailStatusOne, "AWS-LOG-01").summary, /Downgraded to warn: GetTrailStatus unreadable for 1 trail\(s\) \(regional-trail\)/);
  assert.equal(trailStatusOne.errors.length, 1);
  assert.match(trailStatusOne.errors[0], /^cloudtrail:GetTrailStatus regional-trail: AccessDenied \(AccessDeniedException/);
  assert.equal(findingById(trailStatusOne, "AWS-LOG-01").evidence.trails[1].status_error, trailStatusOne.errors[0]);

  const trailStatusAll = await assessAwsLoggingDetection(compliantLoggingClient({
    async getTrailStatus() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(trailStatusAll, { "AWS-LOG-01": "manual" }, "GetTrailStatus denied for every trail");
  assert.match(findingById(trailStatusAll, "AWS-LOG-01").summary, /logging state could not be read \(cloudtrail:GetTrailStatus org-trail: AccessDenied/);

  const selectorsOne = await assessAwsLoggingDetection(compliantLoggingClient({
    async getEventSelectors(nameOrArn) {
      if (nameOrArn === "arn:trail/regional") throw accessDenied();
      return { AdvancedEventSelectors: [{ Name: "data-events" }] };
    },
  }));
  assertOnlyDemoted(selectorsOne, { "AWS-LOG-02": "warn" }, "GetEventSelectors denied for one trail");
  assert.match(findingById(selectorsOne, "AWS-LOG-02").summary, /Downgraded to warn: GetEventSelectors unreadable for 1 trail\(s\) \(regional-trail\)/);
  assert.deepEqual(findingById(selectorsOne, "AWS-LOG-02").evidence.selectors_unreadable, ["regional-trail"]);

  const selectorsAll = await assessAwsLoggingDetection(compliantLoggingClient({
    async getEventSelectors() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(selectorsAll, { "AWS-LOG-02": "manual" }, "GetEventSelectors denied for every trail");
  assert.match(findingById(selectorsAll, "AWS-LOG-02").summary, /Event selectors could not be read for 2 of 2 trail\(s\) \(cloudtrail:GetEventSelectors org-trail: AccessDenied/);

  const standards = await assessAwsLoggingDetection(compliantLoggingClient({
    async getEnabledSecurityHubStandards() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(standards, { "AWS-LOG-03": "warn" }, "GetEnabledStandards denied");
  assert.match(findingById(standards, "AWS-LOG-03").summary, /Security Hub is enabled, but enabled standards could not be listed \(securityhub:GetEnabledStandards: AccessDenied/);
  assert.equal(findingById(standards, "AWS-LOG-03").evidence.standards_readable, false);
  assert.equal(findingById(standards, "AWS-LOG-03").evidence.hub_enabled, true);

  const detectorOne = await assessAwsLoggingDetection(compliantLoggingClient({
    async getDetector(detectorId) {
      if (detectorId === "detector-2") throw accessDenied();
      return { Status: "ENABLED" };
    },
  }));
  assertOnlyDemoted(detectorOne, { "AWS-LOG-04": "warn" }, "GetDetector denied for one detector");
  assert.match(findingById(detectorOne, "AWS-LOG-04").summary, /Downgraded to warn: GetDetector unreadable for 1 detector\(s\)/);
  assert.deepEqual(findingById(detectorOne, "AWS-LOG-04").evidence.detectors_unreadable, ["detector-2"]);

  const detectorAll = await assessAwsLoggingDetection(compliantLoggingClient({
    async getDetector() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(detectorAll, { "AWS-LOG-04": "manual" }, "GetDetector denied for every detector");
  assert.match(findingById(detectorAll, "AWS-LOG-04").summary, /GetDetector could not be read for 2 of them \(guardduty:GetDetector detector-1: AccessDenied/);

  const recorderStatus = await assessAwsLoggingDetection(compliantLoggingClient({
    async describeConfigurationRecorderStatus() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(recorderStatus, { "AWS-LOG-05": "manual" }, "DescribeConfigurationRecorderStatus denied");
  assert.match(findingById(recorderStatus, "AWS-LOG-05").summary, /recording state could not be read \(config:DescribeConfigurationRecorderStatus: AccessDenied/);
  assert.equal(findingById(recorderStatus, "AWS-LOG-05").evidence.recorder_status_readable, false);
  assert.equal(recorderStatus.summary.collection_errors, 1);
});

test("assessAwsLoggingDetection goes manual when a primary list is denied and fail only on readable evidence", async () => {
  const trails = await assessAwsLoggingDetection(compliantLoggingClient({
    async describeTrails() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(trails, { "AWS-LOG-01": "manual", "AWS-LOG-02": "manual" }, "DescribeTrails denied");
  assert.match(findingById(trails, "AWS-LOG-01").summary, /CloudTrail trails could not be listed \(cloudtrail:DescribeTrails: AccessDenied/);
  assert.equal(findingById(trails, "AWS-LOG-01").evidence.trails_readable, false);

  const hubDenied = await assessAwsLoggingDetection(compliantLoggingClient({
    async describeSecurityHub() {
      throw accessDenied();
    },
    async getEnabledSecurityHubStandards() {
      throw new Error("standards must not be listed when the hub state is unknown");
    },
  }));
  assertOnlyDemoted(hubDenied, { "AWS-LOG-03": "manual" }, "DescribeHub denied");
  assert.match(findingById(hubDenied, "AWS-LOG-03").summary, /Security Hub could not be described \(securityhub:DescribeHub: AccessDenied/);
  assert.equal(findingById(hubDenied, "AWS-LOG-03").evidence.standards_readable, null);
  assert.equal(hubDenied.errors.length, 1);

  const hubDisabled = await assessAwsLoggingDetection(compliantLoggingClient({
    async describeSecurityHub() {
      return null;
    },
  }));
  assertOnlyDemoted(hubDisabled, { "AWS-LOG-03": "fail" }, "DescribeHub reports the hub as not subscribed");
  assert.match(findingById(hubDisabled, "AWS-LOG-03").summary, /Security Hub is not enabled in the configured region/);
  assert.deepEqual(hubDisabled.errors, []);

  const detectors = await assessAwsLoggingDetection(compliantLoggingClient({
    async listDetectors() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(detectors, { "AWS-LOG-04": "manual" }, "ListDetectors denied");
  assert.match(findingById(detectors, "AWS-LOG-04").summary, /GuardDuty detectors could not be listed \(guardduty:ListDetectors: AccessDenied/);

  const recorders = await assessAwsLoggingDetection(compliantLoggingClient({
    async describeConfigurationRecorders() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(recorders, { "AWS-LOG-05": "manual" }, "DescribeConfigurationRecorders denied");
  assert.match(findingById(recorders, "AWS-LOG-05").summary, /AWS Config recorders could not be listed \(config:DescribeConfigurationRecorders: AccessDenied/);
  assert.doesNotMatch(findingById(recorders, "AWS-LOG-05").summary, /No AWS Config/);

  const noRecorder = await assessAwsLoggingDetection(compliantLoggingClient({
    async describeConfigurationRecorders() {
      return [];
    },
  }));
  assertOnlyDemoted(noRecorder, { "AWS-LOG-05": "fail" }, "no recorder exists");
  assert.match(findingById(noRecorder, "AWS-LOG-05").summary, /No AWS Config configuration recorder exists/);
});

test("rule 10: assessAwsLoggingDetection caps truncated standards and detector lists at warn", async () => {
  const result = await assessAwsLoggingDetection(compliantLoggingClient({
    async getEnabledSecurityHubStandards() {
      return paged([{ StandardsArn: "cis" }], true);
    },
    async listDetectors() {
      return paged(["detector-1"], true);
    },
  }));
  assertOnlyDemoted(result, { "AWS-LOG-03": "warn", "AWS-LOG-04": "warn" }, "truncated lists");
  assert.match(findingById(result, "AWS-LOG-03").summary, /Downgraded to warn: standards list truncated at 100/);
  assert.equal(findingById(result, "AWS-LOG-03").evidence.standards_truncated, true);
  assert.match(findingById(result, "AWS-LOG-04").summary, /Downgraded to warn: detector list truncated at 50/);
  assert.equal(findingById(result, "AWS-LOG-04").evidence.detector_list_truncated, true);
});

test("assessAwsOrgGuardrails flags external access and missing Identity Center", async () => {
  const client = {
    async describeOrganization() {
      return { Id: "o-example", FeatureSet: "ALL" };
    },
    async listAccounts() {
      return paged([{ Id: "1111" }, { Id: "2222" }, { Id: "3333" }]);
    },
    async listScps() {
      return paged([{ Id: "p-1", Name: "DenyRegions" }]);
    },
    async listPolicyTargets() {
      return paged([{ TargetId: "ou-1", Name: "Prod", Type: "ORGANIZATIONAL_UNIT" }]);
    },
    async listAnalyzers() {
      return paged([{ arn: "arn:analyzer", status: "ACTIVE" }]);
    },
    async listAccessAnalyzerFindings() {
      return paged([{ id: "f-1", status: "ACTIVE", resource: "arn:aws:s3:::public-bucket" }]);
    },
    async listIdentityCenterInstances() {
      return paged([]);
    },
  };

  const result = await assessAwsOrgGuardrails(client, { maxFindings: 50 });
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-01")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-02")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-03")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-05")?.status, "warn");
});

/** Fixture (d) for the bundle: a compliant account across all five assessment categories. */
function compliantBundleClient(overrides = {}) {
  return {
    ...compliantDataProtectionClient(),
    ...compliantNetworkClient(),
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
      return paged([{ UserName: "alice", PasswordLastUsed: "2026-04-14T00:00:00Z" }]);
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
      return paged([]);
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
      return paged([{ StandardsArn: "cis" }]);
    },
    async describeConfigurationRecorders() {
      return [{ name: "default" }];
    },
    async describeConfigurationRecorderStatus() {
      return [{ name: "default", recording: true }];
    },
    async listDetectors() {
      return paged(["detector-1"]);
    },
    async getDetector() {
      return { Status: "ENABLED" };
    },
    async describeOrganization() {
      return { Id: "o-example" };
    },
    async listAccounts() {
      return paged([{ Id: "123456789012" }]);
    },
    async listScps() {
      return paged([{ Id: "p-1", Name: "DenyRegions" }]);
    },
    async listPolicyTargets() {
      return paged([{ TargetId: "r-root", Type: "ROOT" }]);
    },
    async listAnalyzers() {
      return paged([{ arn: "arn:analyzer", status: "ACTIVE" }]);
    },
    async listAccessAnalyzerFindings() {
      return paged([]);
    },
    async listIdentityCenterInstances() {
      return paged([{ InstanceArn: "arn:sso" }]);
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
    ...overrides,
  };
}

test("exportAwsAuditBundle fixture (d): compliant account writes the shared layout with no error log", async () => {
  const base = createTempBase("grclanker-aws-export-");
  const result = await exportAwsAuditBundle(compliantBundleClient(), sampleConfig(), base);

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(basename(result.zipPath), `${basename(result.outputDir)}.zip`);
  assert.equal(result.findingCount, 27);
  assert.equal(result.errorCount, 0);
  assert.ok(result.fileCount >= 20);

  for (const relative of [
    "README.md",
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access.json",
    "analysis/findings.json",
    "analysis/summary.json",
    "analysis/identity.json",
    "analysis/logging-detection.json",
    "analysis/org-guardrails.json",
    "analysis/data-protection.json",
    "analysis/network-security.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    ...AWS_FRAMEWORKS.map((framework) => `compliance/frameworks/${framework.file}.md`),
  ]) {
    assert.ok(existsSync(join(result.outputDir, relative)), `${relative} should exist`);
  }
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")), "_errors.log must be absent when nothing failed");

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.region, "us-east-1");
  assert.equal(metadata.profile, "prod-audit");
  assert.equal(metadata.findings, 27);
  assert.equal(metadata.controls_total, 25);
  assert.equal(metadata.fail, 0);
  assert.equal(metadata.manual, 0);
  assert.ok(metadata.controls_covered.length >= 20, `expected broad control coverage, saw ${metadata.controls_covered.join(", ")}`);

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 27);
  const notPassing = findings.filter((item) => item.status !== "pass").map((item) => `${item.id}=${item.status}`);
  assert.deepEqual(notPassing, [], `every finding should pass on the compliant fixture, saw ${notPassing.join(", ")}`);

  const executive = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(executive, /Spec controls covered: \d+ of 25/);
  assert.doesNotMatch(executive, /\u2014/, "no em dashes in reports");
  const matrix = readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8");
  for (const framework of AWS_FRAMEWORKS) assert.ok(matrix.includes(`| ${framework.label}`), `${framework.label} column present`);
  const fedramp = readFileSync(join(result.outputDir, "compliance", "frameworks", "fedramp.md"), "utf8");
  assert.match(fedramp, /Mapped findings: \d+/);
});

test("exportAwsAuditBundle records collection errors in _errors.log and never overwrites a prior run", async () => {
  const base = createTempBase("grclanker-aws-export-rerun-");
  const first = await exportAwsAuditBundle(compliantBundleClient(), sampleConfig(), base);

  const degraded = compliantBundleClient({
    async describeSecurityGroups() {
      throw accessDenied("UnauthorizedOperation");
    },
    async listKmsKeys() {
      throw accessDenied();
    },
  });
  const second = await exportAwsAuditBundle(degraded, sampleConfig(), base);

  assert.notEqual(second.outputDir, first.outputDir);
  assert.notEqual(second.zipPath, first.zipPath);
  assert.ok(existsSync(first.outputDir), "first run directory must survive a rerun");
  assert.ok(existsSync(first.zipPath), "first run archive must survive a rerun");
  assert.equal(readdirSync(base).filter((entry) => entry.endsWith(".zip")).length, 2);

  assert.ok(second.errorCount > 0);
  const errorLog = readFileSync(join(second.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /DescribeSecurityGroups|security group/i);
  assert.match(errorLog, /ListKeys|KMS/i);

  const findings = JSON.parse(readFileSync(join(second.outputDir, "analysis", "findings.json"), "utf8"));
  const statuses = Object.fromEntries(findings.map((item) => [item.id, item.status]));
  assert.notEqual(statuses["AWS-NET-21"], "pass", "denied security group surface must not pass");
  assert.notEqual(statuses["AWS-DATA-22"], "pass", "denied KMS surface must not pass");
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

test("normalizePolicyDocument keeps literal % in plain S3 JSON and URL-decodes IAM documents inside a guard", () => {
  const policy = {
    Version: "2012-10-17",
    Statement: [{ Sid: "Deny100%Insecure", Effect: "Deny", Action: "s3:*", Resource: "arn:aws:s3:::bucket/reports%202026/*" }],
  };

  const s3 = normalizePolicyDocument(JSON.stringify(policy), "plain-json");
  assert.equal(s3.Statement[0].Sid, "Deny100%Insecure");
  assert.equal(s3.Statement[0].Resource, "arn:aws:s3:::bucket/reports%202026/*");

  const iam = normalizePolicyDocument(encodeURIComponent(JSON.stringify(policy)), "iam-url-encoded");
  assert.equal(iam.Statement[0].Sid, "Deny100%Insecure");
  assert.equal(iam.Statement[0].Resource, "arn:aws:s3:::bucket/reports%202026/*");

  const notEncoded = normalizePolicyDocument(JSON.stringify(policy), "iam-url-encoded");
  assert.equal(notEncoded.Statement[0].Sid, "Deny100%Insecure");

  assert.equal(normalizePolicyDocument("not json", "plain-json"), undefined);
  assert.equal(normalizePolicyDocument("%7Bnot json", "iam-url-encoded"), undefined);
  assert.deepEqual(normalizePolicyDocument(policy, "plain-json"), policy);
});

test("assessAwsDataProtection keeps all four findings when a bucket policy contains a literal % (review repro)", async () => {
  const policyWithPercent = JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "Deny100%Insecure",
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: ["arn:aws:s3:::reports", "arn:aws:s3:::reports/quarterly%202026/*"],
        Condition: { Bool: { "aws:SecureTransport": "false" } },
      },
    ],
  });
  const result = await assessAwsDataProtection(compliantDataProtectionClient({
    async describeRegions() {
      return ["us-east-1"];
    },
    async listBuckets() {
      return { items: [{ Name: "reports", BucketRegion: "us-east-1" }], truncated: false };
    },
    async getBucketPolicy() {
      return policyWithPercent;
    },
  }));
  assert.equal(result.findings.length, 4);
  assert.deepEqual(statusMap(result), {
    "AWS-DATA-11": "pass",
    "AWS-DATA-12": "pass",
    "AWS-DATA-13": "pass",
    "AWS-DATA-22": "pass",
  });
  assert.deepEqual(result.errors, []);
  assert.deepEqual(findingById(result, "AWS-DATA-13").evidence.buckets_without_tls_deny, []);
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
    // regionLimit: 1 keeps only us-east-1 in scope, so the denials must land there to exercise the caps.
    async describeDbInstances(region) {
      if (region === "us-east-1") throw accessDenied();
      return { items: [{ DBInstanceIdentifier: "orders-db", StorageEncrypted: true }], truncated: false };
    },
    async getKeyRotationStatus(region, keyId) {
      if (region === "us-east-1" && keyId === "k-customer") throw accessDenied();
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
  assert.match(findingById(result, "AWS-DATA-11").summary, /Downgraded to warn: 1 bucket\(s\) could not be read \(s3:GetPublicAccessBlock or s3:GetBucketPolicyStatus\); bucket inventory truncated at 1000/);
  assert.match(findingById(result, "AWS-DATA-12").summary, /rds:DescribeDBInstances unreadable in 1 region\(s\) \(us-east-1\)/);
  assert.match(findingById(result, "AWS-DATA-12").summary, /only 1 of 2 regions assessed/);
  assert.match(findingById(result, "AWS-DATA-13").summary, /bucket inventory truncated/);
  assert.match(findingById(result, "AWS-DATA-22").summary, /kms:GetKeyRotationStatus unreadable for 1 key\(s\)/);
  assert.match(findingById(result, "AWS-DATA-22").summary, /only 1 of 2 regions assessed/);
  assert.equal(result.summary.regions_seen, 1);
  assert.equal(result.summary.regions_total, 2);
  assert.ok(result.errors.some((line) => /Region scope truncated to 1 of 2/.test(line)));
  assert.ok(result.errors.some((line) => /s3:ListBuckets: inventory truncated/.test(line)));
  assert.ok(result.errors.some((line) => /rds:DescribeDBInstances us-east-1: AccessDenied/.test(line)), "the RDS denial is recorded in errors");
  assert.ok(result.errors.some((line) => /kms:GetKeyRotationStatus .*k-customer.*: AccessDenied/.test(line)), "the rotation denial is recorded in errors");
});

test("assessAwsDataProtection names the DescribeRegions failure when the scope falls back to the configured region", async () => {
  const result = await assessAwsDataProtection(compliantDataProtectionClient({
    async describeRegions() {
      throw accessDenied("UnauthorizedOperation");
    },
  }));
  assert.equal(result.summary.regions_seen, 1);
  for (const id of ["AWS-DATA-12", "AWS-DATA-22"]) {
    const item = findingById(result, id);
    assert.equal(item.status, "warn", `${id} is capped while the region list is unreadable`);
    assert.match(item.summary, /only us-east-1 was assessed because the enabled-region list could not be read \(ec2:DescribeRegions: AccessDenied/);
    assert.equal(item.evidence.source, "configured-region-fallback");
    assert.match(item.evidence.scope_error, /^ec2:DescribeRegions: AccessDenied/);
  }
  assert.ok(result.errors.some((line) => /^Region scope fell back to us-east-1 only: ec2:DescribeRegions: AccessDenied/.test(line)));
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
      return paged([{ UserName: "alice", PasswordLastUsed: "2026-04-14T00:00:00Z" }]);
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
      return paged([]);
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

test("assessAwsIdentity URL-decodes IAM documents and survives a literal % in inline and managed policies", async () => {
  const fullAdmin = { Sid: "Allow100%Admin", Effect: "Allow", Action: "*", Resource: "*" };
  const result = await assessAwsIdentity(compliantIdentityClient({
    async getAccountAuthorizationDetails() {
      return paged([
        { RoleName: "EncodedInline", Arn: "arn:aws:iam::123456789012:role/EncodedInline", RolePolicyList: [{ PolicyName: "admin", PolicyDocument: encodeURIComponent(JSON.stringify({ Statement: [fullAdmin] })) }] },
        { RoleName: "RawInline", Arn: "arn:aws:iam::123456789012:role/RawInline", RolePolicyList: [{ PolicyName: "admin", PolicyDocument: JSON.stringify({ Statement: [fullAdmin] }) }] },
      ]);
    },
    async getPolicyVersionDocument(arn) {
      const document = JSON.stringify({ Statement: [arn.endsWith("/Deploy") ? fullAdmin : { Sid: "Read50%", Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::audit/q%202026/*" }] });
      return arn.endsWith("/Deploy") ? encodeURIComponent(document) : document;
    },
  }));
  assert.equal(findingById(result, "AWS-IAM-05").evidence.privileged_roles, 2);
  const policies = findingById(result, "AWS-IAM-08");
  assert.equal(policies.status, "warn");
  assert.deepEqual(policies.evidence.full_admin_unattached, ["Deploy"]);
  assert.deepEqual(policies.evidence.policies_unreadable, []);
  assert.deepEqual(result.errors, []);
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

test("assessAwsIdentity reads root activity from us-east-1 when the configured region differs (review repro)", async () => {
  const lookups = [];
  const result = await assessAwsIdentity(compliantIdentityClient({
    getResolvedConfig: () => sampleConfig({ region: "eu-west-1" }),
    async lookupRootEvents(region, start, end, limit) {
      lookups.push({ region, start: start.toISOString(), end: end.toISOString(), limit });
      return { items: [], truncated: false };
    },
  }));
  assert.deepEqual(lookups, [{ region: "us-east-1", start: "2026-01-16T00:00:00.000Z", end: "2026-04-16T00:00:00.000Z", limit: 500 }]);
  const root = findingById(result, "AWS-IAM-07");
  assert.equal(root.status, "pass");
  assert.match(root.summary, /in us-east-1, the region that receives global console sign-in events/);
  assert.equal(root.evidence.region, "eu-west-1");
  assert.equal(root.evidence.lookup_region, "us-east-1");
  assert.equal(root.evidence.global_event_region, "us-east-1");
  assert.equal(root.evidence.global_lookup_error, null);
  assert.deepEqual(result.errors, []);

  const consoleLogin = await assessAwsIdentity(compliantIdentityClient({
    getResolvedConfig: () => sampleConfig({ region: "eu-west-1" }),
    async lookupRootEvents(region) {
      return {
        items: region === "us-east-1" ? [{ EventId: "e1", EventName: "ConsoleLogin", EventTime: "2026-04-10T08:00:00Z", EventSource: "signin.amazonaws.com", Username: "root" }] : [],
        truncated: false,
      };
    },
  }));
  assert.equal(findingById(consoleLogin, "AWS-IAM-07").status, "fail");
  assert.match(findingById(consoleLogin, "AWS-IAM-07").summary, /lookup region us-east-1/);
});

test("assessAwsIdentity caps root activity at warn when us-east-1 is unreadable and goes manual when nothing is readable", async () => {
  const lookups = [];
  const capped = await assessAwsIdentity(compliantIdentityClient({
    getResolvedConfig: () => sampleConfig({ region: "eu-west-1" }),
    async lookupRootEvents(region) {
      lookups.push(region);
      if (region === "us-east-1") throw accessDenied();
      return { items: [], truncated: false };
    },
  }));
  assert.deepEqual(lookups, ["us-east-1", "eu-west-1"]);
  const root = findingById(capped, "AWS-IAM-07");
  assert.equal(root.status, "warn");
  assert.match(root.summary, /Downgraded to warn: us-east-1 lookup failed \(cloudtrail:LookupEvents Username=root us-east-1: AccessDenied/);
  assert.match(root.summary, /only eu-west-1 API activity was read/);
  assert.equal(root.evidence.lookup_region, "eu-west-1");
  assert.match(root.evidence.global_lookup_error, /^cloudtrail:LookupEvents Username=root us-east-1: AccessDenied/);
  assert.deepEqual(capped.errors.filter((line) => line.startsWith("cloudtrail:LookupEvents")).length, 1);

  const unreadable = await assessAwsIdentity(compliantIdentityClient({
    getResolvedConfig: () => sampleConfig({ region: "eu-west-1" }),
    async lookupRootEvents() {
      throw new Error("endpoint unreachable");
    },
  }));
  const manual = findingById(unreadable, "AWS-IAM-07");
  assert.equal(manual.status, "manual");
  assert.match(manual.summary, /Username=root us-east-1: error \(.*endpoint unreachable.*\); cloudtrail:LookupEvents Username=root eu-west-1: error/);
  assert.equal(unreadable.errors.filter((line) => line.startsWith("cloudtrail:LookupEvents")).length, 2);
});

function compliantOrgClient(overrides = {}) {
  return {
    async describeOrganization() {
      return { Id: "o-example", FeatureSet: "ALL" };
    },
    async listAccounts() {
      return paged([{ Id: "123456789012" }]);
    },
    async listScps() {
      return paged([{ Id: "p-1", Name: "DenyRegions" }]);
    },
    async listPolicyTargets() {
      return paged([{ TargetId: "r-root", Type: "ROOT" }]);
    },
    async listAnalyzers() {
      return paged([{ arn: "arn:analyzer", name: "org-analyzer", status: "ACTIVE" }]);
    },
    async listAccessAnalyzerFindings() {
      return paged([]);
    },
    async listIdentityCenterInstances() {
      return paged([{ InstanceArn: "arn:sso" }]);
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

test("rule 1 corollary: assessAwsOrgGuardrails never passes a control whose secondary read was denied, one secondary at a time", async () => {
  assertOnlyDemoted(await assessAwsOrgGuardrails(compliantOrgClient()), {}, "healthy fixture");

  const accounts = await assessAwsOrgGuardrails(compliantOrgClient({
    async listAccounts() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(accounts, { "AWS-ORG-01": "warn" }, "ListAccounts denied");
  assert.match(findingById(accounts, "AWS-ORG-01").summary, /is visible, but its member accounts could not be listed\. Downgraded to warn: member accounts unreadable \(organizations:ListAccounts: AccessDenied/);
  assert.doesNotMatch(findingById(accounts, "AWS-ORG-01").summary, /0 account\(s\)/);
  assert.equal(findingById(accounts, "AWS-ORG-01").evidence.accounts_readable, false);
  assert.deepEqual(accounts.errors.map((line) => line.split(":").slice(0, 2).join(":")), ["organizations:ListAccounts"]);

  const targetsAll = await assessAwsOrgGuardrails(compliantOrgClient({
    async listPolicyTargets() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(targetsAll, { "AWS-ORG-02": "manual" }, "ListTargetsForPolicy denied for every SCP");
  assert.match(findingById(targetsAll, "AWS-ORG-02").summary, /1 SCP\(s\) exist, but targets could not be read for 1 of them \(organizations:ListTargetsForPolicy DenyRegions: AccessDenied/);
  assert.doesNotMatch(findingById(targetsAll, "AWS-ORG-02").summary, /none is attached/);
  assert.deepEqual(findingById(targetsAll, "AWS-ORG-02").evidence.scps_targets_unreadable, ["DenyRegions"]);

  const targetsOne = await assessAwsOrgGuardrails(compliantOrgClient({
    async listScps() {
      return paged([{ Id: "p-1", Name: "DenyRegions" }, { Id: "p-2", Name: "DenyLeaveOrg" }]);
    },
    async listPolicyTargets(policyId) {
      if (policyId === "p-2") throw accessDenied();
      return paged([{ TargetId: "r-root", Type: "ROOT" }]);
    },
  }));
  assertOnlyDemoted(targetsOne, { "AWS-ORG-02": "warn" }, "ListTargetsForPolicy denied for one SCP");
  assert.match(findingById(targetsOne, "AWS-ORG-02").summary, /^1\/2 SCPs are attached.*Downgraded to warn: ListTargetsForPolicy unreadable for 1 SCP\(s\) \(DenyLeaveOrg\)/);
  assert.equal(findingById(targetsOne, "AWS-ORG-02").evidence.attached_scp_count, 1);

  const findingsAll = await assessAwsOrgGuardrails(compliantOrgClient({
    async listAccessAnalyzerFindings() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(findingsAll, { "AWS-ORG-04": "manual" }, "ListFindings denied for the only analyzer");
  assert.match(findingById(findingsAll, "AWS-ORG-04").summary, /Findings could not be read for any of the 1 active analyzer\(s\) \(access-analyzer:ListFindings org-analyzer: AccessDenied/);
  assert.doesNotMatch(findingById(findingsAll, "AWS-ORG-04").summary, /No active Access Analyzer findings/);
  assert.deepEqual(findingById(findingsAll, "AWS-ORG-04").evidence.analyzers_sampled, []);
  assert.deepEqual(findingById(findingsAll, "AWS-ORG-04").evidence.analyzers_findings_unreadable, ["org-analyzer"]);
  assert.equal(findingById(findingsAll, "AWS-ORG-03").status, "pass", "the analyzer list itself stays readable evidence");

  const findingsOne = await assessAwsOrgGuardrails(compliantOrgClient({
    async listAnalyzers() {
      return paged([
        { arn: "arn:analyzer/org", name: "org-analyzer", status: "ACTIVE" },
        { arn: "arn:analyzer/unused", name: "unused-access", status: "ACTIVE" },
      ]);
    },
    async listAccessAnalyzerFindings(analyzerArn) {
      if (analyzerArn === "arn:analyzer/unused") throw accessDenied();
      return paged([]);
    },
  }));
  assertOnlyDemoted(findingsOne, { "AWS-ORG-04": "warn" }, "ListFindings denied for one of two analyzers");
  assert.match(findingById(findingsOne, "AWS-ORG-04").summary, /No active Access Analyzer findings were visible in the 1 sampled analyzer\(s\)\. Downgraded to warn: ListFindings unreadable for 1 analyzer\(s\) \(unused-access\)/);
  assert.deepEqual(findingById(findingsOne, "AWS-ORG-04").evidence.analyzers_sampled, ["org-analyzer"]);

  const identityCenter = await assessAwsOrgGuardrails(compliantOrgClient({
    async listIdentityCenterInstances() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(identityCenter, { "AWS-ORG-05": "manual" }, "sso:ListInstances denied");
  assert.match(findingById(identityCenter, "AWS-ORG-05").summary, /could not be listed \(sso:ListInstances: AccessDenied/);
  assert.equal(findingById(identityCenter, "AWS-ORG-05").evidence.instances_readable, false);
});

test("assessAwsOrgGuardrails renders manual when the analyzer list is denied or no analyzer is ACTIVE, and describes organization state honestly", async () => {
  const analyzersDenied = await assessAwsOrgGuardrails(compliantOrgClient({
    async listAnalyzers() {
      throw accessDenied();
    },
    async listAccessAnalyzerFindings() {
      throw new Error("findings must not be sampled without an analyzer list");
    },
  }));
  assertOnlyDemoted(analyzersDenied, { "AWS-ORG-03": "manual", "AWS-ORG-04": "manual" }, "ListAnalyzers denied");
  assert.match(findingById(analyzersDenied, "AWS-ORG-04").summary, /analyzers could not be listed \(access-analyzer:ListAnalyzers: AccessDenied.*so external access findings could not be sampled/);
  assert.equal(analyzersDenied.errors.length, 1);

  const noneActive = await assessAwsOrgGuardrails(compliantOrgClient({
    async listAnalyzers() {
      return paged([{ arn: "arn:analyzer/new", name: "creating", status: "CREATING" }]);
    },
  }));
  assertOnlyDemoted(noneActive, { "AWS-ORG-03": "fail", "AWS-ORG-04": "manual" }, "no ACTIVE analyzer");
  assert.match(findingById(noneActive, "AWS-ORG-04").summary, /No ACTIVE Access Analyzer instance was available to sample \(see AWS-ORG-03\)/);
  assert.deepEqual(noneActive.errors, []);

  const orgDenied = await assessAwsOrgGuardrails(compliantOrgClient({
    async describeOrganization() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(orgDenied, { "AWS-ORG-01": "manual" }, "DescribeOrganization denied");
  assert.match(findingById(orgDenied, "AWS-ORG-01").summary, /could not be described \(organizations:DescribeOrganization: AccessDenied/);
  assert.equal(findingById(orgDenied, "AWS-ORG-01").evidence.organization_readable, false);
  assert.equal(findingById(orgDenied, "AWS-ORG-02").status, "pass", "SCPs are governed by a separate IAM action and stay readable evidence");

  const calls = [];
  const standalone = await assessAwsOrgGuardrails(compliantOrgClient({
    async describeOrganization() {
      return null;
    },
    async listAccounts() {
      calls.push("listAccounts");
      return paged([]);
    },
    async listScps() {
      calls.push("listScps");
      return paged([]);
    },
  }));
  assertOnlyDemoted(standalone, { "AWS-ORG-01": "warn", "AWS-ORG-02": "warn" }, "standalone account");
  assert.match(findingById(standalone, "AWS-ORG-01").summary, /AWSOrganizationsNotInUseException.*standalone account/);
  assert.match(findingById(standalone, "AWS-ORG-02").summary, /not part of an AWS Organization/);
  assert.deepEqual(calls, [], "account and SCP lists are skipped for a standalone account");
  assert.equal(findingById(standalone, "AWS-ORG-01").evidence.accounts_readable, null);
  assert.deepEqual(standalone.errors, []);
});

test("rule 10: assessAwsOrgGuardrails caps truncated account, SCP, target, analyzer, and findings lists at warn", async () => {
  const result = await assessAwsOrgGuardrails(compliantOrgClient({
    async listAccounts() {
      return paged([{ Id: "123456789012" }], true);
    },
    async listScps() {
      return paged([{ Id: "p-1", Name: "DenyRegions" }], true);
    },
    async listPolicyTargets() {
      return paged([{ TargetId: "r-root", Type: "ROOT" }], true);
    },
    async listAnalyzers() {
      return paged([{ arn: "arn:analyzer", name: "org-analyzer", status: "ACTIVE" }], true);
    },
    async listAccessAnalyzerFindings() {
      return paged([], true);
    },
  }), { maxFindings: 25 });
  assertOnlyDemoted(result, { "AWS-ORG-01": "warn", "AWS-ORG-02": "warn", "AWS-ORG-03": "warn", "AWS-ORG-04": "warn" }, "truncated lists");
  assert.match(findingById(result, "AWS-ORG-01").summary, /Downgraded to warn: account list truncated at 1000/);
  assert.equal(findingById(result, "AWS-ORG-01").evidence.account_list_truncated, true);
  assert.match(findingById(result, "AWS-ORG-02").summary, /Downgraded to warn: SCP list truncated at 1000; target list truncated for 1 SCP\(s\)/);
  assert.match(findingById(result, "AWS-ORG-03").summary, /Downgraded to warn: analyzer list truncated at 100/);
  assert.match(findingById(result, "AWS-ORG-04").summary, /Downgraded to warn: findings truncated at 25 for org-analyzer/);
  assert.deepEqual(findingById(result, "AWS-ORG-04").evidence.analyzers_findings_truncated, ["org-analyzer"]);
});

test("rule 9: assessAwsOrgGuardrails keeps the security contact's name and title out of the evidence", async () => {
  const result = await assessAwsOrgGuardrails(compliantOrgClient());
  const contact = findingById(result, "AWS-ORG-07");
  assert.equal(contact.status, "pass");
  assert.equal(contact.evidence.has_name, true);
  assert.equal(contact.evidence.has_title, true);
  assert.equal(contact.evidence.has_phone, true);
  const serialized = JSON.stringify(result);
  for (const value of ["Security Team", "CISO", "security@example.com", "+1 555 0100"]) {
    assert.ok(!serialized.includes(value), `${value} must not appear anywhere in the org guardrails result`);
  }
});

test("rule 10: assessAwsIdentity caps user and role verdicts at warn when the inventories are truncated and records the cut in errors", async () => {
  const result = await assessAwsIdentity(compliantIdentityClient({
    async listIamUsers() {
      return paged([{ UserName: "alice", PasswordLastUsed: "2026-04-14T00:00:00Z" }], true);
    },
    async getAccountAuthorizationDetails() {
      return paged([], true);
    },
  }), { userLimit: 1, roleLimit: 1 });
  assertOnlyDemoted(result, { "AWS-IAM-02": "warn", "AWS-IAM-04": "warn", "AWS-IAM-05": "warn", "AWS-IAM-06": "warn" }, "truncated user and role inventories");
  for (const id of ["AWS-IAM-02", "AWS-IAM-04", "AWS-IAM-06"]) {
    assert.match(findingById(result, id).summary, /Downgraded to warn: user inventory truncated at 1/, id);
    assert.equal(findingById(result, id).evidence.user_inventory_truncated, true, id);
  }
  assert.match(findingById(result, "AWS-IAM-05").summary, /Downgraded to warn: role inventory truncated at 1/);
  assert.equal(findingById(result, "AWS-IAM-05").evidence.role_inventory_truncated, true);
  assert.equal(result.summary.user_inventory_truncated, true);
  assert.equal(result.summary.role_inventory_truncated, true);
  assert.ok(result.errors.some((line) => /^iam:ListUsers: inventory truncated at user_limit 1/.test(line)));
  assert.ok(result.errors.some((line) => /^iam:GetAccountAuthorizationDetails Filter=Role: inventory truncated at role_limit 1/.test(line)));
});

test("rule 1 corollary: assessAwsIdentity never passes a user control whose per-user read was denied, one secondary at a time", async () => {
  const twoUsers = {
    async listIamUsers() {
      return paged([
        { UserName: "alice", PasswordLastUsed: "2026-04-14T00:00:00Z" },
        { UserName: "bob", PasswordLastUsed: "2026-04-13T00:00:00Z" },
      ]);
    },
  };
  assertOnlyDemoted(await assessAwsIdentity(compliantIdentityClient(twoUsers)), {}, "two-user fixture");

  const mfaOne = await assessAwsIdentity(compliantIdentityClient({
    ...twoUsers,
    async listMfaDevices(userName) {
      if (userName === "bob") throw accessDenied();
      return [{ SerialNumber: "mfa-alice" }];
    },
  }));
  assertOnlyDemoted(mfaOne, { "AWS-IAM-02": "warn" }, "ListMFADevices denied for one user");
  assert.match(findingById(mfaOne, "AWS-IAM-02").summary, /All 1 sampled IAM users with readable device lists have MFA devices\. Downgraded to warn: ListMFADevices unreadable for 1 user\(s\) \(bob\)/);
  assert.deepEqual(findingById(mfaOne, "AWS-IAM-02").evidence.users_mfa_unreadable, ["bob"]);
  assert.deepEqual(findingById(mfaOne, "AWS-IAM-02").evidence.users_without_mfa, [], "an unreadable device list is not reported as a missing device");
  assert.ok(mfaOne.errors.some((line) => /^iam:ListMFADevices bob: AccessDenied/.test(line)));

  const mfaAll = await assessAwsIdentity(compliantIdentityClient({
    ...twoUsers,
    async listMfaDevices() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(mfaAll, { "AWS-IAM-02": "manual" }, "ListMFADevices denied for every user");
  assert.match(findingById(mfaAll, "AWS-IAM-02").summary, /MFA devices could not be listed for any of the 2 sampled IAM users \(iam:ListMFADevices alice: AccessDenied/);

  const keysOne = await assessAwsIdentity(compliantIdentityClient({
    ...twoUsers,
    async listAccessKeys(userName) {
      if (userName === "bob") throw accessDenied();
      return [];
    },
  }));
  assertOnlyDemoted(keysOne, { "AWS-IAM-04": "warn", "AWS-IAM-06": "warn" }, "ListAccessKeys denied for one user");
  assert.match(findingById(keysOne, "AWS-IAM-04").summary, /No sampled access key exceeded the 90-day staleness threshold\. Downgraded to warn: ListAccessKeys unreadable for 1 user\(s\) \(bob\)/);
  assert.match(findingById(keysOne, "AWS-IAM-06").summary, /Downgraded to warn: ListAccessKeys unreadable for 1 user\(s\) \(bob\)/);
  assert.deepEqual(findingById(keysOne, "AWS-IAM-04").evidence.users_keys_unreadable, ["bob"]);

  const keysAll = await assessAwsIdentity(compliantIdentityClient({
    ...twoUsers,
    async listAccessKeys() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(keysAll, { "AWS-IAM-04": "manual", "AWS-IAM-06": "warn" }, "ListAccessKeys denied for every user");
  assert.match(findingById(keysAll, "AWS-IAM-04").summary, /Access keys could not be listed for any of the 2 sampled IAM users \(iam:ListAccessKeys alice: AccessDenied/);

  const noPasswordUser = await assessAwsIdentity(compliantIdentityClient({
    async listIamUsers() {
      return paged([{ UserName: "svc-deploy" }]);
    },
    async listAccessKeys() {
      throw accessDenied();
    },
  }));
  assert.equal(findingById(noPasswordUser, "AWS-IAM-06").status, "warn");
  assert.deepEqual(findingById(noPasswordUser, "AWS-IAM-06").evidence.dormant_users, [], "a user without password activity is not called dormant while its key list is unreadable");
  assert.match(findingById(noPasswordUser, "AWS-IAM-06").summary, /Downgraded to warn: ListAccessKeys unreadable for 1 user\(s\) \(svc-deploy\)/);

  const lastUsed = await assessAwsIdentity(compliantIdentityClient({
    async listAccessKeys() {
      return [{ AccessKeyId: "AKIAIOSFODNN7EXAMPLE", CreateDate: "2026-04-01T00:00:00Z" }];
    },
    async getAccessKeyLastUsed() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(lastUsed, { "AWS-IAM-04": "manual" }, "GetAccessKeyLastUsed denied for the only sampled key");
  assert.match(findingById(lastUsed, "AWS-IAM-04").summary, /Last-used dates could not be read for any of the 1 sampled access key\(s\) \(iam:GetAccessKeyLastUsed AKIA\*\*\*\*MPLE: AccessDenied/);
  assert.match(findingById(lastUsed, "AWS-IAM-04").summary, /no key was judged/);
  assert.deepEqual(findingById(lastUsed, "AWS-IAM-04").evidence.keys_last_used_unreadable, ["AKIA****MPLE"]);
  assert.deepEqual(findingById(lastUsed, "AWS-IAM-04").evidence.stale_access_keys, [], "an unjudged key is never listed as stale");
  assert.ok(lastUsed.errors.some((line) => /^iam:GetAccessKeyLastUsed AKIA\*\*\*\*MPLE: AccessDenied/.test(line)), "the error line carries the masked key id only");
  assert.ok(!JSON.stringify(lastUsed).includes("AKIAIOSFODNN7EXAMPLE"));

  // The review-round fixture: svc-deploy holds a key older than the threshold whose last use is denied. The creation
  // date must not stand in for the denied last-used date, so the user is never failed on evidence the run did not see.
  const oldKeyDenied = await assessAwsIdentity(compliantIdentityClient({
    async listIamUsers() {
      return paged([
        { UserName: "alice", PasswordLastUsed: "2026-04-14T00:00:00Z" },
        { UserName: "svc-deploy", PasswordLastUsed: "2026-04-13T00:00:00Z" },
      ]);
    },
    async listAccessKeys(userName) {
      if (userName === "svc-deploy") return [{ AccessKeyId: "AKIAIOSFODNN7EXAMPLE", CreateDate: "2024-01-01T00:00:00Z" }];
      return [{ AccessKeyId: "AKIAALICEKEY00000001", CreateDate: "2026-04-01T00:00:00Z" }];
    },
    async getAccessKeyLastUsed(accessKeyId) {
      if (accessKeyId === "AKIAIOSFODNN7EXAMPLE") throw accessDenied();
      return { LastUsedDate: "2026-04-15T00:00:00Z" };
    },
  }));
  assertOnlyDemoted(oldKeyDenied, { "AWS-IAM-04": "warn" }, "GetAccessKeyLastUsed denied for one of two sampled keys");
  const oldKeyFinding = findingById(oldKeyDenied, "AWS-IAM-04");
  assert.notEqual(oldKeyFinding.status, "fail", "a user is never failed on a key whose last use was unreadable");
  assert.deepEqual(oldKeyFinding.evidence.stale_access_keys, [], "the 2024 key is not judged stale by its creation date");
  assert.deepEqual(oldKeyFinding.evidence.keys_last_used_unreadable, ["AKIA****MPLE"]);
  assert.match(oldKeyFinding.summary, /No sampled access key exceeded the 90-day staleness threshold\. Downgraded to warn: GetAccessKeyLastUsed unreadable for 1 key\(s\) \(AKIA\*\*\*\*MPLE\); those keys were not judged and need a manual last-used review/);
  assert.ok(!JSON.stringify(oldKeyDenied).includes("AKIAIOSFODNN7EXAMPLE"));
});

test("assessAwsIdentity renders manual, never fail, when a primary IAM read is denied", async () => {
  const summary = await assessAwsIdentity(compliantIdentityClient({
    async getAccountSummary() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(summary, { "AWS-IAM-01": "manual" }, "GetAccountSummary denied");
  assert.match(findingById(summary, "AWS-IAM-01").summary, /could not be read \(iam:GetAccountSummary: AccessDenied/);

  const password = await assessAwsIdentity(compliantIdentityClient({
    async getPasswordPolicy() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(password, { "AWS-IAM-03": "manual" }, "GetAccountPasswordPolicy denied");
  assert.match(findingById(password, "AWS-IAM-03").summary, /could not be read \(iam:GetAccountPasswordPolicy: AccessDenied/);
  assert.doesNotMatch(findingById(password, "AWS-IAM-03").summary, /No account password policy/);
  assert.equal(findingById(password, "AWS-IAM-03").evidence.password_policy_readable, false);

  const noPolicy = await assessAwsIdentity(compliantIdentityClient({
    async getPasswordPolicy() {
      return null;
    },
  }));
  assertOnlyDemoted(noPolicy, { "AWS-IAM-03": "fail" }, "no password policy configured");
  assert.match(findingById(noPolicy, "AWS-IAM-03").summary, /No account password policy is configured \(GetAccountPasswordPolicy returned NoSuchEntity\)/);

  const users = await assessAwsIdentity(compliantIdentityClient({
    async listIamUsers() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(users, { "AWS-IAM-02": "manual", "AWS-IAM-04": "manual", "AWS-IAM-06": "manual" }, "ListUsers denied");
  assert.match(findingById(users, "AWS-IAM-02").summary, /IAM users could not be listed \(iam:ListUsers: AccessDenied/);
  assert.equal(findingById(users, "AWS-IAM-02").evidence.users_readable, false);

  const roles = await assessAwsIdentity(compliantIdentityClient({
    async getAccountAuthorizationDetails() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(roles, { "AWS-IAM-05": "manual" }, "GetAccountAuthorizationDetails denied");
  assert.match(findingById(roles, "AWS-IAM-05").summary, /IAM roles could not be read \(iam:GetAccountAuthorizationDetails Filter=Role: AccessDenied/);
  assert.equal(roles.errors.length, 1);
});

test("assessAwsNetworkSecurity names the DescribeRegions failure when the scope falls back to the configured region", async () => {
  const result = await assessAwsNetworkSecurity(compliantNetworkClient({
    async describeRegions() {
      throw accessDenied("UnauthorizedOperation");
    },
  }));
  for (const id of ["AWS-NET-14", "AWS-NET-20", "AWS-NET-21"]) {
    const item = findingById(result, id);
    assert.equal(item.status, "warn", `${id} is capped while the region list is unreadable`);
    assert.match(item.summary, /only us-east-1 was assessed because the enabled-region list could not be read \(ec2:DescribeRegions: AccessDenied/);
    assert.equal(item.evidence.source, "configured-region-fallback");
  }
  assert.ok(result.errors.some((line) => /^Region scope fell back to us-east-1 only: ec2:DescribeRegions: AccessDenied/.test(line)));
});

const FAKE_AWS_SECRETS = {
  accessKeyId: "AKIAFAKESECRETKEYID01",
  contactName: "FAKE_SECRET_CONTACT_NAME_2",
  contactTitle: "FAKE_SECRET_CONTACT_TITLE_3",
  contactEmail: "FAKE_SECRET_CONTACT_4@example.test",
  contactPhone: "+1 555 0199 FAKE5",
};

test("verdict rule 9: exportAwsAuditBundle never writes access key ids or the security contact's identity into the bundle or its zip", async () => {
  const base = createTempBase("grclanker-aws-secrets-");
  const client = compliantBundleClient({
    async listAccessKeys() {
      return [{ AccessKeyId: FAKE_AWS_SECRETS.accessKeyId, CreateDate: "2025-01-01T00:00:00Z" }];
    },
    async getAccessKeyLastUsed() {
      return { LastUsedDate: "2025-01-02T00:00:00Z" };
    },
    async getSecurityAlternateContact() {
      return {
        AlternateContactType: "SECURITY",
        Name: FAKE_AWS_SECRETS.contactName,
        Title: FAKE_AWS_SECRETS.contactTitle,
        EmailAddress: FAKE_AWS_SECRETS.contactEmail,
        PhoneNumber: FAKE_AWS_SECRETS.contactPhone,
      };
    },
  });

  const result = await exportAwsAuditBundle(client, sampleConfig(), base);
  const files = readBundleFiles(result.outputDir);
  const entries = readZipEntries(result.zipPath);
  assert.ok(files.size > 10);
  assert.equal(entries.size, files.size, "every written file is in the zip");
  assertSecretsAbsent(assert, files, Object.values(FAKE_AWS_SECRETS), "bundle files");
  assertSecretsAbsent(assert, entries, Object.values(FAKE_AWS_SECRETS), "zip entries");

  const findings = JSON.parse(files.get("analysis/findings.json"));
  const keyRotation = findings.find((item) => item.id === "AWS-IAM-04");
  assert.equal(keyRotation.status, "fail", "the stale key is still reported");
  assert.deepEqual(keyRotation.evidence.stale_access_keys.map((key) => key.accessKeyId), ["AKIA****ID01"]);
  const contact = findings.find((item) => item.id === "AWS-ORG-07");
  assert.equal(contact.status, "pass");
  assert.equal(contact.evidence.email_domain, "@example.test");
  assert.match(contact.summary, /\*\*\*@example\.test/);
});
