import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import dns from "node:dns";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  AWS_CONTROL_CATALOG,
  AWS_FINDING_CONTROLS,
  AWS_FRAMEWORKS,
  AWS_REQUIRED_OUTPUT_MEMBERS,
  AwsApiError,
  AwsCredentialProviderError,
  assessAwsDataProtection,
  assessAwsIdentity,
  assessAwsLoggingDetection,
  assessAwsNetworkSecurity,
  assessAwsOrgGuardrails,
  awsFixedTexts,
  buildAwsMappings,
  checkAwsAccess,
  exportAwsAuditBundle,
  isAwsAccessDenied,
  labelIdentifier,
  maskAccessKeyId,
  normalizePolicyDocument,
  paginateAwsList,
  permissiveNaclEntries,
  redactCarrierText,
  redactErrorText,
  resolveAwsConfiguration,
  resolveRegionScope,
  resolveSecureOutputPath,
  scrubSnapshotValue,
  statementDeniesInsecureTransport,
  unrestrictedSecurityGroupRules,
} from "../dist/extensions/grc-tools/aws.js";
import {
  AWS_CANARIES,
  CANARY_URL,
  FIXTURE_ACCOUNT,
  canaryHtmlBody,
  contextLeakingDeniedError,
  healthySdkRoutes,
  proxyHtmlError,
  realAwsClient,
  realAwsConfig,
  sdkAccessDenied,
  sdkServiceUnavailable,
  sdkThrottled,
  sdkTimeout,
  shortBodyParseError,
  withSdkRoutes,
} from "./helpers/aws-sdk-fixture.mjs";
import { readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import {
  CANARY,
  ENCODED_FORM_SECRET,
  PARSER_SNIPPET_CANARY,
  PARSER_WORDING,
  SHORT_BODY_CANARY,
  SHORT_BODY_CONTENT_TYPE,
  assertCanaryFixture,
  assertNoCanaryWindows,
  assertNoCanaryWindowsInFiles,
  assertNoShortBodyFragments,
  assertRedactionCases,
  assertScrubBoundary,
  assertShortBodyRecordedAsNote,
  jsonCanaryMessage,
  parserMessageFor,
  parserSnippetBody,
} from "./helpers/error-canaries.mjs";
import {
  BEARER_ID_CARRIER_CONTROL_ROWS,
  BEARER_ID_VALUES,
  DEPTH_CONTROL,
  ESCAPED_HEADER_LINES,
  JSON_ESCAPES,
  MASKED_HEX_ID_GROUP,
  QUOTED_NON_CREDENTIAL_GROUP,
  SERVER_ASSIGNED_HEX_IDS,
  assertBearerIdKeyRows,
  assertBearerIdSnapshotKeys,
  assertCarrierTextScrub,
  assertCredentialPairValuesRemoved,
  assertDepthControl,
  assertDepthControlOutputs,
  assertEscapedHeaderCarriers,
  assertFixedTextsSurvive,
  assertHexIdentifierPolicy,
  assertIdentifierKeyRows,
  assertFlagAndPathPairRows,
  assertMustKeepRows,
  assertMustRedactRowsBesideMustKeep,
  plantDeepProbeInPolicyDocument,
} from "./helpers/redaction-table.mjs";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** A raw access key id the fixtures return; only its masked form (first and last four characters) may reach an output. */
const RAW_ACCESS_KEY_ID = "AKIA3HPK8LPDA53DZLCF";
const MASKED_ACCESS_KEY_ID = `AKIA****${RAW_ACCESS_KEY_ID.slice(-4)}`;

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

test("config resolution: the profile, region, and account set through the environment survive an argument overlay that carries every key as undefined and names only an unrelated argument, the source chain names the environment, and static environment credentials still sign the request through the real SDK", async () => {
  // Every documented key present as undefined (the shape an argument overlay emits), one unrelated argument set.
  const overlay = { region: undefined, profile: undefined, account_id: undefined, region_limit: 1 };

  const profile = resolveAwsConfiguration(overlay, { AWS_PROFILE: "audit-env-profile", AWS_REGION: "eu-west-1", AWS_ACCOUNT_ID: "123456789012" });
  assert.deepEqual({ region: profile.region, profile: profile.profile, accountId: profile.accountId }, { region: "eu-west-1", profile: "audit-env-profile", accountId: "123456789012" }, "the environment values resolve");
  assert.deepEqual(profile.sourceChain, ["environment-region", "environment-profile", "environment-account"], "the source chain names the environment");

  const defaultRegion = resolveAwsConfiguration(overlay, { AWS_DEFAULT_REGION: "ap-southeast-2" });
  assert.equal(defaultRegion.region, "ap-southeast-2", "AWS_DEFAULT_REGION resolves when AWS_REGION is unset");
  assert.deepEqual(defaultRegion.sourceChain, ["environment-region"]);

  // A blank string argument is "not provided" as well: it never shadows the environment value.
  const blank = resolveAwsConfiguration({ ...overlay, profile: "", region: "  " }, { AWS_PROFILE: "audit-env-profile", AWS_REGION: "eu-west-1" });
  assert.deepEqual({ region: blank.region, profile: blank.profile }, { region: "eu-west-1", profile: "audit-env-profile" }, "blank arguments do not erase the environment values");

  // The credential itself is the SDK's: with no profile resolved, the default chain reads the static environment key and signs with it.
  await withLocalAwsEndpoint(() => STS_IDENTITY_RESPONSE, async ({ requests }) => {
    const config = resolveAwsConfiguration(overlay, process.env);
    assert.equal(config.profile, undefined, "no profile is resolved, so the default credential chain is used");
    assert.deepEqual(config.sourceChain, ["environment-region"]);
    const identity = await realAwsClient(config).getCallerIdentity();
    assert.equal(identity.Account, FIXTURE_ACCOUNT, "the identity read completes with the environment credential");
    assert.deepEqual(requests.map((entry) => [entry.label, entry.accessKeyId]), [["sts:GetCallerIdentity", process.env.AWS_ACCESS_KEY_ID]], "the request was signed with the environment access key id");
  });
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
        return [{ AccessKeyId: RAW_ACCESS_KEY_ID, CreateDate: "2025-01-01T00:00:00Z" }];
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
  assert.deepEqual(staleKeys.map((key) => key.accessKeyId), [MASKED_ACCESS_KEY_ID], "access key ids are masked in evidence");
  assertNoCanaryWindows(assert, result, [RAW_ACCESS_KEY_ID], "the raw access key id never reaches the assessment output");
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
  assert.equal(maskAccessKeyId(RAW_ACCESS_KEY_ID), MASKED_ACCESS_KEY_ID);
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

  // Round 4 open ruling: a real 32-hex detector id is named by its masked form in the read label and every
  // sentence built from it, and kept whole in the structured detectors_unreadable list.
  const realDetector = SERVER_ASSIGNED_HEX_IDS.find((entry) => entry.label === "GuardDuty detector id");
  const realDetectorDenied = await assessAwsLoggingDetection(compliantLoggingClient({
    async listDetectors() {
      return paged([realDetector.id, "detector-1"]);
    },
    async getDetector(detectorId) {
      if (detectorId === realDetector.id) throw accessDenied();
      return { Status: "ENABLED" };
    },
  }));
  const realDetectorFinding = findingById(realDetectorDenied, "AWS-LOG-04");
  assert.equal(realDetectorFinding.status, "warn", realDetectorFinding.summary);
  assert.deepEqual(realDetectorFinding.evidence.detectors_unreadable, [realDetector.id], "the structured list carries the real id whole");
  assert.equal(realDetectorFinding.evidence.detector_count, 2);
  const realDetectorLine = realDetectorDenied.errors.find((line) => line.startsWith("guardduty:GetDetector "));
  assert.match(realDetectorLine, /^guardduty:GetDetector 12ab\*\*\*\*89f0: AccessDenied/, `the read label names the detector by its masked id: ${realDetectorLine}`);
  assertNoCanaryWindows(assert, [realDetectorFinding.summary, ...realDetectorDenied.errors].join("\n"), [realDetector.id], "LOG-04 sentences");
  const realDetectorAllDenied = await assessAwsLoggingDetection(compliantLoggingClient({
    async listDetectors() {
      return paged([realDetector.id]);
    },
    async getDetector() {
      throw accessDenied();
    },
  }));
  assert.match(findingById(realDetectorAllDenied, "AWS-LOG-04").summary, /GetDetector could not be read for 1 of them \(guardduty:GetDetector 12ab\*\*\*\*89f0: AccessDenied/);
  assertNoCanaryWindows(assert, JSON.stringify(findingById(realDetectorAllDenied, "AWS-LOG-04").summary), [realDetector.id], "LOG-04 manual summary");

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
  // Every region's RDS inventory was read: the sentence counts the instances against the regions that were read.
  assert.match(encryption.summary, /all \d+ RDS instances in the 2 readable region\(s\) report StorageEncrypted=true/);
  assert.equal(findingById(result, "AWS-DATA-22").evidence.eligible_keys, 2);
});

test("AWS-DATA-12 (round 4 item B): the RDS clause counts only the instances that reported StorageEncrypted, so an instance without the flag is named beside the count instead of inside an 'all N' claim", async () => {
  const result = await assessAwsDataProtection(
    compliantDataProtectionClient({
      async describeDbInstances(region) {
        return {
          items:
            region === "us-east-1"
              ? [{ DBInstanceIdentifier: "orders-db", Engine: "postgres", StorageEncrypted: true }]
              : [{ DBInstanceIdentifier: "noflag-db", Engine: "mysql" }],
          truncated: false,
        };
      },
    }),
  );
  const encryption = findingById(result, "AWS-DATA-12");
  assert.equal(encryption.status, "warn", encryption.summary);
  assert.match(encryption.summary, /1 of 2 RDS instances in the 2 readable region\(s\) report StorageEncrypted=true; 1 did not report the flag/, encryption.summary);
  assert.doesNotMatch(encryption.summary, /all 2 RDS instances/, "the clause never claims every instance reported the flag");
  assert.match(encryption.summary, /Downgraded to warn: .*1 RDS instance\(s\) without a StorageEncrypted flag/, encryption.summary);
  assert.deepEqual(encryption.evidence.rds_without_flag, ["noflag-db"]);
  assert.deepEqual(encryption.evidence.rds_unencrypted, []);
  assert.equal(encryption.evidence.rds_instances, 2);

  // Every instance reported the flag: the "all N" wording is kept for that case alone.
  const complete = findingById(await assessAwsDataProtection(compliantDataProtectionClient()), "AWS-DATA-12");
  assert.match(complete.summary, /all 1 RDS instances in the 2 readable region\(s\) report StorageEncrypted=true/, complete.summary);
  assert.doesNotMatch(complete.summary, /did not report the flag/);

  // No instance reported the flag: none is counted as encrypted.
  const noneReported = findingById(
    await assessAwsDataProtection(
      compliantDataProtectionClient({
        async describeDbInstances(region) {
          return { items: region === "us-east-1" ? [{ DBInstanceIdentifier: "noflag-db", Engine: "mysql" }] : [], truncated: false };
        },
      }),
    ),
    "AWS-DATA-12",
  );
  assert.match(noneReported.summary, /0 of 1 RDS instances in the 2 readable region\(s\) report StorageEncrypted=true; 1 did not report the flag/, noneReported.summary);
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
  // The RDS inventory was unreadable in every assessed region: the summary says so and never claims "all 0 RDS instances".
  assert.match(findingById(result, "AWS-DATA-12").summary, /RDS instances could not be listed in any of 1 region\(s\) \(rds:DescribeDBInstances us-east-1: AccessDenied/);
  assert.doesNotMatch(findingById(result, "AWS-DATA-12").summary, /all 0 RDS instances|0 RDS instances report/);
  assert.deepEqual({ instances: result.summary.rds_instances, unencrypted: result.summary.rds_unencrypted, evidence: findingById(result, "AWS-DATA-12").evidence.rds_instances }, { instances: null, unencrypted: null, evidence: null }, "the RDS counts are unread, matching the summary sentence");
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
  assert.equal(findingById(findingsAll, "AWS-ORG-04").evidence.analyzers_sampled, null, "no analyzer was sampled, so the list is unread rather than empty");
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
      return [{ AccessKeyId: RAW_ACCESS_KEY_ID, CreateDate: "2026-04-01T00:00:00Z" }];
    },
    async getAccessKeyLastUsed() {
      throw accessDenied();
    },
  }));
  assertOnlyDemoted(lastUsed, { "AWS-IAM-04": "manual" }, "GetAccessKeyLastUsed denied for the only sampled key");
  assert.ok(
    findingById(lastUsed, "AWS-IAM-04").summary.startsWith(`Last-used dates could not be read for any of the 1 sampled access key(s) (iam:GetAccessKeyLastUsed ${MASKED_ACCESS_KEY_ID}: AccessDenied`),
    findingById(lastUsed, "AWS-IAM-04").summary,
  );
  assert.match(findingById(lastUsed, "AWS-IAM-04").summary, /no key was judged/);
  assert.deepEqual(findingById(lastUsed, "AWS-IAM-04").evidence.keys_last_used_unreadable, [MASKED_ACCESS_KEY_ID]);
  // No key was judged, so the stale list and the judged count are unread (null), not an empty list beside an unreadable key.
  assert.deepEqual(
    { stale: findingById(lastUsed, "AWS-IAM-04").evidence.stale_access_keys, judged: findingById(lastUsed, "AWS-IAM-04").evidence.keys_judged, summaryStale: lastUsed.summary.stale_access_keys, summaryJudged: lastUsed.summary.keys_judged },
    { stale: null, judged: null, summaryStale: null, summaryJudged: null },
    "an unjudged key is never listed as stale, and 0 never stands beside the unreadable key",
  );
  assert.equal(lastUsed.summary.keys_last_used_unreadable, 1);
  assert.ok(lastUsed.errors.some((line) => line.startsWith(`iam:GetAccessKeyLastUsed ${MASKED_ACCESS_KEY_ID}: AccessDenied`)), "the error line carries the masked key id only");
  assertNoCanaryWindows(assert, lastUsed, [RAW_ACCESS_KEY_ID], "last-used evidence");

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
      if (userName === "svc-deploy") return [{ AccessKeyId: RAW_ACCESS_KEY_ID, CreateDate: "2024-01-01T00:00:00Z" }];
      return [{ AccessKeyId: "AKIAALICEKEY00000001", CreateDate: "2026-04-01T00:00:00Z" }];
    },
    async getAccessKeyLastUsed(accessKeyId) {
      if (accessKeyId === RAW_ACCESS_KEY_ID) throw accessDenied();
      return { LastUsedDate: "2026-04-15T00:00:00Z" };
    },
  }));
  assertOnlyDemoted(oldKeyDenied, { "AWS-IAM-04": "warn" }, "GetAccessKeyLastUsed denied for one of two sampled keys");
  const oldKeyFinding = findingById(oldKeyDenied, "AWS-IAM-04");
  assert.notEqual(oldKeyFinding.status, "fail", "a user is never failed on a key whose last use was unreadable");
  assert.deepEqual(oldKeyFinding.evidence.stale_access_keys, [], "the 2024 key is not judged stale by its creation date");
  assert.deepEqual(oldKeyFinding.evidence.keys_last_used_unreadable, [MASKED_ACCESS_KEY_ID]);
  assert.ok(
    oldKeyFinding.summary.includes(`No sampled access key exceeded the 90-day staleness threshold. Downgraded to warn: GetAccessKeyLastUsed unreadable for 1 key(s) (${MASKED_ACCESS_KEY_ID}); those keys were not judged and need a manual last-used review`),
    oldKeyFinding.summary,
  );
  // One of two keys was judged: the stale count is 0 of the 1 judged key, stated beside the judged count and the unreadable key.
  assert.deepEqual(
    { stale: oldKeyFinding.evidence.stale_access_keys, judged: oldKeyFinding.evidence.keys_judged, sampled: oldKeyFinding.evidence.keys_sampled, summary: { stale: oldKeyDenied.summary.stale_access_keys, judged: oldKeyDenied.summary.keys_judged, unreadable: oldKeyDenied.summary.keys_last_used_unreadable } },
    { stale: [], judged: 1, sampled: 2, summary: { stale: 0, judged: 1, unreadable: 1 } },
    "a partially judged sample renders its stale count beside the number judged",
  );
  assertNoCanaryWindows(assert, oldKeyDenied, [RAW_ACCESS_KEY_ID], "denied last-used evidence");
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

/**
 * Planted values that must never reach the bundle, alphanumeric and random-looking so no 6-character window of
 * them occurs in the fixture's legitimate values (see the fixture self-check). The contact email's canary is its
 * local part and the phone's is its digits; the domain and the dialing prefix are legitimate text.
 */
const FAKE_AWS_SECRETS = {
  accessKeyId: RAW_ACCESS_KEY_ID,
  contactName: "UzJmyw4Cp8MNezmK",
  contactTitle: "v2rpGAgG74uwFcGs",
  contactEmail: "VyrQ3HB5ZSp2@example.test",
  contactPhone: "+1 555 5835367",
};
const FAKE_AWS_CANARIES = Object.values(FAKE_AWS_SECRETS).map((value) => value.split("@")[0].replace(/^\+1 555 /, ""));

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
  assertNoCanaryWindowsInFiles(assert, files, FAKE_AWS_CANARIES, "bundle files");
  assertNoCanaryWindowsInFiles(assert, entries, FAKE_AWS_CANARIES, "zip entries");

  const findings = JSON.parse(files.get("analysis/findings.json"));
  const keyRotation = findings.find((item) => item.id === "AWS-IAM-04");
  assert.equal(keyRotation.status, "fail", "the stale key is still reported");
  assert.deepEqual(keyRotation.evidence.stale_access_keys.map((key) => key.accessKeyId), [MASKED_ACCESS_KEY_ID]);
  const contact = findings.find((item) => item.id === "AWS-ORG-07");
  assert.equal(contact.status, "pass");
  assert.equal(contact.evidence.email_domain, "@example.test");
  assert.match(contact.summary, /\*\*\*@example\.test/);
});

// ---------------------------------------------------------------------------------------------------------------
// Real-client coverage: the tests below drive AwsAuditorClient itself through the shared SDK send() so request
// shapes, SDK error decoration, and the error-string sink are exercised end to end (see helpers/aws-sdk-fixture).
// ---------------------------------------------------------------------------------------------------------------

/** Probe names in core_data/access.json keyed by the IAM action each probe issues. */
const ACCESS_PROBES = {
  "iam:GetAccountSummary": "iam_summary",
  "iam:ListUsers": "iam_users",
  "cloudtrail:DescribeTrails": "cloudtrail",
  "securityhub:GetEnabledStandards": "security_hub",
  "config:DescribeConfigurationRecorders": "config",
  "guardduty:ListDetectors": "guardduty",
  "access-analyzer:ListAnalyzers": "access_analyzer",
  "organizations:DescribeOrganization": "organizations",
  "sso:ListInstances": "identity_center",
  "ec2:DescribeRegions": "ec2_regions",
  "s3:ListBuckets": "s3_buckets",
  "kms:ListKeys": "kms_keys",
  "rds:DescribeDBInstances": "rds_instances",
  "auditmanager:ListAssessments": "audit_manager",
  "account:GetAlternateContact": "account_contacts",
};

/**
 * Summary leaves that depend on each command and must render null, never a defaulted count or flag, when that
 * command fails. Keys are analysis files; values are the summary fields of that assessment.
 */
const DEPENDENT_SUMMARY_LEAVES = {
  "iam:GetAccountSummary": {},
  "iam:GetAccountPasswordPolicy": {},
  "iam:ListUsers": { identity: ["users", "user_inventory_truncated", "users_without_mfa", "stale_access_keys", "keys_last_used_unreadable", "dormant_users"] },
  "iam:ListMFADevices": {},
  "iam:ListAccessKeys": {},
  "iam:GetAccessKeyLastUsed": {},
  "iam:GetAccountAuthorizationDetails": { identity: ["roles", "role_inventory_truncated", "privileged_roles", "roles_without_boundaries"] },
  "iam:ListPolicies": { identity: ["customer_managed_policies", "full_admin_policies_attached"] },
  "iam:GetPolicyVersion": {},
  "cloudtrail:LookupEvents": { identity: ["root_console_logins"] },
  "cloudtrail:DescribeTrails": { "logging-detection": ["trails", "compliant_trails"] },
  "cloudtrail:GetTrailStatus": { "logging-detection": ["compliant_trails"] },
  "cloudtrail:GetEventSelectors": {},
  "securityhub:DescribeHub": { "logging-detection": ["security_hub_enabled", "security_hub_standards"] },
  "securityhub:GetEnabledStandards": { "logging-detection": ["security_hub_standards"] },
  "config:DescribeConfigurationRecorders": { "logging-detection": ["config_recorders", "recording_config_recorders"] },
  "config:DescribeConfigurationRecorderStatus": { "logging-detection": ["recording_config_recorders"] },
  "guardduty:ListDetectors": { "logging-detection": ["guardduty_detectors", "enabled_guardduty_detectors"] },
  "guardduty:GetDetector": { "logging-detection": ["enabled_guardduty_detectors"] },
  "organizations:DescribeOrganization": { "org-guardrails": ["organization_visible"] },
  "organizations:ListAccounts": { "org-guardrails": ["accounts"] },
  "organizations:ListPolicies": { "org-guardrails": ["scps", "attached_scps"] },
  "organizations:ListTargetsForPolicy": { "org-guardrails": ["attached_scps"] },
  "access-analyzer:ListAnalyzers": { "org-guardrails": ["analyzers", "active_analyzers", "active_external_findings"] },
  "access-analyzer:ListFindings": { "org-guardrails": ["active_external_findings"] },
  "sso:ListInstances": { "org-guardrails": ["identity_center_instances"] },
  "auditmanager:ListAssessments": { "org-guardrails": ["audit_manager_active_assessments"] },
  "account:GetAlternateContact": { "org-guardrails": ["security_contact_configured"] },
  "ec2:DescribeRegions": { "data-protection": ["regions_total"], "network-security": ["regions_total"] },
  "s3control:GetPublicAccessBlock": { "data-protection": ["buckets_without_full_block"] },
  "s3:ListBuckets": { "data-protection": ["buckets", "buckets_without_full_block", "buckets_without_bucket_level_block", "buckets_with_public_policy", "buckets_without_default_encryption", "buckets_without_tls_deny"] },
  "s3:GetPublicAccessBlock": {},
  "s3:GetBucketPolicyStatus": {},
  "s3:GetBucketEncryption": {},
  "s3:GetBucketPolicy": {},
  "ec2:GetEbsEncryptionByDefault": { "data-protection": ["ebs_regions_without_default_encryption"] },
  "rds:DescribeDBInstances": { "data-protection": ["rds_instances", "rds_unencrypted"] },
  "kms:ListKeys": { "data-protection": ["customer_managed_keys", "keys_not_rotating"] },
  "kms:DescribeKey": { "data-protection": ["customer_managed_keys"] },
  "kms:GetKeyRotationStatus": {},
  "ec2:DescribeVpcs": { "network-security": ["vpcs", "vpcs_without_active_flow_logs"] },
  "ec2:DescribeFlowLogs": { "network-security": ["vpcs_without_active_flow_logs"] },
  "ec2:DescribeNetworkAcls": { "network-security": ["network_acls", "permissive_network_acls"] },
  "ec2:DescribeSecurityGroups": { "network-security": ["security_groups", "unrestricted_security_groups"] },
};

/** Every action the healthy fixture serves other than the run's own identity, which is a primary that fails the tool outright. */
const SECONDARY_ACTIONS = Object.keys(healthySdkRoutes()).filter((action) => action !== "sts:GetCallerIdentity");

async function runAllAssessments(client) {
  return {
    access: await checkAwsAccess(client),
    identity: await assessAwsIdentity(client),
    "logging-detection": await assessAwsLoggingDetection(client),
    "org-guardrails": await assessAwsOrgGuardrails(client),
    "data-protection": await assessAwsDataProtection(client),
    "network-security": await assessAwsNetworkSecurity(client),
  };
}

/** Flattens an output tree into dotted leaf paths; empty arrays and objects are leaves so a collapse to [] or {} is visible. */
function leafValues(value, path = "", out = new Map()) {
  if (Array.isArray(value)) {
    if (value.length === 0) out.set(path, "[]");
    for (const [index, item] of value.entries()) leafValues(item, `${path}[${index}]`, out);
  } else if (value !== null && typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.length === 0) out.set(path, "{}");
    for (const [key, item] of entries) leafValues(item, path ? `${path}.${key}` : key, out);
  } else {
    out.set(path, JSON.stringify(value));
  }
  return out;
}

/**
 * Every leaf that a failed read changes must change to null, an error string, or an explicit marker, never to the
 * value an empty-but-readable dataset would produce (0, false, [], {}, "none"); readability flags are the one
 * boolean allowed to flip to false.
 */
function assertNoDefaultedLeaves(healthyOutputs, degradedOutputs, label) {
  const before = leafValues(healthyOutputs);
  const after = leafValues(degradedOutputs);
  const changed = [...after].filter(([path, value]) => before.get(path) !== value);
  assert.ok(changed.length > 0, `${label}: the failed read left every output leaf unchanged, so the failure is invisible`);
  const defaulted = changed.filter(([path, value]) =>
    ["0", "false", "[]", "{}", "\"none\""].includes(value)
    && !/\.(status|summary)$/.test(path)
    && !/_readable$/.test(path)
    && !/\.collected$/.test(path));
  assert.deepEqual(defaulted.map(([path, value]) => `${path} -> ${value}`), [], `${label}: leaves defaulted to an empty-dataset value instead of null`);
}

/** Planted credentials of the must-keep redaction text: a Basic password, a URL userinfo password, and a signature query value. */
const AWS_MUST_KEEP_CANARIES = Object.freeze({ basicPassword: "MCuGTqGBG8dmEzse", userinfoPassword: "b4usg7S4JD6bbWTW", signature: "yMsNMGW3jpjWBk5MznMJ" });

/** The secret planted on the malformed line of every shared-config fixture. */
const SHARED_CONFIG_CANARY = "qf9apUYznyvTJPXKF2dreQwY";

/** Every planted canary an AWS output is swept for, window by window. */
const AWS_PLANTED_CANARIES = Object.freeze([
  ...Object.values(AWS_CANARIES),
  ...Object.values(CANARY),
  SHORT_BODY_CANARY,
  PARSER_SNIPPET_CANARY,
  ...FAKE_AWS_CANARIES,
  ...Object.values(AWS_MUST_KEEP_CANARIES),
  SHARED_CONFIG_CANARY,
]);

function assertNoCanaries(text, label) {
  assertNoCanaryWindows(assert, text, AWS_PLANTED_CANARIES, label);
}

test("rule 9 scrub boundary: name-shaped values stay bare, any value in a carrier is removed, token-shaped values are removed bare, the resolved secret access key is a configured secret removed in every encoded form, and the fixed texts survive", async () => {
  // The secret arrives the way a real run's does: resolved by the guarded fromIni provider from the shared credentials file.
  await withSharedAwsFiles({ credentials: ["[audit]", "aws_access_key_id = AKIAEXAMPLE000000001", `aws_secret_access_key = ${ENCODED_FORM_SECRET}`, ""].join("\n") }, async () => {
    let resolved;
    const routes = {
      ...healthySdkRoutes(),
      "sts:GetCallerIdentity": async (input, region, sdk) => {
        resolved = await sdk.resolveCredentials();
        return healthySdkRoutes()["sts:GetCallerIdentity"]();
      },
    };
    await withSdkRoutes(routes, [], () => realAwsClient(realAwsConfig({ profile: "audit" })).getCallerIdentity());
    assert.equal(resolved?.secretAccessKey, ENCODED_FORM_SECRET, "positive control: the provider resolved the planted secret verbatim");
  });
  assertScrubBoundary(assert, redactErrorText, {
    configuredSecret: ENCODED_FORM_SECRET,
    mustKeep: [
      `iam:GetAccessKeyLastUsed ${MASKED_ACCESS_KEY_ID}: AccessDenied (AccessDeniedException (HTTP 403): User is not authorized to perform this operation (AccessDeniedException))`,
      "credentials could not be resolved by fromIni (profile audit) (CredentialsProviderError ENOENT). The provider's message is not recorded because it can quote the shared config or credentials file; check the profile in ~/.aws/credentials and ~/.aws/config.",
      "SyntaxError (HTTP 502): non-JSON body (text/html, 5120 bytes)",
      "SyntaxError: response could not be parsed as the service protocol; the parser's message is not recorded because it quotes the body",
      "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events-2026",
      "only 1 of 17 regions assessed (ec2:DescribeRegions us-east-1: AccessDeniedException (HTTP 403))",
      "bucket cloudtrail-logs-123456789012-us-east-1 has no bucket policy (s3:GetBucketPolicy NoSuchBucketPolicy (HTTP 404))",
      ...awsFixedTexts(),
    ],
  });
});

test("rule 9 configured secrets from construction: static AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN in the environment are registered when the client is constructed, before any request is signed, and leave every sink in prose, under a setting key, and in a JSON member", () => {
  // Name-shaped values short enough that no bare rule on any sink touches them: only the registration can.
  const secret = "ctor-registered-first-2026";
  const session = "ctor-registered-second-2026";
  const control = "ctor-unregistered-control-2026";
  const sinks = [
    ["redactErrorText", redactErrorText],
    ["redactCarrierText", redactCarrierText],
    ["scrubSnapshotValue", (text) => scrubSnapshotValue(text)],
  ];
  const carriers = (value) => [`the value ${value} was echoed by the proxy`, `auth_method=${value}`, `{"detail":"${value}"}`];
  // Positive control: before construction every sink keeps them, a setting value and a JSON member included.
  for (const [name, sink] of sinks) {
    for (const value of [secret, session, control]) {
      for (const text of carriers(value)) assert.ok(sink(text).includes(value), `${name} keeps the unregistered ${text}`);
    }
  }
  const previous = { AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN: process.env.AWS_SESSION_TOKEN };
  process.env.AWS_SECRET_ACCESS_KEY = secret;
  process.env.AWS_SESSION_TOKEN = session;
  try {
    realAwsClient(realAwsConfig());
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
  for (const [name, sink] of sinks) {
    for (const value of [secret, session]) {
      for (const text of carriers(value)) {
        const output = sink(text);
        assert.ok(!output.includes(value), `${name} removes the configured ${text}: ${output}`);
        assert.ok(output.includes("[REDACTED]"), `${name} leaves the marker in ${text}: ${output}`);
      }
      assert.equal(sink(`auth_method=${value}`), "auth_method=[REDACTED]", `${name} keeps the setting key`);
    }
    for (const text of carriers(control)) assert.ok(sink(text).includes(control), `${name} still keeps the unregistered control ${text}`);
  }
});

test("rule 9 fixed texts (GWS note 1): every fixed-text message the integration emits survives redactErrorText unchanged, from the SyntaxError and non-JSON notes through every AwsApiError, IncompleteResponse, and AwsCredentialProviderError rendering to the region-scope, not_readable, and downgrade wordings", () => {
  const texts = awsFixedTexts();
  assertFixedTextsSurvive(assert, redactErrorText, texts, { minimum: 45 });
  const denied = "AccessDeniedException (HTTP 403): User is not authorized to perform this operation";
  for (const required of [
    "response could not be parsed as the service protocol; the parser's message is not recorded because it quotes the body",
    "SyntaxError: response could not be parsed as the service protocol; the parser's message is not recorded because it quotes the body",
    "SyntaxError (HTTP 502): non-JSON body (text/html, 89 bytes)",
    "body: not observed",
    "body: empty, 0 bytes",
    "body: text/html, 512 bytes",
    denied,
    `NoSuchEntity (HTTP 404): The Access Key with id ${maskAccessKeyId("AKIAEXAMPLE000000001")} cannot be found.`,
    "TimeoutError: Request did not complete within 10000 ms",
    "HTTP 403",
    "UnknownError (HTTP 403): rejected",
    "UnknownError",
    "IncompleteResponse (HTTP 200): ListUsers answered without its Users member (body: empty, 0 bytes)",
    "IncompleteResponse (HTTP 200): GetCallerIdentity answered without its Account member (body: text/html, 512 bytes)",
    "IncompleteResponse: GetAccountSummary answered without its SummaryMap member (body: not observed)",
    `iam:ListUsers: AccessDenied (${denied})`,
    `ec2:DescribeVpcs us-east-1: error (IncompleteResponse (HTTP 200): DescribeVpcs answered without its Vpcs member (body: text/xml, 240 bytes))`,
    `guardduty:GetDetector 12ab****89f0: AccessDenied (${denied})`,
    `guardduty:GetDetector detector-1: AccessDenied (${denied})`,
    "Region scope truncated to 1 of 17 regions by region_limit.",
    "only 1 of 17 regions assessed",
    "Current AWS account could not be determined.",
    "14/15 AWS audit surfaces are readable.",
    "Grant read-only access for the audit principal to the surfaces marked not_readable (iam, ec2); unreadable surfaces render manual findings, never pass.",
  ]) {
    assert.ok(texts.includes(required), `the fixed-text list carries: ${required}`);
  }
  assert.ok(texts.some((text) => /^credentials could not be resolved by fromIni \(profile audit\) \(CredentialsProviderError ENOENT\)\. The provider's message is not recorded because it can quote the shared config or credentials file; check the profile in .+ and .+\.$/.test(text)), "the credential-provider rendering is in the list");
  assert.ok(texts.some((text) => /^credentials could not be resolved by fromNodeProviderChain \(default credential chain\) \(UnknownError\)\./.test(text)), "the default-chain rendering with a nameless cause is in the list");
  assert.ok(texts.some((text) => /^Last-used dates could not be read for any of the 2 sampled access key\(s\) \(iam:GetAccessKeyLastUsed AKIA\*{4}[0-9A-Z]{4}: AccessDenied .*\); no key was judged\./.test(text)), "the no-key-judged wording is in the list");

  // A nameless, message-less SDK error renders as its status alone, never as "[object Object]".
  assert.equal(new AwsApiError({ $metadata: { httpStatusCode: 403 } }).message, "HTTP 403");
  assert.ok(!texts.some((text) => text.includes("[object Object]")), "no fixed text stringifies an object");

  // The read label keeps a server-assigned id whole when the scrub keeps it and masks it otherwise, so a
  // 32-hex GuardDuty detector id (a hex digest to the scrub) still names the detector in the recorded line.
  assert.equal(labelIdentifier("detector-1"), "detector-1");
  assert.equal(labelIdentifier("12abc34d567e8fa901bc2d34e56789f0"), "12ab****89f0");
  assert.equal(redactErrorText(`guardduty:GetDetector ${labelIdentifier("12abc34d567e8fa901bc2d34e56789f0")}: AccessDenied (${denied})`), `guardduty:GetDetector 12ab****89f0: AccessDenied (${denied})`);
  assert.equal(redactErrorText("guardduty:GetDetector 12abc34d567e8fa901bc2d34e56789f0"), "guardduty:GetDetector [REDACTED]", "negative control: the bare 32-hex id is a hex digest to the scrub");
  assertHexIdentifierPolicy(assert, redactErrorText, { mask: labelIdentifier });

  // The renderings the client throws, built by AwsApiError and AwsCredentialProviderError, survive too.
  const thrown = [
    new AwsApiError({ name: "AccessDeniedException", message: "User is not authorized to perform this operation", $metadata: { httpStatusCode: 403 } }),
    new AwsApiError({ name: "SyntaxError", $metadata: { httpStatusCode: 502 }, $bodyNote: "non-JSON body (text/html, 5120 bytes)" }),
    new AwsApiError(new SyntaxError("Unexpected token '<', \"<html>\" is not valid JSON")),
    new AwsApiError({ name: "TimeoutError", message: "Request did not complete within 10000 ms" }),
    new AwsCredentialProviderError("fromIni (profile audit)", { name: "CredentialsProviderError", code: "ENOENT" }),
  ];
  for (const error of thrown) {
    assert.equal(redactErrorText(error.message), error.message, `the thrown rendering survives the scrub: ${error.message}`);
  }
});

test("rule 9 must-keep and must-redact table (addendum 7): every command with its region or identifier, name, principal, status text, finding id, and fixed text the summaries, markers, probes, and evidence rely on survives redactErrorText alone and inside a realistic summary sentence, and every canary planted in every carrier beside one of them is removed while the row survives (extends the rule 9 scrub boundary fixed texts)", () => {
  const denied = "AccessDeniedException (HTTP 403): User is not authorized to perform this operation";
  const groups = [
    {
      label: "commands",
      values: [
        "iam:ListUsers",
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        `iam:GetAccessKeyLastUsed ${MASKED_ACCESS_KEY_ID}`,
        "iam:ListMFADevices svc-deploy",
        "iam:ListAccessKeys alice",
        "iam:GetPolicyVersion arn:aws:iam::123456789012:policy/ReadOnlyAudit",
        "sts:GetCallerIdentity",
        "ec2:DescribeVpcs us-east-1",
        "ec2:DescribeRegions us-east-1",
        "ec2:DescribeSecurityGroups us-west-2",
        "ec2:DescribeFlowLogs us-east-1",
        "rds:DescribeDBInstances us-east-1",
        "kms:DescribeKey us-east-1/1234abcd-12ab-34cd-56ef-1234567890ab",
        "kms:ListKeys us-east-1",
        "s3:GetBucketPolicy cloudtrail-logs-123456789012-us-east-1",
        "s3:GetBucketEncryption audit-logs",
        "s3control:GetPublicAccessBlock",
        "cloudtrail:GetTrailStatus arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events-2026",
        "cloudtrail:DescribeTrails",
        "config:DescribeConfigurationRecorders",
        "guardduty:GetDetector detector-1",
        `guardduty:GetDetector ${labelIdentifier("12abc34d567e8fa901bc2d34e56789f0")}`,
        "securityhub:DescribeHub",
        "organizations:ListAccounts",
        "organizations:ListTargetsForPolicy DenyRegions",
        "access-analyzer:ListFindings arn:aws:access-analyzer:us-east-1:123456789012:analyzer/prod-analyzer",
        "sso:ListInstances",
      ],
      sentence: (value) => `${value}: AccessDenied (${denied})`,
    },
    {
      label: "names",
      values: [
        "us-east-1",
        "us-west-2",
        "prod-us-east-2026",
        "management-events-2026",
        "cloudtrail-logs-123456789012-us-east-1",
        "audit-logs",
        "orders-db",
        "detector-1",
        "DenyRegions",
        "ReadOnlyAudit",
        "region_limit",
        "not_readable",
        "SummaryMap",
        "AccountMFAEnabled",
        "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0",
        "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
      ],
      sentence: (value) => `${value} could not be read (${denied}); its count is null, the surface is marked not_readable, and the verdict is manual.`,
    },
    {
      label: "principals",
      values: [
        "svc-deploy",
        "alice",
        "arn:aws:iam::123456789012:user/svc-deploy",
        "arn:aws:iam::123456789012:user/auditor",
        "arn:aws:iam::123456789012:role/AuditRole",
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "123456789012",
        MASKED_ACCESS_KEY_ID,
      ],
      sentence: (value) => `Caller ${value} could not read iam:ListUsers (${denied}); the IAM user inventory is null and AWS-IAM-02 is manual.`,
    },
    {
      label: "status text",
      values: [
        "AccessDeniedException (HTTP 403)",
        "NoSuchEntity (HTTP 404)",
        "NoSuchBucketPolicy (HTTP 404)",
        "IncompleteResponse (HTTP 200)",
        "SyntaxError (HTTP 502)",
        "TimeoutError",
        "UnknownError",
        "HTTP 403",
        "CredentialsProviderError ENOENT",
        "User is not authorized to perform this operation",
        "body: empty, 0 bytes",
        "non-JSON body (text/html, 89 bytes)",
      ],
      sentence: (value) => `iam:ListUsers: error (${value}), so the IAM user inventory is null and the dependent findings are manual.`,
    },
    {
      label: "finding ids",
      values: ["AWS-IAM-01", "AWS-IAM-04", "AWS-LOG-01", "AWS-ORG-04", "AWS-DATA-12", "AWS-NET-14"],
      sentence: (value) => `${value} is manual because iam:ListUsers returned ${denied}.`,
    },
    {
      label: "fixed texts",
      values: awsFixedTexts(),
      sentence: (value) => `AWS-IAM-04 ${value}`,
    },
    QUOTED_NON_CREDENTIAL_GROUP,
    MASKED_HEX_ID_GROUP,
  ];
  assertMustKeepRows(assert, redactErrorText, groups);
  assertMustRedactRowsBesideMustKeep(assert, redactErrorText, groups);
});

test("rule 9 escapes (reviewer D round 5 escapes): a header carrier after a two-character or six-character JSON escape is removed exactly as at a line start, for the nineteen header lines the integrations send, the six escapes, and five forms, at 6-to-24 windows, direct and through the client's JSON error path", async () => {
  const judged = assertEscapedHeaderCarriers(assert, redactErrorText);
  assert.equal(judged, ESCAPED_HEADER_LINES.length * JSON_ESCAPES.length * 5);
  assert.equal(ESCAPED_HEADER_LINES.length, 19);

  // The two classes reviewer D found leaking, carried by an error message on a probed surface: a later cookie
  // pair whose name has no credential word, and X-Auth-Key with an alphabetic value, each after a two-character
  // and a six-character escape.
  const tracker = "Rk7mVq2Zt9Xw4Ly6Pn8Hc3Jb";
  const globalKey = "prodkeyQz8Nv3Tm5Rk2Wy7";
  const message = `request failed\\nCookie: theme=dark; my.tracker=${tracker}\\u000aX-Auth-Key: ${globalKey}`;
  assert.ok(message.includes("\\n") && message.includes("\\u000a"), "the message carries the escapes as backslash text");
  const expectedTail = "\\nCookie: [REDACTED]\\u000aX-Auth-Key: [REDACTED]";
  const denied = ({ service }) => {
    if (JSON_PROTOCOL_SERVICES.has(service)) {
      return { status: 403, contentType: "application/x-amz-json-1.1", body: JSON.stringify({ __type: "AccessDeniedException", message }) };
    }
    return { status: 403, contentType: "text/xml", body: `<ErrorResponse xmlns="https://${service}.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>${escapeXml(message)}</Message></Error><RequestId>req-1</RequestId></ErrorResponse>` };
  };
  await withLocalAwsEndpoint(denied, async () => {
    const client = realAwsClient();
    for (const [name, , call] of [LOCAL_AWS_METHODS[1], LOCAL_AWS_METHODS[6]]) {
      await assert.rejects(() => call(client), (error) => {
        assert.ok(error instanceof AwsApiError, name);
        assert.ok(error.message.includes(expectedTail), `${name}: both carriers are removed whole after their escapes: ${error.message}`);
        assertNoCanaryWindows(assert, thrownErrorRecord(error), [tracker, globalKey], `${name} thrown error after escaped headers`);
        return true;
      });
    }
  });
});

test("rule 9 depth control (reviewer D round 5 depth control): every string a snapshot keeps passes the data-side carrier scrub at every depth in place, a credential-keyed value is the marker in place with its benign sibling kept, and a container nested past the cap of 32 is the marker, on scrubSnapshotValue and end to end with the tree planted inside the two policy documents the code parses, through every assessment and the export into the bundle, the zip, and every tool payload", async () => {
  assert.equal(DEPTH_CONTROL.cap, 32);
  // The exported walker: level k of the tree handed to it sits at depth k, so levels 1 to 32 are in place and level 33 is the marker.
  assertDepthControl(assert, scrubSnapshotValue, { label: "aws.scrubSnapshotValue" });
  assertDepthControl(assert, (tree) => scrubSnapshotValue({ Statement: [{ Condition: tree }] }).Statement[0].Condition, { label: "aws.scrubSnapshotValue under a policy statement", rootDepth: 4 });
  // The string half on its own: carriers go, identifiers stay (an access key id, an ARN, a GuardDuty detector id among them).
  assertCarrierTextScrub(assert, redactCarrierText, { label: "aws.redactCarrierText" });
  for (const { label, id } of SERVER_ASSIGNED_HEX_IDS) {
    assert.equal(redactCarrierText(`detector ${id} read`), `detector ${id} read`, `a snapshot keeps a ${label} whole`);
  }

  // End to end. An unknown output member is dropped by the SDK's typed deserializer and cannot arrive, so the tree
  // travels inside the two policy documents the code parses (iam:GetPolicyVersion Document, URL-encoded, and
  // s3:GetBucketPolicy Policy) as a statement whose Sid carries the bearer and whose Condition carries the quoted
  // name-shaped bearer and the tree. Statements are normalized to derived facts and never echoed, so no bundle
  // file, zip entry, or tool payload carries a trace of it.
  const healthy = healthySdkRoutes();
  const planted = { iam: 0, s3: 0 };
  const routes = {
    ...healthy,
    "iam:GetPolicyVersion": async (...args) => {
      const output = await healthy["iam:GetPolicyVersion"](...args);
      planted.iam += 1;
      return { ...output, PolicyVersion: { ...output.PolicyVersion, Document: plantDeepProbeInPolicyDocument(output.PolicyVersion.Document, { encoded: true }) } };
    },
    "s3:GetBucketPolicy": async (...args) => {
      const output = await healthy["s3:GetBucketPolicy"](...args);
      planted.s3 += 1;
      return { ...output, Policy: plantDeepProbeInPolicyDocument(output.Policy) };
    },
  };
  // Fixture self-check: both planted documents carry the canaries and the tree as real statement strings.
  const iamDocument = decodeURIComponent((await routes["iam:GetPolicyVersion"]({}, "us-east-1")).PolicyVersion.Document);
  const s3Document = (await routes["s3:GetBucketPolicy"]({}, "us-east-1")).Policy;
  for (const [name, text] of [["iam:GetPolicyVersion Document", iamDocument], ["s3:GetBucketPolicy Policy", s3Document]]) {
    assert.ok(text.includes(DEPTH_CONTROL.carrierCanary) && text.includes(DEPTH_CONTROL.keyedCanary) && text.includes("benign-note-40"), `${name} carries both canaries and the whole tree`);
    assert.ok(JSON.parse(text).Statement.some((statement) => statement.Sid === `Authorization: Bearer ${DEPTH_CONTROL.carrierCanary}`), `${name} carries the bearer in a Sid`);
  }
  planted.iam = 0;
  planted.s3 = 0;

  const log = [];
  const { outputs, exported } = await withSdkRoutes(routes, log, async () => {
    const client = realAwsClient();
    const results = await runAllAssessments(client);
    return { outputs: results, exported: await exportAwsAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-aws-depth-")) };
  });
  assert.ok(planted.iam > 0 && planted.s3 > 0, `both planted documents were read (${planted.iam} policy versions, ${planted.s3} bucket policies)`);
  assert.ok(log.every((entry) => entry.status === 200), "the planted documents cause no read to fail");
  assert.equal(exported.errorCount, 0, "the export records no failed read");
  assertDepthControlOutputs(
    assert,
    { files: readBundleFiles(exported.outputDir), zipEntries: readZipEntries(exported.zipPath), outputs: Object.values(outputs) },
    { label: "aws", treeExpected: false },
  );
  // The verdicts that read the documents still hold: the planted Deny statements grant nothing and the TLS-only deny stays.
  for (const [name, result] of Object.entries(outputs)) {
    if (name === "access") continue;
    for (const item of result.findings) assert.equal(item.status, "pass", `${item.id} still passes with the planted statements: ${item.summary}`);
  }
});

test("rule 9 credential-named pairs (reviewer D round 5 baseline): a value under a credential-named key is removed whatever its shape and length, unquoted as well as quoted, in every form the pair takes, while identifier-named keys keep their values unless the value's own shape removes it", () => {
  assertCredentialPairValuesRemoved(assert, redactErrorText);
  assertIdentifierKeyRows(assert, redactErrorText);
  assertFlagAndPathPairRows(assert, redactErrorText);
  // The retired value-shape test would have kept every one of these; the pair rule no longer asks.
  for (const [text, expected] of [
    ["password=letmein", "password=[REDACTED]"],
    ["DB_PASSWORD=Sunshine", "DB_PASSWORD=[REDACTED]"],
    ["AZURE_CLIENT_SECRET: abc12", "AZURE_CLIENT_SECRET: [REDACTED]"],
    ["DUO_SKEY=p@ss", "DUO_SKEY=[REDACTED]"],
    ["DUO_IKEY=DIXXXXXXXXXXXXXXXXXX", "DUO_IKEY=[REDACTED]"],
    ["DUO_IKEY=letmein", "DUO_IKEY=[REDACTED]"],
    ["ikey: monkey", "ikey: [REDACTED]"],
    ['{"DUO_IKEY":"Sunshine"}', '{"DUO_IKEY":"[REDACTED]"}'],
    ['"ikey": "abc12"', '"ikey": "[REDACTED]"'],
    ["Authorization: Basic letmein", "Authorization: Basic [REDACTED]"],
    ["token: value shape", "token: [REDACTED] shape"],
  ]) {
    assert.equal(redactErrorText(text), expected, `credential-named pair: ${text}`);
  }
  // A PascalCase error code that ends in a credential word is prose, and a bare scheme word is not a pair; a path segment
  // ending in a credential word is one (assertFlagAndPathPairRows).
  for (const text of [
    "InvalidAuthenticationToken: Access token has expired. Basic authentication is disabled for this tenant.",
    "ExpiredToken: The security token included in the request is expired",
    "sent as Authorization: Bearer) or as X-Auth-Key",
    "oauth: invalid_grant was returned",
  ]) {
    assert.equal(redactErrorText(text), text, `prose beside a credential word survives: ${text}`);
  }
});

test("rule 9 bearer-id override (CodeRabbit r4077259415 on #78): a key ending in secret_id or naming a session id is a credential key despite its id suffix, so a Vault AppRole secret id goes whatever its shape, a UUID included, through the error sink, the data-string sink, the snapshot walker, and the thrown error, while AZURE_TENANT_ID=<uuid> and the other identifier keys keep their values", async () => {
  assertBearerIdKeyRows(assert, redactErrorText);
  assertBearerIdKeyRows(assert, redactCarrierText, { controls: BEARER_ID_CARRIER_CONTROL_ROWS });
  assertBearerIdSnapshotKeys(assert, scrubSnapshotValue);
  const [uuid, random] = BEARER_ID_VALUES;
  const tenant = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
  const echoed = `VAULT_SECRET_ID=${uuid} and role_secret_id: ${random} were rejected; AZURE_TENANT_ID=${tenant} was accepted`;
  const expected = `VAULT_SECRET_ID=[REDACTED] and role_secret_id: [REDACTED] were rejected; AZURE_TENANT_ID=${tenant} was accepted`;
  const thrown = new AwsApiError({ name: "AccessDeniedException", message: echoed, $metadata: { httpStatusCode: 403 } });
  assert.equal(thrown.message, `AccessDeniedException (HTTP 403): ${expected}`);
  assertNoCanaryWindows(assert, thrown.message, [uuid, random], "AwsApiError message");
});

test("rule 9: redactErrorText scrubs authorization values, JWTs, AWS key ids and secrets, cookie and api key pairs, and URL userinfo and query strings anywhere in the text", () => {
  assertRedactionCases(assert, redactErrorText);

  // The AWS-specific shapes: an SDK message that echoes the signing identity, request context, and a
  // proxy header block, with the cookie header on its own line as HTTP writes it.
  const basic = Buffer.from(`auditor:${AWS_MUST_KEEP_CANARIES.basicPassword}`).toString("base64");
  const text = [
    `Authorization: Bearer ${AWS_CANARIES.bearer} was rejected; Basic ${basic} also failed. Token ${CANARY.jwt} expired.`,
    `Signed with ${AWS_CANARIES.accessKeyId} and ${AWS_CANARIES.secretKey}; x-api-key: ${AWS_CANARIES.apiKey}; session_id=${AWS_CANARIES.session}.`,
    `Retry at ${CANARY_URL} or https://auditor:${AWS_MUST_KEEP_CANARIES.userinfoPassword}@api.example.com/v1/y?sig=${AWS_MUST_KEEP_CANARIES.signature} later.`,
    `Set-Cookie: AWSALB=${AWS_CANARIES.session}; Path=/`,
  ].join("\n");

  const scrubbed = redactErrorText(text);
  assertNoCanaries(scrubbed, "redactErrorText");
  assertNoCanaryWindows(assert, scrubbed, [basic], "redactErrorText Basic value");
  assert.match(scrubbed, /Bearer \[REDACTED\] was rejected/);
  assert.match(scrubbed, /Basic \[REDACTED\] also failed/);
  assert.match(scrubbed, /Signed with \[REDACTED\] and \[REDACTED\]; x-api-key: \[REDACTED\]; session_id=\[REDACTED\]/, "AWS key ids, secrets, api key and session pairs are replaced in place");
  assert.match(scrubbed, /https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\] or/, "the URL host and path survive while the query is replaced");
  assert.match(scrubbed, /https:\/\/api\.example\.com\/v1\/y\?\[REDACTED\] later\./, "URL userinfo is dropped and the query replaced even mid-sentence");
  assert.match(scrubbed, /Set-Cookie: \[REDACTED\]$/, "the cookie header keeps its name and loses its whole value");
  assert.equal(redactErrorText("Basic authentication is required; Invalid token."), "Basic authentication is required; Invalid token.", "prose after a scheme word or credential noun is left alone");
});

test("fixture self-check: every planted canary is alphanumeric and random-looking, and no 6-to-24-character window of any canary occurs in the healthy fixture's legitimate values, so a windowed leak assertion can fail only on a real echo", async () => {
  const legitimate = new Map();
  for (const [action, route] of Object.entries(healthySdkRoutes())) {
    try {
      legitimate.set(`route ${action}`, await route({}, "us-east-1"));
    } catch {
      // A route that needs a real input is exercised by the healthy run below.
    }
  }
  const { outputs, exported } = await withSdkRoutes(healthySdkRoutes(), [], async () => {
    const client = realAwsClient();
    const results = await runAllAssessments(client);
    return { outputs: results, exported: await exportAwsAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-aws-self-check-")) };
  });
  for (const [name, result] of Object.entries(outputs)) legitimate.set(name, result);
  for (const [name, text] of readBundleFiles(exported.outputDir)) legitimate.set(`bundle ${name}`, text);
  for (const [name, text] of readZipEntries(exported.zipPath)) legitimate.set(`zip ${name}`, text);
  legitimate.set("config", realAwsConfig());
  legitimate.set("shared config fixture lines", ["[audit]", "aws_access_key_id = AKIAEXAMPLE000000001", "credential_source = Environment"]);
  // The contact phone's digits are the shortest canary (seven digits behind the dialing prefix).
  assertCanaryFixture(assert, AWS_PLANTED_CANARIES, legitimate, "aws fixture", { minLength: 7 });
});

test("rule 9: a 502 HTML proxy body on any surface never carries credentials into the access check, assess results, bundle files, or zip entries, and the error string carries the status-and-length note", async () => {
  const noteText = `non-JSON body (text/html, ${Buffer.byteLength(proxyHtmlError().$responseBodyText, "utf8")} bytes)`;
  const errorLine = /SyntaxError \(HTTP 502\): non-JSON body \(text\/html, \d+ bytes\)/;

  for (const action of SECONDARY_ACTIONS) {
    const routes = { ...healthySdkRoutes(), [action]: () => { throw proxyHtmlError(); } };
    const log = [];
    const { outputs, exported } = await withSdkRoutes(routes, log, async () => {
      const client = realAwsClient();
      const results = await runAllAssessments(client);
      return { outputs: results, exported: await exportAwsAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-aws-canary-")) };
    });
    assert.ok(log.some((entry) => entry.action === action && entry.status === 502), `${action}: the fixture served the 502 body`);

    const files = readBundleFiles(exported.outputDir);
    const entries = readZipEntries(exported.zipPath);
    assertNoCanaries(JSON.stringify(outputs), `${action}: assess and check_access results`);
    for (const [name, text] of files) assertNoCanaries(text, `${action}: bundle file ${name}`);
    for (const [name, text] of entries) assertNoCanaries(text, `${action}: zip entry ${name}`);

    const recorded = [
      ...Object.values(outputs).flatMap((result) => result.errors ?? []),
      ...(files.get("_errors.log") ?? "").split("\n"),
      ...outputs.access.surfaces.map((surface) => surface.error ?? ""),
    ].filter((line) => line.includes(action.split(":")[1]) && /502/.test(line));
    assert.ok(recorded.length > 0, `${action}: the failure is recorded against the command that failed`);
    for (const line of recorded) {
      assert.match(line, errorLine, `${action}: the error string describes the body by type and length only: ${line}`);
      assert.ok(line.includes(noteText), `${action}: the note carries the byte length of the body: ${line}`);
      assert.ok(!/<html|DOCTYPE|Unexpected token/i.test(line), `${action}: no slice of the HTML body or parser message survives: ${line}`);
    }
  }
});

test("rule 9: an SDK error whose message echoes a URL with a token query and AWS key-shaped values is scrubbed on every surface, keeping the code, status, and host", async () => {
  for (const action of SECONDARY_ACTIONS) {
    const routes = { ...healthySdkRoutes(), [action]: () => { throw contextLeakingDeniedError(); } };
    const { outputs, exported } = await withSdkRoutes(routes, [], async () => {
      const client = realAwsClient();
      const results = await runAllAssessments(client);
      return { outputs: results, exported: await exportAwsAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-aws-canary-json-")) };
    });

    const files = readBundleFiles(exported.outputDir);
    assertNoCanaries(JSON.stringify(outputs), `${action}: assess and check_access results`);
    for (const [name, text] of files) assertNoCanaries(text, `${action}: bundle file ${name}`);
    for (const [name, text] of readZipEntries(exported.zipPath)) assertNoCanaries(text, `${action}: zip entry ${name}`);

    const lines = Object.values(outputs).flatMap((result) => result.errors ?? []).filter((line) => line.startsWith(action));
    const probe = outputs.access.surfaces.find((surface) => surface.command === action);
    if (probe) lines.push(probe.error);
    assert.ok(lines.length > 0, `${action}: the denial is recorded against the command that failed`);
    for (const line of lines) {
      assert.match(line, /AccessDeniedException \(HTTP 403\)/, `${action}: the SDK code and HTTP status are kept: ${line}`);
      assert.match(line, /https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\]/, `${action}: the URL host survives with its query replaced: ${line}`);
      assert.ok(!/AKIA[A-Z0-9]{16}/.test(line), `${action}: no access key id survives: ${line}`);
    }
  }
});

test("rule 9: the aws_check_access tool scrubs the failure of the run's own identity read, which is the one primary that fails the check outright", async () => {
  const { registerAwsTools } = await import("../dist/extensions/grc-tools/aws.js");
  const registered = [];
  registerAwsTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccess = registered.find((tool) => tool.name === "aws_check_access");
  assert.ok(checkAccess, "aws_check_access is registered");

  for (const [label, makeError] of [["502 HTML body", proxyHtmlError], ["context-echoing denial", contextLeakingDeniedError]]) {
    const routes = { ...healthySdkRoutes(), "sts:GetCallerIdentity": () => { throw makeError(); } };
    const result = await withSdkRoutes(routes, [], () => checkAccess.execute("call-1", { region: "us-east-1", account_id: FIXTURE_ACCOUNT }));
    const text = JSON.stringify(result);
    assertNoCanaries(text, `aws_check_access with ${label}`);
    assert.match(text, /AWS access check failed: /);
    if (makeError === proxyHtmlError) assert.match(text, /SyntaxError \(HTTP 502\): non-JSON body \(text\/html, \d+ bytes\)/);
    else assert.match(text, /AccessDeniedException \(HTTP 403\)/);
  }
});

/**
 * Runs `run` with AWS_SHARED_CREDENTIALS_FILE and AWS_CONFIG_FILE pointed at fixtures, restoring the environment
 * afterwards. `files.credentials` is either the file's text or a function that prepares the path itself (a
 * directory, an unreadable file) and returns it.
 */
let sharedAwsFixtureSequence = 0;

/**
 * A fresh directory whose path is name-shaped (letters, hyphens, and one number per segment), so the scrub
 * boundary's long-token rule leaves it in the provider error that names the two documented files; mkdtemp's
 * random suffix is token-shaped often enough to be redacted, which is correct for a real path of that shape
 * but would make the "names the files" assertion depend on the draw.
 */
function createNameShapedFixtureDir() {
  sharedAwsFixtureSequence += 1;
  const dir = join(tmpdir(), "grclanker-aws-creds-fixture", `${process.pid}-${sharedAwsFixtureSequence}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

async function withSharedAwsFiles(files, run) {
  const dir = createNameShapedFixtureDir();
  const configFile = join(dir, "config");
  writeFileSync(configFile, files.config ?? "");
  let credentialsFile = join(dir, "credentials");
  if (typeof files.credentials === "function") credentialsFile = files.credentials(dir);
  else writeFileSync(credentialsFile, files.credentials);
  const previous = { AWS_SHARED_CREDENTIALS_FILE: process.env.AWS_SHARED_CREDENTIALS_FILE, AWS_CONFIG_FILE: process.env.AWS_CONFIG_FILE, AWS_PROFILE: process.env.AWS_PROFILE };
  process.env.AWS_SHARED_CREDENTIALS_FILE = credentialsFile;
  process.env.AWS_CONFIG_FILE = configFile;
  delete process.env.AWS_PROFILE;
  try {
    return await run({ credentialsFile, configFile });
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

const SDK_ERROR_NAME_OR_FS_CODE = /^(?:[A-Za-z]+(?:Error|Exception)(?: E[A-Z]+)?|E[A-Z]+)$/;
/** Node's fs wording ("EISDIR: illegal operation on a directory, read", "EACCES: permission denied, open '<path>'"). */
const FS_WORDING = /illegal operation|permission denied|no such file|operation not permitted|, open '|, read$|, read /i;
/** The SDK's own provider messages, which quote profile names and file values. */
const SDK_PROVIDER_WORDING = /Could not resolve credentials|configuration\/credentials file|Unsupported credential source|invalid SSO credentials|Profile .* could not be found/;

/** Every path-like token of a message; the only ones allowed are the two documented files. */
function pathsNamedIn(text) {
  return [...text.matchAll(/(?:~|\/)[\w.~/-]*[\w~/-]/g)].map((match) => match[0]);
}

function assertProviderErrorShape(error, { credentialsFile, configFile }, label) {
  assert.ok(error instanceof AwsCredentialProviderError, `${label}: the provider failure is wrapped: ${error?.name}: ${error?.message}`);
  assert.equal(error.name, "AwsCredentialProviderError", label);
  assert.equal(error.provider, "fromIni (profile audit)", label);
  assert.match(error.code, SDK_ERROR_NAME_OR_FS_CODE, `${label}: the code is an SDK error name or an fs code: ${error.code}`);
  assertNoCanaryWindows(assert, error.message, [SHARED_CONFIG_CANARY], `${label}: the thrown message`);
  assert.doesNotMatch(error.message, FS_WORDING, `${label}: fs wording reached the thrown message: ${error.message}`);
  assert.doesNotMatch(error.message, SDK_PROVIDER_WORDING, `${label}: the provider's own message was interpolated: ${error.message}`);
  assert.match(error.message, new RegExp(`^credentials could not be resolved by fromIni \\(profile audit\\) \\(${error.code.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\)\\. The provider's message is not recorded`), label);
  assert.ok(error.message.includes(credentialsFile) && error.message.includes(configFile), `${label}: the message names the files to check: ${error.message}`);
  for (const named of pathsNamedIn(error.message)) {
    assert.ok(named === credentialsFile || named === configFile, `${label}: a path other than the two documented files is named: ${named}`);
  }
}

/** The shared-config failure shapes; each names the fs positive control or whether the SDK's own message echoes file text. */
const SHARED_CONFIG_CASES = [
  {
    name: "malformed lines carrying the canary",
    credentials: ["[audit]", "aws_access_key_id = AKIAEXAMPLE000000001", `aws_secret_access_key ${SHARED_CONFIG_CANARY}`, `[${SHARED_CONFIG_CANARY}`, ""].join("\n"),
    config: ["[profile audit]", "region = us-east-1", `output ${SHARED_CONFIG_CANARY}`, ""].join("\n"),
    sdkEchoesCanary: false,
  },
  {
    // Positive control: the installed SDK quotes an unsupported credential_source value verbatim, so this is the
    // shape that proves the wrapper, not the SDK, is what keeps the file's text out of the thrown error.
    name: "unsupported credential_source value (the SDK echoes it)",
    credentials: ["[audit]", "role_arn = arn:aws:iam::123456789012:role/audit", `credential_source = ${SHARED_CONFIG_CANARY}`, ""].join("\n"),
    sdkEchoesCanary: true,
  },
  {
    name: "source_profile naming a missing profile (the SDK echoes it)",
    credentials: ["[audit]", "role_arn = arn:aws:iam::123456789012:role/audit", `source_profile = ${SHARED_CONFIG_CANARY}`, ""].join("\n"),
    sdkEchoesCanary: true,
  },
  {
    name: "incomplete SSO profile whose extra key carries the canary (the SDK echoes the keys)",
    credentials: ["[audit]", "sso_start_url = https://example.awsapps.com/start", `${SHARED_CONFIG_CANARY}_key = 1`, ""].join("\n"),
    sdkEchoesCanary: true,
  },
  {
    name: "EISDIR: AWS_SHARED_CREDENTIALS_FILE is a directory",
    credentials: (dir) => {
      const target = join(dir, "credentials.d");
      mkdirSync(target);
      return target;
    },
    fsCode: "EISDIR",
    sdkEchoesCanary: false,
  },
  {
    name: "EACCES: AWS_SHARED_CREDENTIALS_FILE is a mode 000 file",
    credentials: (dir) => {
      const target = join(dir, "credentials");
      writeFileSync(target, ["[audit]", "aws_access_key_id = AKIAEXAMPLE000000001", `aws_secret_access_key = ${SHARED_CONFIG_CANARY}`, ""].join("\n"));
      chmodSync(target, 0o000);
      return target;
    },
    fsCode: "EACCES",
    skip: process.getuid?.() === 0 ? "root reads a mode 000 file" : undefined,
    sdkEchoesCanary: false,
  },
];

for (const shape of SHARED_CONFIG_CASES) {
  test(`config loader errors: ${shape.name}: the thrown client error and the tool payloads name only the provider, an SDK error name or fs code, and the two documented files`, { skip: shape.skip }, async () => {
    const { registerAwsTools } = await import("../dist/extensions/grc-tools/aws.js");
    const { fromIni } = await import("@aws-sdk/credential-providers");

    await withSharedAwsFiles(shape, async (files) => {
      const { credentialsFile } = files;
      // Positive controls: the fixture really is the failure it claims to be.
      if (shape.fsCode) assert.throws(() => readFileSync(credentialsFile), { code: shape.fsCode }, `reading the fixture fails with ${shape.fsCode}`);
      const sdkMessage = await fromIni({ profile: "audit", ignoreCache: true })().then(() => assert.fail("the SDK resolved credentials from the fixture"), (error) => `${error.name}: ${error.message}`);
      assert.equal(sdkMessage.includes(SHARED_CONFIG_CANARY), shape.sdkEchoesCanary, `the SDK's own message ${shape.sdkEchoesCanary ? "carries" : "does not carry"} the canary: ${sdkMessage}`);

      // The real send(): the provider chain fails while resolving credentials, before any request is signed or sent.
      const client = realAwsClient(realAwsConfig({ profile: "audit" }));
      await assert.rejects(() => client.getCallerIdentity(), (error) => {
        assertProviderErrorShape(error, files, "thrown client error");
        return true;
      });

      const registered = [];
      registerAwsTools({ registerTool: (tool) => registered.push(tool) });
      for (const name of ["aws_check_access", "aws_assess_identity", "aws_export_audit_bundle"]) {
        const tool = registered.find((candidate) => candidate.name === name);
        const payload = await tool.execute("call-1", { region: "us-east-1", profile: "audit", account_id: FIXTURE_ACCOUNT, output_dir: createTempBase("grclanker-aws-creds-export-") });
        const text = JSON.stringify(payload);
        assertNoCanaryWindows(assert, text, [SHARED_CONFIG_CANARY], `${name}: the tool payload`);
        assert.doesNotMatch(text, FS_WORDING, `${name}: fs wording reached the tool payload: ${text}`);
        assert.doesNotMatch(text, SDK_PROVIDER_WORDING, `${name}: the provider's own message is interpolated: ${text}`);
        assert.match(text, /AwsCredentialProviderError: credentials could not be resolved by fromIni \(profile audit\) \((?:[A-Za-z]+(?:Error|Exception)(?: E[A-Z]+)?|E[A-Z]+)\)\. The provider's message is not recorded/, `${name}: the payload names the provider and the SDK error name or fs code only: ${text}`);
        // The error sentence names the two documented files and nothing else (the payload may name its own output_dir).
        const sentence = text.match(/AwsCredentialProviderError: credentials could not be resolved[^"]*/)?.[0] ?? "";
        assert.ok(sentence.includes(credentialsFile) && sentence.includes(files.configFile), `${name}: the payload names the files to check: ${sentence}`);
        for (const named of pathsNamedIn(sentence)) {
          assert.ok(named === credentialsFile || named === files.configFile, `${name}: a path other than the two documented files is named: ${named}`);
        }
      }
    });
  });
}


test("config loader errors: a SyntaxError the SDK raises without attaching the body is recorded by name only, never by the parser's message that quotes the text", async () => {
  const snippet = parserSnippetBody();
  const bareParseError = () => new SyntaxError(`Unexpected token '<', "${snippet}"... is not valid JSON`);
  const { registerAwsTools } = await import("../dist/extensions/grc-tools/aws.js");
  const registered = [];
  registerAwsTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccess = registered.find((tool) => tool.name === "aws_check_access");

  const identityResult = await withSdkRoutes({ ...healthySdkRoutes(), "sts:GetCallerIdentity": () => { throw bareParseError(); } }, [], () => checkAccess.execute("call-1", { region: "us-east-1" }));
  const identityText = JSON.stringify(identityResult);
  assertNoCanaryWindows(assert, identityText, [PARSER_SNIPPET_CANARY], "aws_check_access payload");
  assert.doesNotMatch(identityText, PARSER_WORDING, `the parser's message reached the tool payload: ${identityText}`);
  assert.match(identityText, /AWS access check failed: SyntaxError: response could not be parsed as the service protocol; the parser's message is not recorded/);

  for (const action of ["iam:ListUsers", "cloudtrail:DescribeTrails", "s3:GetBucketPolicy"]) {
    const routes = { ...healthySdkRoutes(), [action]: () => { throw bareParseError(); } };
    const { outputs, exported } = await withSdkRoutes(routes, [], async () => {
      const client = realAwsClient();
      const results = await runAllAssessments(client);
      return { outputs: results, exported: await exportAwsAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-aws-parse-error-")) };
    });
    const text = [JSON.stringify(outputs), ...readBundleFiles(exported.outputDir).values(), ...readZipEntries(exported.zipPath).values()].join("\n");
    assertNoCanaryWindows(assert, text, [PARSER_SNIPPET_CANARY], `${action}: outputs and bundle`);
    assert.doesNotMatch(text, PARSER_WORDING, `${action}: a slice of the parser's message survived`);
    const lines = [...Object.values(outputs).flatMap((result) => result.errors ?? []), ...outputs.access.surfaces.map((surface) => surface.error ?? "")].filter((line) => line.includes(action.split(":")[1]));
    assert.ok(lines.length > 0, `${action}: the failure is recorded against the command`);
    for (const line of lines) assert.match(line, /SyntaxError: response could not be parsed as the service protocol; the parser's message is not recorded because it quotes the body/, `${action}: ${line}`);
  }
});

test("denied-list markers: a failed probe or inventory keeps count and flags null and names the command, region, code, and status, and every dependent summary leaf renders null, per command and per failure mode", async () => {
  const healthy = await withSdkRoutes(healthySdkRoutes(), [], () => runAllAssessments(realAwsClient()));
  assert.equal(healthy.access.status, "healthy");
  assert.equal(healthy.access.surfaces.length, 15);
  for (const surface of healthy.access.surfaces) {
    assert.equal(typeof surface.count, "number", `${surface.name}: a completed probe carries a numeric count`);
    assert.equal(surface.region, "us-east-1");
  }

  const modes = [
    ["denied", sdkAccessDenied, { code: "AccessDeniedException", status: 403 }],
    ["throttled", sdkThrottled, { code: "ThrottlingException", status: 400 }],
    ["unavailable", sdkServiceUnavailable, { code: "ServiceUnavailableException", status: 503 }],
    ["timeout", sdkTimeout, { code: "TimeoutError", status: null }],
  ];
  for (const [mode, makeError, expected] of modes) {
    for (const action of SECONDARY_ACTIONS) {
      const label = `${action} ${mode}`;
      const routes = { ...healthySdkRoutes(), [action]: () => { throw makeError(); } };
      const degraded = await withSdkRoutes(routes, [], () => runAllAssessments(realAwsClient()));
      assertNoDefaultedLeaves(healthy, degraded, label);

      const probeName = ACCESS_PROBES[action];
      if (probeName) {
        const probe = degraded.access.surfaces.find((surface) => surface.name === probeName);
        assert.equal(degraded.access.status, "limited", `${label}: a failed probe makes the check limited`);
        assert.deepEqual(
          { status: probe.status, count: probe.count, truncated: probe.truncated, command: probe.command, region: probe.region, error_code: probe.error_code, http_status: probe.http_status },
          { status: "not_readable", count: null, truncated: null, command: action, region: "us-east-1", error_code: expected.code, http_status: expected.status },
          `${label}: the probe row names what failed and what the service answered, with no count`,
        );
        assert.match(probe.error, new RegExp(expected.code), `${label}: the probe error carries the SDK code`);
      } else {
        assert.equal(degraded.access.status, "healthy", `${label}: a command the access check does not probe leaves the check healthy`);
      }

      for (const [file, fields] of Object.entries(DEPENDENT_SUMMARY_LEAVES[action] ?? {})) {
        for (const field of fields) {
          assert.equal(degraded[file].summary[field], null, `${label}: ${file} summary.${field} renders null, saw ${JSON.stringify(degraded[file].summary[field])}`);
          assert.notEqual(healthy[file].summary[field], null, `${label}: ${file} summary.${field} is populated on the healthy fixture`);
        }
      }
    }
  }
});

test("denied-list markers: the exported bundle writes null probe counts with the observed code and status, records the command in _errors.log, and never writes a defaulted dependent leaf", async () => {
  for (const [action, probeName] of Object.entries(ACCESS_PROBES)) {
    const routes = { ...healthySdkRoutes(), [action]: () => { throw sdkAccessDenied(); } };
    const exported = await withSdkRoutes(routes, [], async () => {
      const client = realAwsClient();
      return exportAwsAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-aws-markers-"));
    });
    const files = readBundleFiles(exported.outputDir);
    const access = JSON.parse(files.get("core_data/access.json"));
    const probe = access.surfaces.find((surface) => surface.name === probeName);
    assert.deepEqual(
      { status: probe.status, count: probe.count, truncated: probe.truncated, command: probe.command, region: probe.region, error_code: probe.error_code, http_status: probe.http_status },
      { status: "not_readable", count: null, truncated: null, command: action, region: "us-east-1", error_code: "AccessDeniedException", http_status: 403 },
      `${action}: core_data/access.json carries the marker shape`,
    );
    assert.equal(access.status, "limited");
    assert.match(files.get("_errors.log") ?? "", new RegExp(`^${action.replace(/[-/]/g, "\\$&")}.*AccessDenied \\(AccessDeniedException \\(HTTP 403\\)`, "m"), `${action}: _errors.log names the command and the observed code and status`);

    for (const [file, fields] of Object.entries(DEPENDENT_SUMMARY_LEAVES[action] ?? {})) {
      const analysis = JSON.parse(files.get(`analysis/${file}.json`));
      for (const field of fields) assert.equal(analysis.summary[field], null, `${action}: analysis/${file}.json summary.${field} renders null`);
    }
  }
});

test("rule 1 corollary: AWS-DATA-11 renders null, a marker, and no uncovered bucket when the account-level block read is denied, while a readable NoSuchPublicAccessBlockConfiguration still fails", async () => {
  const denied = await withSdkRoutes({ ...healthySdkRoutes(), "s3control:GetPublicAccessBlock": () => { throw sdkAccessDenied(); } }, [], () => assessAwsDataProtection(realAwsClient()));
  const finding = findingById(denied, "AWS-DATA-11");
  assert.equal(finding.status, "manual");
  assert.match(finding.summary, /Account-level S3 Block Public Access could not be read \(s3control:GetPublicAccessBlock: AccessDenied \(AccessDeniedException \(HTTP 403\)/);
  assert.match(finding.summary, /whether the account block covers them is unknown/);
  assert.equal(finding.evidence.account_block_readable, false);
  assert.equal(finding.evidence.account_block_configured, null, "an unread account block is neither configured nor unconfigured");
  assert.deepEqual(
    { collected: finding.evidence.account_flags.collected, command: finding.evidence.account_flags.command, error_code: finding.evidence.account_flags.error_code, http_status: finding.evidence.account_flags.http_status },
    { collected: false, command: "s3control:GetPublicAccessBlock", error_code: "AccessDeniedException", http_status: 403 },
    "the flags render as a not-collected marker, not {}",
  );
  assert.equal(finding.evidence.buckets_without_full_block, null, "no bucket is listed as uncovered when the account read failed");
  assert.deepEqual(finding.evidence.buckets_without_bucket_level_block, [], "the bucket-level facts that were read are still reported");
  assert.equal(denied.summary.buckets_without_full_block, null);

  const unset = await withSdkRoutes({ ...healthySdkRoutes(), "s3control:GetPublicAccessBlock": () => { throw sdkAccessDenied("NoSuchPublicAccessBlockConfiguration", 404); } }, [], () => assessAwsDataProtection(realAwsClient()));
  const unsetFinding = findingById(unset, "AWS-DATA-11");
  assert.equal(unsetFinding.status, "fail", "a readable NoSuchPublicAccessBlockConfiguration is a fact about the account block, so the control fails on evidence");
  assert.match(unsetFinding.summary, /^Account-level S3 Block Public Access is not configured \(S3 Control returned NoSuchPublicAccessBlockConfiguration\); 0\/1 buckets lack a full bucket-level block/);
  assert.equal(unsetFinding.evidence.account_block_readable, true, "a NoSuchPublicAccessBlockConfiguration answer is a completed read");
  assert.equal(unsetFinding.evidence.account_block_configured, false);
  assert.equal(unsetFinding.evidence.account_flags.collected, undefined, "a completed read is not a not-collected marker");
  assert.ok(Object.values(unsetFinding.evidence.account_flags).every((flag) => flag === undefined), "no flag is set when the configuration is absent");
  assert.deepEqual(unsetFinding.evidence.buckets_without_full_block, [], "the coverage list is a real empty list here: every bucket carries its own full block");
  assert.equal(unset.summary.buckets_without_full_block, 0);
});

function recordedActions(log) {
  return new Set(log.map((entry) => entry.action));
}

/** IAM actions named anywhere in the outputs; aws:* condition keys are policy vocabulary, not requests. */
function namedActions(text) {
  return new Set((text.match(/\b[a-z0-9-]+:[A-Z][A-Za-z]+\b/g) ?? []).filter((token) => !token.startsWith("aws:")));
}

function namedStatuses(text) {
  const statuses = new Set();
  for (const match of text.matchAll(/HTTP (\d{3})\b/g)) statuses.add(Number(match[1]));
  for (const match of text.matchAll(/"http_status": ?(\d{3})\b/g)) statuses.add(Number(match[1]));
  return statuses;
}

test("request matching: every IAM action and HTTP status named in any output corresponds to a request the run made and a response it observed", async () => {
  const log = [];
  const routes = {
    ...healthySdkRoutes(),
    "iam:ListAccessKeys": () => { throw sdkAccessDenied(); },
    "kms:ListKeys": () => { throw proxyHtmlError(); },
    "organizations:ListAccounts": () => { throw sdkServiceUnavailable(); },
    "ec2:DescribeFlowLogs": () => { throw sdkTimeout(); },
  };
  const { outputs, exported } = await withSdkRoutes(routes, log, async () => {
    const client = realAwsClient();
    const results = await runAllAssessments(client);
    return { outputs: results, exported: await exportAwsAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-aws-request-log-")) };
  });

  const observedStatuses = new Set(log.map((entry) => entry.status).filter((status) => status !== null));
  assert.ok(observedStatuses.has(403) && observedStatuses.has(502) && observedStatuses.has(503), "the fixture served every failure status under test");
  assert.ok(log.some((entry) => entry.action === "ec2:DescribeFlowLogs" && entry.status === null), "the timeout produced no status");

  const text = [JSON.stringify(outputs), ...readBundleFiles(exported.outputDir).values()].join("\n");
  const actions = namedActions(text);
  const statuses = namedStatuses(text);
  for (const action of [...Object.keys(ACCESS_PROBES), "iam:ListAccessKeys", "kms:ListKeys", "organizations:ListAccounts", "ec2:DescribeFlowLogs"]) {
    assert.ok(actions.has(action), `the outputs name ${action}: every probe carries its command and every failed read names the command that failed`);
  }
  assert.ok(statuses.has(403) && statuses.has(502) && statuses.has(503), "the outputs name the observed failure statuses");
  assert.ok(!statuses.has(200), "successful responses are not described as failures");
  const requested = recordedActions(log);
  for (const action of actions) {
    assert.ok(requested.has(action), `action ${action} is named in output but the run never issued it`);
  }
  for (const status of statuses) {
    assert.ok(observedStatuses.has(status), `status ${status} is named in output but no response carried it`);
  }
  for (const entry of log) {
    assert.equal(entry.region, "us-east-1", `${entry.action}: every request was sent to the configured region`);
  }
});

test("config loader errors: a 200 answer whose body is short non-JSON text is recorded as the non-JSON note only; no 6-to-24-character window of the body and no parser wording reaches the thrown client error, the access check, an assessment, or the bundle", async () => {
  // Positive control for the class: V8 quotes the whole source when it is 21 characters or shorter, and the SDK's error carries that message.
  assert.ok(SHORT_BODY_CANARY.length <= 21 && parserMessageFor(SHORT_BODY_CANARY).includes(SHORT_BODY_CANARY), "the parser's message carries the whole short body");
  assert.ok(shortBodyParseError(SHORT_BODY_CANARY).message.includes(SHORT_BODY_CANARY), "the SDK's own error message carries the whole short body");

  const action = "iam:ListUsers";
  const log = [];
  const routes = { ...healthySdkRoutes(), [action]: () => { throw shortBodyParseError(SHORT_BODY_CANARY, SHORT_BODY_CONTENT_TYPE); } };
  const note = `SyntaxError (HTTP 200): non-JSON body (${SHORT_BODY_CONTENT_TYPE}, 18 bytes)`;

  const { outputs, exported } = await withSdkRoutes(routes, log, async () => {
    const client = realAwsClient();
    // The thrown client error is fixed text: a scrub at the tool boundary would not protect a caller that logs it.
    await assert.rejects(() => client.listIamUsers(), (error) => {
      assert.equal(error.name, "AwsApiError", `the client rethrows the SDK error as fixed text: ${error.name}: ${error.message}`);
      assert.equal(error.code, "SyntaxError", "the SDK error name is kept as the code");
      assert.equal(error.httpStatus, 200, "the observed status is kept");
      assertShortBodyRecordedAsNote(assert, error.message, "thrown client error");
      assert.equal(error.message, note);
      assert.equal(isAwsAccessDenied(error), false);
      return true;
    });
    const results = await runAllAssessments(client);
    return { outputs: results, exported: await exportAwsAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-aws-short-body-")) };
  });

  assertShortBodyRecordedAsNote(assert, outputs.access, "check_access");
  const probe = outputs.access.surfaces.find((surface) => surface.name === "iam_users");
  assert.equal(probe.status, "not_readable");
  assert.equal(probe.error, note, "the probe records the note and the observed status only");
  assert.equal(probe.http_status, 200);
  assert.equal(probe.error_code, "SyntaxError");
  assertShortBodyRecordedAsNote(assert, outputs.identity, "identity assessment");
  for (const [name, result] of Object.entries(outputs)) assertNoShortBodyFragments(assert, result, `${name} result`);

  const files = readBundleFiles(exported.outputDir);
  for (const [name, text] of files) assertNoShortBodyFragments(assert, text, `bundle ${name}`);
  for (const [name, text] of readZipEntries(exported.zipPath)) assertNoShortBodyFragments(assert, text, `zip ${name}`);
  assertShortBodyRecordedAsNote(assert, files.get("_errors.log"), "_errors.log");
  assert.ok(log.some((entry) => entry.action === action && entry.status === 200 && entry.code === "SyntaxError"), "the 200 answer named in the note was observed");
});

// ---------------------------------------------------------------------------------------------------------------------
// Real SDK parser path. A local HTTP server answers every request the AWS SDK makes, so each response travels through
// the SDK's own deserializer (query XML for STS, IAM, and RDS; EC2 XML; restXml for S3; JSON 1.1 and restJson for the
// rest) before it reaches the client, the guard, and the assessments.
// ---------------------------------------------------------------------------------------------------------------------

/** Services whose protocol is JSON (1.1 or restJson), by SigV4 signing name; the rest answer in XML. */
const JSON_PROTOCOL_SERVICES = new Set(["cloudtrail", "securityhub", "organizations", "kms", "config", "guardduty", "access-analyzer", "sso", "auditmanager", "account"]);

/** REST-protocol requests carry no Action field; the method and path name the operation. */
const REST_ACTIONS = [
  ["guardduty", /^GET \/detector$/, "ListDetectors"],
  ["guardduty", /^GET \/detector\/[^/]+$/, "GetDetector"],
  ["securityhub", /^GET \/accounts$/, "DescribeHub"],
  ["securityhub", /^POST \/standards\/get$/, "GetEnabledStandards"],
  ["access-analyzer", /^GET \/analyzer$/, "ListAnalyzers"],
  ["access-analyzer", /^POST \/finding$/, "ListFindings"],
  ["auditmanager", /^GET \/assessments$/, "ListAssessments"],
  ["account", /^POST \/getAlternateContact$/, "GetAlternateContact"],
  ["s3control", /^GET \/v20180820\/configuration\/publicAccessBlock$/, "GetPublicAccessBlock"],
  ["s3", /^GET \/$/, "ListBuckets"],
];

/** S3 bucket subresources, named by the query key the SDK sends (virtual-hosted `<bucket>.localhost` or path-style). */
const S3_BUCKET_SUBRESOURCES = [
  ["publicAccessBlock", "GetPublicAccessBlock"],
  ["policyStatus", "GetBucketPolicyStatus"],
  ["encryption", "GetBucketEncryption"],
  ["policy", "GetBucketPolicy"],
];

/** The IAM-prefixed action label (iam:ListUsers) the integration records for one signed request. */
function describeSdkRequest(req, body) {
  const scope = /Credential=([^/]+)\/\d{8}\/[^/]+\/([^/]+)\/aws4_request/.exec(req.headers.authorization ?? "");
  const accessKeyId = scope?.[1];
  const signed = scope?.[2] ?? "unsigned";
  // S3 Control signs as s3; its account-scoped requests carry the account id header and a versioned path.
  const service = signed === "s3" && req.headers["x-amz-account-id"] ? "s3control" : signed;
  const [path, query = ""] = req.url.split("?");
  const hostBucket = /^(.+)\.localhost(?::\d+)?$/.exec(String(req.headers.host ?? ""))?.[1];
  const pathBucket = /^\/([^/]+)/.exec(path)?.[1];
  const bucket = service === "s3" ? hostBucket ?? (path !== "/" ? pathBucket : undefined) : undefined;
  const queryAction = /(?:^|&)Action=([A-Za-z]+)/.exec(body)?.[1];
  const target = req.headers["x-amz-target"] ? String(req.headers["x-amz-target"]).split(".").pop() : undefined;
  const subresource = bucket ? S3_BUCKET_SUBRESOURCES.find(([key]) => new RegExp(`(?:^|&)${key}(?:=|&|$)`).test(query))?.[1] : undefined;
  const rest = subresource ?? (bucket ? undefined : REST_ACTIONS.find(([restService, pattern]) => restService === service && pattern.test(`${req.method} ${path}`))?.[2]);
  const action = queryAction ?? target ?? rest ?? `${req.method} ${path}`;
  return { service, action, label: `${service}:${action}`, accessKeyId, bucket };
}

const escapeXml = (text) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** A genuine STS answer for the run's own identity, so the access check and the assessments get past their one primary. */
const STS_IDENTITY_RESPONSE = Object.freeze({
  status: 200,
  contentType: "text/xml",
  body: `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::${FIXTURE_ACCOUNT}:user/auditor</Arn><UserId>AIDAAUDITOR</UserId><Account>${FIXTURE_ACCOUNT}</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>req-sts-identity</RequestId></ResponseMetadata></GetCallerIdentityResponse>`,
});

/**
 * Runs `run` with the real AWS SDK sending every request to a local server that answers with respond(request). The
 * SDK reaches it through AWS_ENDPOINT_URL with static environment credentials and a single attempt per request;
 * `localhost` and its subdomains resolve to the server for the run (S3 Control prefixes the account id to the
 * endpoint host). Every request is logged as { service, action, label, status }.
 */
async function withLocalAwsEndpoint(respond, run) {
  const requests = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const described = describeSdkRequest(req, Buffer.concat(chunks).toString("utf8"));
      let response;
      try {
        response = respond(described);
      } catch (error) {
        // A fixture without an answer for this request must fail the test, not leave the SDK waiting on an open socket.
        response = { status: 599, contentType: "text/plain", body: `fixture error for ${described.label}: ${error.message}` };
      }
      requests.push({ ...described, status: response.status });
      const headers = { "content-length": String(Buffer.byteLength(response.body)) };
      if (response.contentType !== undefined) headers["content-type"] = response.contentType;
      res.writeHead(response.status, headers);
      res.end(response.body);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const env = {
    AWS_ENDPOINT_URL: `http://localhost:${server.address().port}`,
    AWS_MAX_ATTEMPTS: "1",
    AWS_RETRY_MODE: "standard",
    AWS_ACCESS_KEY_ID: "AKIALOCALENDPOINT001",
    AWS_SECRET_ACCESS_KEY: "local-endpoint-fixture-secret-access-key-2026",
    AWS_REGION: "us-east-1",
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_SHARED_CREDENTIALS_FILE: "/nonexistent/credentials",
    AWS_CONFIG_FILE: "/nonexistent/config",
  };
  const cleared = ["AWS_PROFILE", "AWS_SESSION_TOKEN"];
  const previous = Object.fromEntries([...Object.keys(env), ...cleared].map((key) => [key, process.env[key]]));
  for (const key of cleared) delete process.env[key];
  Object.assign(process.env, env);
  const originalLookup = dns.lookup;
  dns.lookup = function lookupLocalEndpoint(hostname, options, callback) {
    if (typeof options === "function") {
      callback = options;
      options = {};
    }
    if (hostname === "localhost" || hostname.endsWith(".localhost")) {
      return options?.all ? callback(null, [{ address: "127.0.0.1", family: 4 }]) : callback(null, "127.0.0.1", 4);
    }
    return originalLookup.call(dns, hostname, options, callback);
  };
  try {
    return await run({ requests });
  } finally {
    dns.lookup = originalLookup;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await new Promise((resolve) => server.close(resolve));
  }
}

/** Every reader the client exposes that takes no inventory-derived argument, one per SDK client and protocol. */
const LOCAL_AWS_METHODS = [
  ["getCallerIdentity", "sts", (client) => client.getCallerIdentity()],
  ["getAccountSummary", "iam", (client) => client.getAccountSummary()],
  ["listIamUsers", "iam", (client) => client.listIamUsers()],
  ["getPasswordPolicy", "iam", (client) => client.getPasswordPolicy()],
  ["getAccountAuthorizationDetails", "iam", (client) => client.getAccountAuthorizationDetails()],
  ["listCustomerManagedPolicies", "iam", (client) => client.listCustomerManagedPolicies()],
  ["describeTrails", "cloudtrail", (client) => client.describeTrails()],
  ["lookupRootEvents", "cloudtrail", (client) => client.lookupRootEvents("us-east-1", new Date("2026-01-01T00:00:00Z"), new Date("2026-04-01T00:00:00Z"))],
  ["describeSecurityHub", "securityhub", (client) => client.describeSecurityHub()],
  ["getEnabledSecurityHubStandards", "securityhub", (client) => client.getEnabledSecurityHubStandards()],
  ["describeConfigurationRecorders", "config", (client) => client.describeConfigurationRecorders()],
  ["describeConfigurationRecorderStatus", "config", (client) => client.describeConfigurationRecorderStatus()],
  ["listDetectors", "guardduty", (client) => client.listDetectors()],
  ["describeOrganization", "organizations", (client) => client.describeOrganization()],
  ["listAccounts", "organizations", (client) => client.listAccounts()],
  ["listScps", "organizations", (client) => client.listScps()],
  ["listAnalyzers", "access-analyzer", (client) => client.listAnalyzers()],
  ["listIdentityCenterInstances", "sso", (client) => client.listIdentityCenterInstances()],
  ["listActiveAuditManagerAssessments", "auditmanager", (client) => client.listActiveAuditManagerAssessments()],
  ["getSecurityAlternateContact", "account", (client) => client.getSecurityAlternateContact()],
  ["describeRegions", "ec2", (client) => client.describeRegions()],
  ["getEbsEncryptionByDefault", "ec2", (client) => client.getEbsEncryptionByDefault("us-east-1")],
  ["describeVpcs", "ec2", (client) => client.describeVpcs("us-east-1")],
  ["describeFlowLogs", "ec2", (client) => client.describeFlowLogs("us-east-1")],
  ["describeNetworkAcls", "ec2", (client) => client.describeNetworkAcls("us-east-1")],
  ["describeSecurityGroups", "ec2", (client) => client.describeSecurityGroups("us-east-1")],
  ["listBuckets", "s3", (client) => client.listBuckets()],
  ["getAccountPublicAccessBlock", "s3control", (client) => client.getAccountPublicAccessBlock(FIXTURE_ACCOUNT)],
  ["describeDbInstances", "rds", (client) => client.describeDbInstances("us-east-1")],
  ["listKmsKeys", "kms", (client) => client.listKmsKeys("us-east-1")],
];

/** Everything a caller that logs the thrown error would see: name, message, every own property (enumerable or not), and the stack. */
function thrownErrorRecord(error) {
  const own = Object.fromEntries(Object.getOwnPropertyNames(error).map((key) => [key, error[key] instanceof Object ? JSON.stringify(error[key]) : String(error[key])]));
  return JSON.stringify({ name: error.name, message: error.message, cause: String(error.cause), ...own });
}

/** Codes the local fixtures never serve; any of them in an output would be a condition the run invented. */
const UNSERVED_CONDITIONS = /\b(AccessDenied(?:Exception)?|NoSuchEntity(?:Exception)?|ResourceNotFoundException|InvalidAccessException|AWSOrganizationsNotInUseException|UnauthorizedOperation|AuthFailure|ThrottlingException|ServiceUnavailableException|NoSuchBucketPolicy|NoSuchPublicAccessBlockConfiguration)\b/;

async function runAwsTool(name, args) {
  const { registerAwsTools } = await import("../dist/extensions/grc-tools/aws.js");
  const registered = [];
  registerAwsTools({ registerTool: (tool) => registered.push(tool) });
  const tool = registered.find((item) => item.name === name);
  assert.ok(tool, `${name} is registered`);
  try {
    return JSON.stringify(await tool.execute("call-1", args));
  } catch (error) {
    return `threw ${thrownErrorRecord(error)}`;
  }
}

const SILENT_SUCCESS_SHAPES = {
  "200 text/html": { status: 200, contentType: "text/html; charset=utf-8", body: canaryHtmlBody() },
  "200 empty body": { status: 200, contentType: "text/xml", body: "" },
};

const INCOMPLETE_RESPONSE_NOTE = /^IncompleteResponse \(HTTP 200\): [A-Za-z]+ answered without its [A-Za-z/]+ member \(body: (?:text\/html, \d+ bytes|empty, 0 bytes)\)$/;
const HTML_PARSE_NOTE = /^SyntaxError \(HTTP 200\): non-JSON body \(text\/html, \d+ bytes\)$/;

for (const [shape, response] of Object.entries(SILENT_SUCCESS_SHAPES)) {
  test(`silent success: a ${shape} answer through the real SDK parser path is an unreadable surface on every command, recorded with the status and the body note, never read as a default`, async () => {
    const healthy = await withSdkRoutes(healthySdkRoutes(), [], () => runAllAssessments(realAwsClient()));
    let serveIdentity = false;
    await withLocalAwsEndpoint(
      ({ action }) => (serveIdentity && action === "GetCallerIdentity" ? STS_IDENTITY_RESPONSE : response),
      async ({ requests }) => {
        const client = realAwsClient();
        // Every reader, the run's own identity included, rejects with the fixed-text guard error.
        for (const [name, service, call] of LOCAL_AWS_METHODS) {
          await assert.rejects(() => call(client), (error) => {
            const record = thrownErrorRecord(error);
            assert.ok(error instanceof AwsApiError, `${name}: the client throws AwsApiError, not the SDK's error or a resolved default: ${record}`);
            assert.equal(error.httpStatus, 200, `${name}: the observed status is kept`);
            if (shape === "200 empty body" || !JSON_PROTOCOL_SERVICES.has(service)) {
              assert.equal(error.code, "IncompleteResponse", `${name}: an output the deserializer emptied is IncompleteResponse: ${error.message}`);
              assert.match(error.message, INCOMPLETE_RESPONSE_NOTE, name);
            } else {
              // A JSON-protocol deserializer rejects an HTML body outright; that path was already fixed text.
              assert.equal(error.code, "SyntaxError", `${name}: ${error.message}`);
              assert.match(error.message, HTML_PARSE_NOTE, name);
            }
            assert.deepEqual(
              Object.getOwnPropertyNames(error).filter((key) => !["stack", "message", "name", "code", "httpStatus", "$metadata"].includes(key)),
              [],
              `${name}: nothing that can hold body text is retained on the thrown error`,
            );
            assertNoCanaryWindows(assert, record, AWS_PLANTED_CANARIES, `${name} thrown error`);
            assert.doesNotMatch(record, PARSER_WORDING, `${name}: no parser wording`);
            return true;
          });
        }
        assert.ok(requests.length >= LOCAL_AWS_METHODS.length && requests.every((request) => request.status === 200), "every request was answered by the local server with 200");

        // With the run's own identity served, the access check, every assessment, and the export see the same 200 answers.
        serveIdentity = true;
        const outputs = await runAllAssessments(client);
        const exported = await exportAwsAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-aws-silent-success-"));

        const access = outputs.access;
        assert.equal(access.status, "limited");
        assert.equal(access.accountId, FIXTURE_ACCOUNT, "the served identity is read");
        for (const probe of access.surfaces) {
          assert.equal(probe.status, "not_readable", `${probe.name}: a 200 that carries nothing is not a readable surface`);
          assert.equal(probe.count, null, `${probe.name}: no count`);
          assert.equal(probe.truncated, null, `${probe.name}: no truncation state`);
          assert.equal(probe.http_status, 200, `${probe.name}: the observed status`);
          assert.ok(["IncompleteResponse", "SyntaxError"].includes(probe.error_code), `${probe.name}: ${probe.error_code}`);
          assert.ok(INCOMPLETE_RESPONSE_NOTE.test(probe.error) || HTML_PARSE_NOTE.test(probe.error), `${probe.name}: ${probe.error}`);
        }
        assert.ok(access.notes.includes(`0/${access.surfaces.length} AWS audit surfaces are readable.`), access.notes.join(" | "));

        for (const [name, result] of Object.entries(outputs)) {
          if (name === "access") continue;
          for (const finding of result.findings) {
            assert.equal(finding.status, "manual", `${name} ${finding.id}: a finding whose every read answered with nothing renders manual, never pass or fail: ${finding.summary}`);
          }
          assertNoDefaultedLeaves(healthy[name], result, `${name} under ${shape}`);
        }
        assertNoDefaultedLeaves(healthy.access, access, `access check under ${shape}`);

        const files = readBundleFiles(exported.outputDir);
        const text = [JSON.stringify(outputs), ...files.values()].join("\n");
        for (const fragment of ['"users": 0', '"user_inventory_truncated": false', '"security_hub_enabled": true', '"collection_errors": 0', "Root MFA enabled=false", '"status": "pass"', '"status": "fail"']) {
          assert.ok(!text.includes(fragment), `no output renders the default ${fragment}`);
        }
        assert.doesNotMatch(text, UNSERVED_CONDITIONS, "no output names a condition the fixture never served");
        assert.deepEqual([...namedStatuses(text)], [200], "the only status named anywhere is the one every response carried");
        const requested = new Set(requests.map((request) => request.label));
        for (const action of namedActions(text)) {
          assert.ok(requested.has(action), `action ${action} is named in output but the run never issued it (requested: ${[...requested].join(", ")})`);
        }
        assertNoCanaryWindows(assert, text, AWS_PLANTED_CANARIES, `outputs and bundle under ${shape}`);
        assert.doesNotMatch(text, PARSER_WORDING);
        for (const [name, entry] of readZipEntries(exported.zipPath)) assertNoCanaryWindows(assert, entry, AWS_PLANTED_CANARIES, `zip ${name}`);
        assert.match(files.get("_errors.log"), /IncompleteResponse \(HTTP 200\): [A-Za-z]+ answered without its/, "_errors.log records the guard's note");
        if (shape === "200 text/html") assert.match(files.get("_errors.log"), /SyntaxError \(HTTP 200\): non-JSON body \(text\/html, \d+ bytes\)/);
      },
    );
  });
}

test("silent success: the shape guard also holds behind a patched send, so a route that answers without the command's member is IncompleteResponse rather than an empty inventory", async () => {
  const log = [];
  const routes = { ...healthySdkRoutes(), "iam:ListUsers": () => ({}) };
  await withSdkRoutes(routes, log, async () => {
    const client = realAwsClient();
    await assert.rejects(() => client.listIamUsers(), (error) => {
      assert.ok(error instanceof AwsApiError);
      assert.equal(error.code, "IncompleteResponse");
      assert.equal(error.httpStatus, undefined, "a patched send carries no HTTP response, so no status is invented");
      assert.equal(error.message, "IncompleteResponse: ListUsers answered without its Users member (body: not observed)");
      return true;
    });
    const access = await checkAwsAccess(client);
    const probe = access.surfaces.find((surface) => surface.name === "iam_users");
    assert.equal(probe.status, "not_readable");
    assert.equal(probe.error_code, "IncompleteResponse");
    assert.equal(probe.http_status, null);
    assert.equal(probe.count, null);
    const identity = await assessAwsIdentity(client);
    assert.equal(identity.summary.users, null, "the user inventory renders null, not 0");
    assert.equal(findingById(identity, "AWS-IAM-02").status, "manual");
  });
});

test("silent success: the required-member table names every command the client sends and nothing else", () => {
  const source = readFileSync(new URL("../extensions/grc-tools/aws.ts", import.meta.url), "utf8");
  const aliases = new Map([...source.matchAll(/(\w+Command) as (\w+Command)/g)].map(([, original, alias]) => [alias, original]));
  const sent = new Set([...source.matchAll(/new (\w+Command)\(/g)].map(([, name]) => (aliases.get(name) ?? name).replace(/Command$/, "")));
  assert.deepEqual([...sent].filter((name) => !AWS_REQUIRED_OUTPUT_MEMBERS[name]), [], "every command the client sends has a required-member entry");
  assert.deepEqual(Object.keys(AWS_REQUIRED_OUTPUT_MEMBERS).filter((name) => !sent.has(name)), [], "no entry names a command the client does not send");
  const kinds = new Set(["list", "map", "structure", "string", "boolean", "policyDocument"]);
  for (const [name, members] of Object.entries(AWS_REQUIRED_OUTPUT_MEMBERS)) {
    const entries = Object.entries(members);
    assert.ok(entries.length > 0 && entries.every(([member]) => /^[A-Za-z]+$/.test(member)), `${name}: member names are identifiers`);
    assert.ok(entries.every(([, kind]) => kinds.has(kind)), `${name}: every member carries a documented kind (${entries.map(([, kind]) => kind).join(", ")})`);
  }
  // The S3 REST-XML payload operations bind the whole body to one member; each is judged as a structure or a policy document.
  assert.deepEqual(
    [AWS_REQUIRED_OUTPUT_MEMBERS.GetPublicAccessBlock, AWS_REQUIRED_OUTPUT_MEMBERS.GetBucketPolicyStatus, AWS_REQUIRED_OUTPUT_MEMBERS.GetBucketEncryption, AWS_REQUIRED_OUTPUT_MEMBERS.GetBucketPolicy],
    [{ PublicAccessBlockConfiguration: "structure" }, { PolicyStatus: "structure" }, { ServerSideEncryptionConfiguration: "structure" }, { Policy: "policyDocument" }],
  );
});

// ---------------------------------------------------------------------------------------------------------------------
// Round 4 item A: a 200 whose required member is present in another shape (a string where a list is documented, bare
// text inside an XML container the deserializer reads as empty, a foreign document bound to an S3 payload member).
// ---------------------------------------------------------------------------------------------------------------------

/** The 21-character text planted where a documented member should be; the same length the reviewer measured. */
const UNDOCUMENTED_SHAPE_TEXT = "BdeUYKVakcjwaWzzvP3gS";
const FIXTURE_BUCKET = "app-data";
const FIXTURE_DETECTOR_ID = "12abc34d567e8fa901bc2d34e56789f0";
const FIXTURE_KEY_ID = "1234abcd-12ab-34cd-56ef-1234567890ab";
const FIXTURE_VPC_ID = "vpc-0a1b2c3d4e5f60718";
const REST_JSON_SERVICES = new Set(["securityhub", "guardduty", "access-analyzer", "auditmanager", "account"]);
const QUERY_XML_NAMESPACES = { sts: "https://sts.amazonaws.com/doc/2011-06-15/", iam: "https://iam.amazonaws.com/doc/2010-05-08/", rds: "http://rds.amazonaws.com/doc/2014-10-31/" };
const S3_XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/";

const queryXml = (service, action, inner) => ({ status: 200, contentType: "text/xml", body: `<${action}Response xmlns="${QUERY_XML_NAMESPACES[service]}"><${action}Result>${inner}</${action}Result><ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata></${action}Response>` });
const ec2Xml = (action, inner) => ({ status: 200, contentType: "text/xml", body: `<${action}Response xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>req-1</requestId>${inner}</${action}Response>` });
const restXml = (body) => ({ status: 200, contentType: "application/xml", body });
const jsonBody = (service, body) => ({ status: 200, contentType: REST_JSON_SERVICES.has(service) ? "application/json" : "application/x-amz-json-1.1", body: JSON.stringify(body) });
const PAB_XML = (xmlns) => `<PublicAccessBlockConfiguration xmlns="${xmlns}"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`;
const foreignXmlDocument = () => ({ status: 200, contentType: "text/xml", body: `<?xml version="1.0" encoding="UTF-8"?><ForeignDocument xmlns="urn:example:foreign"><Item>ok</Item><Token>${CANARY.apiKey}</Token><Session>${CANARY.sessionCookie}</Session></ForeignDocument>` });
const foreignJsonDocument = () => ({ status: 200, contentType: "application/json", body: JSON.stringify({ message: "ok", items: [], token: CANARY.apiKey, nested: { session: CANARY.sessionCookie } }) });
const htmlWithoutContentType = () => ({ status: 200, contentType: undefined, body: canaryHtmlBody() });

/**
 * A documented, healthy answer to every command the client sends, in each service's own wire protocol, so the real
 * deserializer produces the SDK output a compliant single-region account would: a root with MFA and no access keys, one
 * user with an MFA device and a fresh key, one multi-region logging trail with data events, a hub, a recorder, a
 * detector, an organization with an attached SCP, an analyzer, an instance, an assessment, a security contact, one
 * region with a flow-logged VPC and unremarkable NACL and security group, one bucket that is blocked, encrypted, and
 * TLS-only, one encrypted RDS instance, and one rotated customer-managed key.
 */
function documentedLocalResponse({ service, action }) {
  const account = FIXTURE_ACCOUNT;
  switch (`${service}:${action}`) {
    case "sts:GetCallerIdentity": return STS_IDENTITY_RESPONSE;
    case "iam:GetAccountSummary": return queryXml("iam", action, "<SummaryMap><entry><key>AccountMFAEnabled</key><value>1</value></entry><entry><key>AccountAccessKeysPresent</key><value>0</value></entry><entry><key>Users</key><value>1</value></entry></SummaryMap>");
    case "iam:GetAccountPasswordPolicy": return queryXml("iam", action, "<PasswordPolicy><MinimumPasswordLength>16</MinimumPasswordLength><RequireSymbols>true</RequireSymbols><RequireNumbers>true</RequireNumbers><RequireUppercaseCharacters>true</RequireUppercaseCharacters><RequireLowercaseCharacters>true</RequireLowercaseCharacters><AllowUsersToChangePassword>true</AllowUsersToChangePassword><ExpirePasswords>false</ExpirePasswords></PasswordPolicy>");
    case "iam:ListUsers": return queryXml("iam", action, `<Users><member><Path>/</Path><UserName>svc-deploy</UserName><UserId>AIDASVCDEPLOY0000001</UserId><Arn>arn:aws:iam::${account}:user/svc-deploy</Arn><CreateDate>2025-01-01T00:00:00Z</CreateDate><PasswordLastUsed>2026-04-14T00:00:00Z</PasswordLastUsed></member></Users><IsTruncated>false</IsTruncated>`);
    case "iam:ListMFADevices": return queryXml("iam", action, `<MFADevices><member><UserName>svc-deploy</UserName><SerialNumber>arn:aws:iam::${account}:mfa/svc-deploy</SerialNumber><EnableDate>2025-01-01T00:00:00Z</EnableDate></member></MFADevices><IsTruncated>false</IsTruncated>`);
    case "iam:ListAccessKeys": return queryXml("iam", action, "<AccessKeyMetadata><member><UserName>svc-deploy</UserName><AccessKeyId>AKIAALICEKEY00000001</AccessKeyId><Status>Active</Status><CreateDate>2026-04-01T00:00:00Z</CreateDate></member></AccessKeyMetadata><IsTruncated>false</IsTruncated>");
    case "iam:GetAccessKeyLastUsed": return queryXml("iam", action, "<UserName>svc-deploy</UserName><AccessKeyLastUsed><LastUsedDate>2026-04-15T00:00:00Z</LastUsedDate><ServiceName>s3</ServiceName><Region>us-east-1</Region></AccessKeyLastUsed>");
    case "iam:GetAccountAuthorizationDetails": return queryXml("iam", action, "<UserDetailList/><GroupDetailList/><RoleDetailList/><Policies/><IsTruncated>false</IsTruncated>");
    case "iam:ListPolicies": return queryXml("iam", action, `<Policies><member><PolicyName>ReadOnlyAudit</PolicyName><PolicyId>ANPAREADONLYAUDIT0001</PolicyId><Arn>arn:aws:iam::${account}:policy/ReadOnlyAudit</Arn><Path>/</Path><DefaultVersionId>v2</DefaultVersionId><AttachmentCount>1</AttachmentCount><PermissionsBoundaryUsageCount>0</PermissionsBoundaryUsageCount><IsAttachable>true</IsAttachable><CreateDate>2025-01-01T00:00:00Z</CreateDate><UpdateDate>2025-01-01T00:00:00Z</UpdateDate></member></Policies><IsTruncated>false</IsTruncated>`);
    case "iam:GetPolicyVersion": return queryXml("iam", action, `<PolicyVersion><Document>${encodeURIComponent(JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: ["s3:GetObject"], Resource: "arn:aws:s3:::audit/*" }] }))}</Document><VersionId>v2</VersionId><IsDefaultVersion>true</IsDefaultVersion><CreateDate>2025-01-01T00:00:00Z</CreateDate></PolicyVersion>`);
    case "cloudtrail:LookupEvents": return jsonBody(service, { Events: [] });
    case "cloudtrail:DescribeTrails": return jsonBody(service, { trailList: [{ Name: "org-trail", TrailARN: `arn:aws:cloudtrail:us-east-1:${account}:trail/org-trail`, IsMultiRegionTrail: true, LogFileValidationEnabled: true, HomeRegion: "us-east-1", S3BucketName: "audit-logs", IsOrganizationTrail: false }] });
    case "cloudtrail:GetTrailStatus": return jsonBody(service, { IsLogging: true, LatestDeliveryTime: 1776297600 });
    case "cloudtrail:GetEventSelectors": return jsonBody(service, { TrailARN: `arn:aws:cloudtrail:us-east-1:${account}:trail/org-trail`, AdvancedEventSelectors: [{ Name: "data-events", FieldSelectors: [{ Field: "eventCategory", Equals: ["Data"] }] }] });
    case "securityhub:DescribeHub": return jsonBody(service, { HubArn: `arn:aws:securityhub:us-east-1:${account}:hub/default`, SubscribedAt: "2025-01-01T00:00:00.000Z", AutoEnableControls: true });
    case "securityhub:GetEnabledStandards": return jsonBody(service, { StandardsSubscriptions: [{ StandardsSubscriptionArn: `arn:aws:securityhub:us-east-1:${account}:subscription/cis-aws-foundations-benchmark/v/1.4.0`, StandardsArn: "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0", StandardsInput: {}, StandardsStatus: "READY" }] });
    case "config:DescribeConfigurationRecorders": return jsonBody(service, { ConfigurationRecorders: [{ name: "default", roleARN: `arn:aws:iam::${account}:role/config`, recordingGroup: { allSupported: true, includeGlobalResourceTypes: true } }] });
    case "config:DescribeConfigurationRecorderStatus": return jsonBody(service, { ConfigurationRecordersStatus: [{ name: "default", recording: true, lastStatus: "SUCCESS" }] });
    case "guardduty:ListDetectors": return jsonBody(service, { detectorIds: [FIXTURE_DETECTOR_ID] });
    case "guardduty:GetDetector": return jsonBody(service, { createdAt: "2025-01-01T00:00:00.000Z", findingPublishingFrequency: "FIFTEEN_MINUTES", serviceRole: `arn:aws:iam::${account}:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty`, status: "ENABLED" });
    case "organizations:DescribeOrganization": return jsonBody(service, { Organization: { Id: "o-exampleorgid", Arn: `arn:aws:organizations::${account}:organization/o-exampleorgid`, FeatureSet: "ALL", MasterAccountArn: `arn:aws:organizations::${account}:account/o-exampleorgid/${account}`, MasterAccountId: account, MasterAccountEmail: "aws-root@example.com" } });
    case "organizations:ListAccounts": return jsonBody(service, { Accounts: [{ Id: account, Arn: `arn:aws:organizations::${account}:account/o-exampleorgid/${account}`, Email: "aws-root@example.com", Name: "audit", Status: "ACTIVE", JoinedMethod: "INVITED", JoinedTimestamp: 1735689600 }] });
    case "organizations:ListPolicies": return jsonBody(service, { Policies: [{ Id: "p-examplescp1", Arn: `arn:aws:organizations::${account}:policy/o-exampleorgid/service_control_policy/p-examplescp1`, Name: "DenyRegions", Description: "Deny unapproved regions", Type: "SERVICE_CONTROL_POLICY", AwsManaged: false }] });
    case "organizations:ListTargetsForPolicy": return jsonBody(service, { Targets: [{ TargetId: "r-exam", Arn: `arn:aws:organizations::${account}:root/o-exampleorgid/r-exam`, Name: "Root", Type: "ROOT" }] });
    case "access-analyzer:ListAnalyzers": return jsonBody(service, { analyzers: [{ arn: `arn:aws:access-analyzer:us-east-1:${account}:analyzer/org`, name: "org", type: "ORGANIZATION", status: "ACTIVE", createdAt: "2026-01-01T00:00:00Z" }] });
    case "access-analyzer:ListFindings": return jsonBody(service, { findings: [] });
    case "sso:ListInstances": return jsonBody(service, { Instances: [{ InstanceArn: "arn:aws:sso:::instance/ssoins-1234567890abcdef", IdentityStoreId: "d-1234567890" }] });
    case "auditmanager:ListAssessments": return jsonBody(service, { assessmentMetadata: [{ id: "a1b2c3d4-0000-4000-8000-000000000001", name: "FedRAMP Moderate", status: "ACTIVE", complianceType: "FedRAMP", creationTime: 1767225600, lastUpdated: 1775001600 }] });
    case "account:GetAlternateContact": return jsonBody(service, { AlternateContact: { AlternateContactType: "SECURITY", Name: "Security Team", Title: "CISO", EmailAddress: "security@example.com", PhoneNumber: "+1 555 0100" } });
    case "ec2:DescribeRegions": return ec2Xml(action, "<regionInfo><item><regionName>us-east-1</regionName><regionEndpoint>ec2.us-east-1.amazonaws.com</regionEndpoint><optInStatus>opt-in-not-required</optInStatus></item></regionInfo>");
    case "ec2:GetEbsEncryptionByDefault": return ec2Xml(action, "<ebsEncryptionByDefault>true</ebsEncryptionByDefault><sseType>sse-kms</sseType>");
    case "ec2:DescribeVpcs": return ec2Xml(action, `<vpcSet><item><vpcId>${FIXTURE_VPC_ID}</vpcId><ownerId>${account}</ownerId><state>available</state><cidrBlock>10.0.0.0/16</cidrBlock><isDefault>false</isDefault></item></vpcSet>`);
    case "ec2:DescribeFlowLogs": return ec2Xml(action, `<flowLogSet><item><flowLogId>fl-0a1b2c3d4e5f60718</flowLogId><resourceId>${FIXTURE_VPC_ID}</resourceId><flowLogStatus>ACTIVE</flowLogStatus><trafficType>ALL</trafficType><logDestinationType>s3</logDestinationType><logDestination>arn:aws:s3:::audit-logs</logDestination><deliverLogsStatus>SUCCESS</deliverLogsStatus></item></flowLogSet>`);
    case "ec2:DescribeNetworkAcls": return ec2Xml(action, `<networkAclSet><item><networkAclId>acl-0a1b2c3d4e5f60718</networkAclId><vpcId>${FIXTURE_VPC_ID}</vpcId><default>true</default><entrySet><item><ruleNumber>100</ruleNumber><protocol>6</protocol><ruleAction>allow</ruleAction><egress>false</egress><cidrBlock>10.0.0.0/8</cidrBlock><portRange><from>22</from><to>22</to></portRange></item><item><ruleNumber>110</ruleNumber><protocol>6</protocol><ruleAction>allow</ruleAction><egress>false</egress><cidrBlock>0.0.0.0/0</cidrBlock><portRange><from>443</from><to>443</to></portRange></item><item><ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>true</egress><cidrBlock>0.0.0.0/0</cidrBlock></item><item><ruleNumber>32767</ruleNumber><protocol>-1</protocol><ruleAction>deny</ruleAction><egress>false</egress><cidrBlock>0.0.0.0/0</cidrBlock></item></entrySet></item></networkAclSet>`);
    case "ec2:DescribeSecurityGroups": return ec2Xml(action, `<securityGroupInfo><item><ownerId>${account}</ownerId><groupId>sg-0a1b2c3d4e5f60718</groupId><groupName>web</groupName><groupDescription>web tier</groupDescription><vpcId>${FIXTURE_VPC_ID}</vpcId><ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>443</fromPort><toPort>443</toPort><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges><ipv6Ranges><item><cidrIpv6>::/0</cidrIpv6></item></ipv6Ranges></item><item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort><ipRanges><item><cidrIp>203.0.113.0/24</cidrIp></item></ipRanges></item></ipPermissions></item></securityGroupInfo>`);
    case "s3control:GetPublicAccessBlock": return restXml(PAB_XML("http://awss3control.amazonaws.com/doc/2018-08-20/"));
    case "s3:ListBuckets": return restXml(`<ListAllMyBucketsResult xmlns="${S3_XMLNS}"><Owner><ID>owner-canonical-id</ID><DisplayName>owner</DisplayName></Owner><Buckets><Bucket><Name>${FIXTURE_BUCKET}</Name><CreationDate>2025-06-01T00:00:00.000Z</CreationDate><BucketRegion>us-east-1</BucketRegion></Bucket></Buckets></ListAllMyBucketsResult>`);
    case "s3:GetPublicAccessBlock": return restXml(PAB_XML(S3_XMLNS));
    case "s3:GetBucketPolicyStatus": return restXml(`<PolicyStatus xmlns="${S3_XMLNS}"><IsPublic>false</IsPublic></PolicyStatus>`);
    case "s3:GetBucketEncryption": return restXml(`<ServerSideEncryptionConfiguration xmlns="${S3_XMLNS}"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>arn:aws:kms:us-east-1:${account}:key/${FIXTURE_KEY_ID}</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>`);
    case "s3:GetBucketPolicy": return { status: 200, contentType: "application/json", body: TLS_ONLY_POLICY.replaceAll("arn:aws:s3:::bucket", `arn:aws:s3:::${FIXTURE_BUCKET}`) };
    case "rds:DescribeDBInstances": return queryXml("rds", action, `<DBInstances><DBInstance><DBInstanceIdentifier>orders-db</DBInstanceIdentifier><DBInstanceArn>arn:aws:rds:us-east-1:${account}:db:orders-db</DBInstanceArn><Engine>postgres</Engine><DBInstanceStatus>available</DBInstanceStatus><StorageEncrypted>true</StorageEncrypted><KmsKeyId>arn:aws:kms:us-east-1:${account}:key/${FIXTURE_KEY_ID}</KmsKeyId></DBInstance></DBInstances>`);
    case "kms:ListKeys": return jsonBody(service, { Keys: [{ KeyId: FIXTURE_KEY_ID, KeyArn: `arn:aws:kms:us-east-1:${account}:key/${FIXTURE_KEY_ID}` }], Truncated: false });
    case "kms:DescribeKey": return jsonBody(service, { KeyMetadata: { AWSAccountId: account, KeyId: FIXTURE_KEY_ID, Arn: `arn:aws:kms:us-east-1:${account}:key/${FIXTURE_KEY_ID}`, CreationDate: 1735689600, Enabled: true, KeyUsage: "ENCRYPT_DECRYPT", KeyState: "Enabled", Origin: "AWS_KMS", KeyManager: "CUSTOMER", KeySpec: "SYMMETRIC_DEFAULT", MultiRegion: false } });
    case "kms:GetKeyRotationStatus": return jsonBody(service, { KeyRotationEnabled: true, RotationPeriodInDays: 365 });
    default: throw new Error(`no documented local response for ${service}:${action}`);
  }
}

/**
 * The same 200 with the correct content type, but the command's required member written in another shape: the planted
 * text where the protocol documents a list, map, structure, or boolean (bare text inside the XML element, a JSON string
 * in place of the array or object), and for the S3 payload operations a body that is not the documented document.
 */
function undocumentedShapeResponse({ service, action }) {
  const text = UNDOCUMENTED_SHAPE_TEXT;
  switch (`${service}:${action}`) {
    case "sts:GetCallerIdentity": return queryXml("sts", action, "<Account></Account>");
    case "iam:GetAccountSummary": return queryXml("iam", action, `<SummaryMap>${text}</SummaryMap>`);
    case "iam:GetAccountPasswordPolicy": return queryXml("iam", action, `<PasswordPolicy>${text}</PasswordPolicy>`);
    case "iam:ListUsers": return queryXml("iam", action, `<Users>${text}</Users><IsTruncated>false</IsTruncated>`);
    case "iam:ListMFADevices": return queryXml("iam", action, `<MFADevices>${text}</MFADevices>`);
    case "iam:ListAccessKeys": return queryXml("iam", action, `<AccessKeyMetadata>${text}</AccessKeyMetadata>`);
    case "iam:GetAccessKeyLastUsed": return queryXml("iam", action, `<AccessKeyLastUsed>${text}</AccessKeyLastUsed>`);
    case "iam:GetAccountAuthorizationDetails": return queryXml("iam", action, `<RoleDetailList>${text}</RoleDetailList>`);
    case "iam:ListPolicies": return queryXml("iam", action, `<Policies>${text}</Policies>`);
    case "iam:GetPolicyVersion": return queryXml("iam", action, `<PolicyVersion>${text}</PolicyVersion>`);
    case "cloudtrail:LookupEvents": return jsonBody(service, { Events: text });
    case "cloudtrail:DescribeTrails": return jsonBody(service, { trailList: text });
    case "cloudtrail:GetTrailStatus": return jsonBody(service, { IsLogging: text });
    case "cloudtrail:GetEventSelectors": return jsonBody(service, { TrailARN: "", EventSelectors: text, AdvancedEventSelectors: { nested: text } });
    case "securityhub:DescribeHub": return jsonBody(service, { HubArn: "" });
    case "securityhub:GetEnabledStandards": return jsonBody(service, { StandardsSubscriptions: text });
    case "config:DescribeConfigurationRecorders": return jsonBody(service, { ConfigurationRecorders: text });
    case "config:DescribeConfigurationRecorderStatus": return jsonBody(service, { ConfigurationRecordersStatus: text });
    case "guardduty:ListDetectors": return jsonBody(service, { detectorIds: text });
    case "guardduty:GetDetector": return jsonBody(service, { status: "", serviceRole: "" });
    case "organizations:DescribeOrganization": return jsonBody(service, { Organization: text });
    case "organizations:ListAccounts": return jsonBody(service, { Accounts: text });
    case "organizations:ListPolicies": return jsonBody(service, { Policies: text });
    case "organizations:ListTargetsForPolicy": return jsonBody(service, { Targets: text });
    case "access-analyzer:ListAnalyzers": return jsonBody(service, { analyzers: text });
    case "access-analyzer:ListFindings": return jsonBody(service, { findings: text });
    case "sso:ListInstances": return jsonBody(service, { Instances: text });
    case "auditmanager:ListAssessments": return jsonBody(service, { assessmentMetadata: text });
    case "account:GetAlternateContact": return jsonBody(service, { AlternateContact: text });
    case "ec2:DescribeRegions": return ec2Xml(action, `<regionInfo>${text}</regionInfo>`);
    case "ec2:GetEbsEncryptionByDefault": return ec2Xml(action, `<ebsEncryptionByDefault>${text}</ebsEncryptionByDefault>`);
    case "ec2:DescribeVpcs": return ec2Xml(action, `<vpcSet>${text}</vpcSet>`);
    case "ec2:DescribeFlowLogs": return ec2Xml(action, `<flowLogSet>${text}</flowLogSet>`);
    case "ec2:DescribeNetworkAcls": return ec2Xml(action, `<networkAclSet>${text}</networkAclSet>`);
    case "ec2:DescribeSecurityGroups": return ec2Xml(action, `<securityGroupInfo>${text}</securityGroupInfo>`);
    case "s3control:GetPublicAccessBlock": return restXml(`<PublicAccessBlockConfiguration xmlns="http://awss3control.amazonaws.com/doc/2018-08-20/">${text}</PublicAccessBlockConfiguration>`);
    case "s3:ListBuckets": return restXml(`<ListAllMyBucketsResult xmlns="${S3_XMLNS}"><Buckets>${text}</Buckets></ListAllMyBucketsResult>`);
    case "s3:GetPublicAccessBlock": return restXml(`<PublicAccessBlockConfiguration xmlns="${S3_XMLNS}">${text}</PublicAccessBlockConfiguration>`);
    case "s3:GetBucketPolicyStatus": return restXml(`<PolicyStatus xmlns="${S3_XMLNS}">${text}</PolicyStatus>`);
    case "s3:GetBucketEncryption": return restXml(`<ServerSideEncryptionConfiguration xmlns="${S3_XMLNS}">${text}</ServerSideEncryptionConfiguration>`);
    case "s3:GetBucketPolicy": return { status: 200, contentType: "application/json", body: text };
    case "rds:DescribeDBInstances": return queryXml("rds", action, `<DBInstances>${text}</DBInstances>`);
    case "kms:ListKeys": return jsonBody(service, { Keys: text, Truncated: false });
    case "kms:DescribeKey": return jsonBody(service, { KeyMetadata: text });
    case "kms:GetKeyRotationStatus": return jsonBody(service, { KeyRotationEnabled: text });
    default: throw new Error(`no undocumented-shape local response for ${service}:${action}`);
  }
}

/** Readers that take an inventory-derived argument, exercised with the fixture's own identifiers. */
const LOCAL_AWS_ARGUMENT_METHODS = [
  ["listMfaDevices", "iam", (client) => client.listMfaDevices("svc-deploy")],
  ["listAccessKeys", "iam", (client) => client.listAccessKeys("svc-deploy")],
  ["getAccessKeyLastUsed", "iam", (client) => client.getAccessKeyLastUsed("AKIAALICEKEY00000001")],
  ["getPolicyVersionDocument", "iam", (client) => client.getPolicyVersionDocument(`arn:aws:iam::${FIXTURE_ACCOUNT}:policy/ReadOnlyAudit`, "v2")],
  ["getTrailStatus", "cloudtrail", (client) => client.getTrailStatus("org-trail")],
  ["getEventSelectors", "cloudtrail", (client) => client.getEventSelectors("org-trail")],
  ["getDetector", "guardduty", (client) => client.getDetector(FIXTURE_DETECTOR_ID)],
  ["listPolicyTargets", "organizations", (client) => client.listPolicyTargets("p-examplescp1")],
  ["listAccessAnalyzerFindings", "access-analyzer", (client) => client.listAccessAnalyzerFindings(`arn:aws:access-analyzer:us-east-1:${FIXTURE_ACCOUNT}:analyzer/org`)],
  ["getBucketPublicAccessBlock", "s3", (client) => client.getBucketPublicAccessBlock(FIXTURE_BUCKET)],
  ["getBucketPolicyStatus", "s3", (client) => client.getBucketPolicyStatus(FIXTURE_BUCKET)],
  ["getBucketEncryption", "s3", (client) => client.getBucketEncryption(FIXTURE_BUCKET)],
  ["getBucketPolicy", "s3", (client) => client.getBucketPolicy(FIXTURE_BUCKET)],
  ["describeKmsKey", "kms", (client) => client.describeKmsKey("us-east-1", FIXTURE_KEY_ID)],
  ["getKeyRotationStatus", "kms", (client) => client.getKeyRotationStatus("us-east-1", FIXTURE_KEY_ID)],
];

const UNDOCUMENTED_SHAPE_NOTE = /^IncompleteResponse \(HTTP 200\): [A-Za-z]+ answered (?:with its [A-Za-z]+ member as (?:a string|an empty string|an empty structure|a structure|a number|an empty list|a list|a boolean|null) where (?:a list|a map|a structure|a string|a boolean|a policy document) is documented|with bare text in its [A-Za-z]+ element where (?:a list|a map|a structure|a boolean) is documented|with a value outside its documented shape|without its [A-Za-z/]+ member) \(body: [a-z0-9/.+-]+(?: content type)?, \d+ bytes\)$/;

test("silent success (round 4 item A): a 200 whose required member is present in another shape, through the real SDK parser path, is IncompleteResponse on every reader and every S3 payload operation, recorded in fixed words with the observed status and never as a default, a TypeError, or the planted text", async () => {
  // Positive control: the healthy protocol bodies resolve on every reader, so the guard is judging shape and not the fixture.
  await withLocalAwsEndpoint(documentedLocalResponse, async ({ requests }) => {
    const client = realAwsClient();
    for (const [name, , call] of [...LOCAL_AWS_METHODS, ...LOCAL_AWS_ARGUMENT_METHODS]) {
      const value = await call(client);
      assert.ok(value !== null && value !== undefined, `${name}: the documented body resolves`);
    }
    assert.ok(requests.every((request) => request.status === 200));
    assert.deepEqual(requests.filter((request) => request.action.startsWith("GET ") || request.action.startsWith("POST ")).map((request) => request.label), [], "every request the fixture saw is labelled by its operation");
  });

  const healthy = await withSdkRoutes(healthySdkRoutes(), [], () => runAllAssessments(realAwsClient()));
  let serveDocumented = false;
  await withLocalAwsEndpoint(
    (request) => (serveDocumented && request.action === "GetCallerIdentity" ? STS_IDENTITY_RESPONSE : undocumentedShapeResponse(request)),
    async ({ requests }) => {
      const client = realAwsClient();
      for (const [name, , call] of [...LOCAL_AWS_METHODS, ...LOCAL_AWS_ARGUMENT_METHODS]) {
        await assert.rejects(() => call(client), (error) => {
          const record = thrownErrorRecord(error);
          assert.ok(error instanceof AwsApiError, `${name}: the client throws AwsApiError, not a TypeError or a resolved default: ${record}`);
          assert.equal(error.code, "IncompleteResponse", `${name}: ${error.message}`);
          assert.equal(error.httpStatus, 200, `${name}: the observed status is kept`);
          assert.match(error.message, UNDOCUMENTED_SHAPE_NOTE, `${name}: ${error.message}`);
          assert.ok(!record.includes(UNDOCUMENTED_SHAPE_TEXT), `${name}: the planted text never enters the error`);
          assert.doesNotMatch(record, /TypeError|is not a function|Cannot read properties/, `${name}: no TypeError text`);
          assertNoCanaryWindows(assert, record, AWS_PLANTED_CANARIES, `${name} thrown error`);
          return true;
        });
      }
      assert.ok(requests.length >= LOCAL_AWS_METHODS.length + LOCAL_AWS_ARGUMENT_METHODS.length && requests.every((request) => request.status === 200), "every request was answered 200 by the local server");

      serveDocumented = true;
      const outputs = await runAllAssessments(client);
      const exported = await exportAwsAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-aws-undocumented-shape-"));
      const access = outputs.access;
      assert.equal(access.status, "limited");
      for (const probe of access.surfaces) {
        assert.equal(probe.status, "not_readable", `${probe.name}: a 200 in another shape is not a readable surface`);
        assert.equal(probe.http_status, 200, `${probe.name}: the observed 200, never null`);
        assert.equal(probe.error_code, "IncompleteResponse", `${probe.name}: ${probe.error}`);
        assert.equal(probe.count, null, probe.name);
        assert.match(probe.error, UNDOCUMENTED_SHAPE_NOTE, `${probe.name}: ${probe.error}`);
      }
      for (const [name, result] of Object.entries(outputs)) {
        if (name === "access") continue;
        for (const finding of result.findings) {
          assert.equal(finding.status, "manual", `${name} ${finding.id}: every read answered in another shape, so the finding is manual: ${finding.summary}`);
        }
        assertNoDefaultedLeaves(healthy[name], result, `${name} under undocumented shapes`);
      }
      const text = [JSON.stringify(outputs), ...readBundleFiles(exported.outputDir).values()].join("\n");
      for (const fragment of ["Root MFA enabled=false", "Minimum length 0", "All 0 sampled IAM users", '"users": 0', '"user_count": 0', "TypeError", "is not a function", '"http_status": null', "EBS default encryption disabled", "lack default server-side encryption", "have no policy statement denying", "Block Public Access is incomplete", '"status": "pass"', '"status": "fail"']) {
        assert.ok(!text.includes(fragment), `no output renders ${fragment}`);
      }
      assert.ok(!text.includes(UNDOCUMENTED_SHAPE_TEXT), "the planted text reaches no output");
      assert.doesNotMatch(text, UNSERVED_CONDITIONS, "no output names a condition the fixture never served");
      assert.deepEqual([...namedStatuses(text)], [200], "the only status named anywhere is the one every response carried");
      assertNoCanaries(text, "outputs and bundle under undocumented shapes");
      for (const [name, entry] of readZipEntries(exported.zipPath)) assertNoCanaries(entry, `zip ${name}`);
    },
  );
});

/**
 * One read answered in another shape inside an otherwise documented account (the reviewer's `mixed` and `s3mix`
 * fixtures): the finding it feeds and the verdict it must not fabricate.
 */
const MIXED_UNDOCUMENTED_ROWS = [
  { label: "GetAccountSummary as bare text", match: (r) => r.label === "iam:GetAccountSummary", shape: undocumentedShapeResponse, tool: "identity", finding: "AWS-IAM-01", status: "manual", surface: "iam_summary", never: ["Root MFA enabled=false"] },
  { label: "GetAccountPasswordPolicy as bare text", match: (r) => r.label === "iam:GetAccountPasswordPolicy", shape: undocumentedShapeResponse, tool: "identity", finding: "AWS-IAM-03", status: "manual", never: ["Minimum length 0"] },
  { label: "ListUsers as bare text", match: (r) => r.label === "iam:ListUsers", shape: undocumentedShapeResponse, tool: "identity", finding: "AWS-IAM-02", status: "manual", surface: "iam_users", never: ["All 0 sampled IAM users", '"users": 0', '"user_count": 0'] },
  { label: "ListMFADevices as bare text", match: (r) => r.label === "iam:ListMFADevices", shape: undocumentedShapeResponse, tool: "identity", finding: "AWS-IAM-02", status: "manual", never: ["1/1 IAM users are missing MFA", '"users_without_mfa": [\n        "svc-deploy"'] },
  { label: "DescribeTrails as a string", match: (r) => r.label === "cloudtrail:DescribeTrails", shape: undocumentedShapeResponse, tool: "logging-detection", finding: "AWS-LOG-01", status: "manual", surface: "cloudtrail", never: ["TypeError", "is not a function"] },
  { label: "GetTrailStatus as a string", match: (r) => r.label === "cloudtrail:GetTrailStatus", shape: undocumentedShapeResponse, tool: "logging-detection", finding: "AWS-LOG-01", status: "manual", never: ["TypeError", '"IsLogging": "'] },
  { label: "ListKeys as a string", match: (r) => r.label === "kms:ListKeys", shape: undocumentedShapeResponse, tool: "data-protection", finding: "AWS-DATA-22", status: "manual", surface: "kms_keys", never: ["TypeError", "is not a function"] },
  { label: "GetEbsEncryptionByDefault as bare text", match: (r) => r.label === "ec2:GetEbsEncryptionByDefault", shape: undocumentedShapeResponse, tool: "data-protection", finding: "AWS-DATA-12", status: "manual", never: ["EBS default encryption disabled in 1/1", "EBS default encryption is disabled"] },
  { label: "account GetPublicAccessBlock as a foreign XML document", match: (r) => r.label === "s3control:GetPublicAccessBlock", shape: foreignXmlDocument, tool: "data-protection", finding: "AWS-DATA-11", status: "manual", never: ["Block Public Access is incomplete", "BlockPublicAcls=unset"] },
  { label: "account GetPublicAccessBlock as an HTML page without a content type", match: (r) => r.label === "s3control:GetPublicAccessBlock", shape: htmlWithoutContentType, tool: "data-protection", finding: "AWS-DATA-11", status: "manual", never: ["Block Public Access is incomplete", "BlockPublicAcls=unset"] },
  { label: "account GetPublicAccessBlock as bare text", match: (r) => r.label === "s3control:GetPublicAccessBlock", shape: undocumentedShapeResponse, tool: "data-protection", finding: "AWS-DATA-11", status: "manual", never: ["Block Public Access is incomplete", "BlockPublicAcls=unset"] },
  { label: "bucket GetBucketEncryption as a foreign XML document", match: (r) => r.label === "s3:GetBucketEncryption", shape: foreignXmlDocument, tool: "data-protection", finding: "AWS-DATA-12", status: "warn", never: ["1/1 buckets lack default server-side encryption"] },
  { label: "bucket GetBucketEncryption as an HTML page without a content type", match: (r) => r.label === "s3:GetBucketEncryption", shape: htmlWithoutContentType, tool: "data-protection", finding: "AWS-DATA-12", status: "warn", never: ["1/1 buckets lack default server-side encryption"] },
  { label: "bucket GetBucketEncryption as bare text", match: (r) => r.label === "s3:GetBucketEncryption", shape: undocumentedShapeResponse, tool: "data-protection", finding: "AWS-DATA-12", status: "warn", never: ["1/1 buckets lack default server-side encryption"] },
  { label: "bucket GetBucketPolicy as an HTML page without a content type", match: (r) => r.label === "s3:GetBucketPolicy", shape: htmlWithoutContentType, tool: "data-protection", finding: "AWS-DATA-13", status: "warn", never: ["1/1 buckets have no policy statement denying"] },
  { label: "bucket GetBucketPolicy as a foreign JSON document", match: (r) => r.label === "s3:GetBucketPolicy", shape: foreignJsonDocument, tool: "data-protection", finding: "AWS-DATA-13", status: "warn", never: ["1/1 buckets have no policy statement denying"] },
  { label: "bucket GetBucketPolicyStatus as a foreign XML document", match: (r) => r.label === "s3:GetBucketPolicyStatus", shape: foreignXmlDocument, tool: "data-protection", finding: "AWS-DATA-11", status: "warn", never: ['"IsPublic": true'] },
  { label: "bucket GetPublicAccessBlock as an HTML page without a content type", match: (r) => r.label === "s3:GetPublicAccessBlock", shape: htmlWithoutContentType, tool: "data-protection", finding: "AWS-DATA-11", status: "warn", never: ["1/1 buckets lack a full bucket-level block"] },
];

test("silent success (round 4 item A): one read answered in another shape inside a documented account demotes only the verdict it feeds, marks its probe not_readable on the observed 200, and renders no fabricated pass or fail; the documented account itself passes every control the fixture satisfies", async () => {
  const control = await withLocalAwsEndpoint(documentedLocalResponse, async () => {
    const client = realAwsClient();
    const outputs = await runAllAssessments(client);
    assert.equal(outputs.access.status, "healthy", outputs.access.notes.join(" | "));
    assert.equal(outputs.access.surfaces.filter((probe) => probe.status === "readable").length, outputs.access.surfaces.length, "control: every surface is readable through the real parser");
    for (const id of ["AWS-IAM-01", "AWS-IAM-02", "AWS-IAM-03"]) assert.equal(findingById(outputs.identity, id).status, "pass", `control ${id}: ${findingById(outputs.identity, id).summary}`);
    for (const id of ["AWS-DATA-11", "AWS-DATA-12", "AWS-DATA-13", "AWS-DATA-22"]) assert.equal(findingById(outputs["data-protection"], id).status, "pass", `control ${id}: ${findingById(outputs["data-protection"], id).summary}`);
    assert.equal(findingById(outputs["logging-detection"], "AWS-LOG-01").status, "pass", `control AWS-LOG-01: ${findingById(outputs["logging-detection"], "AWS-LOG-01").summary}`);
    assert.equal(findingById(outputs["network-security"], "AWS-NET-14").status, "pass", `control AWS-NET-14: ${findingById(outputs["network-security"], "AWS-NET-14").summary}`);
    return outputs;
  });

  for (const row of MIXED_UNDOCUMENTED_ROWS) {
    await withLocalAwsEndpoint(
      (request) => (row.match(request) ? row.shape(request) : documentedLocalResponse(request)),
      async ({ requests }) => {
        const client = realAwsClient();
        const outputs = await runAllAssessments(client);
        const exported = await exportAwsAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-aws-mixed-shape-"));
        assert.ok(requests.some((request) => row.match(request)), `${row.label}: the planted read was requested`);
        assert.ok(requests.every((request) => request.status === 200), `${row.label}: every answer was a 200`);

        const finding = findingById(outputs[row.tool], row.finding);
        assert.equal(finding.status, row.status, `${row.label}: ${row.finding} renders ${row.status}, never the fabricated verdict: ${finding.summary}`);
        assert.match(finding.summary, /IncompleteResponse \(HTTP 200\)|SyntaxError \(HTTP 200\)|Error \(HTTP 200\)|unreadable|could not be read|could not be listed/, `${row.label}: the summary names the refused read: ${finding.summary}`);
        if (row.surface) {
          const probe = outputs.access.surfaces.find((surface) => surface.name === row.surface);
          assert.ok(probe, `${row.label}: surface ${row.surface} exists (${outputs.access.surfaces.map((surface) => surface.name).join(", ")})`);
          assert.equal(probe.status, "not_readable", `${row.label}: ${row.surface}`);
          assert.equal(probe.http_status, 200, `${row.label}: the probe keeps the observed 200`);
          assert.equal(probe.error_code, "IncompleteResponse", `${row.label}: ${probe.error_code} ${probe.error}`);
          assert.equal(probe.count, null, row.label);
        }
        const text = [JSON.stringify(outputs, null, 2), ...readBundleFiles(exported.outputDir).values()].join("\n");
        for (const fragment of row.never) assert.ok(!text.includes(fragment), `${row.label}: no output renders ${fragment}`);
        assert.doesNotMatch(text, /TypeError|is not a function|Cannot read properties/, `${row.label}: no TypeError text`);
        assert.ok(!text.includes(UNDOCUMENTED_SHAPE_TEXT), `${row.label}: the planted text reaches no output`);
        assert.ok(!/"http_status": null/.test(text), `${row.label}: no probe loses the observed 200`);
        assertNoCanaries(text, `${row.label}: outputs and bundle`);
        for (const [name, entry] of readZipEntries(exported.zipPath)) assertNoCanaries(entry, `${row.label}: zip ${name}`);
        assert.deepEqual([...namedStatuses(text)].filter((status) => status !== 200), [], `${row.label}: no status other than the observed 200 is named`);
        assert.doesNotMatch(text, UNSERVED_CONDITIONS, `${row.label}: no condition the fixture never served`);

        // Every verdict the planted read does not feed keeps the control's status; none flips to a pass or fail it did not have.
        for (const [tool, result] of Object.entries(outputs)) {
          if (tool === "access") continue;
          for (const item of result.findings) {
            if (item.id === row.finding) continue;
            const before = findingById(control[tool], item.id);
            assert.ok(item.status !== "fail" || before.status === "fail", `${row.label}: ${item.id} ${before.status} -> ${item.status} is a fabricated fail: ${item.summary}`);
            assert.ok(item.status !== "pass" || before.status === "pass", `${row.label}: ${item.id} ${before.status} -> ${item.status} is a fabricated pass: ${item.summary}`);
          }
        }
      },
    );
  }
});

/** A 403 whose error code slot carries a credential-shaped value, in each protocol's error shape. */
function deniedWithCanaryCode({ service }) {
  const message = jsonCanaryMessage();
  if (JSON_PROTOCOL_SERVICES.has(service)) {
    return { status: 403, contentType: "application/x-amz-json-1.1", body: JSON.stringify({ __type: CANARY.sessionCookie, message }) };
  }
  const code = `Bearer ${CANARY.bearer}`;
  if (service === "s3" || service === "s3control") {
    return { status: 403, contentType: "application/xml", body: `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${escapeXml(code)}</Code><Message>${escapeXml(message)}</Message><RequestId>req-1</RequestId><HostId>host-1</HostId></Error>` };
  }
  if (service === "ec2") {
    return { status: 403, contentType: "text/xml;charset=UTF-8", body: `<?xml version="1.0" encoding="UTF-8"?><Response><Errors><Error><Code>${escapeXml(code)}</Code><Message>${escapeXml(message)}</Message></Error></Errors><RequestID>req-1</RequestID></Response>` };
  }
  return { status: 403, contentType: "text/xml", body: `<ErrorResponse xmlns="https://${service}.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>${escapeXml(code)}</Code><Message>${escapeXml(message)}</Message></Error><RequestId>req-1</RequestId></ErrorResponse>` };
}

test("rule 9: a server-controlled error code (<Code>Bearer …</Code>, a __type carrying a token) renders as UnknownError with the observed status; no 6-to-24-character window of it survives in the thrown client error, the access check, the tool payloads, or the bundle", async () => {
  // Positive control: both planted codes are what the SDK would hand back, and both fail the code shape or the scrub.
  assert.ok(redactErrorText(CANARY.sessionCookie) !== CANARY.sessionCookie, "the __type token is token-shaped, so the scrub changes it");
  assert.ok(!/^[A-Za-z][A-Za-z0-9._:-]{0,63}$/.test(`Bearer ${CANARY.bearer}`), "the XML code carries a space");

  let serveIdentity = false;
  await withLocalAwsEndpoint(
    (request) => (serveIdentity && request.action === "GetCallerIdentity" ? STS_IDENTITY_RESPONSE : deniedWithCanaryCode(request)),
    async ({ requests }) => {
      const client = realAwsClient();
      for (const [name, , call] of LOCAL_AWS_METHODS) {
        await assert.rejects(() => call(client), (error) => {
          const record = thrownErrorRecord(error);
          assert.ok(error instanceof AwsApiError, `${name}: ${record}`);
          assert.equal(error.code, "UnknownError", `${name}: the server's code slot is not accepted`);
          assert.equal(error.httpStatus, 403, name);
          assert.ok(error.message.startsWith("UnknownError (HTTP 403)"), `${name}: ${error.message}`);
          assert.equal(isAwsAccessDenied(error), true, `${name}: the observed 403 still classifies as a denial`);
          assertNoCanaryWindows(assert, record, [...AWS_PLANTED_CANARIES, `Bearer ${CANARY.bearer}`], `${name} thrown error`);
          return true;
        });
      }
      assert.ok(requests.every((request) => request.status === 403), "every request observed the 403");

      serveIdentity = true;
      const outputs = await runAllAssessments(client);
      for (const probe of outputs.access.surfaces) {
        assert.equal(probe.status, "not_readable", probe.name);
        assert.equal(probe.error_code, "UnknownError", probe.name);
        assert.equal(probe.http_status, 403, probe.name);
      }
      const outputDir = createTempBase("grclanker-aws-canary-code-");
      const exported = await exportAwsAuditBundle(client, client.getResolvedConfig(), outputDir);
      const payloads = [];
      for (const tool of ["aws_check_access", "aws_assess_identity", "aws_export_audit_bundle"]) {
        payloads.push(await runAwsTool(tool, { region: "us-east-1", account_id: FIXTURE_ACCOUNT, output_dir: createTempBase("grclanker-aws-canary-code-tool-") }));
      }
      const text = [JSON.stringify(outputs), ...payloads, ...readBundleFiles(exported.outputDir).values(), ...[...readZipEntries(exported.zipPath)].map(([, entry]) => entry)].join("\n");
      assertNoCanaryWindows(assert, text, AWS_PLANTED_CANARIES, "outputs, tool payloads, and bundle");
      assert.match(text, /UnknownError \(HTTP 403\)/);
      assert.deepEqual([...namedStatuses(text)], [403], "the only status named is the one every failing response carried");
      for (const result of Object.values(outputs)) {
        for (const finding of result.findings ?? []) assert.ok(!["pass", "fail"].includes(finding.status), `${finding.id}: ${finding.status}`);
      }
    },
  );
});

test("rule 9: a 502 HTML page through the real SDK parser path is recorded on every protocol as the non-JSON body note with the observed status, measured from the response rather than quoted from the SDK error", async () => {
  const page = { status: 502, contentType: "text/html; charset=utf-8", body: canaryHtmlBody() };
  await withLocalAwsEndpoint(() => page, async ({ requests }) => {
    const client = realAwsClient();
    for (const [name, , call] of LOCAL_AWS_METHODS) {
      await assert.rejects(() => call(client), (error) => {
        const record = thrownErrorRecord(error);
        assert.ok(error instanceof AwsApiError, `${name}: ${record}`);
        assert.equal(error.httpStatus, 502, name);
        assert.match(error.message, new RegExp(`^(?:Unknown|SyntaxError) \\(HTTP 502\\): non-JSON body \\(text/html, ${Buffer.byteLength(page.body)} bytes\\)$`), `${name}: ${error.message}`);
        assertNoCanaryWindows(assert, record, AWS_PLANTED_CANARIES, `${name} thrown error`);
        assert.doesNotMatch(record, PARSER_WORDING, name);
        return true;
      });
    }
    assert.ok(requests.length >= LOCAL_AWS_METHODS.length && requests.every((request) => request.status === 502));
    const text = await runAwsTool("aws_check_access", { region: "us-east-1", account_id: FIXTURE_ACCOUNT });
    assert.match(text, /AWS access check failed: Unknown \(HTTP 502\): non-JSON body \(text\/html, \d+ bytes\)/);
    assertNoCanaryWindows(assert, text, AWS_PLANTED_CANARIES, "aws_check_access payload");
  });
});
