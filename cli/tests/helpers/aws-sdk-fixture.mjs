/**
 * Drives the real AwsAuditorClient without credentials or network by serving the send() that every AWS SDK
 * client inherits from the shared smithy Client prototype. Routes are keyed by IAM action
 * (for example iam:ListUsers) so a fixture reads like the labels the assessments record, and every request
 * is logged with the region it was sent to and the status or SDK error code it observed.
 */
import { IAMClient } from "@aws-sdk/client-iam";

import { AwsAuditorClient } from "../../dist/extensions/grc-tools/aws.js";

const SMITHY_CLIENT_PROTOTYPE = Object.getPrototypeOf(Object.getPrototypeOf(new IAMClient({ region: "us-east-1" })));

/** IAM action prefix for each SDK client's serviceId. */
const SERVICE_PREFIXES = {
  IAM: "iam",
  STS: "sts",
  CloudTrail: "cloudtrail",
  SecurityHub: "securityhub",
  "Config Service": "config",
  GuardDuty: "guardduty",
  Organizations: "organizations",
  AccessAnalyzer: "access-analyzer",
  "SSO Admin": "sso",
  S3: "s3",
  "S3 Control": "s3control",
  AuditManager: "auditmanager",
  Account: "account",
  EC2: "ec2",
  RDS: "rds",
  KMS: "kms",
};

export const FIXTURE_ACCOUNT = "123456789012";
export const FIXTURE_NOW = new Date("2026-04-16T00:00:00.000Z");

/**
 * Credential-shaped canaries, alphanumeric and random-looking so no 6-character window of them occurs in the
 * fixture's legitimate values (the aws test's fixture self-check asserts it); each travels in the carrier its
 * name says, and the key id and secret keep the AKIA prefix and 40-character shape those rules key on.
 */
export const AWS_CANARIES = {
  bearer: "wK2kypVFjDA4rjxzRzL5QHTnMKaZtPy3",
  session: "rwfx9tWvvz458GCrFtwaX9cXXMVy",
  apiKey: "PMZ4hQaDC37k7PXPKkdSzUg6vD4H",
  urlToken: "QrNKBjvvWTSh7JRk6Eux",
  accessKeyId: "AKIAZZSK7Q46ALH3TEZ5",
  secretKey: "qNBXsx64Xxg9ux7wejCurgQsZArbXcGkbUN4ZfdY",
};
export const CANARY_URL = `https://api.example.com/v1/x?token=${AWS_CANARIES.urlToken}`;

function commandAction(client, command) {
  const prefix = SERVICE_PREFIXES[client.config.serviceId];
  if (!prefix) throw new Error(`Unmapped SDK service: ${client.config.serviceId}`);
  return `${prefix}:${command.constructor.name.replace(/Command$/, "")}`;
}

/**
 * Runs `run` while every SDK request is answered by routes[action](input, region, sdk); each request is appended
 * to `log` as { action, region, status, code }. `sdk.resolveCredentials()` runs the client's real credential
 * provider (the guarded chain the integration built), which a patched send otherwise never reaches. The shared
 * prototype is restored even when the run throws.
 */
export async function withSdkRoutes(routes, log, run) {
  const original = SMITHY_CLIENT_PROTOTYPE.send;
  SMITHY_CLIENT_PROTOTYPE.send = async function patchedSend(command) {
    const region = typeof this.config.region === "function" ? await this.config.region() : this.config.region;
    const action = commandAction(this, command);
    const route = routes[action];
    if (!route) throw new Error(`Unexpected SDK request: ${action}`);
    try {
      const output = await route(command.input, region, { resolveCredentials: () => this.config.credentials() });
      log.push({ action, region, status: 200, code: null });
      return output;
    } catch (error) {
      log.push({ action, region, status: error?.$metadata?.httpStatusCode ?? null, code: error?.name ?? null });
      throw error;
    }
  };
  try {
    return await run();
  } finally {
    SMITHY_CLIENT_PROTOTYPE.send = original;
  }
}

export function realAwsConfig(overrides = {}) {
  return { region: "us-east-1", profile: undefined, accountId: FIXTURE_ACCOUNT, sourceChain: ["tests"], ...overrides };
}

export function realAwsClient(config = realAwsConfig()) {
  return new AwsAuditorClient(config, { now: () => FIXTURE_NOW });
}

const FULL_BLOCK = { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true };

const TLS_ONLY_POLICY = JSON.stringify({
  Version: "2012-10-17",
  Statement: [{
    Sid: "DenyInsecureTransport",
    Effect: "Deny",
    Principal: "*",
    Action: "s3:*",
    Resource: ["arn:aws:s3:::app-data", "arn:aws:s3:::app-data/*"],
    Condition: { Bool: { "aws:SecureTransport": "false" } },
  }],
});

/** SDK outputs for a compliant single-region account: every finding passes and no read fails. */
export function healthySdkRoutes() {
  return {
    "sts:GetCallerIdentity": () => ({ Account: FIXTURE_ACCOUNT, Arn: `arn:aws:iam::${FIXTURE_ACCOUNT}:user/auditor` }),
    "iam:GetAccountSummary": () => ({ SummaryMap: { AccountMFAEnabled: 1, AccountAccessKeysPresent: 0 } }),
    "iam:GetAccountPasswordPolicy": () => ({
      PasswordPolicy: { MinimumPasswordLength: 16, RequireSymbols: true, RequireNumbers: true, RequireUppercaseCharacters: true, RequireLowercaseCharacters: true },
    }),
    "iam:ListUsers": () => ({
      Users: [{ UserName: "alice", Arn: `arn:aws:iam::${FIXTURE_ACCOUNT}:user/alice`, CreateDate: new Date("2025-01-01T00:00:00Z"), PasswordLastUsed: new Date("2026-04-14T00:00:00Z") }],
      IsTruncated: false,
    }),
    "iam:ListMFADevices": () => ({ MFADevices: [{ SerialNumber: `arn:aws:iam::${FIXTURE_ACCOUNT}:mfa/alice`, UserName: "alice" }] }),
    "iam:ListAccessKeys": () => ({ AccessKeyMetadata: [{ AccessKeyId: "AKIAALICEKEY00000001", Status: "Active", CreateDate: new Date("2026-04-01T00:00:00Z"), UserName: "alice" }] }),
    "iam:GetAccessKeyLastUsed": () => ({ AccessKeyLastUsed: { LastUsedDate: new Date("2026-04-15T00:00:00Z"), ServiceName: "s3", Region: "us-east-1" } }),
    "iam:GetAccountAuthorizationDetails": () => ({ RoleDetailList: [], IsTruncated: false }),
    "iam:ListPolicies": () => ({
      Policies: [{ PolicyName: "ReadOnlyAudit", Arn: `arn:aws:iam::${FIXTURE_ACCOUNT}:policy/ReadOnlyAudit`, DefaultVersionId: "v2", AttachmentCount: 1, PermissionsBoundaryUsageCount: 0 }],
      IsTruncated: false,
    }),
    "iam:GetPolicyVersion": () => ({
      PolicyVersion: { Document: encodeURIComponent(JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: ["s3:GetObject"], Resource: "arn:aws:s3:::audit/*" }] })), VersionId: "v2" },
    }),
    "cloudtrail:LookupEvents": () => ({ Events: [] }),
    "cloudtrail:DescribeTrails": () => ({
      trailList: [{ Name: "org-trail", TrailARN: `arn:aws:cloudtrail:us-east-1:${FIXTURE_ACCOUNT}:trail/org-trail`, IsMultiRegionTrail: true, LogFileValidationEnabled: true, HomeRegion: "us-east-1", S3BucketName: "audit-logs" }],
    }),
    "cloudtrail:GetTrailStatus": () => ({ IsLogging: true }),
    "cloudtrail:GetEventSelectors": () => ({ AdvancedEventSelectors: [{ Name: "data-events", FieldSelectors: [{ Field: "eventCategory", Equals: ["Data"] }] }] }),
    "securityhub:DescribeHub": () => ({ HubArn: `arn:aws:securityhub:us-east-1:${FIXTURE_ACCOUNT}:hub/default`, AutoEnableControls: true }),
    "securityhub:GetEnabledStandards": () => ({
      StandardsSubscriptions: [{ StandardsArn: "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0", StandardsStatus: "READY", StandardsSubscriptionArn: `arn:aws:securityhub:us-east-1:${FIXTURE_ACCOUNT}:subscription/cis` }],
    }),
    "config:DescribeConfigurationRecorders": () => ({ ConfigurationRecorders: [{ name: "default", recordingGroup: { allSupported: true, includeGlobalResourceTypes: true }, roleARN: `arn:aws:iam::${FIXTURE_ACCOUNT}:role/config` }] }),
    "config:DescribeConfigurationRecorderStatus": () => ({ ConfigurationRecordersStatus: [{ name: "default", recording: true, lastStatus: "SUCCESS" }] }),
    "guardduty:ListDetectors": () => ({ DetectorIds: ["detector-1"] }),
    "guardduty:GetDetector": () => ({ Status: "ENABLED", FindingPublishingFrequency: "FIFTEEN_MINUTES" }),
    "organizations:DescribeOrganization": () => ({ Organization: { Id: "o-example", FeatureSet: "ALL", MasterAccountId: FIXTURE_ACCOUNT } }),
    "organizations:ListAccounts": () => ({ Accounts: [{ Id: FIXTURE_ACCOUNT, Name: "audit", Status: "ACTIVE" }] }),
    "organizations:ListPolicies": () => ({ Policies: [{ Id: "p-1", Name: "DenyRegions", AwsManaged: false }] }),
    "organizations:ListTargetsForPolicy": () => ({ Targets: [{ TargetId: "r-root", Name: "Root", Type: "ROOT" }] }),
    "access-analyzer:ListAnalyzers": () => ({ analyzers: [{ arn: `arn:aws:access-analyzer:us-east-1:${FIXTURE_ACCOUNT}:analyzer/org`, name: "org", type: "ORGANIZATION", status: "ACTIVE" }] }),
    "access-analyzer:ListFindings": () => ({ findings: [] }),
    "sso:ListInstances": () => ({ Instances: [{ InstanceArn: "arn:aws:sso:::instance/ssoins-example", IdentityStoreId: "d-example" }] }),
    "auditmanager:ListAssessments": () => ({
      assessmentMetadata: [{ id: "a-1", name: "FedRAMP Moderate", status: "ACTIVE", complianceType: "FedRAMP", creationTime: new Date("2026-01-01T00:00:00Z"), lastUpdated: new Date("2026-04-01T00:00:00Z") }],
    }),
    "account:GetAlternateContact": () => ({
      AlternateContact: { AlternateContactType: "SECURITY", Name: "Security Team", Title: "CISO", EmailAddress: "security@example.com", PhoneNumber: "+1 555 0100" },
    }),
    "ec2:DescribeRegions": () => ({ Regions: [{ RegionName: "us-east-1", OptInStatus: "opt-in-not-required" }] }),
    "s3control:GetPublicAccessBlock": () => ({ PublicAccessBlockConfiguration: { ...FULL_BLOCK } }),
    "s3:ListBuckets": () => ({ Buckets: [{ Name: "app-data", CreationDate: new Date("2025-06-01T00:00:00Z"), BucketRegion: "us-east-1" }] }),
    "s3:GetPublicAccessBlock": () => ({ PublicAccessBlockConfiguration: { ...FULL_BLOCK } }),
    "s3:GetBucketPolicyStatus": () => ({ PolicyStatus: { IsPublic: false } }),
    "s3:GetBucketEncryption": () => ({
      ServerSideEncryptionConfiguration: { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: "aws:kms", KMSMasterKeyID: `arn:aws:kms:us-east-1:${FIXTURE_ACCOUNT}:key/k-customer` }, BucketKeyEnabled: true }] },
    }),
    "s3:GetBucketPolicy": () => ({ Policy: TLS_ONLY_POLICY }),
    "ec2:GetEbsEncryptionByDefault": () => ({ EbsEncryptionByDefault: true, SseType: "sse-kms" }),
    "rds:DescribeDBInstances": () => ({
      DBInstances: [{ DBInstanceIdentifier: "orders-db", DBInstanceArn: `arn:aws:rds:us-east-1:${FIXTURE_ACCOUNT}:db:orders-db`, Engine: "postgres", StorageEncrypted: true, KmsKeyId: `arn:aws:kms:us-east-1:${FIXTURE_ACCOUNT}:key/k-customer` }],
    }),
    "kms:ListKeys": () => ({ Keys: [{ KeyId: "k-customer", KeyArn: `arn:aws:kms:us-east-1:${FIXTURE_ACCOUNT}:key/k-customer` }], Truncated: false }),
    "kms:DescribeKey": (input) => ({
      KeyMetadata: { KeyId: input.KeyId, Arn: `arn:aws:kms:us-east-1:${FIXTURE_ACCOUNT}:key/${input.KeyId}`, KeyManager: "CUSTOMER", KeyState: "Enabled", KeySpec: "SYMMETRIC_DEFAULT", KeyUsage: "ENCRYPT_DECRYPT", Origin: "AWS_KMS", MultiRegion: false },
    }),
    "kms:GetKeyRotationStatus": () => ({ KeyRotationEnabled: true, RotationPeriodInDays: 365 }),
    "ec2:DescribeVpcs": (_input, region) => ({ Vpcs: [{ VpcId: `vpc-${region}`, IsDefault: false, CidrBlock: "10.0.0.0/16", State: "available" }] }),
    "ec2:DescribeFlowLogs": (_input, region) => ({
      FlowLogs: [{ FlowLogId: `fl-${region}`, ResourceId: `vpc-${region}`, FlowLogStatus: "ACTIVE", TrafficType: "ALL", LogDestinationType: "s3", LogDestination: "arn:aws:s3:::audit-logs" }],
    }),
    "ec2:DescribeNetworkAcls": (_input, region) => ({
      NetworkAcls: [{
        NetworkAclId: `acl-${region}`,
        VpcId: `vpc-${region}`,
        IsDefault: true,
        Entries: [
          { RuleNumber: 100, Protocol: "6", RuleAction: "allow", Egress: false, CidrBlock: "10.0.0.0/8", PortRange: { From: 22, To: 22 } },
          { RuleNumber: 110, Protocol: "6", RuleAction: "allow", Egress: false, CidrBlock: "0.0.0.0/0", PortRange: { From: 443, To: 443 } },
          { RuleNumber: 100, Protocol: "-1", RuleAction: "allow", Egress: true, CidrBlock: "0.0.0.0/0" },
          { RuleNumber: 32767, Protocol: "-1", RuleAction: "deny", Egress: false, CidrBlock: "0.0.0.0/0" },
        ],
      }],
    }),
    "ec2:DescribeSecurityGroups": (_input, region) => ({
      SecurityGroups: [{
        GroupId: `sg-${region}`,
        GroupName: "web",
        VpcId: `vpc-${region}`,
        IpPermissions: [
          { IpProtocol: "tcp", FromPort: 443, ToPort: 443, IpRanges: [{ CidrIp: "0.0.0.0/0" }], Ipv6Ranges: [{ CidrIpv6: "::/0" }] },
          { IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "203.0.113.0/24" }], Ipv6Ranges: [] },
        ],
      }],
    }),
  };
}

/** An SDK-shaped AccessDenied for the request-matching and denial fixtures. */
export function sdkAccessDenied(code = "AccessDeniedException", status = 403) {
  const error = new Error(`User: arn:aws:iam::${FIXTURE_ACCOUNT}:user/auditor is not authorized to perform this operation`);
  error.name = code;
  error.$fault = "client";
  error.$metadata = { httpStatusCode: status, attempts: 1, totalRetryDelay: 0 };
  return error;
}

/** A throttling error with the shape the SDK raises after its retries are spent. */
export function sdkThrottled() {
  const error = new Error("Rate exceeded");
  error.name = "ThrottlingException";
  error.$fault = "client";
  error.$retryable = { throttling: true };
  error.$metadata = { httpStatusCode: 400, attempts: 3, totalRetryDelay: 900 };
  return error;
}

/** A 503 from the service with the shape the SDK raises after its retries are spent. */
export function sdkServiceUnavailable() {
  const error = new Error("Service Unavailable");
  error.name = "ServiceUnavailableException";
  error.$fault = "server";
  error.$metadata = { httpStatusCode: 503, attempts: 3, totalRetryDelay: 900 };
  return error;
}

/** A transport timeout: no response, no status, only the node-http-handler error code. */
export function sdkTimeout() {
  const error = new Error("Request timed out after 30000ms");
  error.name = "TimeoutError";
  error.code = "ETIMEDOUT";
  error.$metadata = { attempts: 3, totalRetryDelay: 900 };
  return error;
}

export function canaryHtmlBody() {
  return [
    "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body>",
    "<h1>502 Bad Gateway</h1>",
    `<p>Upstream request headers: Authorization: Bearer ${AWS_CANARIES.bearer}; X-Api-Key: ${AWS_CANARIES.apiKey}</p>`,
    `<p>Set-Cookie: AWSALB=${AWS_CANARIES.session}; Path=/; HttpOnly</p>`,
    `<p>Retry the request at ${CANARY_URL} once the upstream recovers.</p>`,
    "</body></html>",
  ].join("\n");
}

/**
 * The error the SDK deserializer middleware raises for a proxy's 502 HTML page: the parse failure carries the
 * raw body and the response on hidden, non-enumerable fields and the HTTP status in $metadata.
 */
export function proxyHtmlError() {
  const body = canaryHtmlBody();
  const error = new SyntaxError(
    "Unexpected token '<', \"<!DOCTYPE \"... is not valid JSON\n  Deserialization error: to see the raw response, inspect the hidden field {error}.$response on this object.",
  );
  Object.defineProperty(error, "$responseBodyText", { value: body, enumerable: false });
  Object.defineProperty(error, "$response", {
    value: { statusCode: 502, reason: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8", "content-length": String(Buffer.byteLength(body)) }, body },
    enumerable: false,
  });
  error.$metadata = { httpStatusCode: 502, attempts: 1, totalRetryDelay: 0 };
  return error;
}

/**
 * The error the SDK deserializer raises for a 200 answer whose body is a short non-JSON text (a proxy's
 * interstitial, a placeholder page): V8 quotes the whole source when it is 21 characters or shorter, so the
 * SyntaxError message carries the entire body, and the SDK attaches the body and the response as well.
 */
export function shortBodyParseError(body, contentType = "text/plain") {
  let parserMessage;
  try {
    JSON.parse(body);
  } catch (error) {
    parserMessage = error.message;
  }
  const error = new SyntaxError(`${parserMessage}\n  Deserialization error: to see the raw response, inspect the hidden field {error}.$response on this object.`);
  Object.defineProperty(error, "$responseBodyText", { value: body, enumerable: false });
  Object.defineProperty(error, "$response", {
    value: { statusCode: 200, reason: "OK", headers: { "content-type": contentType, "content-length": String(Buffer.byteLength(body)) }, body },
    enumerable: false,
  });
  error.$metadata = { httpStatusCode: 200, attempts: 1, totalRetryDelay: 0 };
  return error;
}

/** A service error whose message echoes request context: a URL with a token query and key-shaped values. */
export function contextLeakingDeniedError() {
  const error = new Error(
    `User: arn:aws:iam::${FIXTURE_ACCOUNT}:user/auditor is not authorized to perform this operation; see ${CANARY_URL} for details (request signed with ${AWS_CANARIES.accessKeyId} / ${AWS_CANARIES.secretKey})`,
  );
  error.name = "AccessDeniedException";
  error.$fault = "client";
  error.$metadata = { httpStatusCode: 403, attempts: 1, totalRetryDelay: 0 };
  return error;
}
