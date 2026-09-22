import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  SalesforceApiClient,
  SalesforceApiError,
  assessSalesforceDataProtection,
  assessSalesforceDataProtectionData,
  assessSalesforceIdentityAccess,
  assessSalesforceIdentityData,
  assessSalesforceMonitoringData,
  assessSalesforceMonitoringIntegrations,
  assessSalesforcePlatformData,
  assessSalesforcePlatformSecurity,
  buildJwtAssertion,
  checkSalesforceAccess,
  collectProfileMetadata,
  decodeJwtClaims,
  exportSalesforceAuditBundle,
  isSalesforceRecordId,
  parseSimpleXml,
  projectMyDomainSettings,
  projectProfileMetadata,
  projectSecuritySettings,
  registerSalesforceTools,
  resolveSalesforceConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/salesforce.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretFragmentsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import { CONFIG_CANARIES, assertConfigLoaderMatrix, configLoaderCases } from "./helpers/config-loader-matrix.mjs";
import { assertFixedTextsSurvive, collectFixedTexts, collectThrownMessage, collectToolTexts, logLines } from "./helpers/fixed-text-survival.mjs";
import { assertLeavesNullUnderDenial } from "./helpers/leaf-diff.mjs";
import { assertFragmentsAbsent, assertPlantedValuesWellFormed } from "./helpers/planted-values.mjs";
import { assertScrubBoundary } from "./helpers/scrub-boundary-matrix.mjs";

const { privateKey: TEST_PRIVATE_KEY, publicKey: TEST_PUBLIC_KEY } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

const NOW = new Date("2026-09-21T00:00:00Z");

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    headers: { "content-type": "application/json", ...(options.headers ?? {}) },
  });
}

function xmlResponse(body, status = 200) {
  return new Response(body, { status, headers: { "content-type": "text/xml" } });
}

/** The configured access token: a planted credential, so random-looking (see the planted-values self-check). */
const SAMPLE_ACCESS_TOKEN = "aYQEGbnRuCrFfp76eu";

function sampleConfig(overrides = {}) {
  return {
    authMode: "access-token",
    loginUrl: "https://login.salesforce.com",
    instanceUrl: "https://acme.my.salesforce.com",
    apiVersion: "64.0",
    accessToken: SAMPLE_ACCESS_TOKEN,
    timeoutMs: 30000,
    maxRetries: 2,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function queryResult(records, extra = {}) {
  return { records, totalSize: records.length, done: true, truncated: false, pages: 1, ...extra };
}

function forbidden() {
  const error = new Error("Salesforce request failed (403) INSUFFICIENT_ACCESS: insufficient access rights");
  error.name = "SalesforceApiError";
  error.status = 403;
  error.errorCode = "INSUFFICIENT_ACCESS";
  Object.setPrototypeOf(error, ForbiddenPrototype);
  return error;
}

let ForbiddenPrototype;

function securitySettingsFixture(overrides = {}) {
  return {
    fullName: "Security",
    passwordPolicies: {
      complexity: "UpperLowerCaseNumericSpecialCharacters",
      expiration: "NinetyDays",
      historyRestriction: "12",
      lockoutInterval: "ThirtyMinutes",
      maxLoginAttempts: "FiveAttempts",
      minimumPasswordLength: "14",
      ...(overrides.passwordPolicies ?? {}),
    },
    sessionSettings: {
      sessionTimeout: "TwoHours",
      forceLogoutOnSessionTimeout: "true",
      lockSessionsToIp: "true",
      enforceIpRangesEveryRequest: "true",
      enableClickjackSetup: "true",
      enableClickjackNonsetupSFDC: "true",
      enableClickjackNonsetupUser: "true",
      enableClickjackNonsetupUserHeaderless: "true",
      enableCSRFOnGet: "true",
      enableCSRFOnPost: "true",
      enableMFADirectUILoginOptIn: "true",
      ...(overrides.sessionSettings ?? {}),
    },
    networkAccess: { ipRanges: [{ start: "10.0.0.1", end: "10.0.0.254" }] },
  };
}

function okDataset(name, data, extra = {}) {
  const list = Array.isArray(data) ? data : data ? [data] : [];
  return { name, status: "ok", data, truncated: false, seen: list.length, total: list.length, ...extra };
}

function forbiddenDataset(name, empty) {
  return { name, status: "forbidden", data: empty, error: "Salesforce request failed (403) INSUFFICIENT_ACCESS", truncated: false, seen: 0 };
}

const goodOrganization = {
  Id: "00D000000000001", Name: "Acme", OrganizationType: "Enterprise Edition", IsSandbox: false, InstanceName: "NA1",
  DefaultAccountAccess: "Read", DefaultContactAccess: "ControlledByParent", DefaultCaseAccess: "Private", DefaultLeadAccess: "Private",
  DefaultOpportunityAccess: "Private", DefaultCampaignAccess: "Private", DefaultCalendarAccess: "HideDetails", DefaultPricebookAccess: "None",
};

const goodProfiles = [
  { Id: "P-admin", Name: "System Administrator", PermissionsApiEnabled: true, PermissionsModifyAllData: true, PermissionsViewAllData: true },
  { Id: "P-std", Name: "Standard User", PermissionsApiEnabled: false, PermissionsModifyAllData: false },
  { Id: "P-int", Name: "Integration", PermissionsApiEnabled: true, PermissionsApiUserOnly: true },
  { Id: "P-guest", Name: "Site Guest", PermissionsApiEnabled: false },
  { Id: "P-ro", Name: "Read Only", PermissionsApiEnabled: false },
  { Id: "P-mkt", Name: "Marketing User", PermissionsApiEnabled: false },
  { Id: "P-sol", Name: "Solution Manager", PermissionsApiEnabled: false },
  { Id: "P-cm", Name: "Contract Manager", PermissionsApiEnabled: false },
];

const goodUsers = [
  { Id: "U1", Username: "admin@acme.example", IsActive: true, UserType: "Standard", ProfileId: "P-admin", LastLoginDate: "2026-09-20T10:00:00Z", CreatedDate: "2020-01-01T00:00:00Z" },
  { Id: "U2", Username: "user@acme.example", IsActive: true, UserType: "Standard", ProfileId: "P-std", LastLoginDate: "2026-09-19T10:00:00Z", CreatedDate: "2021-01-01T00:00:00Z" },
  { Id: "U3", Username: "old@acme.example", IsActive: false, UserType: "Standard", ProfileId: "P-std", LastLoginDate: null, CreatedDate: "2019-01-01T00:00:00Z" },
];

const goodTwoFactor = [
  { UserId: "U1", HasTotp: true },
  { UserId: "U2", HasSalesforceAuthenticator: true },
];

const businessHours = Object.fromEntries([
  ...["monday", "tuesday", "wednesday", "thursday", "friday"].flatMap((day) => [[`${day}Start`, "420"], [`${day}End`, "1140"]]),
  ...["saturday", "sunday"].flatMap((day) => [[`${day}Start`, "0"], [`${day}End`, "0"]]),
]);

const goodProfileListing = [
  { fullName: "Admin", id: "P-admin", type: "Profile", fileName: "profiles/Admin.profile" },
  { fullName: "Standard", id: "P-std", type: "Profile", fileName: "profiles/Standard.profile" },
  { fullName: "Integration", id: "P-int", type: "Profile", fileName: "profiles/Integration.profile" },
];

const goodProfileMetadataRecords = [
  { fullName: "Admin", custom: "false", loginHours: { ...businessHours }, loginIpRanges: [{ startAddress: "10.0.0.1", endAddress: "10.0.0.254", description: "HQ" }], userPermissions: [{ enabled: "true", name: "ModifyAllData" }] },
];

function profileMetadataDataset(records = goodProfileMetadataRecords, extra = {}) {
  const byFullName = new Map(records.map((record) => [record.fullName, record]));
  const listing = new Map(goodProfileListing.map((item) => [item.id, item.fullName]));
  const data = goodProfiles
    .filter((profile) => profile.PermissionsModifyAllData || profile.Name === "System Administrator" || profile.PermissionsViewAllData || profile.PermissionsManageUsers)
    .map((profile) => {
      const fullName = listing.get(profile.Id);
      const record = fullName ? byFullName.get(fullName) : undefined;
      return { ...(record ?? {}), _profileId: profile.Id, _profileName: profile.Name, _fullName: fullName ?? null, _resolved: record !== undefined };
    });
  return okDataset("Profile metadata", data, { seen: data.filter((record) => record._resolved).length, ...extra });
}

const goodCallerPermissions = {
  PermissionsApiEnabled: true,
  PermissionsViewSetup: true,
  PermissionsViewHealthCheck: true,
  PermissionsViewAllUsers: true,
  PermissionsManageUsers: true,
  PermissionsModifyMetadata: true,
  PermissionsModifyAllData: true,
  PermissionsCustomizeApplication: true,
  PermissionsViewEventLogFiles: true,
  PermissionsManageEncryptionKeys: true,
};

function goodIdentityData(overrides = {}) {
  return {
    users: okDataset("User", goodUsers),
    profiles: okDataset("Profile", goodProfiles),
    profileMetadata: profileMetadataDataset(),
    permissionSets: okDataset("PermissionSet", [{ Id: "PS1", Name: "Reporting", IsOwnedByProfile: false, PermissionsModifyAllData: false }]),
    assignments: okDataset("PermissionSetAssignment", [{ Id: "A1", AssigneeId: "U2", PermissionSetId: "PS1", Assignee: { IsActive: true } }]),
    twoFactorMethods: okDataset("TwoFactorMethodsInfo", goodTwoFactor),
    securitySettings: okDataset("SecuritySettings", securitySettingsFixture()),
    healthCheckRisks: okDataset("SecurityHealthCheckRisks", [{ Setting: "Require multi-factor authentication (MFA) for all direct UI logins to your org", RiskType: "MEETS_STANDARD", OrgValue: "Enabled" }]),
    ...overrides,
  };
}

function goodPlatformData(overrides = {}) {
  return {
    organization: okDataset("Organization", goodOrganization),
    healthCheck: okDataset("SecurityHealthCheck", { Score: 95 }),
    healthCheckRisks: okDataset("SecurityHealthCheckRisks", [{ Setting: "Minimum password length", SettingGroup: "Password Policies", RiskType: "MEETS_STANDARD", OrgValue: "14 characters", StandardValue: "8 characters" }]),
    securitySettings: okDataset("SecuritySettings", securitySettingsFixture()),
    myDomainSettings: okDataset("MyDomainSettings", { myDomainName: "acme", canOnlyLoginWithMyDomainUrl: "true", doesApiLoginRequireOrgDomain: "true" }),
    profiles: okDataset("Profile", goodProfiles),
    profileMetadata: profileMetadataDataset(),
    instanceUrl: "https://acme.my.salesforce.com",
    ...overrides,
  };
}

function goodDataProtectionData(overrides = {}) {
  return {
    organization: okDataset("Organization", goodOrganization),
    fieldPermissions: okDataset("FieldPermissions", [
      { Field: "Contact.SSN__c", SobjectType: "Contact", ParentId: "PS1", PermissionsRead: true, PermissionsEdit: false },
      { Field: "Contact.SSN__c", SobjectType: "Contact", ParentId: "PS2", PermissionsRead: true, PermissionsEdit: true },
    ]),
    tenantSecrets: okDataset("TenantSecret", [{ Id: "T1", Status: "Active", Type: "Data", Version: 3, CreatedDate: "2026-06-01T00:00:00Z" }]),
    certificates: okDataset("Certificate", [{ Id: "C1", DeveloperName: "sso_cert", ExpirationDate: "2027-09-01T00:00:00Z", KeySize: 2048, OptionsIsCaSigned: true, OptionsIsPrivateKeyExportable: false, OptionsIsUnusable: false }]),
    ...overrides,
  };
}

function goodMonitoringData(overrides = {}) {
  const logins = [];
  for (let index = 0; index < 40; index += 1) {
    logins.push({ Id: `L${index}`, UserId: "U1", LoginTime: "2026-09-20T10:00:00Z", Status: index % 20 === 0 ? "Invalid Password" : "Success", SourceIp: "10.0.0.5", CountryIso: "US", TlsProtocol: "TLS 1.3" });
  }
  return {
    connectedApplications: okDataset("ConnectedApplication", [{ Id: "CA1", Name: "Auditor", OptionsAllowAdminApprovedUsersOnly: true, RefreshTokenValidityPeriod: 90 }]),
    oauthTokens: okDataset("OauthToken", [{ Id: "OT1", AppName: "Auditor", UserId: "U1", LastUsedDate: "2026-09-20T00:00:00Z", UseCount: 5 }]),
    callerPermissions: okDataset("UserPermissionAccess", goodCallerPermissions),
    loginHistory: okDataset("LoginHistory", logins),
    setupAuditTrail: okDataset("SetupAuditTrail", [{ Id: "S1", Action: "changedEmail", Section: "Users", CreatedDate: "2026-09-10T00:00:00Z", CreatedBy: { Username: "admin@acme.example" }, Display: "Changed email" }]),
    eventLogFiles: okDataset("EventLogFile", [{ Id: "E1", EventType: "Login", LogDate: "2026-09-20T00:00:00Z" }]),
    loginHistoryDays: 30,
    auditTrailDays: 90,
    ...overrides,
  };
}

function findingById(result, id) {
  return result.findings.find((item) => item.id === id);
}

function createFullMockClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    getNow: () => NOW,
    async getSession() { return { accessToken: SAMPLE_ACCESS_TOKEN, instanceUrl: "https://acme.my.salesforce.com" }; },
    async getLimits() { return { DailyApiRequests: { Max: 100000, Remaining: 99000 } }; },
    async getOrganization() { return goodOrganization; },
    async getHealthCheck() { return { Score: 95 }; },
    async listHealthCheckRisks() { return queryResult(goodPlatformData().healthCheckRisks.data); },
    async readSecuritySettings() { return securitySettingsFixture(); },
    async readMyDomainSettings() { return goodPlatformData().myDomainSettings.data; },
    async listProfileMetadata() { return goodProfileListing; },
    async readProfileMetadata(fullNames) { return goodProfileMetadataRecords.filter((record) => fullNames.includes(record.fullName)); },
    async getCallerPermissions() { return goodCallerPermissions; },
    async listUsers() { return queryResult(goodUsers); },
    async listProfiles() { return queryResult(goodProfiles); },
    async listPermissionSets() { return queryResult(goodIdentityData().permissionSets.data); },
    async listPermissionSetAssignments() { return queryResult(goodIdentityData().assignments.data); },
    async listTwoFactorMethods() { return queryResult(goodTwoFactor); },
    async listSensitiveFieldPermissions() { return queryResult(goodDataProtectionData().fieldPermissions.data); },
    async listTenantSecrets() { return queryResult(goodDataProtectionData().tenantSecrets.data); },
    async listCertificates() { return queryResult(goodDataProtectionData().certificates.data); },
    async listConnectedApplications() { return queryResult(goodMonitoringData().connectedApplications.data); },
    async listOauthTokens() { return queryResult(goodMonitoringData().oauthTokens.data); },
    async listLoginHistory() { return queryResult(goodMonitoringData().loginHistory.data); },
    async listSetupAuditTrail() { return queryResult(goodMonitoringData().setupAuditTrail.data); },
    async listEventLogFiles() { return queryResult(goodMonitoringData().eventLogFiles.data); },
    ...overrides,
  };
}

function forbiddenClient() {
  const reject = async () => { throw forbidden(); };
  return createFullMockClient({
    getOrganization: reject,
    getLimits: reject,
    getHealthCheck: reject,
    listHealthCheckRisks: reject,
    readSecuritySettings: reject,
    readMyDomainSettings: reject,
    listProfileMetadata: reject,
    readProfileMetadata: reject,
    getCallerPermissions: reject,
    listUsers: reject,
    listProfiles: reject,
    listPermissionSets: reject,
    listPermissionSetAssignments: reject,
    listTwoFactorMethods: reject,
    listSensitiveFieldPermissions: reject,
    listTenantSecrets: reject,
    listCertificates: reject,
    listConnectedApplications: reject,
    listOauthTokens: reject,
    listLoginHistory: reject,
    listSetupAuditTrail: reject,
    listEventLogFiles: reject,
  });
}

test.before(async () => {
  const module = await import("../dist/extensions/grc-tools/salesforce.js");
  ForbiddenPrototype = module.SalesforceApiError.prototype;
});

test("resolveSalesforceConfiguration prefers explicit args over env and env over the credentials file", () => {
  const base = createTempBase("grclanker-sf-creds-");
  const credentialsPath = join(base, "salesforce-credentials.json");
  writeFileSync(credentialsPath, JSON.stringify({
    grant_type: "password",
    username: "file@acme.example",
    password: "file-password",
    security_token: "file-token",
    consumer_key: "file-key",
    consumer_secret: "file-secret",
    instance_url: "https://file.my.salesforce.com",
  }));

  const fromFile = resolveSalesforceConfiguration({}, { SF_CREDENTIALS_FILE: credentialsPath });
  assert.equal(fromFile.authMode, "password");
  assert.equal(fromFile.username, "file@acme.example");
  assert.equal(fromFile.loginUrl, "https://login.salesforce.com");
  assert.ok(fromFile.sourceChain.some((item) => item.startsWith("credentials-file")));

  const fromEnv = resolveSalesforceConfiguration({}, {
    SF_CREDENTIALS_FILE: credentialsPath,
    SF_USERNAME: "env@acme.example",
    SF_INSTANCE_URL: "https://acme--uat.sandbox.my.salesforce.com/",
  });
  assert.equal(fromEnv.username, "env@acme.example");
  assert.equal(fromEnv.instanceUrl, "https://acme--uat.sandbox.my.salesforce.com");
  assert.equal(fromEnv.loginUrl, "https://test.salesforce.com");
  assert.ok(fromEnv.sourceChain.includes("environment-SF_USERNAME"));

  const fromArgs = resolveSalesforceConfiguration(
    { username: "arg@acme.example", login_url: "https://acme.my.salesforce.com", api_version: "v63.0", timeout_seconds: 9 },
    { SF_CREDENTIALS_FILE: credentialsPath, SF_USERNAME: "env@acme.example" },
  );
  assert.equal(fromArgs.username, "arg@acme.example");
  assert.equal(fromArgs.loginUrl, "https://acme.my.salesforce.com");
  assert.equal(fromArgs.apiVersion, "63.0");
  assert.equal(fromArgs.timeoutMs, 9000);
  assert.ok(fromArgs.sourceChain.includes("arguments-username"));
  assert.ok(fromArgs.sourceChain.includes("login-host-explicit"));
});

test("addendum 6b: the JSON credentials loader reports read and parse failures with fixed text and never quotes the file, JSON.parse, or the fs error", async () => {
  const cases = configLoaderCases({ format: "json", displayName: "Salesforce", fileNoun: "credentials file", extension: ".json" });
  assert.deepEqual(cases.map((item) => item.name), [
    "json unquoted value",
    "json short source",
    "json trailing comma with position",
    "EISDIR",
    "EACCES",
    "ENOENT on an explicit path",
  ]);
  const registered = [];
  registerSalesforceTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccess = registered.find((tool) => tool.name === "salesforce_check_access");
  await assertConfigLoaderMatrix(cases, {
    resolve: (path) => resolveSalesforceConfiguration({ credentials_file: path }, {}),
    checkAccess: (path) => checkAccess.execute("call-config", checkAccess.prepareArguments({ credentials_file: path })),
  });
  // The env-pointed path takes the same guard.
  const [unquoted] = cases;
  assert.throws(() => resolveSalesforceConfiguration({}, { SF_CREDENTIALS_FILE: unquoted.path }), (error) => {
    assert.equal(error.message, unquoted.expectedMessage);
    assert.equal(error.code, "INVALID_JSON");
    return true;
  });
  // The private key file read carries the same fixed-text read error.
  const keyDirectory = createTempBase("grclanker-sf-key-dir-");
  assert.throws(() => resolveSalesforceConfiguration({
    grant_type: "jwt-bearer",
    consumer_key: "consumer-key",
    username: "user@acme.example",
    private_key_file: keyDirectory,
  }, {}), (error) => {
    assert.equal(error.message, `Unable to read Salesforce private key file ${keyDirectory} (EISDIR)`);
    assert.equal(error.code, "EISDIR");
    return true;
  });
});

test("resolveSalesforceConfiguration selects JWT bearer, sandbox flag, access token, and rejects incomplete credentials", () => {
  const base = createTempBase("grclanker-sf-key-");
  const keyPath = join(base, "server.key");
  writeFileSync(keyPath, TEST_PRIVATE_KEY);

  const jwt = resolveSalesforceConfiguration({}, {
    SF_CONSUMER_KEY: "3MVG9consumer",
    SF_USERNAME: "svc@acme.example",
    SF_PRIVATE_KEY_FILE: keyPath,
    SF_INSTANCE_URL: "https://acme.my.salesforce.com",
  });
  assert.equal(jwt.authMode, "jwt-bearer");
  assert.equal(jwt.loginUrl, "https://login.salesforce.com");
  assert.match(jwt.privateKey, /BEGIN PRIVATE KEY/);

  const sandbox = resolveSalesforceConfiguration({ sandbox: true }, {
    SF_CONSUMER_KEY: "3MVG9consumer",
    SF_USERNAME: "svc@acme.example.uat",
    SF_PRIVATE_KEY_FILE: keyPath,
  });
  assert.equal(sandbox.loginUrl, "https://test.salesforce.com");
  assert.ok(sandbox.sourceChain.includes("login-host-sandbox"));

  const token = resolveSalesforceConfiguration({}, { SF_ACCESS_TOKEN: "00D!abc", SF_INSTANCE_URL: "https://acme.my.salesforce.com" });
  assert.equal(token.authMode, "access-token");

  assert.throws(() => resolveSalesforceConfiguration({}, {}), /Salesforce credentials are required/);
  assert.throws(() => resolveSalesforceConfiguration({}, { SF_USERNAME: "a@b.c", SF_PASSWORD: "pw" }), /Username-password flow requires/);
  assert.throws(() => resolveSalesforceConfiguration({}, { SF_ACCESS_TOKEN: "x" }), /requires SF_ACCESS_TOKEN and SF_INSTANCE_URL/);
});

test("buildJwtAssertion signs RS256 claims for the login host and exchanges them for a session", async () => {
  const config = sampleConfig({
    authMode: "jwt-bearer",
    accessToken: undefined,
    instanceUrl: undefined,
    consumerKey: "3MVG9consumer",
    username: "svc@acme.example",
    privateKey: TEST_PRIVATE_KEY,
  });
  const assertion = buildJwtAssertion(config, NOW);
  const [header, claims, signature] = assertion.split(".");
  assert.equal(JSON.parse(Buffer.from(header, "base64url").toString()).alg, "RS256");
  const decoded = decodeJwtClaims(assertion);
  assert.equal(decoded.iss, "3MVG9consumer");
  assert.equal(decoded.sub, "svc@acme.example");
  assert.equal(decoded.aud, "https://login.salesforce.com");
  assert.equal(decoded.exp, Math.floor(NOW.getTime() / 1000) + 180);
  const verifier = createVerify("RSA-SHA256").update(`${header}.${claims}`);
  assert.ok(verifier.verify(TEST_PUBLIC_KEY, Buffer.from(signature, "base64url")));

  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    seen.push({ url, body: init.body, auth: new Headers(init.headers ?? {}).get("authorization") });
    if (url.pathname === "/services/oauth2/token") {
      return jsonResponse({ access_token: "jwt-session", instance_url: "https://acme.my.salesforce.com", token_type: "Bearer" });
    }
    return jsonResponse({ totalSize: 1, done: true, records: [{ Score: 88 }] });
  };
  const client = new SalesforceApiClient(config, { fetchImpl, now: () => NOW });
  const health = await client.getHealthCheck();
  assert.equal(health.Score, 88);
  const tokenCall = seen[0];
  assert.equal(tokenCall.url.origin, "https://login.salesforce.com");
  const form = new URLSearchParams(tokenCall.body);
  assert.equal(form.get("grant_type"), "urn:ietf:params:oauth:grant-type:jwt-bearer");
  assert.equal(form.get("assertion"), assertion);
  assert.equal(seen[1].url.pathname, "/services/data/v64.0/tooling/query");
  assert.equal(seen[1].auth, "Bearer jwt-session");
});

test("SalesforceApiClient runs the username-password flow with the security token and redacts secrets from errors", async () => {
  const config = resolveSalesforceConfiguration({}, {
    SF_USERNAME: "user@acme.example",
    SF_PASSWORD: "hunter22",
    SF_SECURITY_TOKEN: "TOKEN12345",
    SF_CONSUMER_KEY: "key",
    SF_CONSUMER_SECRET: "supersecret",
  });
  const bodies = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    if (url.pathname === "/services/oauth2/token") {
      bodies.push(new URLSearchParams(init.body));
      if (bodies.length === 1) {
        return jsonResponse({ error: "invalid_grant", error_description: "authentication failure for hunter22TOKEN12345 with supersecret" }, { status: 400 });
      }
      return jsonResponse({ access_token: "pw-session", instance_url: "https://acme.my.salesforce.com" });
    }
    return jsonResponse({ totalSize: 0, done: true, records: [] });
  };
  const client = new SalesforceApiClient(config, { fetchImpl, sleep: async () => {} });
  await assert.rejects(() => client.getLimits(), (error) => {
    assert.match(error.message, /Salesforce token request failed \(400\)/);
    assert.ok(!error.message.includes("hunter22"));
    assert.ok(!error.message.includes("supersecret"));
    assert.ok(error.message.includes("[REDACTED]"));
    return true;
  });
  assert.equal(bodies[0].get("grant_type"), "password");
  assert.equal(bodies[0].get("password"), "hunter22TOKEN12345");
  assert.equal(bodies[0].get("client_secret"), "supersecret");
  await client.getLimits();
  assert.equal(bodies.length, 2);
});

test("SalesforceApiClient paginates SOQL with nextRecordsUrl, records truncation, retries 429 and 5xx, and queries the Tooling API", async () => {
  const calls = [];
  const sleeps = [];
  let queryAttempts = 0;
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    calls.push(`${init.method ?? "GET"} ${url.pathname}${url.search}`);
    if (url.pathname === "/services/data/v64.0/query") {
      queryAttempts += 1;
      if (queryAttempts === 1) return new Response("", { status: 429, headers: { "retry-after": "1" } });
      if (queryAttempts === 2) return jsonResponse([{ message: "upstream", errorCode: "UNKNOWN" }], { status: 503 });
      return jsonResponse({ totalSize: 5, done: false, nextRecordsUrl: "/services/data/v64.0/query/01g-2", records: [{ Id: "1" }, { Id: "2" }] });
    }
    if (url.pathname === "/services/data/v64.0/query/01g-2") {
      return jsonResponse({ totalSize: 5, done: false, nextRecordsUrl: "/services/data/v64.0/query/01g-4", records: [{ Id: "3" }, { Id: "4" }] });
    }
    if (url.pathname === "/services/data/v64.0/query/01g-4") {
      return jsonResponse({ totalSize: 5, done: true, records: [{ Id: "5" }] });
    }
    if (url.pathname === "/services/data/v64.0/tooling/query") {
      return jsonResponse({ totalSize: 1, done: true, records: [{ Score: 77 }] });
    }
    return jsonResponse({}, { status: 404 });
  };
  const client = new SalesforceApiClient(sampleConfig({ maxRetries: 3 }), { fetchImpl, sleep: async (ms) => { sleeps.push(ms); } });

  const full = await client.query("SELECT Id FROM User");
  assert.deepEqual(full.records.map((record) => record.Id), ["1", "2", "3", "4", "5"]);
  assert.equal(full.done, true);
  assert.equal(full.truncated, false);
  assert.equal(full.pages, 3);
  assert.deepEqual(sleeps, [1000, 1000]);

  queryAttempts = 3;
  const capped = await client.query("SELECT Id FROM User", 3);
  assert.equal(capped.records.length, 3);
  assert.equal(capped.truncated, true);
  assert.equal(capped.totalSize, 5);

  const tooling = await client.toolingQuery("SELECT Score FROM SecurityHealthCheck");
  assert.equal(tooling.records[0].Score, 77);
  assert.ok(calls.some((call) => call.startsWith("GET /services/data/v64.0/tooling/query?q=SELECT")));
});

test("SalesforceApiClient reads SecuritySettings through Metadata API readMetadata and surfaces SOAP faults", async () => {
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    requests.push({ pathname: url.pathname, body: init.body, contentType: new Headers(init.headers ?? {}).get("content-type") });
    if (requests.length === 1) {
      return xmlResponse([
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns=\"http://soap.sforce.com/2006/04/metadata\">",
        "<soapenv:Body><readMetadataResponse><result><records xsi:type=\"SecuritySettings\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">",
        "<fullName>Security</fullName>",
        "<networkAccess><ipRanges><start>10.0.0.1</start><end>10.0.0.9</end></ipRanges><ipRanges><start>10.1.0.1</start><end>10.1.0.9</end></ipRanges></networkAccess>",
        "<passwordPolicies><complexity>AlphaNumeric</complexity><minimumPasswordLength>8</minimumPasswordLength><expiration>Never</expiration><historyRestriction>3</historyRestriction></passwordPolicies>",
        "<sessionSettings><sessionTimeout>TwelveHours</sessionTimeout><forceLogoutOnSessionTimeout>false</forceLogoutOnSessionTimeout><lockSessionsToIp>false</lockSessionsToIp><enableCSRFOnGet>true</enableCSRFOnGet><enableCSRFOnPost>true</enableCSRFOnPost></sessionSettings>",
        "</records></result></readMetadataResponse></soapenv:Body></soapenv:Envelope>",
      ].join(""));
    }
    return xmlResponse("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body><soapenv:Fault><faultcode>sf:INSUFFICIENT_ACCESS</faultcode><faultstring>INSUFFICIENT_ACCESS: no metadata access</faultstring></soapenv:Fault></soapenv:Body></soapenv:Envelope>", 500);
  };
  const client = new SalesforceApiClient(sampleConfig({ maxRetries: 0 }), { fetchImpl });
  const settings = await client.readSecuritySettings();
  assert.equal(requests[0].pathname, "/services/Soap/m/64.0");
  assert.match(requests[0].contentType, /text\/xml/);
  assert.match(requests[0].body, /<met:type>SecuritySettings<\/met:type><met:fullNames>Security<\/met:fullNames>/);
  assert.ok(requests[0].body.includes(`<met:sessionId>${SAMPLE_ACCESS_TOKEN}</met:sessionId>`));
  assert.equal(settings.sessionSettings.sessionTimeout, "TwelveHours");
  assert.equal(settings.passwordPolicies.minimumPasswordLength, "8");
  assert.equal(settings.networkAccess.ipRanges.length, 2);

  await assert.rejects(() => client.readMyDomainSettings(), (error) => {
    assert.equal(error.errorCode, "INSUFFICIENT_ACCESS");
    assertFragmentsAbsent(assert, error.message, [SAMPLE_ACCESS_TOKEN], "SOAP fault error message");
    return true;
  });

  const parsed = parseSimpleXml("<a><b>1</b><b>2</b><c xsi:nil=\"true\"/><d>x &amp; y</d></a>");
  assert.deepEqual(parsed, { a: { b: ["1", "2"], c: null, d: "x & y" } });
});

test("checkSalesforceAccess reports healthy when core surfaces are readable and limited with permission hints otherwise", async () => {
  const healthy = await checkSalesforceAccess(createFullMockClient());
  assert.equal(healthy.status, "healthy");
  assert.equal(healthy.surfaces.filter((surface) => surface.status === "readable").length, healthy.surfaces.length);
  assert.equal(healthy.organization.name, "Acme");
  assert.deepEqual(healthy.missingPermissions, []);
  assert.match(healthy.recommendedNextStep, /salesforce_assess_platform_security/);

  const degraded = await checkSalesforceAccess(createFullMockClient({
    async getHealthCheck() { throw forbidden(); },
    async readSecuritySettings() { throw forbidden(); },
    async listSetupAuditTrail() { throw forbidden(); },
  }));
  assert.equal(degraded.status, "limited");
  assert.ok(degraded.missingPermissions.some((item) => /View Health Check/.test(item)));
  assert.ok(degraded.missingPermissions.some((item) => /Modify Metadata Through Metadata API Functions/.test(item)));
  assert.ok(degraded.notes.some((note) => /Likely missing permissions/.test(note)));
  assert.match(degraded.recommendedNextStep, /re-run salesforce_check_access/);
});

test("assessSalesforcePlatformSecurity passes a hardened org and reads every flag it depends on", async () => {
  const result = await assessSalesforcePlatformSecurity(createFullMockClient());
  assert.deepEqual(result.findings.map((item) => item.control), [1, 2, 3, 5, 18, 19, 20]);
  for (const item of result.findings) {
    assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);
    assert.equal(item.mappings.length, 8);
  }
  assert.equal(findingById(result, "SF-02").evidence.lock_sessions_to_ip, true);
  assert.equal(findingById(result, "SF-02").evidence.force_logout_on_session_timeout, true);
  assert.equal(findingById(result, "SF-18").evidence.can_only_login_with_my_domain_url, true);
  assert.deepEqual(result.errors, []);
});

test("assessSalesforcePlatformData fails weak session, password, My Domain, clickjack, and CSRF settings", () => {
  const weakSettings = securitySettingsFixture({
    sessionSettings: {
      sessionTimeout: "TwelveHours",
      forceLogoutOnSessionTimeout: "false",
      enableClickjackSetup: "false",
      enableClickjackNonsetupUser: "false",
      enableCSRFOnGet: "false",
    },
    passwordPolicies: { minimumPasswordLength: "8", complexity: "AlphaNumeric", expiration: "Never", historyRestriction: "3", maxLoginAttempts: "NoLimit" },
  });
  const result = assessSalesforcePlatformData(goodPlatformData({
    healthCheck: okDataset("SecurityHealthCheck", { Score: 55 }),
    healthCheckRisks: okDataset("SecurityHealthCheckRisks", [{ Setting: "Minimum password length", RiskType: "HIGH_RISK", OrgValue: "8 characters", StandardValue: "8 characters" }]),
    securitySettings: okDataset("SecuritySettings", weakSettings),
    myDomainSettings: okDataset("MyDomainSettings", { myDomainName: "acme", canOnlyLoginWithMyDomainUrl: "false" }),
  }));
  assert.equal(findingById(result, "SF-01").status, "fail");
  assert.equal(findingById(result, "SF-02").status, "fail");
  assert.equal(findingById(result, "SF-03").status, "fail");
  assert.equal(findingById(result, "SF-18").status, "fail");
  assert.equal(findingById(result, "SF-19").status, "fail");
  assert.equal(findingById(result, "SF-20").status, "fail");
});

test("assessSalesforcePlatformData never passes when an enabling flag is absent (rule 6)", () => {
  const settings = securitySettingsFixture();
  delete settings.sessionSettings.forceLogoutOnSessionTimeout;
  delete settings.sessionSettings.enableCSRFOnPost;
  delete settings.sessionSettings.enableClickjackNonsetupUserHeaderless;
  const result = assessSalesforcePlatformData(goodPlatformData({
    securitySettings: okDataset("SecuritySettings", settings),
    myDomainSettings: okDataset("MyDomainSettings", { myDomainName: "acme" }),
  }));
  assert.equal(findingById(result, "SF-02").status, "manual");
  assert.equal(findingById(result, "SF-18").status, "manual");
  assert.equal(findingById(result, "SF-19").status, "manual");
  assert.equal(findingById(result, "SF-20").status, "manual");
  assert.match(findingById(result, "SF-02").summary, /forceLogoutOnSessionTimeout \(absent\)/);
});

test("assessSalesforceIdentityAccess passes a well-governed org and fails an overprivileged one", async () => {
  const good = await assessSalesforceIdentityAccess(createFullMockClient(), { maxAdmins: 5 });
  assert.deepEqual(good.findings.map((item) => item.control), [4, 6, 7, 9, 10, 13]);
  assert.equal(findingById(good, "SF-04").status, "pass");
  assert.equal(findingById(good, "SF-06").status, "pass");
  assert.deepEqual(findingById(good, "SF-06").evidence.profiles_with_login_hours, ["System Administrator"]);
  assert.equal(findingById(good, "SF-07").status, "pass");
  assert.equal(findingById(good, "SF-09").status, "pass");
  assert.equal(findingById(good, "SF-10").status, "pass");
  assert.equal(findingById(good, "SF-13").status, "pass");
  assert.match(findingById(good, "SF-13").summary, /emptiness is compliant/);

  const bad = assessSalesforceIdentityData(goodIdentityData({
    users: okDataset("User", [
      ...goodUsers,
      { Id: "U4", Username: "admin2@acme.example", IsActive: true, UserType: "Standard", ProfileId: "P-admin", LastLoginDate: "2026-01-01T00:00:00Z" },
      { Id: "U5", Username: "guest@acme.example", IsActive: true, UserType: "Guest", ProfileId: "P-admin" },
    ]),
    profiles: okDataset("Profile", goodProfiles.map((profile) => ({ ...profile, PermissionsApiEnabled: true }))),
    permissionSets: okDataset("PermissionSet", [{ Id: "PS-god", Name: "GodMode", PermissionsModifyAllData: true }]),
    assignments: okDataset("PermissionSetAssignment", ["U1", "U2", "U4", "U5", "U6", "U7"].map((id) => ({ Id: `A-${id}`, AssigneeId: id, PermissionSetId: "PS-god", Assignee: { IsActive: true } }))),
    twoFactorMethods: okDataset("TwoFactorMethodsInfo", []),
    securitySettings: okDataset("SecuritySettings", securitySettingsFixture({ sessionSettings: { enableMFADirectUILoginOptIn: "false" } })),
    healthCheckRisks: okDataset("SecurityHealthCheckRisks", []),
  }), { maxAdmins: 1, now: NOW });
  assert.equal(findingById(bad, "SF-04").status, "fail");
  assert.equal(findingById(bad, "SF-07").status, "fail");
  assert.equal(findingById(bad, "SF-09").status, "fail");
  assert.equal(findingById(bad, "SF-10").status, "fail");
  assert.equal(findingById(bad, "SF-13").status, "fail");
});

test("assessSalesforceIdentityData never counts undated admins as active and downgrades partial user views (rules 4 and 5)", () => {
  const undated = assessSalesforceIdentityData(goodIdentityData({
    users: okDataset("User", [
      { Id: "U1", Username: "admin@acme.example", IsActive: true, UserType: "Standard", ProfileId: "P-admin", LastLoginDate: null },
    ]),
  }), { maxAdmins: 5, now: NOW });
  assert.equal(findingById(undated, "SF-10").status, "warn");
  assert.deepEqual(findingById(undated, "SF-10").evidence.admins_without_login_date, ["admin@acme.example"]);

  const partial = assessSalesforceIdentityData(goodIdentityData({
    users: okDataset("User", goodUsers, { truncated: true, seen: 3, total: 4000 }),
  }), { maxAdmins: 5, now: NOW });
  assert.equal(findingById(partial, "SF-04").status, "warn");
  assert.equal(findingById(partial, "SF-10").status, "warn");
  assert.equal(findingById(partial, "SF-13").status, "warn");
  assert.match(findingById(partial, "SF-10").summary, /Only 3 of 4000 User records were read/);
});

test("assessSalesforceDataProtection passes healthy evidence and fails weak evidence", async () => {
  const good = await assessSalesforceDataProtection(createFullMockClient());
  assert.deepEqual(good.findings.map((item) => item.control), [8, 12, 16, 17]);
  assert.equal(findingById(good, "SF-08").status, "pass");
  assert.equal(findingById(good, "SF-12").status, "warn");
  assert.equal(findingById(good, "SF-16").status, "pass");
  assert.equal(findingById(good, "SF-17").status, "pass");

  const bad = assessSalesforceDataProtectionData(goodDataProtectionData({
    organization: okDataset("Organization", { ...goodOrganization, DefaultAccountAccess: "Edit", DefaultContactAccess: "Edit", DefaultCaseAccess: "ReadWriteTransfer" }),
    fieldPermissions: okDataset("FieldPermissions", Array.from({ length: 8 }, (_, index) => ({ Field: "Contact.SSN__c", ParentId: `PS${index}`, PermissionsRead: true, PermissionsEdit: true }))),
    tenantSecrets: okDataset("TenantSecret", [{ Id: "T1", Status: "Archived", Type: "Data", CreatedDate: "2020-01-01T00:00:00Z" }]),
    certificates: okDataset("Certificate", [
      { Id: "C1", DeveloperName: "expired_cert", ExpirationDate: "2025-01-01T00:00:00Z", KeySize: 2048 },
      { Id: "C2", DeveloperName: "weak_cert", ExpirationDate: "2028-01-01T00:00:00Z", KeySize: 1024 },
    ]),
  }), { now: NOW });
  assert.equal(findingById(bad, "SF-08").status, "warn");
  assert.equal(findingById(bad, "SF-12").status, "fail");
  assert.equal(findingById(bad, "SF-16").status, "fail");
  assert.equal(findingById(bad, "SF-17").status, "fail");

  const undatedCert = assessSalesforceDataProtectionData(goodDataProtectionData({
    certificates: okDataset("Certificate", [{ Id: "C3", DeveloperName: "nodate", ExpirationDate: null, KeySize: 2048 }]),
    tenantSecrets: okDataset("TenantSecret", [{ Id: "T2", Status: "Active", Type: "Data", CreatedDate: null }]),
  }), { now: NOW });
  assert.equal(findingById(undatedCert, "SF-17").status, "warn");
  assert.equal(findingById(undatedCert, "SF-16").status, "warn");

  const unknownSigning = assessSalesforceDataProtectionData(goodDataProtectionData({
    certificates: okDataset("Certificate", [{ Id: "C4", DeveloperName: "nosign", ExpirationDate: "2027-09-01T00:00:00Z", KeySize: 2048 }]),
  }), { now: NOW });
  assert.equal(findingById(unknownSigning, "SF-17").status, "warn", "a certificate whose OptionsIsCaSigned flag is absent must not pass (rule 6)");
  assert.match(findingById(unknownSigning, "SF-17").summary, /OptionsIsCaSigned was not returned/);

  const exportable = assessSalesforceDataProtectionData(goodDataProtectionData({
    certificates: okDataset("Certificate", [{ Id: "C5", DeveloperName: "exportable", ExpirationDate: "2027-09-01T00:00:00Z", KeySize: 4096, OptionsIsCaSigned: false, OptionsIsPrivateKeyExportable: true, OptionsIsUnusable: false }]),
  }), { now: NOW });
  assert.equal(findingById(exportable, "SF-17").status, "warn");
  assert.match(findingById(exportable, "SF-17").summary, /1 self-signed and 0 CA-signed/);
});

test("assessSalesforceDataProtectionData renders Shield encryption as manual not-applicable when TenantSecret is unavailable (rule 3)", () => {
  const unavailable = { name: "TenantSecret", status: "unavailable", data: [], error: "INVALID_TYPE: sObject type 'TenantSecret' is not supported", truncated: false, seen: 0 };
  const result = assessSalesforceDataProtectionData(goodDataProtectionData({ tenantSecrets: unavailable }), { now: NOW });
  assert.equal(findingById(result, "SF-16").status, "manual");
  assert.match(findingById(result, "SF-16").summary, /not applicable or not visible/);
});

test("assessSalesforceMonitoringIntegrations passes clean telemetry and fails brute force plus self-authorizing apps", async () => {
  const good = await assessSalesforceMonitoringIntegrations(createFullMockClient());
  assert.deepEqual(good.findings.map((item) => item.control), [11, 14, 15]);
  assert.equal(findingById(good, "SF-11").status, "warn");
  assert.equal(findingById(good, "SF-14").status, "pass");
  assert.equal(findingById(good, "SF-15").status, "pass");

  const failures = Array.from({ length: 30 }, (_, index) => ({ Id: `F${index}`, LoginTime: "2026-09-20T10:00:00Z", Status: "Invalid Password", SourceIp: "203.0.113.9", CountryIso: "US", TlsProtocol: "TLS 1.2" }));
  const bad = assessSalesforceMonitoringData(goodMonitoringData({
    connectedApplications: okDataset("ConnectedApplication", [
      { Id: "CA1", Name: "OpenApp", OptionsAllowAdminApprovedUsersOnly: false },
      { Id: "CA2", Name: "OtherOpenApp", OptionsAllowAdminApprovedUsersOnly: false },
    ]),
    loginHistory: okDataset("LoginHistory", [...failures, { Id: "S1", LoginTime: "2026-09-20T10:00:00Z", Status: "Success", SourceIp: "10.0.0.5", CountryIso: "US", TlsProtocol: "TLS 1.3" }]),
    setupAuditTrail: okDataset("SetupAuditTrail", [{ Id: "S1", Action: "PermSetCreate", Section: "Manage Users", CreatedDate: "2026-09-10T00:00:00Z", CreatedBy: { Username: "admin@acme.example" }, Display: "Created permission set GodMode" }]),
  }));
  assert.equal(findingById(bad, "SF-11").status, "fail");
  assert.equal(findingById(bad, "SF-14").status, "fail");
  assert.equal(findingById(bad, "SF-15").status, "warn");
  assert.deepEqual(findingById(bad, "SF-14").evidence.brute_force_sources, ["203.0.113.9 (30 failures)"]);
});

test("false-pass self-check (a): when every endpoint is forbidden no assess tool reports pass (rule 1)", async () => {
  const client = forbiddenClient();
  const results = await Promise.all([
    assessSalesforcePlatformSecurity(client),
    assessSalesforceIdentityAccess(client),
    assessSalesforceDataProtection(client),
    assessSalesforceMonitoringIntegrations(client),
  ]);
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  for (const item of findings) {
    assert.equal(item.status, "manual", `${item.id} should be manual when forbidden: ${item.summary}`);
    assert.ok(item.manualEvidence, `${item.id} must tell a human what to collect`);
  }
  assert.ok(findings.every((item) => /forbidden|could not be verified|not applicable/i.test(item.summary)));
  assert.ok(results.every((result) => result.errors.length > 0));
});

test("false-pass self-check (b): empty inventories never pass except where emptiness is compliant (rule 2)", async () => {
  const empty = createFullMockClient({
    async getHealthCheck() { return undefined; },
    async listHealthCheckRisks() { return queryResult([]); },
    async readSecuritySettings() { return { fullName: "Security" }; },
    async readMyDomainSettings() { return { fullName: "MyDomain" }; },
    async listProfileMetadata() { return []; },
    async readProfileMetadata() { return []; },
    async getCallerPermissions() { return undefined; },
    async listUsers() { return queryResult([]); },
    async listProfiles() { return queryResult([]); },
    async listPermissionSets() { return queryResult([]); },
    async listPermissionSetAssignments() { return queryResult([]); },
    async listTwoFactorMethods() { return queryResult([]); },
    async listSensitiveFieldPermissions() { return queryResult([]); },
    async listTenantSecrets() { return queryResult([]); },
    async listCertificates() { return queryResult([]); },
    async listConnectedApplications() { return queryResult([]); },
    async listOauthTokens() { return queryResult([]); },
    async listLoginHistory() { return queryResult([]); },
    async listSetupAuditTrail() { return queryResult([]); },
    async listEventLogFiles() { return queryResult([]); },
  });
  const results = await Promise.all([
    assessSalesforcePlatformSecurity(empty),
    assessSalesforceIdentityAccess(empty),
    assessSalesforceDataProtection(empty),
    assessSalesforceMonitoringIntegrations(empty),
  ]);
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  const passing = findings.filter((item) => item.status === "pass");
  assert.deepEqual(passing.map((item) => item.id), [], "no control may pass when every inventory is empty");
  assert.equal(findingById(results[1], "SF-13").status, "manual");
  assert.match(findingById(results[1], "SF-13").summary, /zero profiles were returned/);
  assert.equal(findingById(results[2], "SF-16").status, "fail");
  assert.equal(findingById(results[3], "SF-14").status, "manual");
  assert.equal(findingById(results[3], "SF-15").status, "manual");
  assert.equal(findingById(results[1], "SF-10").status, "manual");
  assert.equal(findingById(results[1], "SF-06").status, "manual");
  assert.equal(findingById(results[0], "SF-05").status, "manual");
  assert.equal(findingById(results[0], "SF-01").status, "manual");

  const noGuests = assessSalesforceIdentityData(goodIdentityData({
    users: okDataset("User", goodUsers.filter((user) => user.UserType !== "Guest")),
  }));
  const guestFinding = findingById(noGuests, "SF-13");
  assert.equal(guestFinding.status, "pass", "zero guest users inside a visible population is the only compliant emptiness");
  assert.match(guestFinding.summary, /emptiness is compliant/);
});

test("false-pass self-check (c): partial or truncated inventories never pass (rules 5 and 7)", async () => {
  const partial = (records) => queryResult(records, { truncated: true, done: false, totalSize: records.length + 5000 });
  const client = createFullMockClient({
    async listHealthCheckRisks() { return partial(goodPlatformData().healthCheckRisks.data); },
    async listUsers() { return partial(goodUsers); },
    async listProfiles() { return partial(goodProfiles); },
    async listPermissionSets() { return partial(goodIdentityData().permissionSets.data); },
    async listPermissionSetAssignments() { return partial(goodIdentityData().assignments.data); },
    async listSensitiveFieldPermissions() { return partial(goodDataProtectionData().fieldPermissions.data); },
    async listTenantSecrets() { return partial(goodDataProtectionData().tenantSecrets.data); },
    async listCertificates() { return partial(goodDataProtectionData().certificates.data); },
    async listConnectedApplications() { return partial(goodMonitoringData().connectedApplications.data); },
    async listLoginHistory() { return partial(goodMonitoringData().loginHistory.data); },
    async listSetupAuditTrail() { return partial(goodMonitoringData().setupAuditTrail.data); },
  });
  const results = await Promise.all([
    assessSalesforcePlatformSecurity(client),
    assessSalesforceIdentityAccess(client),
    assessSalesforceDataProtection(client),
    assessSalesforceMonitoringIntegrations(client),
  ]);
  const inventoryControls = new Set([1, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17]);
  const findings = results.flatMap((result) => result.findings).filter((item) => inventoryControls.has(item.control));
  assert.equal(findings.length, inventoryControls.size);
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} must not pass on a partial inventory: ${item.summary}`);
  }
  assert.match(findingById(results[1], "SF-10").summary, /Only 3 of 5003 User records were read/);
});

const SOAP_ENVELOPE_OPEN = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns=\"http://soap.sforce.com/2006/04/metadata\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><soapenv:Body>";
const SOAP_ENVELOPE_CLOSE = "</soapenv:Body></soapenv:Envelope>";
const ALL_WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];

test("review fix 1: control 6 reads Profile metadata loginHours and control 5 closes per-profile loginIpRanges through listMetadata and batched readMetadata", async () => {
  const soapBodies = [];
  const manyProfiles = Array.from({ length: 12 }, (_, index) => ({ Id: `P-${index}`, Name: `Elevated ${index}`, PermissionsApiEnabled: true, PermissionsModifyAllData: true }));
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    if (url.pathname !== "/services/Soap/m/64.0") return jsonResponse({}, { status: 404 });
    soapBodies.push(init.body);
    if (init.body.includes("<met:listMetadata>")) {
      const results = manyProfiles.map((profile) => `<result><fullName>Full_${profile.Id}</fullName><id>${profile.Id}</id><type>Profile</type><fileName>profiles/Full_${profile.Id}.profile</fileName></result>`).join("");
      return xmlResponse(`${SOAP_ENVELOPE_OPEN}<listMetadataResponse>${results}</listMetadataResponse>${SOAP_ENVELOPE_CLOSE}`);
    }
    const names = [...init.body.matchAll(/<met:fullNames>([^<]+)<\/met:fullNames>/g)].map((match) => match[1]);
    const records = names.map((name) => `<records xsi:type="Profile"><fullName>${name}</fullName><custom>true</custom><loginHours><mondayStart>480</mondayStart><mondayEnd>1080</mondayEnd></loginHours><loginIpRanges><startAddress>10.0.0.1</startAddress><endAddress>10.0.0.9</endAddress></loginIpRanges><userPermissions><enabled>true</enabled><name>ModifyAllData</name></userPermissions></records>`).join("");
    return xmlResponse(`${SOAP_ENVELOPE_OPEN}<readMetadataResponse><result>${records}</result></readMetadataResponse>${SOAP_ENVELOPE_CLOSE}`);
  };
  const client = new SalesforceApiClient(sampleConfig(), { fetchImpl });
  const dataset = await collectProfileMetadata(client, okDataset("Profile", manyProfiles));
  assert.equal(dataset.status, "ok");
  assert.equal(dataset.seen, 12);
  assert.equal(dataset.total, 12);
  assert.equal(dataset.truncated, false);
  assert.match(soapBodies[0], /<met:listMetadata><met:queries><met:type>Profile<\/met:type><\/met:queries><met:asOfVersion>64\.0<\/met:asOfVersion><\/met:listMetadata>/);
  const readCalls = soapBodies.filter((body) => body.includes("<met:readMetadata>"));
  assert.equal(readCalls.length, 2, "12 profiles are read in batches of 10");
  assert.equal((readCalls[0].match(/<met:fullNames>/g) ?? []).length, 10);
  assert.equal((readCalls[1].match(/<met:fullNames>/g) ?? []).length, 2);
  assert.match(readCalls[0], /<met:type>Profile<\/met:type><met:fullNames>Full_P-0<\/met:fullNames>/);
  assert.equal(dataset.data[11]._fullName, "Full_P-11");
  assert.equal(dataset.data[11]._profileName, "Elevated 11");
  assert.equal(dataset.data[11]._resolved, true);
  assert.equal(dataset.data[11].loginHours.mondayStart, "480");

  const good = assessSalesforceIdentityData(goodIdentityData(), { now: NOW });
  assert.equal(findingById(good, "SF-06").status, "pass");
  assert.deepEqual(findingById(good, "SF-06").evidence.profiles_without_login_hours, []);
  const goodPlatform = assessSalesforcePlatformData(goodPlatformData());
  assert.equal(findingById(goodPlatform, "SF-05").status, "pass");
  assert.deepEqual(findingById(goodPlatform, "SF-05").evidence.profiles_with_login_ip_ranges, ["System Administrator (1)"]);

  const bare = [{ fullName: "Admin", custom: "false" }];
  const noHours = assessSalesforceIdentityData(goodIdentityData({ profileMetadata: profileMetadataDataset(bare) }), { now: NOW });
  assert.equal(findingById(noHours, "SF-06").status, "fail");
  assert.deepEqual(findingById(noHours, "SF-06").evidence.profiles_without_login_hours, ["System Administrator"]);
  const noProfileRanges = assessSalesforcePlatformData(goodPlatformData({ profileMetadata: profileMetadataDataset(bare) }));
  assert.equal(findingById(noProfileRanges, "SF-05").status, "warn", "org-wide ranges without per-profile ranges is a gap, not a pass");
  assert.match(findingById(noProfileRanges, "SF-05").summary, /1\/1 sensitive profiles have no login IP ranges/);
  const noRangesAnywhere = securitySettingsFixture();
  noRangesAnywhere.networkAccess = {};
  const nothing = assessSalesforcePlatformData(goodPlatformData({ profileMetadata: profileMetadataDataset(bare), securitySettings: okDataset("SecuritySettings", noRangesAnywhere) }));
  assert.equal(findingById(nothing, "SF-05").status, "fail");

  const allDay = Object.fromEntries(ALL_WEEKDAYS.flatMap((day) => [[`${day}Start`, "0"], [`${day}End`, "1440"]]));
  const fullDay = assessSalesforceIdentityData(goodIdentityData({ profileMetadata: profileMetadataDataset([{ fullName: "Admin", loginHours: allDay }]) }), { now: NOW });
  assert.equal(findingById(fullDay, "SF-06").status, "fail", "a full-day window on every day is not a restriction");

  const mixed = okDataset("Profile metadata", [
    { ...goodProfileMetadataRecords[0], _profileId: "P-admin", _profileName: "System Administrator", _fullName: "Admin", _resolved: true },
    { _profileId: "P-x", _profileName: "Custom Admin", _fullName: null, _resolved: false },
  ], { seen: 1 });
  const partial = assessSalesforceIdentityData(goodIdentityData({ profileMetadata: mixed }), { now: NOW });
  assert.equal(findingById(partial, "SF-06").status, "warn", "an unresolved sensitive profile never passes");
  assert.deepEqual(findingById(partial, "SF-06").evidence.profiles_unresolved, ["Custom Admin"]);
  const partialPlatform = assessSalesforcePlatformData(goodPlatformData({ profileMetadata: mixed }));
  assert.equal(findingById(partialPlatform, "SF-05").status, "warn");

  const denied = forbiddenDataset("Profile metadata", []);
  const manual = assessSalesforceIdentityData(goodIdentityData({ profileMetadata: denied }), { now: NOW });
  assert.equal(findingById(manual, "SF-06").status, "manual");
  assert.match(findingById(manual, "SF-06").summary, /forbidden.*Modify Metadata Through Metadata API Functions or Modify All Data/);
  const manualPlatform = assessSalesforcePlatformData(goodPlatformData({ profileMetadata: denied }));
  assert.equal(findingById(manualPlatform, "SF-05").status, "manual");
  assert.match(findingById(manualPlatform, "SF-05").summary, /1 org-wide trusted IP ranges are defined.*per-profile login IP ranges could not be verified because/);

  const forbiddenProfiles = await collectProfileMetadata(createFullMockClient({ async listProfileMetadata() { throw forbidden(); } }), okDataset("Profile", goodProfiles));
  assert.equal(forbiddenProfiles.status, "forbidden");
  assert.equal(forbiddenProfiles.total, 1);
});

test("review fix 2: identity verdicts render manual when no administrator-class population is visible (rule 5)", () => {
  const withoutAdminProfile = goodProfiles.filter((profile) => profile.Id !== "P-admin");
  const lonely = assessSalesforceIdentityData(goodIdentityData({
    users: okDataset("User", [goodUsers[1]]),
    profiles: okDataset("Profile", withoutAdminProfile),
    profileMetadata: okDataset("Profile metadata", []),
  }), { now: NOW });
  for (const id of ["SF-04", "SF-06", "SF-07", "SF-09", "SF-10", "SF-13"]) {
    const item = findingById(lonely, id);
    assert.equal(item.status, "manual", `${id} must not pass without a visible System Administrator profile: ${item.summary}`);
    assert.match(item.summary, /permission-limited view/);
    assert.ok(item.manualEvidence);
  }
  assert.deepEqual(findingById(lonely, "SF-10").evidence.admin_profiles, []);

  const noActiveAdmins = assessSalesforceIdentityData(goodIdentityData({
    users: okDataset("User", [goodUsers[1], goodUsers[2]]),
  }), { now: NOW });
  for (const id of ["SF-04", "SF-07", "SF-09", "SF-10", "SF-13"]) {
    const item = findingById(noActiveAdmins, id);
    assert.equal(item.status, "manual", `${id} must not pass when zero active administrators are visible: ${item.summary}`);
    assert.match(item.summary, /View All Users is likely missing/);
  }
  assert.equal(findingById(noActiveAdmins, "SF-10").evidence.active_admins_seen, 0);
  assert.deepEqual(findingById(noActiveAdmins, "SF-10").evidence.admin_profiles, ["System Administrator"]);
  assert.equal(findingById(noActiveAdmins, "SF-06").status, "pass", "login hours depend on the profile list, which is complete here");
  assert.equal(noActiveAdmins.summary.population_view_issue !== null, true);

  const healthy = assessSalesforceIdentityData(goodIdentityData(), { now: NOW });
  assert.equal(healthy.summary.population_view_issue, null);
  assert.equal(findingById(healthy, "SF-10").status, "pass");
});

test("review fixes 3, 5, and 6: SOQL selects only documented fields and probes Permissions* fields through describe", async () => {
  const queries = [];
  const describedObjects = [];
  const describeFields = {
    Profile: ["Id", "Name", "PermissionsApiEnabled", "PermissionsModifyAllData", "PermissionsViewAllData", "PermissionsManageUsers", "PermissionsAuthorApex"],
    PermissionSet: ["Id", "Name", "PermissionsApiEnabled", "PermissionsModifyAllData", "PermissionsViewAllData", "PermissionsManageUsers", "PermissionsAuthorApex", "PermissionsCustomizeApplication"],
    UserPermissionAccess: ["LastCacheUpdate", "PermissionsCustomizeApplication", "PermissionsViewAllUsers"],
  };
  const fetchImpl = async (input) => {
    const url = new URL(input);
    if (url.pathname.endsWith("/describe")) {
      const object = url.pathname.split("/").at(-2);
      describedObjects.push(object);
      return jsonResponse({ name: object, fields: (describeFields[object] ?? []).map((name) => ({ name })) });
    }
    if (url.pathname === "/services/data/v64.0/query") {
      queries.push(url.searchParams.get("q"));
      return jsonResponse({ totalSize: 1, done: true, records: [{ PermissionsCustomizeApplication: false, PermissionsViewAllUsers: true }] });
    }
    return jsonResponse({}, { status: 404 });
  };
  const fieldsOf = (soql) => soql.replace(/^SELECT\s+/i, "").split(/\s+FROM\s+/i)[0].split(",").map((field) => field.trim());
  const client = new SalesforceApiClient(sampleConfig(), { fetchImpl });

  const profiles = await client.listProfiles();
  assert.deepEqual(profiles.omittedFields, ["PermissionsApiUserOnly", "PermissionsCustomizeApplication", "PermissionsViewSetup", "PermissionsManageProfilesPermissionsets", "PermissionsPasswordNeverExpires"]);
  const profileFields = fieldsOf(queries.at(-1));
  assert.ok(!profileFields.includes("PermissionsApiUserOnly"));
  assert.ok(profileFields.includes("PermissionsAuthorApex"));
  for (const field of ["PermissionsApiEnabled", "PermissionsModifyAllData", "PermissionsViewAllData", "PermissionsManageUsers"]) {
    assert.ok(profileFields.includes(field), `${field} is always selected`);
  }
  await client.listProfiles();
  assert.equal(describedObjects.filter((object) => object === "Profile").length, 1, "describe results are cached per object");

  const permissionSets = await client.listPermissionSets();
  assert.deepEqual(permissionSets.omittedFields, ["PermissionsViewSetup", "PermissionsManageProfilesPermissionsets", "PermissionsPasswordNeverExpires"]);
  assert.ok(fieldsOf(queries.at(-1)).includes("PermissionsCustomizeApplication"));
  assert.ok(!fieldsOf(queries.at(-1)).includes("PermissionsApiUserOnly"));

  const caller = await client.getCallerPermissions();
  assert.deepEqual(fieldsOf(queries.at(-1)).sort(), ["PermissionsCustomizeApplication", "PermissionsViewAllUsers"]);
  assert.match(queries.at(-1), /FROM UserPermissionAccess$/);
  assert.equal(caller.PermissionsCustomizeApplication, false);

  await client.listOauthTokens();
  const documentedOauthToken = new Set(["AccessToken", "AppMenuItemId", "AppName", "DeleteToken", "Id", "LastUsedDate", "RequestToken", "UseCount", "UserId"]);
  for (const field of fieldsOf(queries.at(-1))) assert.ok(documentedOauthToken.has(field), `${field} is not a documented OauthToken field`);
  assert.ok(!queries.at(-1).includes("CreatedDate"));

  await client.listConnectedApplications();
  const documentedConnectedApp = new Set(["Id", "Name", "MobileSessionTimeout", "MobileStartUrl", "NamedUserUvidTimeout", "OptionsAllowAdminApprovedUsersOnly", "OptionsAppIssueJwtTokenEnabled", "OptionsHasSessionLevelPolicy", "OptionsRefreshTokenValidityMetric", "OptionsTokenExchangeManageBitEnabled", "PinLength", "RefreshTokenValidityPeriod", "StartUrl", "UvidTimeout"]);
  for (const field of fieldsOf(queries.at(-1))) assert.ok(documentedConnectedApp.has(field), `${field} is not a documented ConnectedApplication field`);
  assert.ok(!/CreatedDate|LastModifiedDate|OptionsIsInternal|OptionsCodeCredentialGuestEnabled/.test(queries.at(-1)));

  await client.listTwoFactorMethods();
  const documentedTwoFactor = new Set(["ExternalId", "HasBuiltInAuthenticator", "HasSalesforceAuthenticator", "HasSecurityKey", "HasTempCode", "HasTotp", "HasU2F", "HasUserVerifiedEmailAddress", "HasUserVerifiedMobileNumber", "HasVerifiedMobileNumber", "UserId"]);
  const twoFactorFields = fieldsOf(queries.at(-1));
  for (const field of twoFactorFields) assert.ok(documentedTwoFactor.has(field), `${field} is not a documented TwoFactorMethodsInfo field`);
  assert.ok(!twoFactorFields.includes("Id"));

  const fallbackQueries = [];
  const fallback = new SalesforceApiClient(sampleConfig({ maxRetries: 0 }), {
    fetchImpl: async (input) => {
      const url = new URL(input);
      if (url.pathname.endsWith("/describe")) return jsonResponse([{ errorCode: "NOT_FOUND", message: "no describe" }], { status: 404 });
      fallbackQueries.push(url.searchParams.get("q"));
      return jsonResponse({ totalSize: 0, done: true, records: [] });
    },
  });
  const fallbackProfiles = await fallback.listProfiles();
  assert.deepEqual(fallbackProfiles.omittedFields, []);
  assert.ok(fallbackQueries[0].includes("PermissionsApiUserOnly"), "an unavailable describe falls back to the full documented list");

  const omitted = assessSalesforceIdentityData(goodIdentityData({
    profiles: okDataset("Profile", goodProfiles.map(({ PermissionsApiUserOnly, ...rest }) => rest), { omittedFields: ["PermissionsApiUserOnly"] }),
  }), { now: NOW });
  assert.equal(findingById(omitted, "SF-07").status, "pass");
  assert.equal(findingById(omitted, "SF-07").evidence.api_only_flag_available, false);
  assert.match(findingById(omitted, "SF-07").summary, /PermissionsApiUserOnly is not available in this org/);
  assert.match(findingById(assessSalesforceIdentityData(goodIdentityData(), { now: NOW }), "SF-07").summary, /1 are API Only User profiles/);
});

test("review fix 4: TwoFactorMethodsInfo names Manage MFA in API and treats the 2500-row cap as a possibly truncated result", async () => {
  const rows = Array.from({ length: 2500 }, (_, index) => ({ UserId: `U${index}`, HasTotp: true }));
  let requestedLimitRows = 0;
  const client = new SalesforceApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(input);
      if (url.pathname === "/services/data/v64.0/query") {
        requestedLimitRows = rows.length;
        return jsonResponse({ totalSize: 2500, done: true, records: rows });
      }
      return jsonResponse({}, { status: 404 });
    },
  });
  const capped = await client.listTwoFactorMethods();
  assert.equal(requestedLimitRows, 2500);
  assert.equal(capped.records.length, 2500);
  assert.equal(capped.done, true);
  assert.equal(capped.truncated, true, "2500 rows with done=true is the documented cap and must read as possibly truncated");

  const cappedFinding = findingById(assessSalesforceIdentityData(goodIdentityData({
    twoFactorMethods: okDataset("TwoFactorMethodsInfo", goodTwoFactor, { truncated: true }),
  }), { now: NOW }), "SF-04");
  assert.equal(cappedFinding.status, "warn");
  assert.match(cappedFinding.summary, /TwoFactorMethodsInfo returned 2 rows, and the query reported more rows than were returned \(done=false or a stalled cursor\), so enrollment coverage is incomplete/);
  assert.equal(cappedFinding.evidence.two_factor_methods_possibly_capped, true);

  const denied = findingById(assessSalesforceIdentityData(goodIdentityData({
    twoFactorMethods: forbiddenDataset("TwoFactorMethodsInfo", []),
  }), { now: NOW }), "SF-04");
  assert.equal(denied.status, "manual");
  assert.match(denied.summary, /requires the Manage MFA in API permission/);
  assert.equal(denied.evidence.requires, "Manage MFA in API");

  const access = await checkSalesforceAccess(createFullMockClient({ async listTwoFactorMethods() { throw forbidden(); } }));
  const surface = access.surfaces.find((item) => item.name === "two_factor_methods");
  assert.equal(surface.status, "not_readable");
  assert.equal(surface.permissionHint, "Manage MFA in API");
  assert.ok(access.missingPermissions.includes("Manage MFA in API"));
});

test("review fix 7: certificates with an unknown KeySize are reported and never counted as compliant", () => {
  const result = assessSalesforceDataProtectionData(goodDataProtectionData({
    certificates: okDataset("Certificate", [
      { Id: "C6", DeveloperName: "nokeysize", ExpirationDate: "2027-09-01T00:00:00Z", KeySize: null, OptionsIsCaSigned: true, OptionsIsPrivateKeyExportable: false, OptionsIsUnusable: false },
      { Id: "C7", DeveloperName: "strong", ExpirationDate: "2027-09-01T00:00:00Z", KeySize: 4096, OptionsIsCaSigned: true, OptionsIsPrivateKeyExportable: false, OptionsIsUnusable: false },
    ]),
  }), { now: NOW });
  const item = findingById(result, "SF-17");
  assert.equal(item.status, "warn");
  assert.deepEqual(item.evidence.unknown_key_size, ["nokeysize (2027-09-01T00:00:00Z)"]);
  assert.deepEqual(item.evidence.weak_keys, []);
  assert.match(item.summary, /KeySize was not returned for 1, so they are not counted as compliant/);
});

test("review fix 8: OauthToken is a partial view without Customize Application and check_access names the permission", async () => {
  const partial = findingById(assessSalesforceMonitoringData(goodMonitoringData({
    callerPermissions: okDataset("UserPermissionAccess", { ...goodCallerPermissions, PermissionsCustomizeApplication: false }),
  })), "SF-11");
  assert.notEqual(partial.status, "pass");
  assert.equal(partial.evidence.oauth_tokens_partial_view, true);
  assert.equal(partial.evidence.caller_has_customize_application, false);
  assert.match(partial.summary, /only the caller's own tokens without Customize Application \(caller permission: false\)/);

  const unknown = findingById(assessSalesforceMonitoringData(goodMonitoringData({
    callerPermissions: forbiddenDataset("UserPermissionAccess", undefined),
  })), "SF-11");
  assert.equal(unknown.evidence.oauth_tokens_partial_view, true);
  assert.match(unknown.summary, /caller permission: unknown/);

  const full = assessSalesforceMonitoringData(goodMonitoringData());
  assert.equal(findingById(full, "SF-11").evidence.oauth_tokens_partial_view, false);
  assert.equal(full.summary.caller_has_customize_application, true);

  const access = await checkSalesforceAccess(createFullMockClient({
    async getCallerPermissions() { return { ...goodCallerPermissions, PermissionsCustomizeApplication: false, PermissionsViewAllUsers: false }; },
  }));
  assert.equal(access.status, "limited");
  assert.ok(access.missingPermissions.includes("Customize Application"));
  assert.ok(access.missingPermissions.includes("View All Users"));
  assert.ok(access.notes.some((note) => /Customize Application=false/.test(note)));
  const tokenSurface = access.surfaces.find((surface) => surface.name === "oauth_tokens");
  assert.equal(tokenSurface.status, "readable");
  assert.match(tokenSurface.permissionHint, /Customize Application/);
  assert.ok(access.surfaces.some((surface) => surface.name === "caller_permissions" && surface.status === "readable"));
});

test("review round 2 fix 1: control 6 requires every weekday to be bounded and never passes a profile that restricts a single day", () => {
  const adminRecord = (loginHours) => ({ fullName: "Admin", custom: "false", loginHours, loginIpRanges: goodProfileMetadataRecords[0].loginIpRanges });
  const hoursFor = (days, start, end) => Object.fromEntries(days.flatMap((day) => [[`${day}Start`, start], [`${day}End`, end]]));
  const weekdays = ["monday", "tuesday", "wednesday", "thursday", "friday"];
  const sf06 = (loginHours) => findingById(assessSalesforceIdentityData(goodIdentityData({ profileMetadata: profileMetadataDataset([adminRecord(loginHours)]) }), { now: NOW }), "SF-06");

  const saturdayOnly = sf06({ saturdayStart: "0", saturdayEnd: "60" });
  assert.equal(saturdayOnly.status, "warn", "bounding Saturday alone leaves every other day open and must not pass");
  assert.deepEqual(saturdayOnly.evidence.profiles_with_login_hours, []);
  assert.deepEqual(saturdayOnly.evidence.profiles_with_partial_login_hours, ["System Administrator (unbounded: monday, tuesday, wednesday, thursday, friday, sunday)"]);
  assert.deepEqual(saturdayOnly.evidence.profiles_without_login_hours, []);
  assert.match(saturdayOnly.summary, /0\/1 sensitive profiles restrict login hours on every day of the week; 1 restrict only some days and leave the others open: System Administrator \(unbounded: monday, tuesday, wednesday, thursday, friday, sunday\)/);

  const weekdaysOnly = sf06(hoursFor(weekdays, "420", "1140"));
  assert.equal(weekdaysOnly.status, "warn", "unspecified weekend days are unrestricted");
  assert.match(weekdaysOnly.summary, /unbounded: saturday, sunday/);

  const fullDayWeekend = sf06({ ...hoursFor(weekdays, "420", "1140"), ...hoursFor(["saturday", "sunday"], "0", "1440") });
  assert.equal(fullDayWeekend.status, "warn", "a full-day window is not a restriction");
  assert.match(fullDayWeekend.summary, /unbounded: saturday, sunday/);

  assert.equal(sf06({ ...hoursFor(weekdays, "420", "1140"), ...hoursFor(["saturday", "sunday"], "0", "0") }).status, "pass", "blocked weekend days (start equals end) are bounded");
  assert.equal(sf06(hoursFor(ALL_WEEKDAYS, "480", "1080")).status, "pass");
  assert.equal(sf06(hoursFor(ALL_WEEKDAYS, "0", "1440")).status, "fail");
  assert.equal(sf06(undefined).status, "fail");

  const population = okDataset("Profile metadata", [
    { ...adminRecord(hoursFor(ALL_WEEKDAYS, "480", "1080")), _profileId: "P-admin", _profileName: "System Administrator", _fullName: "Admin", _resolved: true },
    { ...adminRecord({ mondayStart: "480", mondayEnd: "1080" }), fullName: "Ops", _profileId: "P-ops", _profileName: "Ops Admin", _fullName: "Ops", _resolved: true },
    { ...adminRecord(undefined), fullName: "Sec", _profileId: "P-sec", _profileName: "Security Admin", _fullName: "Sec", _resolved: true },
  ]);
  const mixed = findingById(assessSalesforceIdentityData(goodIdentityData({ profileMetadata: population }), { now: NOW }), "SF-06");
  assert.equal(mixed.status, "warn");
  assert.deepEqual(mixed.evidence.profiles_with_login_hours, ["System Administrator"]);
  assert.deepEqual(mixed.evidence.profiles_with_partial_login_hours, ["Ops Admin (unbounded: tuesday, wednesday, thursday, friday, saturday, sunday)"]);
  assert.deepEqual(mixed.evidence.profiles_without_login_hours, ["Security Admin"]);
  assert.match(mixed.summary, /^1\/3 sensitive profiles restrict login hours on every day of the week; 1 restrict only some days and leave the others open: Ops Admin \(unbounded: tuesday, wednesday, thursday, friday, saturday, sunday\); 1 restrict no day\.$/);

  const capped = okDataset("Profile metadata", [population.data[0]], { truncated: true, total: 60 });
  const cappedFinding = findingById(assessSalesforceIdentityData(goodIdentityData({ profileMetadata: capped }), { now: NOW }), "SF-06");
  assert.equal(cappedFinding.status, "warn", "a truncated sensitive profile read never passes");
  assert.match(cappedFinding.summary, /only 1 of 60 sensitive profiles were read/);
});

test("review round 2 fix 2: OauthToken treats the 2500-row cap as a possibly truncated result in evidence and summary", async () => {
  const rows = Array.from({ length: 2500 }, (_, index) => ({ Id: null, AppName: "Auditor", AppMenuItemId: "AM1", UserId: `U${index}`, LastUsedDate: "2026-09-20T10:00:00Z", UseCount: 1 }));
  const queries = [];
  const clientFor = (records) => new SalesforceApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(input);
      if (url.pathname === "/services/data/v64.0/query") {
        queries.push(url.searchParams.get("q"));
        return jsonResponse({ totalSize: records.length, done: true, records });
      }
      return jsonResponse({}, { status: 404 });
    },
  });
  const capped = await clientFor(rows).listOauthTokens();
  assert.match(queries.at(-1), /^SELECT Id, AppName, AppMenuItemId, UserId, LastUsedDate, UseCount FROM OauthToken/);
  assert.equal(capped.records.length, 2500);
  assert.equal(capped.done, true);
  assert.equal(capped.truncated, true, "2500 rows with done=true is the documented cap and must read as possibly truncated");
  const below = await clientFor(rows.slice(0, 2499)).listOauthTokens();
  assert.equal(below.truncated, false);
  const smallLimit = await clientFor(rows).listOauthTokens(50);
  assert.equal(smallLimit.truncated, true, "an explicit smaller limit still reads to the cap so the cap can be detected");

  const cappedResult = assessSalesforceMonitoringData(goodMonitoringData({ oauthTokens: okDataset("OauthToken", rows, { truncated: true }) }));
  const cappedFinding = findingById(cappedResult, "SF-11");
  assert.notEqual(cappedFinding.status, "pass");
  assert.equal(cappedFinding.evidence.oauth_tokens, 2500);
  assert.equal(cappedFinding.evidence.oauth_tokens_possibly_capped, true);
  assert.equal(cappedFinding.evidence.oauth_tokens_truncated, true);
  assert.match(cappedFinding.summary, /OauthToken returned 2500 rows, which is the documented 2500-row cap with no done=false signal, so the token count is possibly truncated/);
  assert.equal(cappedResult.summary.oauth_tokens_possibly_capped, true);

  const noApps = findingById(assessSalesforceMonitoringData(goodMonitoringData({
    connectedApplications: okDataset("ConnectedApplication", []),
    oauthTokens: okDataset("OauthToken", rows, { truncated: true }),
  })), "SF-11");
  assert.equal(noApps.status, "manual");
  assert.equal(noApps.evidence.oauth_tokens_possibly_capped, true);
  assert.match(noApps.summary, /documented 2500-row cap/);

  const partialRead = findingById(assessSalesforceMonitoringData(goodMonitoringData({
    oauthTokens: okDataset("OauthToken", rows.slice(0, 100), { truncated: true, total: 300 }),
  })), "SF-11");
  assert.equal(partialRead.evidence.oauth_tokens_possibly_capped, false);
  assert.equal(partialRead.evidence.oauth_tokens_truncated, true);
  assert.match(partialRead.summary, /Only 100 of 300 OauthToken rows were read, so the token count is incomplete/);

  const complete = assessSalesforceMonitoringData(goodMonitoringData());
  assert.equal(findingById(complete, "SF-11").evidence.oauth_tokens_possibly_capped, false);
  assert.equal(findingById(complete, "SF-11").evidence.oauth_tokens_truncated, false);
  assert.doesNotMatch(findingById(complete, "SF-11").summary, /row cap|rows were read/);
});

test("exportSalesforceAuditBundle writes core_data, analysis, compliance reports, quick reference, zip, and _errors.log on partial failure", async () => {
  const base = createTempBase("grclanker-sf-export-");
  const client = createFullMockClient({
    async listTenantSecrets() { throw forbidden(); },
  });
  const result = await exportSalesforceAuditBundle(client, sampleConfig(), base, { now: NOW });
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.equal(result.findingCount, 20);
  assert.equal(result.errorCount, 1);

  for (const relativePath of [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "_errors.log",
    "core_data/organization.json",
    "core_data/security_settings.json",
    "core_data/users.json",
    "core_data/profile_metadata.json",
    "core_data/caller_permissions.json",
    "core_data/login_history.json",
    "core_data/setup_audit_trail.json",
    "analysis/findings.json",
    "analysis/summary.json",
    "analysis/platform_security.json",
    "analysis/identity_access.json",
    "analysis/data_protection.json",
    "analysis/monitoring_integrations.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp/fedramp_compliance_report.md",
    "compliance/cmmc/cmmc_compliance_report.md",
    "compliance/soc2/soc2_compliance_report.md",
    "compliance/cis/cis_compliance_report.md",
    "compliance/pci_dss/pci_dss_compliance_report.md",
    "compliance/disa_stig/stig_compliance_checklist.md",
    "compliance/irap/irap_compliance_report.md",
    "compliance/ismap/ismap_compliance_report.md",
  ]) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `missing ${relativePath}`);
  }
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 20);
  assert.equal(findings.find((item) => item.id === "SF-16").status, "manual");
  assert.match(readFileSync(join(result.outputDir, "_errors.log"), "utf8"), /TenantSecret read: forbidden/);
  const bundleText = JSON.stringify(readdirSync(result.outputDir, { recursive: true }));
  assertFragmentsAbsent(assert, readFileSync(join(result.outputDir, "metadata.json"), "utf8"), [SAMPLE_ACCESS_TOKEN], "metadata.json");
  assert.ok(bundleText.length > 0);

  const rerun = await exportSalesforceAuditBundle(client, sampleConfig(), base, { now: NOW });
  assert.notEqual(rerun.outputDir, result.outputDir);
  assert.notEqual(rerun.zipPath, result.zipPath);
  assert.equal(rerun.zipPath, `${rerun.outputDir}.zip`);
  assert.ok(existsSync(result.zipPath));
  assert.ok(existsSync(rerun.zipPath));
});

/** Random-looking alphanumeric planted secrets; the bundle and zip scans check every substring of them at lengths 6 through 24. */
const FAKE_SALESFORCE_SECRETS = {
  accessToken: "qnHCnRw8pYkatSZNXj",
  consumerSecret: "deg982tgLeJyLWypFZ",
  privateKey: "6H9X9nDrdanEaDShqe",
  sessionSecret: "bzG37r6jxUXAkc56md",
  samlCertificate: "RCqRLjqNBpR5fGgkQb",
  domainSuffix: "7kLrq8MRAcTg64rfGM",
  ipRangeDescription: "ZXgcx84vAq2twxrCf3",
  profileHash: "xgFzukmt8W36KEYLc6",
  loginSid: "yjRfDyYNx4DgeApW7t",
  startUrlKey: "AHj4JRZH2pFB6rJ2dV",
};

test("rule 9: exportSalesforceAuditBundle projects Metadata API trees so fake secrets never reach the bundle directory or the zip", async () => {
  const base = createTempBase("grclanker-sf-export-secrets-");
  const secrets = Object.values(FAKE_SALESFORCE_SECRETS);
  const config = sampleConfig({
    accessToken: FAKE_SALESFORCE_SECRETS.accessToken,
    consumerSecret: FAKE_SALESFORCE_SECRETS.consumerSecret,
    privateKey: FAKE_SALESFORCE_SECRETS.privateKey,
  });
  const client = createFullMockClient({
    getResolvedConfig: () => config,
    async getSession() { return { accessToken: FAKE_SALESFORCE_SECRETS.accessToken, instanceUrl: "https://acme.my.salesforce.com" }; },
    async readSecuritySettings() {
      return {
        ...securitySettingsFixture({ sessionSettings: { identityConfirmationSecret: FAKE_SALESFORCE_SECRETS.sessionSecret } }),
        singleSignOnSettings: { samlCertificate: FAKE_SALESFORCE_SECRETS.samlCertificate, signingKey: FAKE_SALESFORCE_SECRETS.privateKey },
        networkAccess: { ipRanges: [{ start: "10.0.0.1", end: "10.0.0.254", description: FAKE_SALESFORCE_SECRETS.ipRangeDescription }] },
      };
    },
    async readMyDomainSettings() { return { ...goodPlatformData().myDomainSettings.data, myDomainSuffix: FAKE_SALESFORCE_SECRETS.domainSuffix }; },
    async readProfileMetadata(fullNames) {
      return goodProfileMetadataRecords.filter((record) => fullNames.includes(record.fullName)).map((record) => ({
        ...record,
        loginHours: { ...record.loginHours, note: FAKE_SALESFORCE_SECRETS.sessionSecret },
        loginIpRanges: [{ startAddress: "10.0.0.1", endAddress: "10.0.0.254", description: FAKE_SALESFORCE_SECRETS.profileHash }],
        customPermissions: [{ enabled: "true", name: FAKE_SALESFORCE_SECRETS.samlCertificate }],
      }));
    },
    async listLoginHistory() {
      return queryResult(goodMonitoringData().loginHistory.data.map((login, index) => ({ ...login, LoginUrl: index === 0 ? `acme.my.salesforce.com/?sid=${FAKE_SALESFORCE_SECRETS.loginSid}` : `https://acme.my.salesforce.com/secur/frontdoor.jsp?sid=${FAKE_SALESFORCE_SECRETS.loginSid}#frag` })));
    },
    async listConnectedApplications() {
      return queryResult(goodMonitoringData().connectedApplications.data.map((app) => ({ ...app, StartUrl: `https://app.example.com/start?key=${FAKE_SALESFORCE_SECRETS.startUrlKey}`, MobileStartUrl: `https://m.example.com/start?key=${FAKE_SALESFORCE_SECRETS.startUrlKey}` })));
    },
  });
  const result = await exportSalesforceAuditBundle(client, config, base, { now: NOW });
  assert.equal(result.errorCount, 0);

  const files = readBundleFiles(result.outputDir);
  for (const relativePath of ["core_data/security_settings.json", "core_data/my_domain_settings.json", "core_data/profile_metadata.json", "analysis/platform_security.json", "analysis/identity_access.json", "QUICK_REFERENCE.md"]) {
    assert.ok(files.has(join(...relativePath.split("/"))), `expected ${relativePath}`);
  }
  assertSecretFragmentsAbsent(assert, files, secrets, "bundle directory");
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, files.size, "the zip carries exactly the written files");
  assertSecretFragmentsAbsent(assert, zipEntries, secrets, "zip archive");

  const settings = JSON.parse(files.get(join("core_data", "security_settings.json"))).data;
  assert.equal(settings.sessionSettings.sessionTimeout, "TwoHours");
  assert.equal(settings.sessionSettings.identityConfirmationSecret, undefined);
  assert.equal(settings.passwordPolicies.minimumPasswordLength, "14");
  assert.deepEqual(settings.networkAccess.ipRanges, [{ start: "10.0.0.1", end: "10.0.0.254" }]);
  assert.deepEqual(settings._omittedSections, ["singleSignOnSettings"]);
  const myDomain = JSON.parse(files.get(join("core_data", "my_domain_settings.json"))).data;
  assert.equal(myDomain.myDomainName, "acme");
  assert.deepEqual(myDomain._omittedSections, ["myDomainSuffix"]);
  const admin = JSON.parse(files.get(join("core_data", "profile_metadata.json"))).data.find((record) => record._fullName === "Admin");
  assert.equal(admin._resolved, true);
  assert.deepEqual(admin.loginIpRanges, [{ startAddress: "10.0.0.1", endAddress: "10.0.0.254" }]);
  assert.equal(admin.loginHours.mondayStart, "420");
  assert.equal(admin.loginHours.note, undefined);
  assert.deepEqual(admin._omittedSections, ["customPermissions", "userPermissions"]);

  const findings = JSON.parse(files.get(join("analysis", "findings.json")));
  for (const id of ["SF-02", "SF-03", "SF-05", "SF-06", "SF-18", "SF-19", "SF-20"]) {
    assert.equal(findings.find((item) => item.id === id).status, "pass", `${id} must still pass on the projected trees`);
  }
  // URL fields keep scheme, host, and path only (review round item 11): LoginUrl carries ?sid= and StartUrl can carry ?key=.
  const loginHistory = JSON.parse(files.get(join("core_data", "login_history.json"))).data;
  assert.equal(loginHistory[0].LoginUrl, "acme.my.salesforce.com/");
  assert.equal(loginHistory[1].LoginUrl, "https://acme.my.salesforce.com/secur/frontdoor.jsp");
  const connectedApps = JSON.parse(files.get(join("core_data", "connected_applications.json"))).data;
  assert.equal(connectedApps[0].StartUrl, "https://app.example.com/start");
  assert.equal(connectedApps[0].MobileStartUrl, "https://m.example.com/start");

  assert.equal(projectSecuritySettings(undefined), undefined);
  assert.equal(projectMyDomainSettings(undefined), undefined);
  assert.deepEqual(projectProfileMetadata({ fullName: "Bare" }), { fullName: "Bare", _omittedSections: [] });
});

test("rule 9: SalesforceApiClient never echoes a non-JSON error body into error messages", async () => {
  const fetchImpl = async () => new Response(`<html>gateway down ${FAKE_SALESFORCE_SECRETS.sessionSecret} Bearer ${sampleConfig().accessToken}</html>`, { status: 502, headers: { "content-type": "text/html" } });
  const client = new SalesforceApiClient(sampleConfig({ maxRetries: 0 }), { fetchImpl });
  await assert.rejects(() => client.getLimits(), (error) => {
    assert.equal(error.status, 502);
    assertFragmentsAbsent(assert, error.message, [FAKE_SALESFORCE_SECRETS.sessionSecret, SAMPLE_ACCESS_TOKEN], "502 HTML error message");
    assert.ok(!error.message.includes("gateway down"), error.message);
    assert.match(error.message, /non-JSON body \(text\/html, \d+ bytes\)/);
    return true;
  });
});

test("rule 10: SalesforceApiClient reports truncated with an unknown total on stalled cursors, empty pages, and missing done or totalSize", async () => {
  const pages = new Map();
  const fetchImpl = async (input) => {
    const url = new URL(input);
    const key = url.pathname.endsWith("/query") ? `${url.pathname}?${url.searchParams.get("q")}` : url.pathname;
    const page = pages.get(key);
    return page ? jsonResponse(page) : jsonResponse([{ message: `no fixture for ${key}`, errorCode: "NOT_FOUND" }], { status: 404 });
  };
  const client = new SalesforceApiClient(sampleConfig({ maxRetries: 0 }), { fetchImpl });
  const query = "/services/data/v64.0/query";

  pages.set(`${query}?SELECT Id FROM Stuck`, { totalSize: 10, done: false, nextRecordsUrl: `${query}/stuck-2`, records: [{ Id: "1" }] });
  pages.set(`${query}/stuck-2`, { totalSize: 10, done: false, nextRecordsUrl: `${query}/stuck-2`, records: [{ Id: "2" }] });
  const stuck = await client.query("SELECT Id FROM Stuck");
  assert.deepEqual(stuck.records.map((record) => record.Id), ["1", "2"]);
  assert.equal(stuck.pages, 2, "a repeated nextRecordsUrl is fetched once and never looped");
  assert.equal(stuck.done, false);
  assert.equal(stuck.truncated, true);

  pages.set(`${query}?SELECT Id FROM Empty`, { totalSize: 10, done: false, nextRecordsUrl: `${query}/empty-2`, records: [{ Id: "1" }] });
  pages.set(`${query}/empty-2`, { totalSize: 10, done: false, nextRecordsUrl: `${query}/empty-3`, records: [] });
  const empty = await client.query("SELECT Id FROM Empty");
  assert.equal(empty.pages, 2, "an empty page that still promises more stops the loop");
  assert.equal(empty.done, false);
  assert.equal(empty.truncated, true);

  pages.set(`${query}?SELECT Id FROM NoCursor`, { totalSize: 10, done: false, records: [{ Id: "1" }] });
  const noCursor = await client.query("SELECT Id FROM NoCursor");
  assert.equal(noCursor.truncated, true);
  assert.equal(noCursor.done, false);

  pages.set(`${query}?SELECT Id FROM Bare`, { records: [{ Id: "1" }, { Id: "2" }] });
  const bare = await client.query("SELECT Id FROM Bare");
  assert.equal(bare.records.length, 2);
  assert.equal(bare.totalSize, undefined, "a missing totalSize is not replaced by the page size");
  assert.equal(bare.truncated, true, "a missing done flag and total cannot prove completeness");

  pages.set(`${query}?SELECT Id FROM Inferred`, { totalSize: 3, nextRecordsUrl: `${query}/inferred-2`, records: [{ Id: "1" }, { Id: "2" }] });
  pages.set(`${query}/inferred-2`, { totalSize: 3, done: true, records: [{ Id: "3" }] });
  const inferred = await client.query("SELECT Id FROM Inferred");
  assert.equal(inferred.pages, 2, "a missing done flag with a nextRecordsUrl keeps paginating");
  assert.equal(inferred.truncated, false);
  assert.deepEqual(inferred.records.map((record) => record.Id), ["1", "2", "3"]);

  const identity = await assessSalesforceIdentityAccess(createFullMockClient({
    async listUsers() { return { records: goodUsers, totalSize: undefined, done: true, truncated: true, pages: 1 }; },
  }));
  for (const id of ["SF-07", "SF-10", "SF-13"]) {
    const item = findingById(identity, id);
    assert.notEqual(item.status, "pass", `${id} must not pass on an unknown-total user list: ${item.summary}`);
  }
  assert.match(findingById(identity, "SF-10").summary, /Only 3 of an unknown total of User records were read/);
  assert.match(findingById(identity, "SF-13").summary, /Only 3 of unknown users were read/);
});

test("rule 10: SF-07, SF-09, and SF-10 demote when a secondary list is truncated and state seen versus total", () => {
  const truncated = (name, data, total) => okDataset(name, data, { truncated: true, seen: data.length, total });
  const elevatedSets = [{ Id: "PS-elevated", Name: "Elevated", IsOwnedByProfile: false, PermissionsModifyAllData: true }];
  const noAssignees = okDataset("PermissionSetAssignment", []);

  const completeSets = assessSalesforceIdentityData(goodIdentityData({ permissionSets: okDataset("PermissionSet", elevatedSets), assignments: noAssignees }), { now: NOW });
  assert.equal(findingById(completeSets, "SF-09").status, "pass", "an elevated set with no active assignees passes on a complete list");
  const cappedSets = assessSalesforceIdentityData(goodIdentityData({ permissionSets: truncated("PermissionSet", elevatedSets, 400), assignments: noAssignees }), { now: NOW });
  const sf09 = findingById(cappedSets, "SF-09");
  assert.equal(sf09.status, "warn");
  assert.match(sf09.summary, /Only 1 of 400 PermissionSet records were read/);
  assert.ok(sf09.manualEvidence);
  const cappedAssignments = assessSalesforceIdentityData(goodIdentityData({ permissionSets: okDataset("PermissionSet", elevatedSets), assignments: truncated("PermissionSetAssignment", [], undefined) }), { now: NOW });
  assert.equal(findingById(cappedAssignments, "SF-09").status, "warn");
  assert.match(findingById(cappedAssignments, "SF-09").summary, /Only 0 of an unknown total of PermissionSetAssignment records were read/);

  assert.equal(findingById(assessSalesforceIdentityData(goodIdentityData(), { now: NOW }), "SF-10").status, "pass");
  const cappedProfiles = assessSalesforceIdentityData(goodIdentityData({ profiles: truncated("Profile", goodProfiles, 60) }), { now: NOW });
  const sf10 = findingById(cappedProfiles, "SF-10");
  assert.equal(sf10.status, "warn");
  assert.match(sf10.summary, /Only 8 of 60 Profile records were read/);
  assert.equal(sf10.evidence.profiles_truncated, true);

  assert.equal(findingById(assessSalesforceIdentityData(goodIdentityData(), { now: NOW }), "SF-07").status, "pass");
  const cappedUsers = assessSalesforceIdentityData(goodIdentityData({ users: truncated("User", goodUsers, undefined) }), { now: NOW });
  const sf07 = findingById(cappedUsers, "SF-07");
  assert.equal(sf07.status, "warn");
  assert.match(sf07.summary, /Only 3 of an unknown total of User records were read/);
});

test("rule 1 corollary: multi-inventory findings never pass when a secondary inventory is forbidden and the summary names it", () => {
  const elevatedIdentity = (overrides = {}) => goodIdentityData({
    permissionSets: okDataset("PermissionSet", [{ Id: "PS-elevated", Name: "Elevated", IsOwnedByProfile: false, PermissionsModifyAllData: true }]),
    assignments: okDataset("PermissionSetAssignment", []),
    ...overrides,
  });
  const cases = [
    { id: "SF-01", assess: assessSalesforcePlatformData, data: goodPlatformData, secondaries: [["healthCheckRisks", "SecurityHealthCheckRisks", []]] },
    { id: "SF-05", assess: assessSalesforcePlatformData, data: goodPlatformData, secondaries: [["profiles", "Profile", []], ["profileMetadata", "Profile metadata", []]] },
    {
      id: "SF-04",
      assess: assessSalesforceIdentityData,
      data: goodIdentityData,
      secondaries: [["securitySettings", "SecuritySettings", undefined], ["healthCheckRisks", "SecurityHealthCheckRisks", []], ["twoFactorMethods", "TwoFactorMethodsInfo", []], ["users", "User", []], ["profiles", "Profile", []]],
    },
    { id: "SF-06", assess: assessSalesforceIdentityData, data: goodIdentityData, secondaries: [["profileMetadata", "Profile metadata", []], ["profiles", "Profile", []]] },
    { id: "SF-07", assess: assessSalesforceIdentityData, data: goodIdentityData, secondaries: [["users", "User", []], ["profiles", "Profile", []]] },
    { id: "SF-09", assess: assessSalesforceIdentityData, data: goodIdentityData, secondaries: [["assignments", "PermissionSetAssignment", []], ["users", "User", []], ["profiles", "Profile", []]] },
    { id: "SF-09", assess: assessSalesforceIdentityData, data: elevatedIdentity, secondaries: [["assignments", "PermissionSetAssignment", []]] },
    { id: "SF-10", assess: assessSalesforceIdentityData, data: goodIdentityData, secondaries: [["profiles", "Profile", []]] },
    { id: "SF-13", assess: assessSalesforceIdentityData, data: goodIdentityData, secondaries: [["profiles", "Profile", []]] },
    { id: "SF-11", assess: assessSalesforceMonitoringData, data: goodMonitoringData, secondaries: [["oauthTokens", "OauthToken", []], ["callerPermissions", "UserPermissionAccess", undefined]] },
    { id: "SF-15", assess: assessSalesforceMonitoringData, data: goodMonitoringData, secondaries: [["eventLogFiles", "EventLogFile", []]] },
  ];
  const checked = [];
  for (const { id, assess, data, secondaries } of cases) {
    const baseline = findingById(assess(data(), { now: NOW }), id);
    assert.ok(baseline, `${id} must exist`);
    for (const [key, name, empty] of secondaries) {
      const result = assess(data({ [key]: forbiddenDataset(name, empty) }), { now: NOW });
      const item = findingById(result, id);
      assert.notEqual(item.status, "pass", `${id} must not pass when ${name} is forbidden (baseline ${baseline.status}): ${item.summary}`);
      assert.ok(item.summary.includes(`the ${name} query was forbidden`), `${id} summary must name ${name}: ${item.summary}`);
      assert.ok(item.manualEvidence, `${id} must tell a human what to collect when ${name} is forbidden`);
      assert.ok(result.errors.some((error) => error.startsWith(`${name} read: forbidden`)), `${id} errors must disclose ${name}`);
      checked.push(`${id}/${name}`);
    }
  }
  assert.equal(checked.length, 21, "every secondary inventory of every multi-inventory finding was exercised");

  const mfa = findingById(assessSalesforceIdentityData(goodIdentityData({ securitySettings: forbiddenDataset("SecuritySettings", undefined) }), { now: NOW }), "SF-04");
  assert.equal(mfa.status, "warn", "Health Check still proves the MFA requirement, so the verdict is judged from it and capped at warn");
  assert.match(mfa.summary, /second source was not checked and the verdict is capped at warn/);
  const eventLog = findingById(assessSalesforceMonitoringData(goodMonitoringData({ eventLogFiles: forbiddenDataset("EventLogFile", []) })), "SF-15");
  assert.equal(eventLog.status, "warn");
  assert.match(eventLog.manualEvidence, /Event Manager/);
  const permissionSets = findingById(assessSalesforceIdentityData(goodIdentityData({ assignments: forbiddenDataset("PermissionSetAssignment", []) }), { now: NOW }), "SF-09");
  assert.equal(permissionSets.status, "warn");
  assert.match(permissionSets.summary, /assignment coverage of the permission sets that were read was not checked/);
  const noSource = findingById(assessSalesforceIdentityData(goodIdentityData({
    securitySettings: okDataset("SecuritySettings", securitySettingsFixture({ sessionSettings: { enableMFADirectUILoginOptIn: undefined } })),
    healthCheckRisks: forbiddenDataset("SecurityHealthCheckRisks", []),
  }), { now: NOW }), "SF-04");
  assert.equal(noSource.status, "manual");
  assert.match(noSource.summary, /the SecurityHealthCheckRisks query was forbidden/);
});

test("round 2 SEND BACK 3: leaf diff per denial, the SF-01, SF-09, and SF-11 leaves derived from a denied dataset render null and no other leaf becomes an empty reading", () => {
  // SF-01 under SecurityHealthCheckRisks denied: the score stays, every risk-derived leaf is null.
  const platformBaseline = findingById(assessSalesforcePlatformData(goodPlatformData()), "SF-01");
  const risksDenied = findingById(assessSalesforcePlatformData(goodPlatformData({ healthCheckRisks: forbiddenDataset("SecurityHealthCheckRisks", []) })), "SF-01");
  assert.deepEqual(platformBaseline.evidence.high_risk_settings, [], "the healthy fixture has no high risk (a complete empty reading)");
  assert.equal(platformBaseline.evidence.settings_evaluated, 1);
  assertLeavesNullUnderDenial(assert, {
    label: "SF-01 under listHealthCheckRisks denied",
    baseline: platformBaseline.evidence,
    denied: risksDenied.evidence,
    nullLeaves: ["high_risk_settings", "medium_risk_settings", "settings_evaluated", "risks_truncated"],
  });
  assert.equal(risksDenied.evidence.score, 95, "the readable score is kept");
  assert.equal(risksDenied.status, "manual");
  assert.match(risksDenied.summary, /the per-setting risk list could not be read because the SecurityHealthCheckRisks query was forbidden/);

  // SF-09 under PermissionSetAssignment denied, with and without elevated permission sets.
  const elevatedSets = [{ Id: "PS-god", Name: "God Mode", IsOwnedByProfile: false, PermissionsModifyAllData: true }];
  for (const [label, overrides] of [
    ["no elevated set", {}],
    ["an elevated set", { permissionSets: okDataset("PermissionSet", elevatedSets), assignments: okDataset("PermissionSetAssignment", [{ Id: "A1", AssigneeId: "U2", PermissionSetId: "PS-god", Assignee: { IsActive: true } }]) }],
  ]) {
    const identityBaseline = findingById(assessSalesforceIdentityData(goodIdentityData(overrides), { now: NOW }), "SF-09");
    const assignmentsDenied = findingById(assessSalesforceIdentityData(goodIdentityData({ ...overrides, assignments: forbiddenDataset("PermissionSetAssignment", []) }), { now: NOW }), "SF-09");
    assert.equal(identityBaseline.evidence.assignments_truncated, false, `${label}: the healthy read is complete`);
    assertLeavesNullUnderDenial(assert, {
      label: `SF-09 (${label}) under listPermissionSetAssignments denied`,
      baseline: identityBaseline.evidence,
      denied: assignmentsDenied.evidence,
      nullLeaves: ["assignments_truncated", "elevated_assignments", "distinct_assignees"],
    });
    assert.equal(assignmentsDenied.evidence.permission_sets, identityBaseline.evidence.permission_sets, `${label}: the readable permission set count is kept`);
    assert.equal(assignmentsDenied.evidence.permission_sets_truncated, false, `${label}: the readable list's own flag is kept`);
  }

  // SF-11 under OauthToken denied: every token-derived count and flag is null; the connected app read keeps its own flag under its own name.
  const monitoringBaseline = findingById(assessSalesforceMonitoringData(goodMonitoringData()), "SF-11");
  const tokensDenied = findingById(assessSalesforceMonitoringData(goodMonitoringData({ oauthTokens: forbiddenDataset("OauthToken", []) })), "SF-11");
  assert.equal(monitoringBaseline.evidence.oauth_tokens, 1);
  assert.equal(monitoringBaseline.evidence.oauth_tokens_partial_view, false);
  assert.deepEqual(monitoringBaseline.evidence.tokens_by_app, { Auditor: 1 });
  assertLeavesNullUnderDenial(assert, {
    label: "SF-11 under listOauthTokens denied",
    baseline: monitoringBaseline.evidence,
    denied: tokensDenied.evidence,
    nullLeaves: ["oauth_tokens", "oauth_tokens_partial_view", "oauth_tokens_possibly_capped", "oauth_tokens_truncated", "tokens_by_app"],
  });
  assert.equal(tokensDenied.evidence.connected_applications_truncated, false, "the connected app list was read completely and its flag names its source");
  assert.equal("truncated" in tokensDenied.evidence, false, "no bare truncated flag is rendered");
  assert.equal(tokensDenied.evidence.caller_has_customize_application, monitoringBaseline.evidence.caller_has_customize_application);
  assert.match(tokensDenied.summary, /OAuth token usage was not checked because the OauthToken query was forbidden/);
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-sf-path-");
  const outside = createTempBase("grclanker-sf-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);
  const safe = resolveSecureOutputPath(base, join("compliance", "safe.txt"));
  assert.match(safe, /compliance\/safe\.txt$/);
});

test("Salesforce tools are registered in the catalog under the Salesforce group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("salesforce_"));
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [
    "salesforce_assess_data_protection",
    "salesforce_assess_identity_access",
    "salesforce_assess_monitoring_integrations",
    "salesforce_assess_platform_security",
    "salesforce_check_access",
    "salesforce_export_audit_bundle",
  ]);
  for (const tool of tools) {
    assert.equal(tool.group, "Salesforce");
    assert.equal(tool.kind, "domain");
    assert.ok(tool.parameterSummaries.some((parameter) => parameter.name === "instance_url"));
  }
});

test("review round item 1: SF-04 never names users as lacking MFA from a truncated TwoFactorMethodsInfo or User read and stops at warn", () => {
  const partialMethods = okDataset("TwoFactorMethodsInfo", [goodTwoFactor[0]], { truncated: true, seen: 1, total: 43 });
  const capped = findingById(assessSalesforceIdentityData(goodIdentityData({ twoFactorMethods: partialMethods }), { now: NOW }), "SF-04");
  assert.equal(capped.status, "warn", `a partial enrollment read stops at warn: ${capped.summary}`);
  assert.equal(capped.evidence.sample_users_without_mfa, null);
  assert.equal(capped.evidence.users_without_registered_mfa_method, null);
  assert.equal(capped.evidence.two_factor_methods_possibly_capped, true);
  assert.match(capped.evidence.principals_withheld, /^TwoFactorMethodsInfo returned 1 of 43 rows; users without a registered method are not named from a partial read$/);
  assert.match(capped.summary, /the read was partial \(TwoFactorMethodsInfo returned 1 of 43 rows\), so the unread rows could hold their enrollments and the count and names are withheld/);
  assert.match(capped.summary, /TwoFactorMethodsInfo returned 1 rows, while the query reported 43 in total, so enrollment coverage is incomplete/);
  assert.doesNotMatch(JSON.stringify(capped), /user@acme\.example|admin@acme\.example/, "no user is named from a partial read");

  const partialUsers = okDataset("User", [goodUsers[0], goodUsers[1], { Id: "U9", Username: "nomfa@acme.example", IsActive: true, UserType: "Standard", ProfileId: "P-std", LastLoginDate: "2026-09-19T10:00:00Z", CreatedDate: "2021-01-01T00:00:00Z" }], { truncated: true, seen: 3, total: 90 });
  const users = findingById(assessSalesforceIdentityData(goodIdentityData({ users: partialUsers }), { now: NOW }), "SF-04");
  assert.equal(users.status, "warn");
  assert.equal(users.evidence.sample_users_without_mfa, null);
  assert.match(users.evidence.principals_withheld, /^User returned 3 of 90 rows;/);
  assert.doesNotMatch(JSON.stringify(users), /nomfa@acme\.example/);

  const documentedCap = okDataset("TwoFactorMethodsInfo", Array.from({ length: 2500 }, (_, index) => ({ UserId: `X${index}`, HasTotp: true })), { truncated: true });
  const atCap = findingById(assessSalesforceIdentityData(goodIdentityData({ twoFactorMethods: documentedCap }), { now: NOW }), "SF-04");
  assert.match(atCap.summary, /TwoFactorMethodsInfo returned 2500 rows, which is the documented 2500-row cap, so enrollment coverage is incomplete/);

  const complete = findingById(assessSalesforceIdentityData(goodIdentityData({
    users: okDataset("User", [...goodUsers, { Id: "U9", Username: "nomfa@acme.example", IsActive: true, UserType: "Standard", ProfileId: "P-std", LastLoginDate: "2026-09-19T10:00:00Z", CreatedDate: "2021-01-01T00:00:00Z" }]),
  }), { now: NOW }), "SF-04");
  assert.equal(complete.status, "fail", "a complete read still names and counts the unenrolled users");
  assert.deepEqual(complete.evidence.sample_users_without_mfa, ["nomfa@acme.example"]);
  assert.equal(complete.evidence.users_without_registered_mfa_method, 1);
  assert.equal(complete.evidence.principals_withheld, null);
});

test("review round item 10: SF-14 and SF-07 stop at warn on a capped read and state no absence count over the unread rows", () => {
  const oneLogin = okDataset("LoginHistory", [{ Id: "L1", UserId: "U1", LoginTime: "2026-09-20T10:00:00Z", Status: "Invalid Password", SourceIp: "10.0.0.5", CountryIso: "US", TlsProtocol: "TLS 1.3" }], { truncated: true, seen: 1, total: 80 });
  const logins = findingById(assessSalesforceMonitoringData(goodMonitoringData({ loginHistory: oneLogin })), "SF-14");
  assert.equal(logins.status, "warn", `a one-row capped read cannot fail: ${logins.summary}`);
  assert.match(logins.summary, /^1 of 80 logins in 30 days were read: 1 failures among the visible rows \(ratio not stated from a partial read\), sources with 10\+ failures: unknown from the visible rows, 1 countries seen, legacy TLS logins: unknown from the visible rows\. The verdict is capped at warn/);
  assert.equal(logins.evidence.failure_ratio, null);
  assert.equal(logins.evidence.brute_force_sources, null);
  assert.equal(logins.evidence.legacy_tls_logins, null);
  assert.equal(logins.evidence.rows_without_login_time, null);
  assert.equal(logins.evidence.failed_logins, 1, "an observed failure is real");
  const legacy = findingById(assessSalesforceMonitoringData(goodMonitoringData({ loginHistory: okDataset("LoginHistory", [{ ...oneLogin.data[0], TlsProtocol: "TLS 1.0" }], { truncated: true, seen: 1, total: 80 }) })), "SF-14");
  assert.equal(legacy.status, "warn");
  assert.equal(legacy.evidence.legacy_tls_logins, 1, "a positive sighting is stated even on a partial read");
  assert.match(legacy.summary, /1 legacy TLS logins/);

  const oneProfile = okDataset("Profile", [goodProfiles[0]], { truncated: true, seen: 1, total: 48 });
  const profiles = findingById(assessSalesforceIdentityData(goodIdentityData({ profiles: oneProfile }), { now: NOW }), "SF-07");
  assert.equal(profiles.status, "warn", `a one-row capped profile read cannot fail: ${profiles.summary}`);
  assert.equal(profiles.evidence.api_only_profiles, null);
  assert.equal(profiles.evidence.profiles_total, 48);
  assert.match(profiles.summary, /1\/1 visible profiles grant API Enabled covering 1 visible active users; no API Only User profile was among the visible rows, which a partial read cannot confirm/);
  assert.match(profiles.summary, /The ratio is over the visible rows only, so the verdict is capped at warn/);
  const completeProfiles = findingById(assessSalesforceIdentityData(goodIdentityData({ profiles: okDataset("Profile", goodProfiles.map((profile) => ({ ...profile, PermissionsApiEnabled: true }))) }), { now: NOW }), "SF-07");
  assert.equal(completeProfiles.status, "fail", "a complete read keeps the ratio verdict");
});

test("review round item 9: denied Salesforce datasets are written as not-collected markers and every derived count renders null", async () => {
  const base = createTempBase("grclanker-sf-markers-");
  const deny = async () => {
    const error = forbidden();
    error.endpoint = "/services/data/v64.0/query";
    throw error;
  };
  const client = createFullMockClient({ listUsers: deny, listProfileMetadata: deny, listLoginHistory: deny, listOauthTokens: deny, getCallerPermissions: deny });
  const result = await exportSalesforceAuditBundle(client, sampleConfig(), base, { now: NOW });
  const files = readBundleFiles(result.outputDir);
  const read = (relativePath) => JSON.parse(files.get(join(...relativePath.split("/"))));

  for (const [file, dataset] of [["core_data/users.json", "User"], ["core_data/profile_metadata.json", "Profile metadata"], ["core_data/login_history.json", "LoginHistory"], ["core_data/oauth_tokens.json", "OauthToken"], ["core_data/caller_permissions.json", "UserPermissionAccess"]]) {
    const marker = read(file);
    assert.equal(marker.collected, false, `${file} is a marker`);
    assert.equal(marker.dataset, dataset);
    assert.equal(marker.status, "forbidden");
    assert.equal(marker.http_status, 403);
    assert.equal(marker.endpoint, "/services/data/v64.0/query");
    assert.match(marker.error, /INSUFFICIENT_ACCESS/);
    assert.equal(marker.data, undefined, `${file} carries no data array`);
    assert.equal(marker.seen, undefined, `${file} carries no seen count`);
    assert.equal(marker.truncated, undefined, `${file} carries no truncated flag`);
  }
  const profilesFile = read("core_data/profiles.json");
  assert.equal(profilesFile.status, "ok");
  assert.equal(profilesFile.data.length, goodProfiles.length, "a readable dataset keeps its snapshot shape");

  const access = read("core_data/access_check.json");
  for (const surface of access.surfaces) {
    if (surface.status === "not_readable") assert.equal(surface.count, undefined, `${surface.name} carries no count when denied`);
  }
  assert.equal(access.surfaces.find((surface) => surface.name === "caller_permissions").count, undefined);

  const identity = read("analysis/identity_access.json");
  for (const key of ["users", "users_total", "active_users", "users_truncated"]) assert.equal(identity.summary[key], null, `identity summary ${key} renders null under the User denial`);
  assert.equal(identity.summary.profiles, goodProfiles.length, "a readable dataset keeps its count");
  assert.equal(identity.summary.sensitive_profiles_read, null);
  assert.match(identity.summary.inventories.User, /^User read: unread \(forbidden: /);
  assert.match(identity.summary.inventories.Profile, /^Profile read: complete \(\d+ rows\)$/);
  for (const id of ["SF-04", "SF-07", "SF-09", "SF-10", "SF-13"]) {
    const item = identity.findings.find((finding) => finding.id === id);
    assert.equal(item.status, "manual", `${id} is manual under the User denial`);
    for (const key of ["users_seen", "active_users", "active_admins_seen"]) {
      if (key in item.evidence) assert.equal(item.evidence[key], null, `${id} ${key} renders null under the User denial`);
    }
  }
  const monitoring = read("analysis/monitoring_integrations.json");
  for (const key of ["oauth_tokens", "oauth_tokens_partial_view", "oauth_tokens_possibly_capped", "login_rows", "login_rows_total"]) assert.equal(monitoring.summary[key], null, `monitoring summary ${key} renders null`);
  assert.equal(monitoring.summary.audit_rows, 1, "a readable dataset keeps its count");
  const platform = read("analysis/platform_security.json");
  const ipRanges = platform.findings.find((finding) => finding.id === "SF-05");
  assert.equal(ipRanges.status, "manual");
  for (const key of ["sensitive_profiles_read", "profiles_with_login_ip_ranges", "profiles_without_login_ip_ranges", "profile_metadata_truncated"]) assert.equal(ipRanges.evidence[key], null, `SF-05 ${key} renders null when profile metadata is unread`);
  assert.match(ipRanges.evidence.profile_metadata_error, /INSUFFICIENT_ACCESS/);
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(JSON.parse(zipEntries.get(join("core_data", "users.json"))).collected, false, "the zip carries the marker too");

  // A Profile list denial cascades: the dependent profile metadata read is never requested and its marker names the parent.
  const cascade = await exportSalesforceAuditBundle(createFullMockClient({ listProfiles: deny }), sampleConfig(), createTempBase("grclanker-sf-cascade-"), { now: NOW });
  const cascadeFiles = readBundleFiles(cascade.outputDir);
  const metadataMarker = JSON.parse(cascadeFiles.get(join("core_data", "profile_metadata.json")));
  assert.equal(metadataMarker.collected, false);
  assert.match(metadataMarker.error, /^not requested: the Profile list was not readable \(.*INSUFFICIENT_ACCESS.*\), so there were no sensitive profiles to read$/);
  assert.equal(metadataMarker.http_status, 403, "the marker carries the parent's status");
});

/** Random-looking alphanumeric canaries; the leak assertions check every substring of them at lengths 6 through 24. */
const SF_CANARY = {
  bearer: "kgzGTsB2sU5cCUKCXz",
  cookie: "FYGJh9Bzbd35bRrBPs",
  apiKey: "KM9PbWt6WxhFxCkaJf",
  urlToken: "nL9EVdZszdTMtgLeS4",
  // The configured password-grant credentials of the canary client, remembered by the constructor.
  password: "Yk63nyEVp6krSwMWtv",
  securityToken: "k2DAkV4Bbutx9hV3YH",
  consumerSecret: "jPuTG7AJfujrN9L4nJ",
};
const SF_CANARY_VALUES = Object.values(SF_CANARY);
const SF_CANARY_URL = `https://api.example.com/v1/x?token=${SF_CANARY.urlToken}`;

function sfCanaryHtml() {
  return [
    "<html><head><title>502 Bad Gateway</title></head><body>",
    `<p>Upstream rejected Authorization: Bearer ${SF_CANARY.bearer} while proxying.</p>`,
    `<p>Set-Cookie: sid=${SF_CANARY.cookie}; Path=/; Secure</p>`,
    `<p>x-api-key: ${SF_CANARY.apiKey}</p>`,
    `<p>Retry the request at ${SF_CANARY_URL} after the gateway recovers.</p>`,
    "</body></html>",
  ].join("");
}

function sfCanaryFetch(failing) {
  const org = goodOrganization;
  const platform = goodPlatformData();
  const identity = goodIdentityData();
  const dataProtection = goodDataProtectionData();
  const monitoring = goodMonitoringData();
  const soqlObject = (query) => query.match(/\bFROM\s+(\w+)/i)?.[1];
  const queryFixtures = {
    Organization: [org],
    SecurityHealthCheck: [{ Score: 95 }],
    SecurityHealthCheckRisks: platform.healthCheckRisks.data,
    User: identity.users.data,
    Profile: identity.profiles.data,
    PermissionSet: identity.permissionSets.data,
    PermissionSetAssignment: identity.assignments.data,
    TwoFactorMethodsInfo: identity.twoFactorMethods.data,
    FieldPermissions: dataProtection.fieldPermissions.data,
    TenantSecret: dataProtection.tenantSecrets.data,
    Certificate: dataProtection.certificates.data,
    ConnectedApplication: monitoring.connectedApplications.data,
    OauthToken: monitoring.oauthTokens.data,
    UserPermissionAccess: [goodCallerPermissions],
    LoginHistory: monitoring.loginHistory.data,
    SetupAuditTrail: monitoring.setupAuditTrail.data,
    EventLogFile: monitoring.eventLogFiles.data,
  };
  const fail = (surface) => {
    if (failing.surface !== surface) return undefined;
    if (failing.flavor === "html") return new Response(sfCanaryHtml(), { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
    // Credential-free failure flavors for the fixed-text harvest: a plain proxy page, an unrecognized JSON shape, a documented error.
    if (failing.flavor === "plainHtml") return new Response("<html><head><title>502 Bad Gateway</title></head><body>upstream unavailable</body></html>", { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
    if (failing.flavor === "opaqueJson") return jsonResponse({ unexpected: { shape: true } }, { status: 403 });
    if (failing.flavor === "plainJson") return jsonResponse([{ errorCode: "INSUFFICIENT_ACCESS", message: "insufficient access rights on object id" }], { status: 403 });
    return jsonResponse([{ errorCode: "SERVER_ERROR", message: `Upstream failed; retry at ${SF_CANARY_URL} with Bearer ${SF_CANARY.bearer} (sid=${SF_CANARY.cookie})` }], { status: 403 });
  };
  const soapResult = (operation, records) => xmlResponse(`${SOAP_ENVELOPE_OPEN}<${operation}Response><result>${records}</result></${operation}Response>${SOAP_ENVELOPE_CLOSE}`);
  return async (input, init = {}) => {
    const url = new URL(String(input));
    if (url.pathname === "/services/oauth2/token") {
      return fail("oauth2/token") ?? jsonResponse({ access_token: "token-live-1234567890", instance_url: "https://acme.my.salesforce.com" });
    }
    if (url.pathname.endsWith("/limits")) return fail("limits") ?? jsonResponse({ DailyApiRequests: { Max: 100000, Remaining: 99000 } });
    if (/\/sobjects\/\w+\/describe$/.test(url.pathname)) {
      const object = url.pathname.split("/").at(-2);
      const fields = Object.keys(Object.assign({}, ...(queryFixtures[object] ?? [{}]))).map((name) => ({ name }));
      return fail(`describe:${object}`) ?? jsonResponse({ name: object, fields });
    }
    if (url.pathname.endsWith("/query") || url.pathname.endsWith("/tooling/query")) {
      const soql = url.searchParams.get("q") ?? "";
      const object = soqlObject(soql);
      const records = queryFixtures[object] ?? [];
      return fail(`query:${object}`) ?? jsonResponse({ totalSize: records.length, done: true, records });
    }
    if (url.pathname.startsWith("/services/Soap/m/")) {
      const body = String(init.body ?? "");
      if (body.includes("<met:listMetadata>")) {
        return fail("soap:listMetadata") ?? soapResult("listMetadata", goodProfileListing.map((item) => `<id>${item.id}</id><fullName>${item.fullName}</fullName>`).join("</result><result>"));
      }
      const type = body.match(/<met:type>(\w+)<\/met:type>/)?.[1];
      if (type === "SecuritySettings") return fail("soap:readMetadata:SecuritySettings") ?? soapResult("readMetadata", "<records xsi:type=\"SecuritySettings\"><sessionSettings><sessionTimeout>TwoHours</sessionTimeout><enableMFADirectUILoginOptIn>true</enableMFADirectUILoginOptIn></sessionSettings></records>");
      if (type === "MyDomainSettings") return fail("soap:readMetadata:MyDomainSettings") ?? soapResult("readMetadata", "<records xsi:type=\"MyDomainSettings\"><myDomainName>acme</myDomainName></records>");
      if (type === "Profile") return fail("soap:readMetadata:Profile") ?? soapResult("readMetadata", "<records xsi:type=\"Profile\"><fullName>Admin</fullName></records>");
    }
    return jsonResponse([{ errorCode: "NOT_FOUND", message: "not found" }], { status: 404 });
  };
}

const SF_CANARY_SURFACES = [
  "oauth2/token", "limits", "soap:listMetadata", "soap:readMetadata:SecuritySettings", "soap:readMetadata:MyDomainSettings", "soap:readMetadata:Profile",
  ...["Organization", "SecurityHealthCheck", "SecurityHealthCheckRisks", "User", "Profile", "PermissionSet", "PermissionSetAssignment", "TwoFactorMethodsInfo", "FieldPermissions", "TenantSecret", "Certificate", "ConnectedApplication", "OauthToken", "UserPermissionAccess", "LoginHistory", "SetupAuditTrail", "EventLogFile"].map((object) => `query:${object}`),
];

/** No canary survives in any substring at lengths 6 through 24. */
function assertSfCanariesAbsent(text, label) {
  assertFragmentsAbsent(assert, text, SF_CANARY_VALUES, label);
}

test("rule 9 error strings: on every Salesforce surface a 502 HTML body or a JSON error embedding a credential URL never reaches results or the bundle", async () => {
  const errorStrings = [];
  let surfacesWithErrors = 0;
  for (const surface of SF_CANARY_SURFACES) {
    for (const flavor of ["html", "json"]) {
      const client = new SalesforceApiClient(sampleConfig({ authMode: "password", username: "auditor@acme.example", password: SF_CANARY.password, securityToken: SF_CANARY.securityToken, consumerKey: "ck", consumerSecret: SF_CANARY.consumerSecret }), { fetchImpl: sfCanaryFetch({ surface, flavor }), sleep: async () => {}, now: () => NOW });
      const access = await checkSalesforceAccess(client);
      const assessments = [];
      for (const assess of [assessSalesforcePlatformSecurity, assessSalesforceIdentityAccess, assessSalesforceDataProtection, assessSalesforceMonitoringIntegrations]) {
        assessments.push(await assess(client, { now: NOW }));
      }
      const base = createTempBase("grclanker-sf-canary-");
      const exported = await exportSalesforceAuditBundle(client, client.getResolvedConfig(), base, { now: NOW });
      const files = readBundleFiles(exported.outputDir);
      const zipEntries = readZipEntries(exported.zipPath);
      const label = `${surface}/${flavor}`;
      assertSfCanariesAbsent(JSON.stringify(access), `${label} check_access`);
      assertSfCanariesAbsent(JSON.stringify(assessments), `${label} assessments`);
      for (const [path, content] of files) assertSfCanariesAbsent(content, `${label} bundle file ${path}`);
      for (const [path, content] of zipEntries) assertSfCanariesAbsent(content, `${label} zip entry ${path}`);
      const surfaceErrors = [
        ...access.surfaces.filter((item) => item.error).map((item) => item.error),
        ...assessments.flatMap((assessment) => assessment.errors),
        ...(files.has("_errors.log") ? [files.get("_errors.log")] : []),
      ];
      assert.ok(surfaceErrors.length > 0, `${label} recorded at least one error`);
      surfacesWithErrors += 1;
      const joined = surfaceErrors.join("\n");
      if (flavor === "html") {
        assert.match(joined, /\(502\)[^\n]*non-(JSON|SOAP) body \(text\/html, \d+ bytes\)/, `${label} error strings carry the status-and-length note: ${joined.slice(0, 400)}`);
      } else if (surface.startsWith("soap:")) {
        // A JSON body on a SOAP endpoint carries no fault string, so it is described by shape rather than quoted.
        assert.match(joined, /\(403\)[^\n]*non-SOAP body \(application\/json, \d+ bytes\)/, `${label} error strings carry the status-and-length note: ${joined.slice(0, 400)}`);
      } else {
        assert.match(joined, /https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\]/, `${label} error strings keep the URL host with the query string redacted: ${joined.slice(0, 400)}`);
      }
      errorStrings.push(joined);
    }
  }
  assert.equal(surfacesWithErrors, SF_CANARY_SURFACES.length * 2, "every surface and both flavors were exercised");
  assertSfCanariesAbsent(errorStrings.join("\n"), "collected error strings");
});

test("planted values self-check: every canary and planted secret is alphanumeric, distinct in every 6-character window, and no window occurs in the healthy fixtures, the sample configuration, or a healthy bundle", async () => {
  const base = createTempBase("grclanker-sf-planted-self-check-");
  const result = await exportSalesforceAuditBundle(createFullMockClient(), sampleConfig(), base, { now: NOW });
  assert.equal(result.errorCount, 0);
  assertPlantedValuesWellFormed(assert, {
    ...Object.fromEntries(Object.entries(SF_CANARY).map(([name, value]) => [`SF_CANARY.${name}`, value])),
    ...Object.fromEntries(Object.entries(FAKE_SALESFORCE_SECRETS).map(([name, value]) => [`FAKE_SALESFORCE_SECRETS.${name}`, value])),
    ...Object.fromEntries(Object.entries(CONFIG_CANARIES).map(([name, value]) => [`CONFIG_CANARIES.${name}`, value])),
    SAMPLE_ACCESS_TOKEN,
  }, [
    ["identity fixture", JSON.stringify(goodIdentityData())],
    ["platform fixture", JSON.stringify(goodPlatformData())],
    ["data protection fixture", JSON.stringify(goodDataProtectionData())],
    ["monitoring fixture", JSON.stringify(goodMonitoringData())],
    ["security settings fixture", JSON.stringify(securitySettingsFixture())],
    ["sample configuration", JSON.stringify({ ...sampleConfig(), accessToken: null })],
    ...[...readBundleFiles(result.outputDir)].map(([name, content]) => [`healthy bundle ${name}`, content]),
  ]);
});

/** Every SOQL object and metadata type the Salesforce collectors read, as the summaries name them. */
const SALESFORCE_DATASETS = [
  "Organization", "SecurityHealthCheck", "SecurityHealthCheckRisks", "User", "Profile", "PermissionSet", "PermissionSetAssignment",
  "TwoFactorMethodsInfo", "FieldPermissions", "TenantSecret", "Certificate", "ConnectedApplication", "OauthToken", "UserPermissionAccess",
  "LoginHistory", "SetupAuditTrail", "EventLogFile", "SecuritySettings", "MyDomainSettings", "ProfileMetadata",
];

const SF_SAMPLE_DENIAL = "Salesforce request /services/data/v64.0/query failed (403) INSUFFICIENT_ACCESS: insufficient access rights on object id";

/**
 * The standing fixed texts Salesforce emits, rendered with sample paths and names: the credentials loader
 * read and parse messages, the non-JSON, non-SOAP, and opaque-body notes, the timeout, the `read:` dataset
 * states, the `not requested:` and withheld wordings, the access-check notes, and the corollary summary
 * templates. Each must come back from SalesforceApiError's pass unchanged.
 */
const SALESFORCE_FIXED_TEXTS = [
  // The resolver's own messages, which reach check_access, assess, and export results live.
  "Salesforce credentials are required: JWT bearer (SF_CONSUMER_KEY, SF_USERNAME, SF_PRIVATE_KEY_FILE), username-password (SF_USERNAME, SF_PASSWORD, SF_SECURITY_TOKEN, SF_CONSUMER_KEY, SF_CONSUMER_SECRET), a refresh token, an access token with SF_INSTANCE_URL, or SF_CREDENTIALS_FILE.",
  "JWT bearer flow requires SF_CONSUMER_KEY, SF_USERNAME, and SF_PRIVATE_KEY_FILE (or SF_PRIVATE_KEY).",
  "Username-password flow requires SF_USERNAME, SF_PASSWORD, SF_CONSUMER_KEY, and SF_CONSUMER_SECRET (SF_SECURITY_TOKEN when the login IP is not trusted).",
  "Refresh token flow requires SF_REFRESH_TOKEN and SF_CONSUMER_KEY (plus SF_CONSUMER_SECRET unless the connected app skips the secret).",
  "Access token mode requires SF_ACCESS_TOKEN and SF_INSTANCE_URL.",
  "PEM private key path for the JWT bearer flow. Defaults to SF_PRIVATE_KEY_FILE.",
  "Pre-issued access token (requires instance_url). Defaults to SF_ACCESS_TOKEN.",
  "Setup > Apps > Connected Apps > Manage Connected Apps: for each app record Permitted Users, IP Relaxation, Refresh Token Policy, and OAuth scopes; Setup > Connected Apps OAuth Usage: review apps with active tokens.",
  "Unable to read Salesforce credentials file /home/svc/.salesforce/credentials.json (ENOENT)",
  "Unable to read Salesforce credentials file /tmp/grclanker-salesforce-loader-Ab3dEf/directory.json (EISDIR)",
  "Unable to read Salesforce credentials file /tmp/grclanker-salesforce-loader-Ab3dEf/locked.json (EACCES)",
  "Unable to parse Salesforce credentials file: invalid JSON in /tmp/grclanker-salesforce-loader-Ab3dEf/short.json",
  "Unable to parse Salesforce credentials file: invalid JSON in /tmp/grclanker-salesforce-loader-Ab3dEf/trailing-comma.json at line 3",
  "Unable to parse Salesforce credentials file: /home/svc/.salesforce/credentials.json must contain a JSON object",
  "Unable to read Salesforce private key file /home/svc/.salesforce/server.key (ENOENT)",
  "Salesforce request /services/data/v64.0/query failed (502): non-JSON body (text/html, 5120 bytes)",
  "Salesforce request /services/data/v64.0/sobjects/User/describe failed (403): JSON body without a recognized error field (application/json, 27 bytes)",
  "Salesforce request /services/data/v64.0/limits returned a non-JSON body (text/html, 5120 bytes) with status 200",
  "Salesforce token request failed (502): non-JSON body (text/html, 5120 bytes)",
  "Salesforce token request failed (400) invalid_grant: authentication failure",
  "Salesforce Metadata API readMetadata(SecuritySettings) failed (502): non-SOAP body (text/html, 5120 bytes)",
  "Salesforce Metadata API listMetadata(Profile) failed (403): SOAP body without a fault string (text/xml, 210 bytes)",
  "Salesforce Metadata API readMetadata(Profile) failed (500) INSUFFICIENT_ACCESS: insufficient access rights",
  "Salesforce request to /services/data/v64.0/query timed out after 30000 ms",
  SF_SAMPLE_DENIAL,
  `User read: unread (forbidden: ${SF_SAMPLE_DENIAL})`,
  `TenantSecret read: unread (forbidden: ${SF_SAMPLE_DENIAL})`,
  `TenantSecret read: forbidden (${SF_SAMPLE_DENIAL})`,
  "OauthToken read: partial (2000 of an unknown total of rows)",
  "SetupAuditTrail read: partial (2000 of 48213 rows)",
  "Profile read: complete (12 rows)",
  "Organization read: complete (1 row)",
  "ProfileMetadata read: error (not requested: the Profile list was not readable (forbidden), so there were no sensitive profiles to read)",
  "not requested: the Profile list was not readable (forbidden), so there were no sensitive profiles to read",
  "the User query was forbidden (401/403 or INSUFFICIENT_ACCESS)",
  "the EventLogFile object or field is unavailable in this org (INVALID_TYPE)",
  "the SetupAuditTrail query failed (unknown error)",
  "Only 3 of 4000 User records were read, so the verdict is downgraded.",
  "MFA is required for direct UI logins, but per-user enrollment could not be verified because the TwoFactorMethodsInfo query was forbidden (401/403 or INSUFFICIENT_ACCESS); TwoFactorMethodsInfo requires the Manage MFA in API permission.",
  "MFA enforcement could not be verified because the SecuritySettings query was forbidden (401/403 or INSUFFICIENT_ACCESS) and Health Check exposed no MFA setting.",
  "Health Check score is 95, but the per-setting risk list could not be read because the SecurityHealthCheckRisks query was forbidden (401/403 or INSUFFICIENT_ACCESS).",
  "12 permission sets grant elevated permissions, but assignments could not be read because the PermissionSetAssignment query was forbidden (401/403 or INSUFFICIENT_ACCESS).",
  "the OauthToken query was forbidden (401/403 or INSUFFICIENT_ACCESS), so assignment coverage of the permission sets that were read was not checked and the verdict is capped at warn.",
  "OAuth token usage was not checked because the OauthToken query was forbidden (401/403 or INSUFFICIENT_ACCESS); review Setup > Connected Apps OAuth Usage manually.",
  "ConnectedApplication returned zero apps; apps without org-managed policies do not appear here, so OAuth usage must be reviewed manually.",
  "Only 50 of 4000 TwoFactorMethodsInfo records were read; users without a registered method are not named from a partial read",
  "Caller permissions could not be read from UserPermissionAccess (forbidden); OauthToken visibility (Customize Application) and user visibility (View All Users) are unknown.",
  "Auth mode access-token against https://login.salesforce.com, instance https://acme.my.salesforce.com, API v64.0.",
  "Auth mode jwt-bearer against https://test.salesforce.com, instance https://acme--uat.sandbox.my.salesforce.com, API v64.0.",
  "Org Acme Production (Enterprise Edition, sandbox=false).",
  "Organization record was not readable.",
  "16/17 Salesforce audit surfaces are readable.",
  "Likely missing permissions: View All Users (Manage Users read); Manage MFA in API; Customize Application (without it only the caller's own tokens are returned).",
  "Grant the auditing user View Setup and Configuration, View Health Check, API Enabled, View All Users, Customize Application, Manage MFA in API, and Modify Metadata Through Metadata API Functions, then re-run salesforce_check_access.",
];

/** Addendum 7 must-keep table for Salesforce: paths and datasets, tenants, principals, finding ids, and the standing fixed texts. */
function salesforceKeepTable(findingIds) {
  return {
    paths: [
      "/services/oauth2/token",
      "/services/data/v64.0/limits",
      "/services/data/v64.0/query",
      "/services/data/v64.0/tooling/query",
      "/services/data/v64.0/sobjects/User/describe",
      "/services/data/v64.0/sobjects/TenantSecret/describe",
      "/services/Soap/m/64.0",
      "/services/data/v64.0/query (Organization)",
      "/services/Soap/m/64.0 readMetadata(SecuritySettings)",
      "/services/Soap/m/64.0 listMetadata(Profile) + readMetadata(Profile)",
    ],
    tables: SALESFORCE_DATASETS,
    tenants: [
      "acme.my.salesforce.com",
      "https://acme.my.salesforce.com",
      "acme--uat.sandbox.my.salesforce.com",
      "https://login.salesforce.com",
      "https://test.salesforce.com",
      "00D5f000001AbCdEAK",
      "Acme_Production_Org",
      "prod-us-east-2026",
    ],
    principals: [
      "bob.user@acme.example",
      "admin@acme.example",
      "auditor@acme.example.uat",
      "svc-integration-2026@acme.example",
      "System Administrator",
      "Standard User",
      "Modify_All_Data_Ops",
      // 18-character record Ids with valid case checksums (user 005, permission set 0PS).
      "0055f000009XyZwAAK",
      "0PS5f000000LmNoGAK",
      "005A0000001kbNzIAI",
    ],
    findingIds,
    fixedTexts: SALESFORCE_FIXED_TEXTS,
  };
}

test("scrub boundary: bare name-shaped values stay, carriers and registered secrets (in every encoded form) and real token shapes go, in SalesforceApiError's message and errorCode; the addendum 7 must-keep table survives in isolation and in sentences", async () => {
  const fetchImpl = async () => jsonResponse({});
  const mustKeep = [
    "Salesforce request failed (502 Bad Gateway) for /services/data/v64.0/query: non-JSON body (text/html, 5120 bytes)",
    "Salesforce SOAP login failed (403 Forbidden): non-SOAP body (application/json, 42 bytes)",
    "Unable to read Salesforce credentials file /home/svc/.salesforce/credentials.json (ENOENT)",
    "Unable to parse Salesforce credentials file: invalid JSON in /tmp/grclanker-salesforce-loader-Ab3dEf/short.json",
    "Metadata read of SecurityHealthCheckRisks, TwoFactorMethodsInfo, and SetupAuditTrail failed for Acme_Production_Org",
  ];
  const healthy = createFullMockClient();
  const findingIds = [];
  for (const assess of [assessSalesforcePlatformSecurity, assessSalesforceIdentityAccess, assessSalesforceDataProtection, assessSalesforceMonitoringIntegrations]) {
    findingIds.push(...(await assess(healthy, { now: NOW })).findings.map((item) => item.id));
  }
  const keepTable = salesforceKeepTable([...new Set(findingIds)]);
  assert.equal(keepTable.findingIds.length, 20, "every Salesforce finding id is in the table");
  assert.ok(keepTable.findingIds.includes("SF-11"));
  // The client constructor is the registration path (rememberSecrets on the configured password); the error constructor is the pass.
  assertScrubBoundary({
    scrub: (text) => new SalesforceApiError(text).message,
    registerSecret: (secret) => new SalesforceApiClient(sampleConfig({ password: secret }), { fetchImpl }),
    mustKeep,
    keepTable,
  });
  assertScrubBoundary({ scrub: (text) => new SalesforceApiError("request failed", { status: 502, errorCode: text }).errorCode, mustKeep, keepTable });

  // A Salesforce Id stays bare only with a valid checksum; the same eighteen characters with a wrong suffix, or a
  // valid Id inside a carrier or registered as a secret, still go.
  const scrub = (text) => new SalesforceApiError(text).message;
  assert.equal(isSalesforceRecordId("0055f000009XyZwAAK"), true);
  assert.equal(isSalesforceRecordId("0055f000009XyZwAAO"), false);
  assert.equal(isSalesforceRecordId("001A0000006Vm9rIAC"), true, "the documented 15-to-18 example");
  assert.equal(scrub("insufficient access rights on cross-reference id: 0055f000009XyZwAAK"), "insufficient access rights on cross-reference id: 0055f000009XyZwAAK");
  assert.equal(scrub("insufficient access rights on cross-reference id: 0055f000009XyZwAAO"), "insufficient access rights on cross-reference id: [REDACTED]");
  assert.equal(scrub("Authorization: Bearer 0055f000009XyZwAAK"), "Authorization: [REDACTED]");
  assert.equal(scrub("https://api.example.com/v1/x?sid=0055f000009XyZwAAK"), "https://api.example.com/v1/x?[REDACTED]");
  assert.equal(scrub("profile 00e5f000001MnopAAC was read"), "profile 00e5f000001MnopAAC was read");
  new SalesforceApiClient(sampleConfig({ password: "00e5f000001MnopAAC" }), { fetchImpl });
  assert.equal(scrub("profile 00e5f000001MnopAAC was read"), "profile [REDACTED] was read", "a registered secret goes whatever its shape");
});

test("round 7 note 1: every fixed-text message Salesforce emits (loader, opaque body, timeout, read: states, not requested, withheld, access-check notes, corollary summaries) comes back from SalesforceApiError's pass unchanged", async () => {
  const texts = new Set(SALESFORCE_FIXED_TEXTS);
  const scrub = (text) => new SalesforceApiError(text).message;

  // The loader's own read and parse messages on real failing files, plus the shape and private key guards.
  for (const item of configLoaderCases({ format: "json", displayName: "Salesforce", fileNoun: "credentials file", extension: ".json" })) {
    if (item.skip) continue;
    assert.throws(() => resolveSalesforceConfiguration({ credentials_file: item.path }, {}), (error) => {
      texts.add(error.message);
      return true;
    });
  }
  const scratch = createTempBase("grclanker-sf-fixed-text-");
  const arrayPath = join(scratch, "credentials.json");
  writeFileSync(arrayPath, "[]\n");
  assert.throws(() => resolveSalesforceConfiguration({ credentials_file: arrayPath }, {}), (error) => {
    texts.add(error.message);
    return true;
  });
  assert.throws(() => resolveSalesforceConfiguration({ grant_type: "jwt-bearer", consumer_key: "consumer-key", username: "user@acme.example", private_key_file: join(scratch, "missing.key") }, {}), (error) => {
    texts.add(error.message);
    return true;
  });

  // The resolver's own messages on the real path with an empty environment: no credentials at all, each
  // grant type named without its credentials, an unsupported grant type, and a malformed API version.
  const resolverMessages = [
    collectThrownMessage(texts, () => resolveSalesforceConfiguration({}, {}), "no credentials"),
    collectThrownMessage(texts, () => resolveSalesforceConfiguration({ grant_type: "jwt-bearer" }, {}), "jwt-bearer without credentials"),
    collectThrownMessage(texts, () => resolveSalesforceConfiguration({ grant_type: "password" }, {}), "password without credentials"),
    collectThrownMessage(texts, () => resolveSalesforceConfiguration({ grant_type: "refresh-token" }, {}), "refresh-token without credentials"),
    collectThrownMessage(texts, () => resolveSalesforceConfiguration({ grant_type: "access-token" }, {}), "access-token without credentials"),
    collectThrownMessage(texts, () => resolveSalesforceConfiguration({ grant_type: "device-code" }, {}), "unsupported grant type"),
    collectThrownMessage(texts, () => resolveSalesforceConfiguration({ api_version: "latest" }, {}), "malformed api version"),
  ];
  assert.ok(resolverMessages.some((message) => /^Salesforce credentials are required: JWT bearer \(SF_CONSUMER_KEY,/.test(message)), "the resolver rendered its credentials-required message");
  assert.ok(resolverMessages.some((message) => /^Username-password flow requires/.test(message)), "the resolver rendered its username-password message");

  // Every tool label, description, and argument description the integration registers.
  const registered = [];
  registerSalesforceTools({ registerTool: (tool) => registered.push(tool) });
  const toolTexts = collectToolTexts(registered);
  assert.ok([...toolTexts].some((text) => /JWT bearer flow/.test(text)), "the tool schemas carry the private key argument description");
  for (const text of toolTexts) texts.add(text);

  // Every surface under three credential-free failure flavors (plain proxy page, unrecognized JSON shape, documented
  // error): the access check, the four assessments, the analysis files, and the error log render the opaque-body
  // notes, the read: states, the manual-review and demotion templates, and the access-check notes on real paths.
  for (const surface of SF_CANARY_SURFACES) {
    for (const flavor of ["plainHtml", "opaqueJson", "plainJson"]) {
      const client = new SalesforceApiClient(sampleConfig({ authMode: "password", username: "auditor@acme.example", password: "file-password", securityToken: "file-token", consumerKey: "ck", consumerSecret: "file-secret" }), { fetchImpl: sfCanaryFetch({ surface, flavor }), sleep: async () => {}, now: () => NOW });
      collectFixedTexts(await checkSalesforceAccess(client), texts);
      for (const assess of [assessSalesforcePlatformSecurity, assessSalesforceIdentityAccess, assessSalesforceDataProtection, assessSalesforceMonitoringIntegrations]) {
        collectFixedTexts(await assess(client, { now: NOW }), texts);
      }
      const exported = await exportSalesforceAuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-sf-fixed-text-bundle-"), { now: NOW });
      const files = readBundleFiles(exported.outputDir);
      for (const line of logLines(files.get("_errors.log"))) texts.add(line);
      for (const [name, content] of files) {
        if (name.startsWith("analysis/") && name.endsWith(".json")) collectFixedTexts(JSON.parse(content), texts);
      }
    }
  }

  // The fake clients: healthy, every read forbidden, and the timeout wording through the real error class.
  for (const client of [createFullMockClient(), forbiddenClient()]) {
    collectFixedTexts(await checkSalesforceAccess(client), texts);
    for (const assess of [assessSalesforcePlatformSecurity, assessSalesforceIdentityAccess, assessSalesforceDataProtection, assessSalesforceMonitoringIntegrations]) {
      collectFixedTexts(await assess(client, { now: NOW }), texts);
    }
  }
  const timingOut = new SalesforceApiClient(sampleConfig({ timeoutMs: 1000, maxRetries: 0 }), {
    fetchImpl: async (_input, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))),
    sleep: async () => {},
    now: () => NOW,
  });
  await assert.rejects(timingOut.getLimits(), (error) => {
    texts.add(error.message);
    return true;
  });

  const checked = assertFixedTextsSurvive(scrub, texts, "Salesforce fixed texts");
  assert.ok(checked >= SALESFORCE_FIXED_TEXTS.length + 40, `the harvest rendered texts beyond the standing list (${checked})`);
  assert.ok([...texts].some((text) => / read: unread \(forbidden: /.test(text)), "the harvest rendered a forbidden read: state");
  assert.ok([...texts].some((text) => /^not requested: /.test(text)), "the harvest rendered a not requested dataset error");
  assert.ok([...texts].some((text) => /non-JSON body \(text\/html, \d+ bytes\)/.test(text)), "the harvest rendered a status-and-length note");
  assert.ok([...texts].some((text) => /non-SOAP body \(/.test(text)), "the harvest rendered a non-SOAP body note");
  assert.ok([...texts].some((text) => /timed out after \d+ ms/.test(text)), "the harvest rendered the timeout wording");
  assert.ok([...texts].some((text) => /could not be verified because the /.test(text)), "the harvest rendered a manual-review template");
});

test("round 7 note 2: credentials and the credentials file path set through the environment survive an unrelated argument, and the source chain names the environment", () => {
  const base = createTempBase("grclanker-sf-env-survives-");
  const credentialsPath = join(base, "salesforce-credentials.json");
  writeFileSync(credentialsPath, JSON.stringify({ grant_type: "password", username: "file@acme.example", password: "file-password", consumer_key: "file-key", consumer_secret: "file-secret", instance_url: "https://file.my.salesforce.com" }));
  const env = {
    SF_CREDENTIALS_FILE: credentialsPath,
    SF_USERNAME: "env@acme.example",
    SF_PASSWORD: "env-password-value",
    SF_CONSUMER_KEY: "env-consumer-key",
    SF_CONSUMER_SECRET: "env-consumer-secret",
  };
  for (const [label, unrelated] of [
    ["api_version", { api_version: "v63.0" }],
    ["timeout_seconds", { timeout_seconds: 9 }],
    ["max_retries", { max_retries: 1 }],
    ["sandbox", { sandbox: false }],
  ]) {
    const resolved = resolveSalesforceConfiguration(unrelated, env);
    assert.equal(resolved.authMode, "password", label);
    assert.equal(resolved.username, "env@acme.example", `${label}: the environment username resolves over the file`);
    assert.equal(resolved.password, "env-password-value", `${label}: the environment password resolves over the file`);
    assert.equal(resolved.consumerKey, "env-consumer-key", label);
    assert.equal(resolved.consumerSecret, "env-consumer-secret", label);
    assert.equal(resolved.instanceUrl, "https://file.my.salesforce.com", `${label}: the file value not set elsewhere still applies`);
    for (const key of ["environment-SF_USERNAME", "environment-SF_PASSWORD", "environment-SF_CONSUMER_KEY", "environment-SF_CONSUMER_SECRET", "credentials-file:salesforce-credentials.json", "credentials-file-instance-url"]) {
      assert.ok(resolved.sourceChain.includes(key), `${label}: the source chain names ${key}: ${JSON.stringify(resolved.sourceChain)}`);
    }
    assert.ok(!resolved.sourceChain.includes("arguments-username"), `${label}: the unrelated argument does not claim the username`);
  }
  // An argument object whose credential keys are present but undefined must not shadow the environment.
  const shadowed = resolveSalesforceConfiguration({ username: undefined, password: undefined, api_version: "v63.0" }, env);
  assert.equal(shadowed.username, "env@acme.example");
  assert.equal(shadowed.password, "env-password-value");
  assert.equal(shadowed.apiVersion, "63.0");
  assert.ok(shadowed.sourceChain.includes("environment-SF_USERNAME"));
});
