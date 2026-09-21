import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  SalesforceApiClient,
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
  parseSimpleXml,
  resolveSalesforceConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/salesforce.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

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

function sampleConfig(overrides = {}) {
  return {
    authMode: "access-token",
    loginUrl: "https://login.salesforce.com",
    instanceUrl: "https://acme.my.salesforce.com",
    apiVersion: "64.0",
    accessToken: "token-abc123",
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

const businessHours = Object.fromEntries(["monday", "tuesday", "wednesday", "thursday", "friday"].flatMap((day) => [[`${day}Start`, "420"], [`${day}End`, "1140"]]));

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
    async getSession() { return { accessToken: "token-abc123", instanceUrl: "https://acme.my.salesforce.com" }; },
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
  assert.match(requests[0].body, /<met:sessionId>token-abc123<\/met:sessionId>/);
  assert.equal(settings.sessionSettings.sessionTimeout, "TwelveHours");
  assert.equal(settings.passwordPolicies.minimumPasswordLength, "8");
  assert.equal(settings.networkAccess.ipRanges.length, 2);

  await assert.rejects(() => client.readMyDomainSettings(), (error) => {
    assert.equal(error.errorCode, "INSUFFICIENT_ACCESS");
    assert.ok(!error.message.includes("token-abc123"));
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
  assert.match(cappedFinding.summary, /documented 2500-row cap with no done=false signal/);
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
  assert.match(readFileSync(join(result.outputDir, "_errors.log"), "utf8"), /TenantSecret: forbidden/);
  const bundleText = JSON.stringify(readdirSync(result.outputDir, { recursive: true }));
  assert.ok(!readFileSync(join(result.outputDir, "metadata.json"), "utf8").includes("token-abc123"));
  assert.ok(bundleText.length > 0);

  const rerun = await exportSalesforceAuditBundle(client, sampleConfig(), base, { now: NOW });
  assert.notEqual(rerun.outputDir, result.outputDir);
  assert.notEqual(rerun.zipPath, result.zipPath);
  assert.equal(rerun.zipPath, `${rerun.outputDir}.zip`);
  assert.ok(existsSync(result.zipPath));
  assert.ok(existsSync(rerun.zipPath));
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
