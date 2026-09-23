import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

import {
  OKTA_CHECK_IDS,
  OktaAuditorClient,
  assessOktaAdminAccess,
  assessOktaAuthentication,
  assessOktaIntegrations,
  assessOktaMonitoring,
  buildOscalAssessmentResults,
  clearOktaTokenCacheForTests,
  collectOktaAdminAccessData,
  collectOktaAuthenticationData,
  collectOktaIntegrationData,
  collectOktaMonitoringData,
  exportOktaAuditBundle,
  redactSnapshot,
  registerOktaTools,
  resolveOktaConfiguration,
  resolveSecureOutputPath,
  runOktaAccessCheck,
  scrubDataText,
  scrubErrorText,
} from "../dist/extensions/grc-tools/okta.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function dataset(data, error) {
  return error ? { data, error } : { data };
}

function findingById(result, id) {
  return result.findings.find((finding) => finding.id === id);
}

function statusOf(result, id) {
  return findingById(result, id)?.status;
}

function createSampleConfig(overrides = {}) {
  return {
    orgUrl: "https://tenant.okta.gov",
    authMode: "SSWS",
    token: "okta-token",
    scopes: [],
    sourceChain: ["tests"],
    ...overrides,
  };
}

function createSampleAuthenticationData() {
  return {
    signOnPolicies: dataset([
      { id: "signon-1", name: "Admin Console Policy", status: "ACTIVE" },
    ]),
    signOnPolicyRules: dataset({
      "signon-1": [
        {
          id: "signon-rule-1",
          name: "Admin console sign-on",
          status: "ACTIVE",
          actions: {
            signon: {
              requireFactor: true,
              session: {
                maxSessionIdleMinutes: 15,
                maxSessionLifetimeMinutes: 480,
                usePersistentCookie: false,
              },
            },
          },
          conditions: {
            network: { connection: "ANYWHERE" },
          },
        },
      ],
    }),
    passwordPolicies: dataset([
      {
        id: "pwd-1",
        name: "Workforce password policy",
        status: "ACTIVE",
        settings: {
          password: {
            complexity: {
              minLength: 14,
              useUpperCase: true,
              useLowerCase: true,
              useNumber: true,
              useSymbol: true,
            },
            age: {
              maxAgeDays: 90,
              historyCount: 8,
            },
            lockout: {
              maxAttempts: 5,
            },
          },
        },
      },
    ]),
    passwordPolicyRules: dataset({}),
    mfaPolicies: dataset([{ id: "mfa-1", name: "MFA Enrollment", status: "ACTIVE" }]),
    accessPolicies: dataset([{ id: "access-1", name: "Workforce Access Policy", status: "ACTIVE" }]),
    accessPolicyRules: dataset({
      "access-1": [
        {
          id: "access-rule-1",
          name: "High risk step-up",
          status: "ACTIVE",
          conditions: {
            risk: { level: "HIGH" },
          },
        },
      ],
    }),
    authenticators: dataset([
      { id: "auth-1", key: "webauthn", status: "ACTIVE" },
      { id: "auth-2", key: "smart_card_idp", name: "Smart Card", status: "ACTIVE" },
      {
        id: "auth-3",
        key: "okta_verify",
        status: "ACTIVE",
        settings: { compliance: { fips: "REQUIRED" }, userVerification: "REQUIRED" },
      },
      { id: "auth-4", key: "okta_email", status: "ACTIVE", settings: { allowedFor: "recovery" } },
    ]),
    idps: dataset([{ id: "idp-1", name: "PIV Smart Card", type: "X509", status: "ACTIVE" }]),
    authorizationServers: dataset([]),
    defaultAuthorizationServer: dataset(null),
    orgFactors: dataset([]),
  };
}

function createSampleAdminData() {
  const now = new Date().toISOString();
  return {
    usersWithRoleAssignments: dataset([
      {
        id: "user-1",
        status: "ACTIVE",
        lastLogin: now,
        created: "2024-01-01T00:00:00.000Z",
        profile: { login: "admin@example.gov" },
      },
    ]),
    userRoles: dataset({
      "user-1": [{ id: "role-1", label: "SUPER_ADMIN" }],
    }),
    groups: dataset([{ id: "group-1", profile: { name: "Admin Team" } }]),
    privilegedGroups: dataset([{ id: "group-1", profile: { name: "Admin Team" } }]),
    privilegedGroupRoles: dataset({
      "group-1": [{ id: "group-role-1", label: "APP_ADMIN" }],
    }),
    privilegedGroupMembers: dataset({
      "group-1": [{ id: "user-1" }],
    }),
    users: dataset([
      {
        id: "user-1",
        status: "ACTIVE",
        lastLogin: now,
        created: "2024-01-01T00:00:00.000Z",
        profile: { login: "admin@example.gov" },
      },
      {
        id: "user-2",
        status: "ACTIVE",
        lastLogin: now,
        created: "2024-02-01T00:00:00.000Z",
        profile: { login: "analyst@example.gov" },
      },
    ]),
    privilegedUserFactors: dataset({
      "user-1": [{ id: "factor-1", factorType: "webauthn", provider: "FIDO", status: "ACTIVE" }],
    }),
    oktaSupportAccess: dataset({ support: "DISABLED", expiration: null }),
    thirdPartyAdminSetting: dataset({ thirdPartyAdmin: false }),
  };
}

function createSampleIntegrationData() {
  return {
    apps: dataset([
      {
        id: "app-1",
        label: "Core OIDC",
        status: "ACTIVE",
        features: ["PUSH_NEW_USERS", "PUSH_USER_DEACTIVATION"],
        settings: {
          oauthClient: {
            grant_types: ["authorization_code"],
          },
        },
      },
    ]),
    trustedOrigins: dataset([{ id: "origin-1", origin: "https://portal.example.gov", status: "ACTIVE" }]),
    networkZones: dataset([
      { id: "zone-0", name: "LegacyIpZone", system: true, status: "ACTIVE" },
      { id: "zone-1", name: "Corporate HQ", system: false, status: "ACTIVE" },
    ]),
    accessPolicies: dataset([{ id: "access-1", name: "Workforce Access Policy", status: "ACTIVE" }]),
    accessPolicyRules: dataset({
      "access-1": [
        {
          id: "access-rule-1",
          name: "High risk step-up",
          status: "ACTIVE",
          conditions: {
            risk: { level: "HIGH" },
          },
        },
      ],
    }),
    signOnPolicies: dataset([{ id: "signon-1", name: "Admin Console Policy", status: "ACTIVE" }]),
    signOnPolicyRules: dataset({
      "signon-1": [
        {
          id: "signon-rule-1",
          name: "Admin console sign-on",
          status: "ACTIVE",
          conditions: {
            network: { connection: "ANYWHERE" },
          },
        },
      ],
    }),
    idps: dataset([]),
    authorizationServers: dataset([]),
    groupRules: dataset([{ id: "rule-1", name: "Engineering auto-assign", status: "ACTIVE" }]),
  };
}

function createSampleMonitoringData() {
  const now = new Date().toISOString();
  const nextMonth = new Date(Date.now() + 20 * 24 * 60 * 60 * 1000).toISOString();
  return {
    eventHooks: dataset([{ id: "hook-1", name: "SIEM Forwarder", status: "ACTIVE" }]),
    logStreams: dataset([{ id: "stream-1", name: "Splunk HEC", type: "splunk_cloud_logstreaming", status: "ACTIVE" }]),
    systemLogs: dataset([
      { published: now, eventType: "user.session.start" },
    ]),
    behaviors: dataset([{ id: "behavior-1", name: "New Device", status: "ACTIVE" }]),
    threatInsight: dataset({ action: "block" }),
    apiTokens: dataset([
      {
        id: "token-1",
        name: "CI token",
        created: "2026-01-01T00:00:00.000Z",
        lastUpdated: now,
        expiresAt: nextMonth,
        tokenWindow: "P30D",
        network: { connection: "ZONE", include: ["zone-1"] },
      },
    ]),
    deviceAssurance: dataset([{ id: "device-1", displayName: "Managed macOS", platform: "MACOS" }]),
    orgContacts: dataset([
      { contactType: "TECHNICAL", userId: "user-1", userStatus: "ACTIVE", userLogin: "admin@example.gov" },
      { contactType: "BILLING", userId: "user-9", userStatus: "ACTIVE", userLogin: "billing@example.gov" },
    ]),
  };
}

function createSampleClient() {
  const authentication = createSampleAuthenticationData();
  const admin = createSampleAdminData();
  const integrations = createSampleIntegrationData();
  const monitoring = createSampleMonitoringData();
  return {
    async listPolicies(type) {
      if (type === "OKTA_SIGN_ON") return authentication.signOnPolicies.data;
      if (type === "PASSWORD") return authentication.passwordPolicies.data;
      if (type === "MFA_ENROLL") return authentication.mfaPolicies.data;
      if (type === "ACCESS_POLICY") return authentication.accessPolicies.data;
      return [];
    },
    async listPolicyRules(policyId) {
      return (
        authentication.signOnPolicyRules.data[policyId]
        ?? authentication.accessPolicyRules.data[policyId]
        ?? []
      );
    },
    async listAuthenticators() {
      return authentication.authenticators.data;
    },
    async listIdps() {
      return authentication.idps.data;
    },
    async listAuthorizationServers() {
      return authentication.authorizationServers.data;
    },
    async getDefaultAuthorizationServer() {
      return authentication.defaultAuthorizationServer.data;
    },
    async listOrgFactors() {
      return authentication.orgFactors.data;
    },
    async listUsersWithRoleAssignments() {
      return admin.usersWithRoleAssignments.data;
    },
    async listUserRoles(userId) {
      return admin.userRoles.data[userId] ?? [];
    },
    async listGroups() {
      return admin.groups.data;
    },
    async listGroupRoles(groupId) {
      return admin.privilegedGroupRoles.data[groupId] ?? [];
    },
    async listGroupUsers(groupId) {
      return admin.privilegedGroupMembers.data[groupId] ?? [];
    },
    async listUsersWithMeta() {
      return { items: admin.users.data, truncated: false, pagesFetched: 1 };
    },
    async listUserFactors(userId) {
      return admin.privilegedUserFactors.data[userId] ?? [];
    },
    async getOktaSupportSettings() {
      return admin.oktaSupportAccess.data;
    },
    async getThirdPartyAdminSetting() {
      return admin.thirdPartyAdminSetting.data;
    },
    async listApps() {
      return integrations.apps.data;
    },
    async listTrustedOrigins() {
      return integrations.trustedOrigins.data;
    },
    async listNetworkZones() {
      return integrations.networkZones.data;
    },
    async listGroupRules() {
      return integrations.groupRules.data;
    },
    async listEventHooks() {
      return monitoring.eventHooks.data;
    },
    async listLogStreams() {
      return monitoring.logStreams.data;
    },
    async listSystemLogs() {
      return monitoring.systemLogs.data;
    },
    async listBehaviors() {
      return monitoring.behaviors.data;
    },
    async getThreatInsight() {
      return monitoring.threatInsight.data;
    },
    async listApiTokens() {
      return monitoring.apiTokens.data;
    },
    async listDeviceAssurancePolicies() {
      return monitoring.deviceAssurance.data;
    },
    async listOrgContacts() {
      return [{ contactType: "TECHNICAL" }, { contactType: "BILLING" }];
    },
    async getOrgContactUser(contactType) {
      return { userId: contactType === "TECHNICAL" ? "user-1" : "user-9" };
    },
    async getUser(userId) {
      return { id: userId, status: "ACTIVE", profile: { login: `${userId}@example.gov` } };
    },
  };
}

const CLIENT_METHODS = Object.keys(createSampleClient());

function forbidden(pathname) {
  return new Error(`Okta API request failed for ${pathname} (403 Forbidden): Access denied`);
}

function createAll403Client() {
  const client = {};
  for (const method of CLIENT_METHODS) {
    client[method] = async () => {
      throw forbidden(`/api/v1/${method}`);
    };
  }
  return client;
}

function createAllEmptyClient() {
  const client = {};
  for (const method of CLIENT_METHODS) {
    client[method] = async () => [];
  }
  client.getDefaultAuthorizationServer = async () => null;
  client.getThreatInsight = async () => null;
  client.getOktaSupportSettings = async () => null;
  client.getThirdPartyAdminSetting = async () => null;
  client.getOrgContactUser = async () => null;
  client.getUser = async () => null;
  client.listUsersWithMeta = async () => ({ items: [], truncated: false, pagesFetched: 1 });
  return client;
}

function createPartialInventoryClient() {
  const sample = createSampleClient();
  const now = new Date().toISOString();
  const adminLikeGroups = Array.from({ length: 30 }, (_, index) => ({
    id: `group-${index}`,
    profile: { name: `Admin Team ${index}` },
  }));
  return {
    ...sample,
    async listAuthenticators() {
      throw forbidden("/api/v1/authenticators");
    },
    async listIdps() {
      throw forbidden("/api/v1/idps");
    },
    async listPolicyRules(policyId) {
      if (policyId === "signon-1") throw forbidden(`/api/v1/policies/${policyId}/rules`);
      return sample.listPolicyRules(policyId);
    },
    async listPolicies(type) {
      if (type === "PASSWORD") throw forbidden("/api/v1/policies?type=PASSWORD");
      return sample.listPolicies(type);
    },
    async listUsersWithRoleAssignments() {
      return [
        { id: "user-1", status: "ACTIVE", lastLogin: now, profile: { login: "admin@example.gov" } },
        { id: "user-2", status: "ACTIVE", lastLogin: now, profile: { login: "second@example.gov" } },
      ];
    },
    async listUserRoles(userId) {
      if (userId === "user-2") throw forbidden(`/api/v1/users/${userId}/roles`);
      return [{ id: "role-1", label: "SUPER_ADMIN" }];
    },
    async listUserFactors(userId) {
      if (userId === "user-2") throw forbidden(`/api/v1/users/${userId}/factors`);
      return [{ id: "factor-1", factorType: "webauthn", provider: "FIDO", status: "ACTIVE" }];
    },
    async listGroups() {
      return adminLikeGroups;
    },
    async listGroupRoles() {
      return [{ id: "role", label: "APP_ADMIN" }];
    },
    async listGroupUsers() {
      return [{ id: "user-1" }];
    },
    async listUsersWithMeta() {
      return {
        items: [{ id: "user-1", status: "ACTIVE", lastLogin: now, created: "2024-01-01T00:00:00.000Z" }],
        truncated: true,
        pagesFetched: 50,
      };
    },
    async getThirdPartyAdminSetting() {
      throw forbidden("/api/v1/org/orgSettings/thirdPartyAdminSetting");
    },
    async listApps() {
      throw forbidden("/api/v1/apps");
    },
    async listTrustedOrigins() {
      throw forbidden("/api/v1/trustedOrigins");
    },
    async listNetworkZones() {
      return [{ id: "zone-0", name: "LegacyIpZone", system: true, status: "ACTIVE" }];
    },
    async listLogStreams() {
      throw forbidden("/api/v1/logStreams");
    },
    async listSystemLogs() {
      return [];
    },
    async getThreatInsight() {
      return { action: "audit" };
    },
    async listBehaviors() {
      return [{ id: "behavior-1", name: "New Device", status: "INACTIVE" }];
    },
    async listApiTokens() {
      return [{ id: "token-1", name: "Legacy token" }];
    },
    async listDeviceAssurancePolicies() {
      return [];
    },
    async getUser() {
      return null;
    },
  };
}

async function runAllAssessments(client, config) {
  return {
    authentication: assessOktaAuthentication(await collectOktaAuthenticationData(client), config),
    admin: assessOktaAdminAccess(await collectOktaAdminAccessData(client), config),
    integrations: assessOktaIntegrations(await collectOktaIntegrationData(client), config),
    monitoring: assessOktaMonitoring(await collectOktaMonitoringData(client), config),
  };
}

function allFindings(results) {
  return Object.values(results).flatMap((result) => result.findings);
}

test("resolveOktaConfiguration follows Okta CLI-style precedence with per-field overrides", async () => {
  const homeDir = createTempBase("grclanker-okta-home-");
  const cwd = createTempBase("grclanker-okta-cwd-");
  const homeConfigDir = join(homeDir, ".okta");
  mkdirSync(homeConfigDir, { recursive: true });

  writeFileSync(
    join(homeConfigDir, "okta.yaml"),
    [
      "okta:",
      "  client:",
      "    orgUrl: https://home.example.okta.com",
      "    authorizationMode: SSWS",
      "    token: home-token",
      "",
    ].join("\n"),
  );

  writeFileSync(
    join(cwd, ".okta.yaml"),
    [
      "okta:",
      "  client:",
      "    orgUrl: https://project.example.okta.com",
      "    token: project-token",
      "",
    ].join("\n"),
  );

  const base = await resolveOktaConfiguration({}, {}, cwd, homeDir);
  assert.equal(base.orgUrl, "https://project.example.okta.com");
  assert.equal(base.token, "project-token");
  assert.deepEqual(base.sourceChain, ["home:.okta/okta.yaml", "project:.okta.yaml"]);

  const overridden = await resolveOktaConfiguration(
    { org_url: "tenant.example.okta.com" },
    { OKTA_CLIENT_TOKEN: "env-token" },
    cwd,
    homeDir,
  );
  assert.equal(overridden.orgUrl, "https://tenant.example.okta.com");
  assert.equal(overridden.token, "env-token");
  assert.deepEqual(overridden.sourceChain, [
    "home:.okta/okta.yaml",
    "project:.okta.yaml",
    "environment",
    "arguments",
  ]);
});

/** Canaries planted on malformed config lines: random alphanumerics, so no 6-character window of one occurs in a legitimate fixture value or in another canary. */
const CONFIG_CANARIES = {
  nestedKey: "Qv7ZkT3mR9pXw2Lc",
  nestedValue: "Hj4NsB8yF6dGa1Ue",
  alias: "Wm2PxK9rT5vLq7Zb",
  unterminated: "Lf9BwD4sN7hVe3Ky",
  indent: "Tn3XcM6zP8gQb5Rw",
  duplicate: "Rk8VqL2tY7jCn4Fs",
  readable: "Zx4HnV7qK2mYt9Pw",
  privateKey: "Bp6TzX3kW9nQ2sRc",
};
const LIBRARY_ERROR_WORDING = [
  "Nested mappings", "is not valid JSON", "Unresolved alias", "illegal operation", "permission denied", "no such file",
  "not a directory", "Unexpected token", "Missing closing", "Map keys must be unique", "must start at the same column", "DECODER routines",
];

/** Every substring of a planted credential at lengths 6 through 24 (sliding windows), so a partial echo such as a JSON.parse window or a truncated token cannot pass a leak assertion. */
function windowsOf(value, { min = 6, max = 24 } = {}) {
  const windows = new Set();
  for (let size = Math.min(min, value.length); size <= Math.min(max, value.length); size += 1) {
    for (let index = 0; index + size <= value.length; index += 1) windows.add(value.slice(index, index + size));
  }
  return [...windows];
}

/** The window set of every planted secret, for bundle, zip, and payload scans through assertSecretsAbsent. */
function leakWindows(secrets) {
  return [...new Set(secrets.flatMap((secret) => windowsOf(secret)))];
}

function assertNoWindowOf(text, secret, label) {
  for (const window of windowsOf(secret)) assert.ok(!text.includes(window), `${label} carries a window (${window}) of the planted credential: ${text.slice(0, 300)}`);
}

/**
 * Fixture self-check: the legitimate values of a fixture (everything it serves
 * with the planted canaries themselves removed) contain no 6-character window
 * of any canary, so a window hit in an output can only be a leak.
 */
function assertFixtureFreeOfCanaryWindows(legitimateText, canaries, label) {
  let legitimate = legitimateText;
  for (const canary of [...canaries].sort((a, b) => b.length - a.length)) legitimate = legitimate.split(canary).join("");
  for (const canary of canaries) {
    for (const window of windowsOf(canary, { min: 6, max: 6 })) {
      assert.ok(!legitimate.includes(window), `${label}: legitimate fixture text contains the window ${window} of canary ${canary}`);
    }
  }
}

function assertConfigErrorText(text, { path, code, line, column, canaries }, label) {
  for (const canary of canaries) assertNoWindowOf(text, canary, `${label} (${canary})`);
  for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!text.includes(wording), `${label} repeats library wording "${wording}": ${text}`);
  if (path) assert.ok(text.includes(path), `${label} names the path ${path}: ${text}`);
  assert.ok(text.includes(`(${code})`), `${label} carries the code ${code}: ${text}`);
  if (line) assert.ok(text.includes(` at line ${line}${column ? `, column ${column}` : ""}`), `${label} carries the position line ${line}: ${text}`);
  else assert.doesNotMatch(text, / at line \d+/, `${label} invents no line: ${text}`);
}

function thrownBy(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  assert.fail("expected the call to throw");
}

async function rejectionOf(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  assert.fail("expected the promise to reject");
}

test("rule 9: Okta config loader errors carry only the path, position, and code, never a config line, an alias name, or filesystem wording", async () => {
  const dir = createTempBase("grclanker-okta-config-errors-");
  const homeDir = createTempBase("grclanker-okta-config-errors-home-");
  const registered = [];
  registerOktaTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccess = registered.find((tool) => tool.name === "okta_check_access");
  const exportBundle = registered.find((tool) => tool.name === "okta_export_audit_bundle");
  const allCanaries = Object.values(CONFIG_CANARIES);
  const head = "okta:\n  client:\n    orgUrl: https://tenant.example.okta.com\n";

  const parseCases = [
    { name: "nested mapping", file: "nested.yaml", text: `${head}    token: ${CONFIG_CANARIES.nestedKey}: Bearer ${CONFIG_CANARIES.nestedValue}\n`, leaks: [CONFIG_CANARIES.nestedKey, CONFIG_CANARIES.nestedValue], control: /Nested mappings/, code: "BLOCK_AS_IMPLICIT_KEY", line: 4, column: 12 },
    { name: "alias", file: "alias.yaml", text: `${head}    token: *${CONFIG_CANARIES.alias}\n`, leaks: [CONFIG_CANARIES.alias], control: /Unresolved alias/, code: "INVALID_YAML" },
    { name: "unterminated quote", file: "quote.yaml", text: `${head}    token: "${CONFIG_CANARIES.unterminated}\n`, leaks: [CONFIG_CANARIES.unterminated], control: /Missing closing/, code: "MISSING_CHAR", line: 5, column: 1 },
    { name: "bad indent", file: "indent.yaml", text: `${head}   token: ${CONFIG_CANARIES.indent}\n`, leaks: [CONFIG_CANARIES.indent], control: /same column/, code: "BAD_INDENT", line: 4, column: 1 },
    { name: "duplicate key", file: "duplicate.yaml", text: `okta:\n  client:\n    token: one\n    token: ${CONFIG_CANARIES.duplicate}\n`, leaks: [CONFIG_CANARIES.duplicate], control: /Map keys must be unique/, code: "DUPLICATE_KEY", line: 4, column: 5 },
  ];
  for (const testCase of parseCases) {
    const configFile = join(dir, testCase.file);
    writeFileSync(configFile, testCase.text);
    const library = thrownBy(() => parseYaml(testCase.text));
    assert.match(library.message, testCase.control, `${testCase.name}: positive control uses the library message`);
    assert.ok(testCase.leaks.some((canary) => windowsOf(canary).some((window) => library.message.includes(window))), `${testCase.name}: positive control, the library message quotes the canary`);
    assertFixtureFreeOfCanaryWindows(testCase.text, allCanaries, `${testCase.name} config fixture`);

    const expected = { path: configFile, code: testCase.code, line: testCase.line, column: testCase.column, canaries: allCanaries };
    const thrown = await rejectionOf(resolveOktaConfiguration({ config_file: configFile }, {}, dir, homeDir));
    assert.match(thrown.message, /^Unable to parse Okta config file: invalid YAML in /, testCase.name);
    assertConfigErrorText(thrown.message, expected, `${testCase.name} resolver error`);
    const fromArgs = await rejectionOf(resolveOktaConfiguration({ config_file: configFile, org_url: "https://tenant.example.okta.com", token: "arg-token" }, {}, dir, homeDir));
    assertConfigErrorText(fromArgs.message, expected, `${testCase.name} resolver error with credentials in arguments`);

    const result = await checkAccess.execute("call", checkAccess.prepareArguments({ config_file: configFile }));
    assertConfigErrorText(JSON.stringify(result), expected, `${testCase.name} check_access payload`);
  }

  const outputRoot = join(dir, "export");
  const exported = await exportBundle.execute("call", exportBundle.prepareArguments({ config_file: join(dir, "alias.yaml"), output_dir: outputRoot }));
  assertConfigErrorText(JSON.stringify(exported), { path: join(dir, "alias.yaml"), code: "INVALID_YAML", canaries: allCanaries }, "export payload");
  assert.equal(existsSync(outputRoot), false, "a config error writes no bundle");

  const readCases = [
    { name: "EISDIR", path: join(dir, "directory.yaml"), setup: (path) => mkdirSync(path), control: /illegal operation/ },
    { name: "ENOTDIR", path: join(dir, "plain-file", "okta.yaml"), setup: () => writeFileSync(join(dir, "plain-file"), `${head}    token: ${CONFIG_CANARIES.readable}\n`), control: /not a directory/ },
  ];
  if (process.getuid?.() !== 0) {
    readCases.push({ name: "EACCES", path: join(dir, "locked.yaml"), setup: (path) => { writeFileSync(path, `${head}    token: ${CONFIG_CANARIES.readable}\n`); chmodSync(path, 0o000); }, control: /permission denied/ });
  }
  for (const testCase of readCases) {
    testCase.setup(testCase.path);
    assert.match(thrownBy(() => readFileSync(testCase.path, "utf8")).message, testCase.control, `${testCase.name}: positive control uses the filesystem message`);
    const expected = { path: testCase.path, code: testCase.name, canaries: allCanaries };
    const thrown = await rejectionOf(resolveOktaConfiguration({ config_file: testCase.path }, {}, dir, homeDir));
    assert.equal(thrown.message, `Unable to read Okta config file ${testCase.path} (${testCase.name})`);
    assertConfigErrorText(thrown.message, expected, `${testCase.name} resolver error`);
    const result = await checkAccess.execute("call", checkAccess.prepareArguments({ config_file: testCase.path }));
    assertConfigErrorText(JSON.stringify(result), expected, `${testCase.name} check_access payload`);
  }

  const missing = join(dir, "missing.yaml");
  const absent = await rejectionOf(resolveOktaConfiguration({ config_file: missing }, {}, dir, homeDir));
  assert.match(absent.message, /Okta org URL is required/, "a missing config file is absent, not a read failure");
  for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!absent.message.includes(wording));
  const absentResult = JSON.stringify(await checkAccess.execute("call", checkAccess.prepareArguments({ config_file: missing })));
  assert.ok(absentResult.includes("Okta org URL is required"));
  for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!absentResult.includes(wording));

  const badKey = await checkAccess.execute("call", checkAccess.prepareArguments({
    org_url: "https://tenant.example.okta.com",
    auth_mode: "PrivateKey",
    client_id: "0oa-client",
    scopes: "okta.users.read",
    private_key: `-----BEGIN PRIVATE KEY-----\n${CONFIG_CANARIES.privateKey}\n-----END PRIVATE KEY-----`,
  }));
  const badKeyText = JSON.stringify(badKey);
  assert.match(badKeyText, /Okta PrivateKey auth could not load the configured private key \((ERR_[A-Z0-9_]+|INVALID_PRIVATE_KEY)\)\./, "an unloadable key names a validated code only");
  assertConfigErrorText(badKeyText, { code: /ERR_/.test(badKeyText) ? badKeyText.match(/\((ERR_[A-Z0-9_]+)\)/)[1] : "INVALID_PRIVATE_KEY", canaries: allCanaries }, "PrivateKey payload");
});

test("OktaAuditorClient handles OAuth token refresh, rate limits, and pagination", async () => {
  clearOktaTokenCacheForTests();
  const state = {
    tokenRequests: 0,
    sawRateLimit: false,
    sawUnauthorized: false,
  };

  const fetchImpl = async (input, init = {}) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    const headers = new Headers(init.headers ?? {});
    const authorization = headers.get("authorization");

    if (requestUrl.pathname === "/oauth2/v1/token") {
      state.tokenRequests += 1;
      return new Response(
        JSON.stringify({
          access_token: `oauth-token-${state.tokenRequests}`,
          expires_in: 3600,
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    }

    if (!state.sawRateLimit) {
      state.sawRateLimit = true;
      return new Response("slow down", {
        status: 429,
        headers: { "retry-after": "0" },
      });
    }

    if (requestUrl.searchParams.get("after") === "page-2" && !state.sawUnauthorized) {
      state.sawUnauthorized = true;
      return new Response(JSON.stringify({ errorSummary: "expired token" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
    }

    const expectedToken = state.sawUnauthorized ? "oauth-token-2" : "oauth-token-1";
    assert.equal(authorization, `Bearer ${expectedToken}`);

    if (!requestUrl.searchParams.get("after")) {
      return new Response(JSON.stringify([{ id: "policy-1", name: "Policy One" }]), {
        status: 200,
        headers: {
          "content-type": "application/json",
          link: '<https://tenant.example.okta.com/api/v1/policies?type=OKTA_SIGN_ON&limit=200&after=page-2>; rel="next"',
        },
      });
    }

    return new Response(JSON.stringify([{ id: "policy-2", name: "Policy Two" }]), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  const client = new OktaAuditorClient(
    {
      orgUrl: "https://tenant.example.okta.com",
      authMode: "PrivateKey",
      clientId: "client-id",
      clientAssertion: "signed-jwt",
      scopes: ["okta.policies.read"],
      sourceChain: ["tests"],
    },
    { fetchImpl },
  );

  const policies = await client.listPolicies("OKTA_SIGN_ON");
  assert.equal(policies.items.length, 2);
  assert.equal(policies.truncated, false);
  assert.equal(state.tokenRequests, 2);
  clearOktaTokenCacheForTests();
});

test("Okta assessments generate mapped findings across authentication, admin, integration, and monitoring", async () => {
  const config = createSampleConfig();

  const access = await runOktaAccessCheck(
    {
      async getJson(pathname) {
        if (pathname.includes("api-tokens")) {
          throw new Error("Okta API request failed for /api/v1/api-tokens (403 Forbidden)");
        }
        return [];
      },
    },
    config,
  );
  assert.equal(access.status, "healthy");
  assert.equal(access.probes.find((probe) => probe.key === "api_tokens")?.status, "forbidden");

  const authentication = assessOktaAuthentication(createSampleAuthenticationData(), config);
  const admin = assessOktaAdminAccess(createSampleAdminData(), config);
  const integrations = assessOktaIntegrations(createSampleIntegrationData(), config);
  const monitoring = assessOktaMonitoring(createSampleMonitoringData(), config);

  assert.equal(statusOf(authentication, "OKTA-AUTH-001"), "Pass");
  assert.ok(findingById(authentication, "OKTA-AUTH-001").frameworks.fedramp.length > 0);
  assert.equal(statusOf(authentication, "OKTA-AUTH-002"), "Pass");
  assert.equal(statusOf(authentication, "OKTA-AUTH-009"), "Pass");
  assert.equal(statusOf(admin, "OKTA-ADMIN-001"), "Pass");
  assert.equal(statusOf(admin, "OKTA-ADMIN-004"), "Pass");
  assert.equal(statusOf(admin, "OKTA-ADMIN-005"), "Pass");
  assert.equal(statusOf(admin, "OKTA-ADMIN-006"), "Pass");
  assert.equal(statusOf(integrations, "OKTA-INTEG-003"), "Pass");
  assert.equal(statusOf(integrations, "OKTA-INTEG-006"), "Pass");
  assert.equal(statusOf(monitoring, "OKTA-MON-003"), "Pass");
  assert.equal(statusOf(monitoring, "OKTA-MON-007"), "Pass");
  assert.equal(statusOf(monitoring, "OKTA-MON-008"), "Pass");
  assert.equal(statusOf(monitoring, "OKTA-MON-009"), "Manual");
  assert.equal(monitoring.summary.Fail, 0);

  const ids = [...authentication.findings, ...admin.findings, ...integrations.findings, ...monitoring.findings]
    .map((finding) => finding.id)
    .sort();
  assert.deepEqual(ids, [...OKTA_CHECK_IDS].sort());
  assert.equal(OKTA_CHECK_IDS.length, 30);
});

test("exportOktaAuditBundle writes the expected package and secure paths stay rooted", async () => {
  const outputRoot = createTempBase("grclanker-okta-export-");
  const config = createSampleConfig();
  const result = await exportOktaAuditBundle(createSampleClient(), config, outputRoot);
  assert.equal(result.errorCount, 0);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
  assert.ok(existsSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md")));
  assert.ok(existsSync(join(result.outputDir, "compliance", "fedramp", "oscal_assessment_results.json")));
  assert.ok(existsSync(join(result.outputDir, "core_data", "users.json")));
  assert.ok(existsSync(join(result.outputDir, "core_data", "org_contacts.json")));
  assert.ok(existsSync(join(result.outputDir, "QUICK_REFERENCE.md")));

  const executiveSummary = readFileSync(
    join(result.outputDir, "compliance", "executive_summary.md"),
    "utf8",
  );
  assert.match(executiveSummary, /tenant\.okta\.gov/);

  const oscal = JSON.parse(
    readFileSync(join(result.outputDir, "compliance", "fedramp", "oscal_assessment_results.json"), "utf8"),
  );
  assert.equal(oscal["assessment-results"].metadata["oscal-version"], "1.1.2");
  const oscalResult = oscal["assessment-results"].results[0];
  const oscalFindings = oscalResult.findings;
  assert.ok(oscalFindings.some((finding) => finding.target["target-id"] === "ia-2.11_obj"));
  assert.ok(oscalFindings.every((finding) => ["satisfied", "not-satisfied"].includes(finding.target.status.state)));
  const reviewedIds = oscalResult["reviewed-controls"]["control-selections"][0]["include-controls"].map(
    (entry) => entry["control-id"],
  );
  assert.ok(reviewedIds.includes("ia-2.11"));
  assert.ok(oscalResult.observations.every((observation) => !("relevant_evidence" in observation)));

  assert.throws(
    () => resolveSecureOutputPath(outputRoot, "../escape"),
    /Refusing to write outside/,
  );
});

test("OSCAL export marks manual findings not-satisfied with a manual reason", () => {
  const config = createSampleConfig();
  const oscal = buildOscalAssessmentResults(
    config,
    [
      {
        id: "OKTA-MON-009",
        title: "Administrator security notification emails",
        category: "monitoring",
        status: "Manual",
        severity: "low",
        summary: "Not exposed by API.",
        evidence: ["evidence"],
        recommendation: "Capture screenshots.",
        manualNote: "Collect manually.",
        frameworks: { fedramp: ["AU-6", "SI-5"], disa_stig: [], irap: [], ismap: [], soc2: [], pci_dss: [], general: [] },
      },
    ],
    "2026-09-21T00:00:00.000Z",
  );
  const findings = oscal["assessment-results"].results[0].findings;
  assert.equal(findings.length, 2);
  assert.equal(findings[0].target.status.state, "not-satisfied");
  assert.equal(findings[0].target.status.reason, "manual");
  assert.equal(findings[0].target["target-id"], "au-6_obj");
});

test("OSCAL export uses relevant-evidence and reviewed-controls per the 1.1.2 assessment-results schema", () => {
  const config = createSampleConfig();
  const frameworks = { fedramp: [], disa_stig: [], irap: [], ismap: [], soc2: [], pci_dss: [], general: [] };
  const oscal = buildOscalAssessmentResults(
    config,
    [
      {
        id: "OKTA-ADMIN-006",
        title: "Okta Support access and third-party admin governance",
        category: "admin_access",
        status: "Pass",
        severity: "medium",
        summary: "Okta Support access is DISABLED and third-party administrators are not permitted.",
        evidence: ["Okta Support access: DISABLED", "Third-party administrators: false"],
        recommendation: "Keep disabled.",
        frameworks: { ...frameworks, fedramp: ["AC-2", "AC-6(5)", "AC-2"] },
      },
      {
        id: "OKTA-MON-009",
        title: "Administrator security notification emails",
        category: "monitoring",
        status: "Manual",
        severity: "low",
        summary: "Not exposed by API.",
        evidence: [],
        recommendation: "Capture screenshots.",
        manualNote: "Collect manually.",
        frameworks: { ...frameworks, fedramp: ["AU-6"] },
      },
    ],
    "2026-09-21T00:00:00.000Z",
  );

  const document = oscal["assessment-results"];
  for (const key of ["uuid", "metadata", "import-ap", "results"]) {
    assert.ok(key in document, `assessment-results.${key}`);
  }
  const result = document.results[0];
  for (const key of ["uuid", "title", "description", "start", "reviewed-controls"]) {
    assert.ok(key in result, `result.${key}`);
  }

  const reviewed = result["reviewed-controls"];
  assert.ok(Array.isArray(reviewed["control-selections"]));
  assert.equal(reviewed["control-selections"].length, 1);
  const included = reviewed["control-selections"][0]["include-controls"];
  assert.deepEqual(
    included.map((entry) => entry["control-id"]),
    ["ac-2", "ac-6.5", "au-6"],
  );
  for (const entry of included) {
    assert.deepEqual(Object.keys(entry), ["control-id"]);
  }

  const [withEvidence, withoutEvidence] = result.observations;
  assert.deepEqual(withEvidence["relevant-evidence"], [
    { description: "Okta Support access: DISABLED" },
    { description: "Third-party administrators: false" },
  ]);
  assert.equal("relevant-evidence" in withoutEvidence, false, "empty evidence omits relevant-evidence (minItems 1)");
  const observationKeys = new Set(["uuid", "title", "description", "props", "links", "methods", "types", "origins", "subjects", "relevant-evidence", "collected", "expires", "remarks"]);
  for (const observation of result.observations) {
    for (const key of Object.keys(observation)) {
      assert.ok(observationKeys.has(key), `observation key ${key} is not allowed by the OSCAL schema`);
    }
    assert.ok(Array.isArray(observation.methods) && observation.methods.length > 0);
    assert.match(observation.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  }

  const serialized = JSON.stringify(oscal);
  assert.equal(serialized.includes("relevant_evidence"), false);
  assert.equal(serialized.includes("reviewed_controls"), false);
});

test("OKTA-ADMIN-006 reads thirdPartyAdmin and passes only for a compliant org", () => {
  const config = createSampleConfig();

  const compliant = createSampleAdminData();
  compliant.oktaSupportAccess = dataset({ support: "DISABLED", expiration: null, caseNumber: null });
  compliant.thirdPartyAdminSetting = dataset({ thirdPartyAdmin: false });
  const passFinding = findingById(assessOktaAdminAccess(compliant, config), "OKTA-ADMIN-006");
  assert.equal(passFinding.status, "Pass");
  assert.match(passFinding.summary, /third-party administrators are not permitted/);
  assert.ok(passFinding.evidence.includes("Third-party administrators: false"));

  const enabled = createSampleAdminData();
  enabled.thirdPartyAdminSetting = dataset({ thirdPartyAdmin: true });
  const enabledFinding = findingById(assessOktaAdminAccess(enabled, config), "OKTA-ADMIN-006");
  assert.equal(enabledFinding.status, "Partial");
  assert.match(enabledFinding.summary, /third-party administrator access is enabled/);

  const legacyField = createSampleAdminData();
  legacyField.thirdPartyAdminSetting = dataset({ thirdPartyAdminSetting: false });
  const legacyFinding = findingById(assessOktaAdminAccess(legacyField, config), "OKTA-ADMIN-006");
  assert.equal(legacyFinding.status, "Partial");
  assert.match(legacyFinding.summary, /did not include the thirdPartyAdmin field/);

  const supportEnabled = createSampleAdminData();
  supportEnabled.oktaSupportAccess = dataset({ support: "ENABLED", expiration: "2026-10-01T00:00:00.000Z" });
  const supportFinding = findingById(assessOktaAdminAccess(supportEnabled, config), "OKTA-ADMIN-006");
  assert.equal(supportFinding.status, "Partial");
  assert.match(supportFinding.summary, /ENABLED until 2026-10-01T00:00:00\.000Z/);
});

test("OKTA-ADMIN-006 names a 404 or 403 on the third-party admin surface instead of swallowing it", async () => {
  const config = createSampleConfig();
  const thirdPartyPath = "/api/v1/org/orgSettings/thirdPartyAdminSetting";

  const notFoundClient = {
    ...createSampleClient(),
    async getThirdPartyAdminSetting() {
      throw new Error(`Okta API request failed for ${thirdPartyPath} (404 Not Found): Not found`);
    },
  };
  const notFoundData = await collectOktaAdminAccessData(notFoundClient);
  assert.match(notFoundData.thirdPartyAdminSetting.error, /404 Not Found/);
  const notFound = findingById(assessOktaAdminAccess(notFoundData, config), "OKTA-ADMIN-006");
  assert.equal(notFound.status, "Partial");
  assert.match(notFound.summary, /third-party admin setting could not be read because the endpoint returned 404 Not Found/);
  assert.ok(notFound.evidence.some((entry) => entry.includes(thirdPartyPath)));

  const forbiddenClient = {
    ...createSampleClient(),
    async getThirdPartyAdminSetting() {
      throw forbidden(thirdPartyPath);
    },
  };
  const forbiddenFinding = findingById(
    assessOktaAdminAccess(await collectOktaAdminAccessData(forbiddenClient), config),
    "OKTA-ADMIN-006",
  );
  assert.equal(forbiddenFinding.status, "Partial");
  assert.match(forbiddenFinding.summary, /403 Forbidden/);

  const supportForbiddenClient = {
    ...createSampleClient(),
    async getOktaSupportSettings() {
      throw forbidden("/api/v1/org/privacy/oktaSupport");
    },
  };
  const supportForbidden = findingById(
    assessOktaAdminAccess(await collectOktaAdminAccessData(supportForbiddenClient), config),
    "OKTA-ADMIN-006",
  );
  assert.equal(supportForbidden.status, "Manual");
  assert.match(supportForbidden.summary, /403 Forbidden.*Okta Support access/);
  assert.ok(supportForbidden.manualNote);

  const bothForbidden = findingById(
    assessOktaAdminAccess(
      await collectOktaAdminAccessData({
        ...supportForbiddenClient,
        async getThirdPartyAdminSetting() {
          throw new Error(`Okta API request failed for ${thirdPartyPath} (404 Not Found): Not found`);
        },
      }),
      config,
    ),
    "OKTA-ADMIN-006",
  );
  assert.equal(bothForbidden.status, "Manual");
  assert.match(bothForbidden.summary, /403 Forbidden.*Okta Support access.*404 Not Found.*third-party admin setting/);
});

test("OktaAuditorClient requests the published org-setting paths and does not swallow 404s", async () => {
  const requested = [];
  const fetchImpl = async (input) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    requested.push(`${requestUrl.pathname}${requestUrl.search}`);
    if (requestUrl.pathname === "/api/v1/org/orgSettings/thirdPartyAdminSetting") {
      return new Response(JSON.stringify({ thirdPartyAdmin: false }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (requestUrl.pathname === "/api/v1/org/privacy/oktaSupport") {
      return new Response(JSON.stringify({ errorCode: "E0000007", errorSummary: "Not found" }), {
        status: 404,
        statusText: "Not Found",
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify([]), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new OktaAuditorClient(
    {
      orgUrl: "https://tenant.example.okta.com",
      authMode: "SSWS",
      token: "ssws-token",
      scopes: [],
      sourceChain: ["tests"],
    },
    { fetchImpl },
  );

  assert.deepEqual(await client.getThirdPartyAdminSetting(), { thirdPartyAdmin: false });
  await assert.rejects(() => client.getOktaSupportSettings(), /\/api\/v1\/org\/privacy\/oktaSupport \(404 Not Found\)/);
  await client.listApiTokens();
  await client.listAuthenticators();

  assert.ok(requested.includes("/api/v1/org/orgSettings/thirdPartyAdminSetting"));
  assert.equal(requested.some((path) => path.startsWith("/api/v1/org/settings/thirdPartyAdminSetting")), false);
  assert.ok(requested.includes("/api/v1/api-tokens"), "api-tokens is requested without a limit parameter");
  assert.ok(requested.includes("/api/v1/authenticators"), "authenticators is requested without a limit parameter");
  assert.equal(requested.some((path) => /\/api\/v1\/(api-tokens|authenticators)\?/.test(path)), false);

  const probed = [];
  await runOktaAccessCheck(
    {
      async getJson(pathname) {
        probed.push(pathname);
        return [];
      },
    },
    createSampleConfig(),
  );
  assert.ok(probed.includes("/api/v1/api-tokens"));
});

test("rule 1: forbidden or errored endpoints yield manual findings that name the cause", () => {
  const config = createSampleConfig();
  const authentication = createSampleAuthenticationData();
  authentication.authenticators = dataset([], "Okta API request failed for /api/v1/authenticators (403 Forbidden)");
  authentication.passwordPolicies = dataset([], "Okta API request failed for /api/v1/policies?type=PASSWORD (403 Forbidden)");
  const authResult = assessOktaAuthentication(authentication, config);
  for (const id of ["OKTA-AUTH-001", "OKTA-AUTH-003", "OKTA-AUTH-004", "OKTA-AUTH-005", "OKTA-AUTH-009"]) {
    const finding = findingById(authResult, id);
    assert.equal(finding.status, "Manual", id);
    assert.match(finding.summary, /403 Forbidden/);
    assert.match(finding.manualNote, /Collect manually/);
  }

  const integrations = createSampleIntegrationData();
  integrations.apps = dataset([], "Okta API request failed for /api/v1/apps (403 Forbidden)");
  integrations.trustedOrigins = dataset([], "Okta API request failed for /api/v1/trustedOrigins (500 Internal Server Error)");
  const integResult = assessOktaIntegrations(integrations, config);
  assert.equal(statusOf(integResult, "OKTA-INTEG-001"), "Manual");
  assert.match(findingById(integResult, "OKTA-INTEG-001").summary, /request failed/);
  assert.equal(statusOf(integResult, "OKTA-INTEG-003"), "Manual");
  assert.equal(statusOf(integResult, "OKTA-INTEG-005"), "Manual");
  assert.equal(statusOf(integResult, "OKTA-INTEG-006"), "Manual");

  const monitoring = createSampleMonitoringData();
  monitoring.systemLogs = dataset([], "Okta API request failed for /api/v1/logs (403 Forbidden)");
  monitoring.logStreams = dataset([], "Okta API request failed for /api/v1/logStreams (403 Forbidden)");
  monitoring.eventHooks = dataset([], "Okta API request failed for /api/v1/eventHooks (403 Forbidden)");
  const monResult = assessOktaMonitoring(monitoring, config);
  assert.equal(statusOf(monResult, "OKTA-MON-001"), "Manual");
  assert.equal(statusOf(monResult, "OKTA-MON-002"), "Manual");

  const admin = createSampleAdminData();
  admin.usersWithRoleAssignments = dataset([], "Okta API request failed for /api/v1/iam/assignees/users (403 Forbidden)");
  const adminResult = assessOktaAdminAccess(admin, config);
  for (const id of ["OKTA-ADMIN-001", "OKTA-ADMIN-002", "OKTA-ADMIN-004"]) {
    assert.equal(statusOf(adminResult, id), "Manual", id);
  }
});

test("rule 2: empty inventories never pass by default and state fail or manual intent", () => {
  const config = createSampleConfig();
  const authentication = createSampleAuthenticationData();
  authentication.authenticators = dataset([]);
  authentication.passwordPolicies = dataset([]);
  const authResult = assessOktaAuthentication(authentication, config);
  assert.equal(statusOf(authResult, "OKTA-AUTH-001"), "Fail");
  assert.match(findingById(authResult, "OKTA-AUTH-001").summary, /empty inventory is treated as a failure/);
  assert.equal(statusOf(authResult, "OKTA-AUTH-003"), "Manual");
  assert.match(findingById(authResult, "OKTA-AUTH-003").summary, /Default policy/);

  const admin = createSampleAdminData();
  admin.usersWithRoleAssignments = dataset([]);
  admin.users = dataset([]);
  const adminResult = assessOktaAdminAccess(admin, config);
  assert.equal(statusOf(adminResult, "OKTA-ADMIN-001"), "Manual");
  assert.match(findingById(adminResult, "OKTA-ADMIN-001").summary, /at least one super admin/);
  assert.equal(statusOf(adminResult, "OKTA-ADMIN-005"), "Manual");

  const integrations = createSampleIntegrationData();
  integrations.apps = dataset([]);
  integrations.networkZones = dataset([]);
  const integResult = assessOktaIntegrations(integrations, config);
  assert.equal(statusOf(integResult, "OKTA-INTEG-002"), "Manual");
  assert.equal(statusOf(integResult, "OKTA-INTEG-003"), "Manual");
  assert.equal(statusOf(integResult, "OKTA-INTEG-005"), "Manual");

  const monitoring = createSampleMonitoringData();
  monitoring.logStreams = dataset([]);
  monitoring.eventHooks = dataset([]);
  monitoring.apiTokens = dataset([]);
  const sswsResult = assessOktaMonitoring(monitoring, config);
  assert.equal(statusOf(sswsResult, "OKTA-MON-001"), "Fail");
  assert.match(findingById(sswsResult, "OKTA-MON-001").summary, /empty inventory fails this control/);
  assert.equal(statusOf(sswsResult, "OKTA-MON-005"), "Manual");
  assert.equal(statusOf(sswsResult, "OKTA-MON-007"), "Manual");

  const oauthResult = assessOktaMonitoring(monitoring, createSampleConfig({ authMode: "PrivateKey", token: undefined, clientId: "app" }));
  assert.equal(statusOf(oauthResult, "OKTA-MON-005"), "Pass");
  assert.match(findingById(oauthResult, "OKTA-MON-005").summary, /compliant by intent/);
});

test("rule 3: controls unavailable on the org edition render manual, never pass", () => {
  const config = createSampleConfig();
  const authentication = createSampleAuthenticationData();
  authentication.authenticators = dataset([]);
  authentication.orgFactors = dataset([{ id: "okta_verify", factorType: "push", status: "ACTIVE" }]);
  const authResult = assessOktaAuthentication(authentication, config);
  assert.equal(statusOf(authResult, "OKTA-AUTH-001"), "Manual");
  assert.match(findingById(authResult, "OKTA-AUTH-001").summary, /Classic Engine/);
  assert.equal(statusOf(authResult, "OKTA-AUTH-009"), "Manual");

  const monitoring = createSampleMonitoringData();
  monitoring.threatInsight = dataset(null);
  monitoring.deviceAssurance = dataset([], "Okta API request failed for /api/v1/device-assurances (404 Not Found)");
  monitoring.behaviors = dataset([], "Okta API request failed for /api/v1/behaviors (404 Not Found)");
  const monResult = assessOktaMonitoring(monitoring, config);
  assert.equal(statusOf(monResult, "OKTA-MON-003"), "Manual");
  assert.match(findingById(monResult, "OKTA-MON-003").summary, /not available on this org edition/);
  assert.equal(statusOf(monResult, "OKTA-MON-006"), "Manual");
  assert.match(findingById(monResult, "OKTA-MON-006").summary, /404 Not Found/);
  assert.equal(statusOf(monResult, "OKTA-MON-004"), "Manual");

  const admin = createSampleAdminData();
  admin.oktaSupportAccess = dataset(null);
  assert.equal(statusOf(assessOktaAdminAccess(admin, config), "OKTA-ADMIN-006"), "Manual");
});

test("rule 4: items missing dates are never counted fresh and cap at partial", () => {
  const config = createSampleConfig();
  const admin = createSampleAdminData();
  admin.usersWithRoleAssignments = dataset([
    { id: "user-1", status: "ACTIVE", profile: { login: "nodate@example.gov" } },
  ]);
  const adminResult = assessOktaAdminAccess(admin, config);
  assert.equal(statusOf(adminResult, "OKTA-ADMIN-002"), "Partial");
  assert.match(findingById(adminResult, "OKTA-ADMIN-002").summary, /no lastLogin/);

  admin.users = dataset([
    { id: "user-1", status: "ACTIVE", profile: { login: "nodate@example.gov" } },
    { id: "user-3", status: "PROVISIONED", profile: { login: "nocreated@example.gov" } },
  ]);
  const lifecycle = assessOktaAdminAccess(admin, config);
  assert.equal(statusOf(lifecycle, "OKTA-ADMIN-005"), "Fail");
  assert.match(findingById(lifecycle, "OKTA-ADMIN-005").evidence.join("\n"), /PROVISIONED or STAGED older than 30 days: 1/);

  const monitoring = createSampleMonitoringData();
  monitoring.apiTokens = dataset([{ id: "token-1", name: "Undated token", network: { connection: "ZONE" } }]);
  const monResult = assessOktaMonitoring(monitoring, config);
  assert.equal(statusOf(monResult, "OKTA-MON-005"), "Partial");
  assert.match(findingById(monResult, "OKTA-MON-005").summary, /no usable date metadata/);
  assert.equal(statusOf(monResult, "OKTA-MON-007"), "Partial");
  assert.match(findingById(monResult, "OKTA-MON-007").summary, /lack an expiry timestamp/);
});

test("rule 5: partial inventories are flagged and never passed on", () => {
  const config = createSampleConfig();
  const admin = createSampleAdminData();
  admin.privilegedGroups = {
    data: admin.privilegedGroups.data,
    truncated: true,
    truncationNote: "Only the first 25 of 30 admin-like groups were expanded.",
  };
  admin.userRoles = dataset(admin.userRoles.data, "user-2: Okta API request failed for /api/v1/users/user-2/roles (403 Forbidden)");
  admin.users = { data: admin.users.data, truncated: true, truncationNote: "User listing stopped after 50 pages." };
  admin.privilegedUserFactors = {
    data: admin.privilegedUserFactors.data,
    truncated: true,
    truncationNote: "Factor enrollment was read for 50 of 60 privileged users.",
  };
  const adminResult = assessOktaAdminAccess(admin, config);
  assert.equal(statusOf(adminResult, "OKTA-ADMIN-001"), "Partial");
  assert.equal(statusOf(adminResult, "OKTA-ADMIN-003"), "Partial");
  assert.match(findingById(adminResult, "OKTA-ADMIN-003").evidence.join("\n"), /Partial data: Only the first 25/);
  assert.equal(statusOf(adminResult, "OKTA-ADMIN-004"), "Partial");
  assert.equal(statusOf(adminResult, "OKTA-ADMIN-005"), "Partial");
  assert.match(findingById(adminResult, "OKTA-ADMIN-005").summary, /inventory truncated/);

  const authentication = createSampleAuthenticationData();
  authentication.signOnPolicyRules = dataset(authentication.signOnPolicyRules.data, "signon-2: Okta API request failed (403 Forbidden)");
  const authResult = assessOktaAuthentication(authentication, config);
  assert.equal(statusOf(authResult, "OKTA-AUTH-002"), "Partial");
  assert.equal(statusOf(authResult, "OKTA-AUTH-006"), "Partial");

  const monitoring = createSampleMonitoringData();
  monitoring.eventHooks = dataset([], "Okta API request failed for /api/v1/eventHooks (403 Forbidden)");
  const monResult = assessOktaMonitoring(monitoring, config);
  assert.equal(statusOf(monResult, "OKTA-MON-001"), "Partial");
});

test("rule 6: verdicts read every documented status flag", () => {
  const config = createSampleConfig();
  const authentication = createSampleAuthenticationData();
  authentication.passwordPolicies.data[0].status = "INACTIVE";
  authentication.signOnPolicies.data[0].status = "INACTIVE";
  authentication.authenticators.data.push({ id: "auth-sms", key: "phone_number", status: "INACTIVE" });
  const authResult = assessOktaAuthentication(authentication, config);
  assert.equal(statusOf(authResult, "OKTA-AUTH-003"), "Fail");
  assert.match(findingById(authResult, "OKTA-AUTH-003").summary, /none are ACTIVE/);
  assert.equal(statusOf(authResult, "OKTA-AUTH-002"), "Partial");
  assert.equal(statusOf(authResult, "OKTA-AUTH-006"), "Manual");
  assert.equal(statusOf(authResult, "OKTA-AUTH-009"), "Pass");

  const integrations = createSampleIntegrationData();
  integrations.apps.data.push({
    id: "app-2",
    label: "Legacy inactive",
    status: "INACTIVE",
    settings: { oauthClient: { grant_types: ["password"] } },
  });
  integrations.networkZones.data[1].status = "INACTIVE";
  const integResult = assessOktaIntegrations(integrations, config);
  assert.equal(statusOf(integResult, "OKTA-INTEG-003"), "Partial");
  assert.equal(statusOf(integResult, "OKTA-INTEG-002"), "Partial");

  const monitoring = createSampleMonitoringData();
  monitoring.logStreams.data[0].status = "INACTIVE";
  monitoring.eventHooks.data[0].status = "INACTIVE";
  const monResult = assessOktaMonitoring(monitoring, config);
  assert.equal(statusOf(monResult, "OKTA-MON-001"), "Fail");

  const admin = createSampleAdminData();
  admin.privilegedUserFactors = dataset({
    "user-1": [{ id: "factor-1", factorType: "webauthn", provider: "FIDO", status: "PENDING_ACTIVATION" }],
  });
  assert.equal(statusOf(assessOktaAdminAccess(admin, config), "OKTA-ADMIN-004"), "Fail");
});

test("rule 7: pagination runs to completion or records truncation", async () => {
  const pages = {
    "": [{ id: "u1" }],
    "p2": [{ id: "u2" }],
    "p3": [{ id: "u3" }],
  };
  const nextOf = { "": "p2", p2: "p3" };
  const fetchImpl = async (input) => {
    const url = new URL(input.toString());
    const after = url.searchParams.get("after") ?? "";
    const headers = { "content-type": "application/json" };
    if (nextOf[after]) {
      headers.link = `<https://tenant.example.okta.com/api/v1/users?limit=200&after=${nextOf[after]}>; rel="next"`;
    }
    return new Response(JSON.stringify(pages[after]), { status: 200, headers });
  };
  const client = new OktaAuditorClient(
    { orgUrl: "https://tenant.example.okta.com", authMode: "SSWS", token: "t", scopes: [], sourceChain: ["tests"] },
    { fetchImpl },
  );
  const complete = await client.listUsersWithMeta();
  assert.equal(complete.items.length, 3);
  assert.equal(complete.truncated, false);
  assert.equal(complete.pagesFetched, 3);

  const capped = await client.listPaginatedWithMeta("/api/v1/users?limit=200", 2);
  assert.equal(capped.items.length, 2);
  assert.equal(capped.truncated, true);

  const admin = await collectOktaAdminAccessData({
    ...createSampleClient(),
    async listUsersWithMeta() {
      return { items: [{ id: "u1", status: "ACTIVE", lastLogin: new Date().toISOString() }], truncated: true, pagesFetched: 50 };
    },
  });
  assert.equal(admin.users.truncated, true);
  assert.match(admin.users.truncationNote, /rel="next" page remained unread/);
  assert.equal(statusOf(assessOktaAdminAccess(admin, createSampleConfig()), "OKTA-ADMIN-005"), "Partial");
});

test("rule 8: re-running the export never overwrites a prior bundle", async () => {
  const outputRoot = createTempBase("grclanker-okta-rerun-");
  const config = createSampleConfig();
  const first = await exportOktaAuditBundle(createSampleClient(), config, outputRoot);
  const firstZipStat = statSync(first.zipPath);
  const firstFindings = readFileSync(join(first.outputDir, "analysis", "findings.json"), "utf8");

  const second = await exportOktaAuditBundle(createSampleClient(), config, outputRoot);
  assert.notEqual(second.outputDir, first.outputDir);
  assert.notEqual(second.zipPath, first.zipPath);
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.ok(second.outputDir.endsWith("-2"));
  assert.ok(existsSync(first.zipPath));
  assert.equal(statSync(first.zipPath).size, firstZipStat.size);
  assert.equal(readFileSync(join(first.outputDir, "analysis", "findings.json"), "utf8"), firstFindings);
});

test("self-check (a): all-403 fixtures produce no pass in any assess tool", async () => {
  const results = await runAllAssessments(createAll403Client(), createSampleConfig());
  const findings = allFindings(results);
  assert.equal(findings.length, OKTA_CHECK_IDS.length);
  const passes = findings.filter((finding) => finding.status === "Pass").map((finding) => finding.id);
  assert.deepEqual(passes, []);
  const manual = findings.filter((finding) => finding.status === "Manual");
  assert.equal(manual.length, findings.length);
  for (const finding of manual) {
    assert.ok(finding.manualNote, `${finding.id} manual note`);
  }
});

test("self-check (b): all-empty fixtures pass only where emptiness is compliant by intent", async () => {
  const ssws = await runAllAssessments(createAllEmptyClient(), createSampleConfig());
  const sswsPasses = allFindings(ssws).filter((finding) => finding.status === "Pass").map((finding) => finding.id);
  assert.deepEqual(sswsPasses, []);

  const oauth = await runAllAssessments(
    createAllEmptyClient(),
    createSampleConfig({ authMode: "PrivateKey", token: undefined, clientId: "service-app" }),
  );
  const oauthPasses = allFindings(oauth).filter((finding) => finding.status === "Pass").map((finding) => finding.id).sort();
  assert.deepEqual(oauthPasses, ["OKTA-MON-005", "OKTA-MON-007"]);
  for (const id of oauthPasses) {
    assert.match(findingById(oauth.monitoring, id).summary, /compliant by intent/);
  }
  assert.equal(statusOf(ssws.integrations, "OKTA-INTEG-001"), "Info");
});

test("self-check (c): partial-inventory fixtures produce no pass in any assess tool", async () => {
  const results = await runAllAssessments(createPartialInventoryClient(), createSampleConfig());
  const findings = allFindings(results);
  assert.equal(findings.length, OKTA_CHECK_IDS.length);
  const passes = findings.filter((finding) => finding.status === "Pass").map((finding) => finding.id);
  assert.deepEqual(passes, []);
  assert.equal(statusOf(results.admin, "OKTA-ADMIN-003"), "Partial");
  assert.equal(statusOf(results.admin, "OKTA-ADMIN-005"), "Partial");
  assert.equal(statusOf(results.admin, "OKTA-ADMIN-001"), "Partial");
  assert.equal(statusOf(results.monitoring, "OKTA-MON-008"), "Partial");
});

test("self-check (d): compliant-org fixtures pass every automatable finding (29 of 29)", async () => {
  const results = await runAllAssessments(createSampleClient(), createSampleConfig());
  const findings = allFindings(results);
  assert.equal(findings.length, OKTA_CHECK_IDS.length);

  const manual = findings.filter((finding) => finding.status === "Manual").map((finding) => finding.id);
  assert.deepEqual(manual, ["OKTA-MON-009"], "only the API-invisible notification control stays Manual");

  const automatable = findings.filter((finding) => finding.id !== "OKTA-MON-009");
  assert.equal(automatable.length, 29);
  const notPassing = automatable
    .filter((finding) => finding.status !== "Pass")
    .map((finding) => `${finding.id}=${finding.status}`);
  assert.deepEqual(notPassing, [], "every automatable finding reaches Pass on a compliant org");

  const adminGovernance = findingById(results.admin, "OKTA-ADMIN-006");
  assert.equal(adminGovernance.status, "Pass");
  assert.ok(adminGovernance.evidence.includes("Okta Support access: DISABLED"));
  assert.ok(adminGovernance.evidence.includes("Third-party administrators: false"));
  for (const result of Object.values(results)) {
    assert.equal(result.summary.Fail, 0);
    assert.equal(result.summary.Partial, 0);
  }
});

/** Planted secrets: random alphanumerics (SSWS tokens keep their 00 prefix and 42-character length), so no 6-character window of one occurs in a legitimate fixture value. */
const FAKE_SECRETS = {
  appClientSecret: "7Yx5FjWaghuQ55JkgA",
  swaPassword: "2D2GP46d8TcMvqSPEv",
  secretHash: "JQqJRUGezzfNVkMgqW",
  appNotesSsws: "00dGXckREU3aRN3gfL69MYjEFFr9Cj8kfYyFXrZ3e9",
  jwtPayload: "bFPe4VLM4KyB3nGRjE",
  jwtSignature: "3JUDFcCTupVYJv58gY",
  acsRelayState: "DZwS4t79QpHVdCJgUn",
  idpClientSecret: "y7PFSxdGWneFdx234j",
  hookPathToken: "98EkVfVxxMHrUjyyWb",
  hookQueryToken: "TbEkCfZtJFNWNHzjwM",
  hookHeaderValue: "6cwxPaScwNqhjU8ygX",
  hookCustomHeaderValue: "qqbfLjKuvqVgNszmj6",
  hookAuthValue: "nHaCnyfzL5fGnBFXGp",
  hecToken: "QUXMgWm9fxYpbS3Ewa",
  duoSecretKey: "jPpMDR6m22qMZCvQHL",
  sessionToken: "BErgdVeGgbmYWqCxkf",
  authnRequestId: "eQw65LsRKMVMGfc28K",
  userPasswordValue: "rcRnVXAexjkGUVsQTy",
  recoveryAnswer: "XM8GY3mhCW2FpgHn4a",
  totpSharedSecret: "TZWTvADmT7CSsgrYHD",
  sswsToken: "00QbNhmq3FzXaXEDy3zZU5fS2EepAmFzLGFkGmhBeB",
};

function fakeJwt() {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "RS256" })}.${encode({ sub: FAKE_SECRETS.jwtPayload, aud: "okta" })}.${FAKE_SECRETS.jwtSignature}`;
}

function secretUser(id, login) {
  const now = new Date().toISOString();
  return {
    id,
    status: "ACTIVE",
    lastLogin: now,
    created: "2024-01-01T00:00:00.000Z",
    profile: { login },
    credentials: {
      password: { value: FAKE_SECRETS.userPasswordValue },
      recovery_question: { question: "first pet", answer: FAKE_SECRETS.recoveryAnswer },
      provider: { type: "OKTA", name: "OKTA" },
    },
  };
}

/** A compliant org whose every credential-capable record carries a distinctive fake secret. */
function createSecretFixtureClient() {
  const sample = createSampleClient();
  const now = new Date().toISOString();
  return {
    ...sample,
    async listAuthenticators() {
      return [
        ...(await sample.listAuthenticators()),
        {
          id: "auth-duo",
          key: "duo",
          name: "Duo Security",
          type: "app",
          status: "ACTIVE",
          provider: {
            type: "DUO",
            configuration: { host: "api-1234.duosecurity.com", integrationKey: "DI-INTEGRATION", secretKey: FAKE_SECRETS.duoSecretKey },
          },
        },
      ];
    },
    async listIdps() {
      return [
        ...(await sample.listIdps()),
        {
          id: "idp-oidc",
          name: "Upstream OIDC",
          type: "OIDC",
          status: "ACTIVE",
          protocol: {
            type: "OIDC",
            credentials: {
              client: { client_id: "upstream-client", client_secret: FAKE_SECRETS.idpClientSecret },
              trust: { kid: "kid-2" },
            },
          },
        },
      ];
    },
    async getDefaultAuthorizationServer() {
      return { id: "default", name: "default", credentials: { signing: { kid: "kid-3", rotationMode: "AUTO" } } };
    },
    async listUsersWithRoleAssignments() {
      return [secretUser("user-1", "admin@example.gov")];
    },
    async listUsersWithMeta() {
      return {
        items: [secretUser("user-1", "admin@example.gov"), secretUser("user-2", "analyst@example.gov")],
        truncated: false,
        pagesFetched: 1,
      };
    },
    async listUserFactors() {
      return [
        { id: "factor-1", factorType: "webauthn", provider: "FIDO", status: "ACTIVE", profile: { credentialId: "cred-1" } },
        {
          id: "factor-2",
          factorType: "token:software:totp",
          provider: "OKTA",
          status: "ACTIVE",
          profile: { credentialId: "admin@example.gov" },
          _embedded: { activation: { sharedSecret: FAKE_SECRETS.totpSharedSecret } },
        },
      ];
    },
    async listApps() {
      return [
        {
          id: "app-1",
          name: "oidc_client",
          label: "Core OIDC",
          status: "ACTIVE",
          signOnMode: "OPENID_CONNECT",
          features: ["PUSH_NEW_USERS", "PUSH_USER_DEACTIVATION"],
          credentials: {
            oauthClient: {
              client_id: "0oa-core-client",
              client_secret: FAKE_SECRETS.appClientSecret,
              autoKeyRotation: true,
              token_endpoint_auth_method: "client_secret_basic",
            },
            signing: { kid: "kid-1" },
            secret_hash: FAKE_SECRETS.secretHash,
          },
          settings: {
            oauthClient: { grant_types: ["authorization_code"], application_type: "web" },
            notes: { admin: FAKE_SECRETS.appNotesSsws },
            app: { bearerAssertion: fakeJwt() },
            signOn: { ssoAcsUrl: `https://acs.example.gov/sso?RelayState=${FAKE_SECRETS.acsRelayState}` },
          },
        },
        {
          id: "app-2",
          name: "template_swa",
          label: "Legacy SWA",
          status: "ACTIVE",
          signOnMode: "SHARED_USERNAME_AND_PASSWORD",
          credentials: {
            scheme: "SHARED_USERNAME_AND_PASSWORD",
            userName: "shared-service",
            password: { value: FAKE_SECRETS.swaPassword },
          },
        },
      ];
    },
    async listEventHooks() {
      return [
        {
          id: "hook-1",
          name: "SIEM Forwarder",
          status: "ACTIVE",
          verificationStatus: "VERIFIED",
          events: { type: "EVENT_TYPE", items: ["user.session.start"] },
          channel: {
            type: "HTTP",
            version: "1.0.0",
            config: {
              uri: `https://hooks.example.gov/ingest/${FAKE_SECRETS.hookPathToken}?token=${FAKE_SECRETS.hookQueryToken}`,
              method: "POST",
              headers: [
                { key: "X-Api-Key", value: FAKE_SECRETS.hookHeaderValue },
                { key: "X-Tenant", value: FAKE_SECRETS.hookCustomHeaderValue },
              ],
              authScheme: { type: "HEADER", key: "Authorization", value: FAKE_SECRETS.hookAuthValue },
            },
          },
        },
      ];
    },
    async listLogStreams() {
      return [
        {
          id: "stream-1",
          name: "Splunk HEC",
          type: "splunk_cloud_logstreaming",
          status: "ACTIVE",
          settings: { host: "acme.splunkcloud.com", edition: "gcp", token: FAKE_SECRETS.hecToken },
        },
      ];
    },
    async listSystemLogs() {
      return [
        {
          uuid: "event-1",
          published: now,
          eventType: "user.session.start",
          displayMessage: "User login to Okta",
          severity: "INFO",
          outcome: { result: "SUCCESS" },
          actor: { id: "user-1", type: "User", alternateId: "admin@example.gov", displayName: "Admin" },
          client: { ipAddress: "10.0.0.1", userAgent: { rawUserAgent: "Mozilla/5.0" } },
          debugContext: {
            debugData: {
              url: `/login/sessionCookieRedirect?token=${FAKE_SECRETS.sessionToken}&redirectUrl=%2Fapp`,
              requestUri: "/api/v1/authn",
              authnRequestId: FAKE_SECRETS.authnRequestId,
            },
          },
          request: { ipChain: [{ ip: "10.0.0.1" }] },
        },
      ];
    },
    async getThreatInsight() {
      return { action: "block", excludeZones: ["zone-1"], lastUpdated: now, _links: { self: { href: "https://tenant.okta.gov/api/v1/threats/configuration" } } };
    },
    async getUser(userId) {
      return secretUser(userId, `${userId}@example.gov`);
    },
  };
}

/** The planted secrets whose windows must never appear: every FAKE_SECRETS value and the two variable segments of the fake JWT (its header is the constant RS256 header). */
function secretValues() {
  return [...Object.values(FAKE_SECRETS), ...fakeJwt().split(".").slice(1)];
}

/** Wraps a fixture client so that everything it serves is recorded, for the fixture self-check. */
function recordingFixtureClient(client) {
  const served = [];
  const wrapped = {};
  for (const [name, member] of Object.entries(client)) {
    wrapped[name] = typeof member === "function"
      ? async (...args) => {
        const value = await member.apply(client, args);
        served.push(value);
        return value;
      }
      : member;
  }
  return { client: wrapped, served };
}

test("rule 9: exportOktaAuditBundle never writes client secrets, passwords, hook credentials, tokens, or debug URLs", async () => {
  const outputRoot = createTempBase("grclanker-okta-secrets-");
  const config = createSampleConfig({ token: FAKE_SECRETS.sswsToken });
  const { client, served } = recordingFixtureClient(createSecretFixtureClient());
  const planted = secretValues();
  const secrets = leakWindows(planted);

  const result = await exportOktaAuditBundle(client, config, outputRoot);
  assert.equal(result.errorCount, 0);
  assertFixtureFreeOfCanaryWindows(JSON.stringify(served), [...planted, fakeJwt()], "secret fixture");
  const files = readBundleFiles(result.outputDir);
  for (const expected of [
    "core_data/apps.json",
    "core_data/idps.json",
    "core_data/event_hooks.json",
    "core_data/log_streams.json",
    "core_data/authenticators.json",
    "core_data/system_logs_recent.json",
    "core_data/users.json",
    "core_data/privileged_user_factors.json",
    "analysis/findings.json",
    "analysis/monitoring.json",
    "compliance/fedramp/oscal_assessment_results.json",
    "QUICK_REFERENCE.md",
  ]) {
    assert.ok(files.has(expected), `${expected} is written`);
  }
  assertSecretsAbsent(assert, files, secrets, "bundle files");
  assertSecretsAbsent(assert, readZipEntries(result.zipPath), secrets, "zip entries");

  const results = await runAllAssessments(client, config);
  const access = await runOktaAccessCheck(
    {
      async getJson(pathname) {
        throw new Error(`Okta API request failed for ${pathname} (403 Forbidden): denied`);
      },
    },
    config,
  );
  assertSecretsAbsent(assert, new Map([["assess results and access check", JSON.stringify({ results, access })]]), secrets, "tool payloads");
  assert.equal(results.monitoring.summary.Fail, 0);
  assert.equal(statusOf(results.integrations, "OKTA-INTEG-006"), "Pass");
  assert.match(findingById(results.monitoring, "OKTA-MON-003").evidence[0], /^ThreatInsight action: block; excluded zones: 1$/);

  const apps = JSON.parse(files.get("core_data/apps.json"));
  assert.equal(apps[0].credentials.oauthClient.client_secret, "[REDACTED]");
  assert.equal(apps[0].credentials.oauthClient.client_id, "0oa-core-client");
  assert.equal(apps[0].credentials.secret_hash, "[REDACTED]");
  assert.equal(apps[0].credentials.signing.kid, "kid-1");
  assert.equal(apps[0].settings.notes.admin, "[REDACTED]", "SSWS-shaped values are redacted by shape");
  assert.equal(apps[0].settings.app.bearerAssertion, "[REDACTED]", "JWT-shaped values are redacted by shape");
  assert.equal(apps[0].settings.signOn.ssoAcsUrl, "https://acs.example.gov/sso?[REDACTED]");
  assert.deepEqual(apps[0].settings.oauthClient.grant_types, ["authorization_code"]);
  assert.equal(apps[1].credentials.password, "[REDACTED]");
  assert.equal(apps[1].credentials.userName, "shared-service");

  const idps = JSON.parse(files.get("core_data/idps.json"));
  const oidcIdp = idps.find((idp) => idp.id === "idp-oidc");
  assert.equal(oidcIdp.protocol.credentials.client.client_secret, "[REDACTED]");
  assert.equal(oidcIdp.protocol.credentials.client.client_id, "upstream-client");
  assert.equal(oidcIdp.protocol.credentials.trust.kid, "kid-2");

  const [hook] = JSON.parse(files.get("core_data/event_hooks.json"));
  assert.equal(hook.channel.config.uri, "https://hooks.example.gov");
  assert.deepEqual(hook.channel.config.headers, [
    { key: "X-Api-Key", value: "[REDACTED]" },
    { key: "X-Tenant", value: "[REDACTED]" },
  ]);
  assert.deepEqual(hook.channel.config.authScheme, { type: "HEADER", key: "Authorization", value: "[REDACTED]" });
  assert.deepEqual(hook.events.items, ["user.session.start"]);
  assert.equal(hook.status, "ACTIVE");

  const [stream] = JSON.parse(files.get("core_data/log_streams.json"));
  assert.equal(stream.settings.token, "[REDACTED]");
  assert.equal(stream.settings.host, "acme.splunkcloud.com");

  const duo = JSON.parse(files.get("core_data/authenticators.json")).find((auth) => auth.key === "duo");
  assert.equal(duo.provider.configuration.secretKey, "[REDACTED]");
  assert.equal(duo.provider.configuration.integrationKey, "DI-INTEGRATION");
  assert.equal(duo.key, "duo", "authenticator key names are not treated as credentials");

  const [event] = JSON.parse(files.get("core_data/system_logs_recent.json"));
  assert.equal(event.eventType, "user.session.start");
  assert.equal(event.actor.alternateId, "admin@example.gov");
  assert.equal(event.client.ipAddress, "10.0.0.1");
  assert.equal("debugContext" in event, false);
  assert.equal("request" in event, false);

  const users = JSON.parse(files.get("core_data/users.json"));
  assert.equal(users[0].credentials.password, "[REDACTED]");
  assert.equal(users[0].credentials.recovery_question.answer, "[REDACTED]");
  assert.equal(users[0].credentials.recovery_question.question, "first pet");
  assert.equal(users[0].profile.login, "admin@example.gov");

  const factors = JSON.parse(files.get("core_data/privileged_user_factors.json"));
  assert.equal(factors["user-1"][1]._embedded.activation.sharedSecret, "[REDACTED]");
  assert.equal(factors["user-1"][1].profile.credentialId, "admin@example.gov");

  const passwordPolicies = JSON.parse(files.get("core_data/password_policies.json"));
  assert.equal(passwordPolicies[0].settings.password.complexity.minLength, 14, "password policy settings survive redaction");
  assert.equal(statusOf(results.authentication, "OKTA-AUTH-003"), "Pass");

  assert.match(files.get("QUICK_REFERENCE.md"), /\[REDACTED\]/);
  assert.doesNotMatch(files.get("QUICK_REFERENCE.md"), /contains raw Okta API responses/);
});

test("rule 9: OktaAuditorClient error strings drop the request cursor, raw bodies, and the caller's token", async () => {
  const token = "00rffNJ2qLsPW5j9bFB7ZVsGWawJFvjtz2ryUf9WQj";
  const bodies = {
    "/api/v1/apps": () =>
      new Response(`<html>proxy error echoing SSWS ${token} ${"x".repeat(5000)}</html>`, {
        status: 502,
        statusText: "Bad Gateway",
        headers: { "content-type": "text/html" },
      }),
    "/api/v1/groups": () =>
      new Response(JSON.stringify({ errorCode: "E0000006", errorSummary: `Rejected credential ${token}` }), {
        status: 403,
        statusText: "Forbidden",
        headers: { "content-type": "application/json" },
      }),
    "/api/v1/zones": () =>
      new Response(JSON.stringify({ unexpected: token }), {
        status: 500,
        statusText: "Internal Server Error",
        headers: { "content-type": "application/json" },
      }),
  };
  const fetchImpl = async (input) => {
    const url = new URL(input.toString());
    return (bodies[url.pathname] ?? bodies["/api/v1/apps"])();
  };
  const client = new OktaAuditorClient(
    { orgUrl: "https://tenant.example.okta.com", authMode: "SSWS", token, scopes: [], sourceChain: ["tests"] },
    { fetchImpl },
  );

  await assert.rejects(
    () => client.listPaginatedWithMeta("https://tenant.example.okta.com/api/v1/apps?limit=200&after=cursor-2"),
    (error) => {
      assert.match(error.message, /^Okta API request failed for \/api\/v1\/apps\?limit=200 \(502 Bad Gateway\): non-JSON body \(text\/html, \d+ bytes\)$/);
      assert.ok(!error.message.includes("after="));
      assertNoWindowOf(error.message, token, "502 HTML error string");
      assert.ok(!error.message.includes("<html>"));
      return true;
    },
  );
  await assert.rejects(
    () => client.listGroups(),
    (error) => {
      assert.match(error.message, /\(403 Forbidden\): Rejected credential \[REDACTED\]$/);
      assertNoWindowOf(error.message, token, "403 JSON error string");
      return true;
    },
  );
  await assert.rejects(
    () => client.listNetworkZones(),
    (error) => {
      assert.match(error.message, /\(500 Internal Server Error\): JSON error body without errorSummary \(\d+ bytes\)$/);
      assertNoWindowOf(error.message, token, "500 JSON error string");
      return true;
    },
  );

  const access = await runOktaAccessCheck(client, createSampleConfig({ token }));
  assert.equal(access.status, "limited");
  assert.ok(access.probes.every((probe) => probe.status !== "ok"));
  assertNoWindowOf(JSON.stringify(access), token, "access check payload");
  assert.ok(!JSON.stringify(access).includes("<html>"), "access check payload never echoes a raw body");
});

function pagedFetch({ pageSize = 200, totalPages = Infinity, nextFor, onRequest } = {}) {
  return async (input) => {
    const url = new URL(input.toString());
    onRequest?.(url);
    if (url.pathname === "/api/v1/threats/configuration") {
      return new Response(JSON.stringify({ action: "block" }), { status: 200, headers: { "content-type": "application/json" } });
    }
    const page = Number(url.searchParams.get("after") ?? "0");
    const items = Array.from({ length: pageSize }, (_, index) => ({
      id: `${url.pathname}-${page}-${index}`,
      status: "ACTIVE",
      published: new Date().toISOString(),
      eventType: "user.session.start",
    }));
    const headers = { "content-type": "application/json" };
    const next = nextFor ? nextFor(page, url) : page + 1 < totalPages ? String(page + 1) : null;
    if (next !== null) {
      const nextUrl = new URL(url);
      nextUrl.searchParams.set("after", next);
      headers.link = `<${nextUrl.toString()}>; rel="next"`;
    }
    return new Response(JSON.stringify(items), { status: 200, headers });
  };
}

function createRealClient(fetchImpl) {
  return new OktaAuditorClient(
    { orgUrl: "https://tenant.example.okta.com", authMode: "SSWS", token: "okta-test-token", scopes: [], sourceChain: ["tests"] },
    { fetchImpl },
  );
}

test("rule 10: every list walk reports truncated on the page cap, a repeated cursor, and an empty page with a next link", async () => {
  const requests = [];
  const endless = createRealClient(pagedFetch({ pageSize: 3, onRequest: (url) => requests.push(url.pathname) }));
  const capped = await endless.listApps();
  assert.equal(capped.truncated, true);
  assert.equal(capped.pagesFetched, 50);
  assert.equal(capped.items.length, 150);
  assert.match(capped.truncationNote, /^GET \/api\/v1\/apps\?limit=200 stopped after 50 pages \(150 items\): the 50-page cap was reached with a Link rel="next" page unread, total unknown\.$/);
  assert.equal(requests.filter((pathname) => pathname === "/api/v1/apps").length, 50, "the walk stops requesting at the cap");

  const complete = await createRealClient(pagedFetch({ pageSize: 2, totalPages: 3 })).listGroups();
  assert.equal(complete.truncated, false);
  assert.equal(complete.items.length, 6);
  assert.equal(complete.truncationNote, undefined);

  const repeating = await createRealClient(pagedFetch({ pageSize: 2, nextFor: (page) => (page === 0 ? "1" : "1") })).listIdps();
  assert.equal(repeating.truncated, true);
  assert.equal(repeating.pagesFetched, 2);
  assert.match(repeating.truncationNote, /cursor repeated a page already read, total unknown/);

  const emptyWithNext = createRealClient(async (input) => {
    const url = new URL(input.toString());
    const page = url.searchParams.get("after");
    const headers = { "content-type": "application/json" };
    const nextUrl = new URL(url);
    nextUrl.searchParams.set("after", page ? `${page}x` : "1");
    headers.link = `<${nextUrl.toString()}>; rel="next"`;
    return new Response(JSON.stringify(page ? [] : [{ id: "zone-1", status: "ACTIVE" }]), { status: 200, headers });
  });
  const stalled = await emptyWithNext.listNetworkZones();
  assert.equal(stalled.truncated, true);
  assert.equal(stalled.items.length, 1);
  assert.match(stalled.truncationNote, /an empty page still advertised a Link rel="next" cursor, total unknown/);
});

const CONFIGURED_ORIGIN = "https://tenant.example.okta.com";
const FOREIGN_ORIGIN = "https://collector.evil-example.net";
/** The windows of a refused link that must reach no text: its path, query, fragment, and userinfo. The origin is the one part a refusal may name. */
const FOREIGN_LINK_WINDOWS = { path: "/harvest/okta-tokens", query: "sink=okta-ssws&after=page-2", fragment: "frag-marker", userinfo: "okta-test-token" };
const FOREIGN_TAIL = `${FOREIGN_LINK_WINDOWS.path}?${FOREIGN_LINK_WINDOWS.query}#${FOREIGN_LINK_WINDOWS.fragment}`;

/**
 * Every next-link shape that must be refused before any request, with the fixed refusal each earns
 * (reviewer C final verdict, item K): off-origin absolute URLs, userinfo-bearing URLs on either origin,
 * protocol-relative and backslash-host forms whatever host they name, relative references, and an
 * unparseable URL. Each refusal names only the configured origin and the rejected origin.
 */
const REFUSED_NEXT_LINKS = [
  { link: `${FOREIGN_ORIGIN}${FOREIGN_TAIL}`, refusal: `is on origin ${FOREIGN_ORIGIN}, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `http://tenant.example.okta.com${FOREIGN_TAIL}`, refusal: `is on origin http://tenant.example.okta.com, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `https://tenant.example.okta.com:8443${FOREIGN_TAIL}`, refusal: `is on origin https://tenant.example.okta.com:8443, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `https://tenant.example.okta.com.evil-example.net${FOREIGN_TAIL}`, refusal: `is on origin https://tenant.example.okta.com.evil-example.net, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `https://${FOREIGN_LINK_WINDOWS.userinfo}@collector.evil-example.net${FOREIGN_TAIL}`, refusal: `carries userinfo for origin ${FOREIGN_ORIGIN} (configured org origin ${CONFIGURED_ORIGIN})` },
  { link: `https://${FOREIGN_LINK_WINDOWS.userinfo}@tenant.example.okta.com${FOREIGN_TAIL}`, refusal: `carries userinfo for origin ${CONFIGURED_ORIGIN} (configured org origin ${CONFIGURED_ORIGIN})` },
  { link: `https://auditor:${FOREIGN_LINK_WINDOWS.userinfo}@tenant.example.okta.com${FOREIGN_TAIL}`, refusal: `carries userinfo for origin ${CONFIGURED_ORIGIN} (configured org origin ${CONFIGURED_ORIGIN})` },
  { link: `//collector.evil-example.net${FOREIGN_TAIL}`, refusal: `is on origin ${FOREIGN_ORIGIN}, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `//tenant.example.okta.com${FOREIGN_TAIL}`, refusal: `is a protocol-relative or relative reference rather than a root path on the configured org origin ${CONFIGURED_ORIGIN} or an absolute URL on it` },
  { link: `\\\\collector.evil-example.net${FOREIGN_TAIL.replaceAll("/", "\\")}`, refusal: `is on origin ${FOREIGN_ORIGIN}, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `\\\\tenant.example.okta.com${FOREIGN_TAIL}`, refusal: `is a protocol-relative or relative reference rather than a root path on the configured org origin ${CONFIGURED_ORIGIN} or an absolute URL on it` },
  { link: `/\\collector.evil-example.net${FOREIGN_TAIL}`, refusal: `is on origin ${FOREIGN_ORIGIN}, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `https:\\\\collector.evil-example.net${FOREIGN_TAIL}`, refusal: `is on origin ${FOREIGN_ORIGIN}, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `api/v1/apps?${FOREIGN_LINK_WINDOWS.query}`, refusal: `is a protocol-relative or relative reference rather than a root path on the configured org origin ${CONFIGURED_ORIGIN} or an absolute URL on it` },
  { link: `@collector.evil-example.net${FOREIGN_TAIL}`, refusal: `is a protocol-relative or relative reference rather than a root path on the configured org origin ${CONFIGURED_ORIGIN} or an absolute URL on it` },
  // A hostless scheme is refused by its scheme, never as the opaque origin "null" (leak-probe class 8).
  { link: `data:text/plain,${FOREIGN_LINK_WINDOWS.userinfo}`, refusal: `is on origin data:, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `javascript:alert('${FOREIGN_LINK_WINDOWS.userinfo}')`, refusal: `is on origin javascript:, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `file:///etc${FOREIGN_LINK_WINDOWS.path}`, refusal: `is on origin file:, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `blob:${FOREIGN_ORIGIN}${FOREIGN_LINK_WINDOWS.path}`, refusal: `is on origin blob:, not the configured org origin ${CONFIGURED_ORIGIN}` },
  // A blob: URL wrapping the configured origin is still not on it: URL.origin would read the inner origin and let it through.
  { link: `blob:${CONFIGURED_ORIGIN}${FOREIGN_LINK_WINDOWS.path}`, refusal: `is on origin blob:, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `http://10.0.0.1${FOREIGN_TAIL}`, refusal: `is on origin http://10.0.0.1, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `https://[::1]:8443${FOREIGN_TAIL}`, refusal: `is on origin https://[::1]:8443, not the configured org origin ${CONFIGURED_ORIGIN}` },
  { link: `https://[::1${FOREIGN_TAIL}`, refusal: `could not be parsed against the configured org origin ${CONFIGURED_ORIGIN}` },
];

test('reviewer C final verdict, item K: a Link rel="next" URL that is off the configured org origin, carries userinfo, or is protocol-relative or backslash-relative is refused before any request with a fixed reason naming only the two origins, the inventory is truncated with that reason, and no window of the link reaches any text', async () => {
  const requests = [];
  const serveWithNext = (nextLink) => async (input, init = {}) => {
    const url = new URL(input.toString());
    requests.push({ url, authorization: new Headers(init.headers ?? {}).get("authorization") });
    const headers = { "content-type": "application/json", link: `<${nextLink}>; rel="next"` };
    return new Response(JSON.stringify([{ id: `${url.pathname}-item`, status: "ACTIVE", label: "App", signOnMode: "SAML_2_0" }]), { status: 200, headers });
  };

  for (const { link, refusal } of REFUSED_NEXT_LINKS) {
    requests.length = 0;
    const client = createRealClient(serveWithNext(link));
    const apps = await client.listApps();
    assert.equal(apps.truncated, true, link);
    assert.equal(apps.pagesFetched, 1, link);
    assert.equal(apps.items.length, 1, link);
    assert.equal(apps.truncationNote, `GET /api/v1/apps?limit=200 stopped after 1 pages (1 items): the Link rel="next" URL ${refusal} and was not followed, total unknown.`, link);
    assert.equal(requests.length, 1, `${link}: the walk sent the first page only`);
    assert.ok(requests.every((request) => request.url.origin === CONFIGURED_ORIGIN), `${link}: no request left the configured origin`);
    assert.ok(requests.every((request) => request.authorization === "SSWS okta-test-token"), `${link}: the credential went to the configured origin only`);
    for (const [name, part] of Object.entries(FOREIGN_LINK_WINDOWS)) assert.ok(!apps.truncationNote.includes(part), `${link}: the truncation note carries no ${name}`);

    const sameOriginRequests = requests.length;
    await assert.rejects(() => client.getJson(link), (error) => {
      assert.equal(error.name, "OktaApiError");
      assert.equal(error.message, `Okta API request refused: the request URL ${refusal}, so no request was sent.`, link);
      assert.equal(error.status, null);
      assert.equal(error.endpoint, "(refused: not on the configured org origin)");
      for (const [name, part] of Object.entries(FOREIGN_LINK_WINDOWS)) assert.ok(!error.message.includes(part), `${link}: the refusal carries no ${name}`);
      return true;
    });
    assert.equal(requests.length, sameOriginRequests, `${link}: a refused URL produces no request at all`);
  }

  const foreign = createRealClient(serveWithNext(`${FOREIGN_ORIGIN}${FOREIGN_TAIL}`));
  const integrations = await collectOktaIntegrationData(foreign);
  assert.equal(integrations.apps.truncated, true);
  const integResult = assessOktaIntegrations(integrations, createSampleConfig());
  for (const id of ["OKTA-INTEG-003", "OKTA-INTEG-005", "OKTA-INTEG-006"]) {
    assert.equal(statusOf(integResult, id), "Partial", id);
    assert.match(findingById(integResult, id).summary, new RegExp(`is on origin ${FOREIGN_ORIGIN.replaceAll(".", "\\.")}, not the configured org origin ${CONFIGURED_ORIGIN.replaceAll(".", "\\.")} and was not followed, total unknown`), id);
  }
  const rendered = JSON.stringify([integrations, integResult]);
  for (const [name, part] of Object.entries(FOREIGN_LINK_WINDOWS)) assert.ok(!rendered.includes(part), `no dataset or finding carries the link ${name}`);

  for (const link of [
    "https://tenant.example.okta.com/api/v1/apps?limit=200&after=page-2",
    "HTTPS://TENANT.EXAMPLE.OKTA.COM/api/v1/apps?limit=200&after=page-2",
    "https://tenant.example.okta.com:443/api/v1/apps?limit=200&after=page-2",
    "/api/v1/apps?limit=200&after=page-2",
  ]) {
    requests.length = 0;
    const followed = await createRealClient(serveWithNext(link)).listApps();
    assert.equal(followed.pagesFetched, 2, `${link}: a next link on the configured origin is followed whatever its casing or default port`);
    assert.match(followed.truncationNote, /cursor repeated a page already read/, link);
    assert.ok(requests.every((request) => request.url.origin === CONFIGURED_ORIGIN), link);
  }
});

test("rule 10: listSystemLogs is bounded, capped at five pages, and demotes OKTA-MON-002 to a total-unknown statement", async () => {
  const requests = [];
  const client = createRealClient(pagedFetch({ pageSize: 4, onRequest: (url) => requests.push(url) }));
  const logs = await client.listSystemLogs();
  assert.equal(logs.truncated, true);
  assert.equal(logs.pagesFetched, 5);
  assert.equal(logs.items.length, 20);
  const first = requests.find((url) => url.pathname === "/api/v1/logs");
  assert.ok(first.searchParams.get("since"), "since bounds the window");
  assert.ok(first.searchParams.get("until"), "until turns the polling query into a bounded one");
  assert.ok(Date.parse(first.searchParams.get("until")) >= Date.parse(first.searchParams.get("since")));
  assert.equal(first.searchParams.get("limit"), "200");
  assert.equal(requests.filter((url) => url.pathname === "/api/v1/logs").length, 5);
  assert.match(logs.truncationNote, /^GET \/api\/v1\/logs\?since=[^&]+&until=[^&]+&limit=200 stopped after 5 pages \(20 items\): the 5-page cap/);
  assert.ok(!logs.truncationNote.includes("after="));

  const monitoring = await collectOktaMonitoringData(client);
  assert.equal(monitoring.systemLogs.truncated, true);
  assert.equal(monitoring.systemLogs.data.length, 20);
  assert.equal(monitoring.eventHooks.truncated, true, "every other list on the endless server is capped too");
  const result = assessOktaMonitoring(monitoring, createSampleConfig());
  const visibility = findingById(result, "OKTA-MON-002");
  assert.equal(visibility.status, "Partial");
  assert.match(visibility.summary, /Retrieved at least 20 system log events from the last 30 days \(page-capped sample, total unknown\)/);
  assert.match(visibility.summary, /stopped after 5 pages \(20 items\)/);
  assert.ok(visibility.evidence.some((line) => line.startsWith("Partial data: GET /api/v1/logs")));
  assert.equal(statusOf(result, "OKTA-MON-003"), "Pass", "the single-object ThreatInsight read is not a list and keeps its verdict");
  for (const id of ["OKTA-MON-001", "OKTA-MON-004", "OKTA-MON-005", "OKTA-MON-006", "OKTA-MON-007"]) {
    const finding = findingById(result, id);
    assert.notEqual(finding.status, "Pass", id);
    assert.match(`${finding.summary}\n${finding.evidence.join("\n")}`, /total unknown/, id);
  }
});

test("rule 10: a truncated page returned by any list method demotes every dependent finding through the collectors", async () => {
  const sample = createSampleClient();
  const appsNote = 'GET /api/v1/apps?limit=200 stopped after 50 pages (10000 items): the 50-page cap was reached with a Link rel="next" page unread, total unknown.';
  const rulesNote = 'GET /api/v1/policies/signon-1/rules?limit=200 stopped after 50 pages (10000 items): the 50-page cap was reached with a Link rel="next" page unread, total unknown.';
  const client = {
    ...sample,
    async listApps() {
      return { items: await sample.listApps(), truncated: true, pagesFetched: 50, truncationNote: appsNote };
    },
    async listPolicyRules(policyId) {
      const items = await sample.listPolicyRules(policyId);
      return policyId === "signon-1" ? { items, truncated: true, pagesFetched: 50, truncationNote: rulesNote } : items;
    },
    async listUserRoles(userId) {
      return { items: await sample.listUserRoles(userId), truncated: true, pagesFetched: 50 };
    },
  };

  const integrations = await collectOktaIntegrationData(client);
  assert.equal(integrations.apps.truncated, true);
  assert.equal(integrations.apps.truncationNote, appsNote);
  assert.equal(integrations.trustedOrigins.truncated, false);
  const integResult = assessOktaIntegrations(integrations, createSampleConfig());
  for (const id of ["OKTA-INTEG-003", "OKTA-INTEG-005", "OKTA-INTEG-006"]) {
    const finding = findingById(integResult, id);
    assert.equal(finding.status, "Partial", id);
    assert.match(finding.summary, /Inventory truncated: GET \/api\/v1\/apps.*total unknown/, id);
    assert.ok(finding.evidence.includes(`Partial data: ${appsNote}`), id);
  }
  assert.equal(statusOf(integResult, "OKTA-INTEG-001"), "Pass", "findings that do not read apps keep their verdict");
  assert.equal(statusOf(integResult, "OKTA-INTEG-002"), "Pass");
  // Reviewer C final verdict, item I: a snapshot counter over a partially read inventory renders null, never the count of the part read (a 0 there would claim an absence from the unread part).
  for (const counter of ["applications", "active_applications", "risky_oidc_apps", "inactive_apps", "provisioning_apps", "deactivation_push_apps"]) {
    assert.equal(integResult.snapshotSummary[counter], null, `${counter} renders null over the truncated apps list`);
  }
  assert.equal(integResult.snapshotSummary.contextual_rules, null, "contextual_rules reads the truncated sign-on rules");
  assert.equal(typeof integResult.snapshotSummary.trusted_origins, "number", "a fully read inventory keeps its count");
  assert.equal(typeof integResult.snapshotSummary.custom_network_zones, "number");
  const hiddenZones = { ...sample, async listNetworkZones() { return { items: (await sample.listNetworkZones()).slice(0, 1), truncated: true, pagesFetched: 2, truncationNote: 'GET /api/v1/zones?limit=200 stopped after 2 pages (1 items): the Link rel="next" cursor repeated a page already read, total unknown.' }; } };
  const hiddenZonesResult = assessOktaIntegrations(await collectOktaIntegrationData(hiddenZones), createSampleConfig());
  assert.equal(hiddenZonesResult.snapshotSummary.custom_network_zones, null, "the custom zone hidden behind the cap is not reported as 0");
  assert.equal(typeof hiddenZonesResult.snapshotSummary.applications, "number");
  assert.equal(statusOf(hiddenZonesResult, "OKTA-INTEG-002"), "Partial");

  // Under every hiding cap (the first item only, the walk reported truncated), no snapshot counter that the complete read rendered as a positive count or true renders 0 or false: it is null, or a seen count that is still positive.
  const assessAll = async (target) => [
    assessOktaAuthentication(await collectOktaAuthenticationData(target), createSampleConfig()),
    assessOktaAdminAccess(await collectOktaAdminAccessData(target), createSampleConfig()),
    assessOktaIntegrations(await collectOktaIntegrationData(target), createSampleConfig()),
    assessOktaMonitoring(await collectOktaMonitoringData(target), createSampleConfig()),
  ];
  const scalarLeaves = (value, prefix = "") => {
    const leaves = new Map();
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      for (const [key, item] of Object.entries(value)) for (const [path, leaf] of scalarLeaves(item, prefix ? `${prefix}.${key}` : key)) leaves.set(path, leaf);
    } else if (typeof value === "number" || typeof value === "boolean") {
      leaves.set(prefix, value);
    }
    return leaves;
  };
  const complete = await assessAll(sample);
  const listMethods = Object.keys(sample).filter((name) => /^list/.test(name) && name !== "listUsersWithMeta");
  assert.ok(listMethods.length >= 20, `every list method of the sample client is swept (${listMethods.length})`);
  for (const method of [...listMethods, "listUsersWithMeta"]) {
    const hidden = {
      ...sample,
      async [method](...args) {
        const result = await sample[method](...args);
        const items = Array.isArray(result) ? result : result.items;
        return { items: items.slice(0, 1), truncated: true, pagesFetched: 2, truncationNote: `GET /api/v1/${method} stopped after 2 pages (1 items): the Link rel="next" cursor repeated a page already read, total unknown.` };
      },
    };
    const capped = await assessAll(hidden);
    for (const [index, area] of complete.entries()) {
      for (const [leaf, value] of scalarLeaves(area.snapshotSummary)) {
        const cappedValue = scalarLeaves(capped[index].snapshotSummary).get(leaf);
        if (typeof value === "number" && value > 0) assert.notEqual(cappedValue, 0, `${method} hidden: ${area.area ?? index} snapshot ${leaf} defaulted ${value} -> 0`);
        if (value === true) assert.notEqual(cappedValue, false, `${method} hidden: ${area.area ?? index} snapshot ${leaf} defaulted true -> false`);
      }
    }
  }

  const authentication = await collectOktaAuthenticationData(client);
  assert.equal(authentication.signOnPolicyRules.truncated, true);
  assert.match(authentication.signOnPolicyRules.truncationNote, /^signon-1: GET \/api\/v1\/policies\/signon-1\/rules/);
  const authResult = assessOktaAuthentication(authentication, createSampleConfig());
  for (const id of ["OKTA-AUTH-002", "OKTA-AUTH-006", "OKTA-AUTH-007"]) {
    assert.equal(statusOf(authResult, id), "Partial", id);
    assert.match(findingById(authResult, id).summary, /total unknown/, id);
  }
  assert.equal(statusOf(authResult, "OKTA-AUTH-003"), "Pass");

  const admin = await collectOktaAdminAccessData(client);
  assert.equal(admin.userRoles.truncated, true);
  assert.match(admin.userRoles.truncationNote, /^user-1: Listing stopped after 50 pages \(1 items\); total unknown\./);
  const adminResult = assessOktaAdminAccess(admin, createSampleConfig());
  assert.equal(statusOf(adminResult, "OKTA-ADMIN-001"), "Partial");
  assert.equal(statusOf(adminResult, "OKTA-ADMIN-002"), "Partial");
  assert.equal(statusOf(adminResult, "OKTA-ADMIN-005"), "Pass");

  const outputRoot = createTempBase("grclanker-okta-truncated-");
  const exported = await exportOktaAuditBundle(client, createSampleConfig(), outputRoot);
  assert.equal(exported.errorCount, 4, "apps, user roles, and the sign-on rules read by two categories are all reported");
  const errorsLog = readFileSync(join(exported.outputDir, "_errors.log"), "utf8");
  assert.match(errorsLog, /Truncated inventory: GET \/api\/v1\/apps/);
  assert.match(errorsLog, /Truncated inventory: signon-1: GET \/api\/v1\/policies/);
  assert.match(errorsLog, /Truncated inventory: user-1: Listing stopped after 50 pages/);
  const findings = JSON.parse(readFileSync(join(exported.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.find((finding) => finding.id === "OKTA-INTEG-003").status, "Partial");
});

test("rule 10: collectors keep per-user factor lookups distinct from empty enrollments", async () => {
  const sample = createSampleClient();
  const admin = await collectOktaAdminAccessData({
    ...sample,
    async listUsersWithRoleAssignments() {
      const now = new Date().toISOString();
      return [
        { id: "user-1", status: "ACTIVE", lastLogin: now, profile: { login: "admin@example.gov" } },
        { id: "user-2", status: "ACTIVE", lastLogin: now, profile: { login: "second@example.gov" } },
      ];
    },
    async listUserFactors(userId) {
      if (userId === "user-2") throw forbidden(`/api/v1/users/${userId}/factors`);
      return sample.listUserFactors("user-1");
    },
  });
  assert.deepEqual(Object.keys(admin.privilegedUserFactors.data), ["user-1"], "a failed lookup leaves no entry rather than an empty enrollment");
  assert.match(admin.privilegedUserFactors.error, /user-2: .*403 Forbidden/);
  const finding = findingById(assessOktaAdminAccess(admin, createSampleConfig()), "OKTA-ADMIN-004");
  assert.equal(finding.status, "Partial");
  assert.match(finding.summary, /All 1 inspected privileged users have an ACTIVE phishing-resistant factor \(inventory partially read\)/);
});

test("multi-inventory verdicts name the unreadable secondary source (OKTA-AUTH-002, 008, INTEG-006, MON-008)", () => {
  const config = createSampleConfig();

  const authentication = createSampleAuthenticationData();
  authentication.authenticators = dataset([], "Okta API request failed for /api/v1/authenticators (403 Forbidden): Access denied");
  const authResult = assessOktaAuthentication(authentication, config);
  const adminMfa = findingById(authResult, "OKTA-AUTH-002");
  assert.equal(adminMfa.status, "Partial");
  assert.match(adminMfa.summary, /authenticator list was unreadable/);
  assert.ok(adminMfa.evidence.includes("Strong authenticators: unknown (authenticator list unreadable)"));
  assert.ok(adminMfa.evidence.some((line) => /^Authenticator error: .*403 Forbidden/.test(line)));
  const certIdpOnly = findingById(authResult, "OKTA-AUTH-008");
  assert.equal(certIdpOnly.status, "Partial", "a found certificate IdP never passes while the authenticator list is unreadable");
  assert.match(certIdpOnly.summary, /^Detected 1 ACTIVE certificate-oriented IdP or authenticator entries, but the authenticator list was unreadable, so the other half of the certificate inventory could not be verified\.$/);
  assert.ok(certIdpOnly.evidence.includes("IdP: PIV Smart Card (ACTIVE)"), "the found IdP stays in evidence");
  assert.ok(certIdpOnly.evidence.some((line) => /^Authenticator data unavailable: .*\/api\/v1\/authenticators \(403 Forbidden\)/.test(line)));

  const idpUnreadable = createSampleAuthenticationData();
  idpUnreadable.idps = dataset([], "Okta API request failed for /api/v1/idps (403 Forbidden): Access denied");
  const certFinding = findingById(assessOktaAuthentication(idpUnreadable, config), "OKTA-AUTH-008");
  assert.equal(certFinding.status, "Partial", "a found certificate authenticator never passes while the IdP list is unreadable");
  assert.match(certFinding.summary, /^Detected 1 ACTIVE certificate-oriented IdP or authenticator entries, but the identity provider list was unreadable, so the other half of the certificate inventory could not be verified\.$/);
  assert.doesNotMatch(certFinding.summary, /one source was unreadable/);
  assert.ok(certFinding.evidence.includes("Authenticator: smart_card_idp / Smart Card"), "the found authenticator stays in evidence");
  assert.ok(certFinding.evidence.some((line) => /^IdP data unavailable: .*\/api\/v1\/idps \(403 Forbidden\)/.test(line)));

  const bothReadable = findingById(assessOktaAuthentication(createSampleAuthenticationData(), config), "OKTA-AUTH-008");
  assert.equal(bothReadable.status, "Pass");
  assert.equal(bothReadable.summary, "Detected 2 ACTIVE certificate-oriented IdP or authenticator entries.");

  const withoutCertificates = () => {
    const data = createSampleAuthenticationData();
    data.idps = dataset([{ id: "idp-2", name: "Corporate SAML", type: "SAML2", status: "ACTIVE" }]);
    data.authenticators = dataset(data.authenticators.data.filter((auth) => auth.key !== "smart_card_idp"));
    return data;
  };
  for (const orgUrl of ["https://tenant.okta.gov", "https://tenant.okta.com"]) {
    const tenantConfig = createSampleConfig({ orgUrl });
    const noCert = findingById(assessOktaAuthentication(withoutCertificates(), tenantConfig), "OKTA-AUTH-008");
    assert.equal(noCert.status, orgUrl.endsWith(".gov") ? "Fail" : "Manual", `${orgUrl}: both lists readable and empty of certificates keeps the shipped verdict`);
    assert.deepEqual(noCert.evidence, [`Org URL: ${orgUrl}`]);

    const idpsUnread = withoutCertificates();
    idpsUnread.idps = dataset([], "Okta API request failed for /api/v1/idps (403 Forbidden): Access denied");
    const idpsUnreadFinding = findingById(assessOktaAuthentication(idpsUnread, tenantConfig), "OKTA-AUTH-008");
    assert.equal(idpsUnreadFinding.status, "Manual", `${orgUrl}: nothing found in the authenticator list never yields Fail while the IdP list is unreadable`);
    assert.match(
      idpsUnreadFinding.summary,
      /^Certificate or PIV\/CAC authentication could not be evaluated because no ACTIVE certificate-oriented entry was found in the authenticator list while the identity provider list was unreadable \(the endpoint returned 403 Forbidden \(missing scope or admin role\)\), so (this federal-domain tenant|the tenant) cannot be judged on half of the certificate inventory\.$/,
    );
    assert.equal(/federal-domain/.test(idpsUnreadFinding.summary), orgUrl.endsWith(".gov"));
    assert.ok(idpsUnreadFinding.evidence.some((line) => /^Org URL: .* \| IdP data unavailable: .*\/api\/v1\/idps \(403 Forbidden\)/.test(line)));
    assert.match(idpsUnreadFinding.manualNote ?? "", /^Collect manually: /);

    const authenticatorsUnread = withoutCertificates();
    authenticatorsUnread.authenticators = dataset([], "Okta API request failed for /api/v1/authenticators (403 Forbidden): Access denied");
    const authenticatorsUnreadFinding = findingById(assessOktaAuthentication(authenticatorsUnread, tenantConfig), "OKTA-AUTH-008");
    assert.equal(authenticatorsUnreadFinding.status, "Manual", `${orgUrl}: nothing found in the IdP list never yields Fail while the authenticator list is unreadable`);
    assert.match(authenticatorsUnreadFinding.summary, /no ACTIVE certificate-oriented entry was found in the identity provider list while the authenticator list was unreadable/);
    assert.ok(authenticatorsUnreadFinding.evidence.some((line) => /^Org URL: .* \| Authenticator data unavailable: .*\/api\/v1\/authenticators \(403 Forbidden\)/.test(line)));
  }

  const orgFactorsUnreadable = createSampleAuthenticationData();
  orgFactorsUnreadable.orgFactors = dataset([], "Okta API request failed for /api/v1/org/factors (403 Forbidden): Access denied");
  const phishing = findingById(assessOktaAuthentication(orgFactorsUnreadable, config), "OKTA-AUTH-001");
  assert.equal(phishing.status, "Pass");
  assert.ok(phishing.evidence.some((line) => /^Org factors were unreadable/.test(line)));

  const integrations = createSampleIntegrationData();
  integrations.groupRules = dataset([], "Okta API request failed for /api/v1/groups/rules (403 Forbidden): Access denied");
  const deprovisioning = findingById(assessOktaIntegrations(integrations, config), "OKTA-INTEG-006");
  assert.equal(deprovisioning.status, "Partial");
  assert.match(deprovisioning.summary, /group rules were unreadable/);

  const zonesUnreadable = createSampleIntegrationData();
  zonesUnreadable.networkZones = dataset([], "Okta API request failed for /api/v1/zones (403 Forbidden): Access denied");
  const contextual = findingById(assessOktaIntegrations(zonesUnreadable, config), "OKTA-INTEG-004");
  assert.ok(contextual.evidence.some((line) => /^Network zones unreadable/.test(line)));

  const monitoring = createSampleMonitoringData();
  monitoring.orgContacts = {
    data: [{ contactType: "BILLING", userId: "user-9", userStatus: "ACTIVE", userLogin: "billing@example.gov" }],
    error: "TECHNICAL: Okta API request failed for /api/v1/org/contacts/TECHNICAL (403 Forbidden): Access denied",
  };
  const contact = findingById(assessOktaMonitoring(monitoring, config), "OKTA-MON-008");
  assert.equal(contact.status, "Partial");
  assert.match(contact.summary, /technical contact lookup failed/);
  assert.doesNotMatch(contact.summary, /No technical contact user is assigned/);

  const unassigned = createSampleMonitoringData();
  unassigned.orgContacts = dataset([{ contactType: "BILLING", userId: "user-9", userStatus: "ACTIVE", userLogin: "billing@example.gov" }]);
  assert.equal(statusOf(assessOktaMonitoring(unassigned, config), "OKTA-MON-008"), "Fail", "a readable list without TECHNICAL is still a real gap");
});

/** Serves the sample fixtures at the Management API paths the real client requests; null (the sample's absent default authorization server) is served as a 404. */
async function oktaFixtureBody(sample, url) {
  const path = url.pathname;
  const segment = (pattern) => pattern.exec(path)?.[1];
  if (path === "/api/v1/policies") return sample.listPolicies(url.searchParams.get("type"));
  const rulesPolicy = segment(/^\/api\/v1\/policies\/([^/]+)\/rules$/);
  if (rulesPolicy) return sample.listPolicyRules(rulesPolicy);
  if (path === "/api/v1/authenticators") return sample.listAuthenticators();
  if (path === "/api/v1/idps") return sample.listIdps();
  if (path === "/api/v1/authorizationServers") return sample.listAuthorizationServers();
  if (path === "/api/v1/authorizationServers/default") return sample.getDefaultAuthorizationServer();
  if (path === "/api/v1/org/factors") return sample.listOrgFactors();
  if (path === "/api/v1/iam/assignees/users") return sample.listUsersWithRoleAssignments();
  const rolesUser = segment(/^\/api\/v1\/users\/([^/]+)\/roles$/);
  if (rolesUser) return sample.listUserRoles(rolesUser);
  const factorsUser = segment(/^\/api\/v1\/users\/([^/]+)\/factors$/);
  if (factorsUser) return sample.listUserFactors(factorsUser);
  const user = segment(/^\/api\/v1\/users\/([^/]+)$/);
  if (user) return sample.getUser(user);
  if (path === "/api/v1/users") return (await sample.listUsersWithMeta()).items;
  if (path === "/api/v1/groups/rules") return sample.listGroupRules();
  if (path === "/api/v1/groups") return sample.listGroups();
  const groupRoles = segment(/^\/api\/v1\/groups\/([^/]+)\/roles$/);
  if (groupRoles) return sample.listGroupRoles(groupRoles);
  const groupUsers = segment(/^\/api\/v1\/groups\/([^/]+)\/users$/);
  if (groupUsers) return sample.listGroupUsers(groupUsers);
  if (path === "/api/v1/org/privacy/oktaSupport") return sample.getOktaSupportSettings();
  if (path === "/api/v1/org/orgSettings/thirdPartyAdminSetting") return sample.getThirdPartyAdminSetting();
  if (path === "/api/v1/apps") return sample.listApps();
  if (path === "/api/v1/trustedOrigins") return sample.listTrustedOrigins();
  if (path === "/api/v1/zones") return sample.listNetworkZones();
  if (path === "/api/v1/eventHooks") return sample.listEventHooks();
  if (path === "/api/v1/logStreams") return sample.listLogStreams();
  if (path === "/api/v1/logs") return sample.listSystemLogs();
  if (path === "/api/v1/behaviors") return sample.listBehaviors();
  if (path === "/api/v1/threats/configuration") return sample.getThreatInsight();
  if (path === "/api/v1/api-tokens") return sample.listApiTokens();
  if (path === "/api/v1/device-assurances") return sample.listDeviceAssurancePolicies();
  if (path === "/api/v1/org/contacts") return sample.listOrgContacts();
  const contactType = segment(/^\/api\/v1\/org\/contacts\/([^/]+)$/);
  if (contactType) return sample.getOrgContactUser(contactType);
  return undefined;
}

/**
 * A fetch that records every request as the client describes it (path plus
 * query without the cursor) and the status it served, denying the paths that
 * match `denied` with a 403 so a test can check that every status code and
 * endpoint named in an output was really observed.
 */
function recordingOktaFetch({ denied = [] } = {}) {
  const sample = createSampleClient();
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input.toString());
    url.searchParams.delete("after");
    const path = `${url.pathname}${url.search}`;
    const respond = (status, body) => {
      requests.push({ method: init.method ?? "GET", path, status });
      const statusText = { 200: "OK", 403: "Forbidden", 404: "Not Found" }[status];
      return new Response(JSON.stringify(body), { status, statusText, headers: { "content-type": "application/json" } });
    };
    if (denied.some((pattern) => pattern.test(path))) {
      return respond(403, { errorCode: "E0000006", errorSummary: "You do not have permission to access the feature you are requesting" });
    }
    const body = await oktaFixtureBody(sample, url);
    if (body === null || body === undefined) return respond(404, { errorCode: "E0000007", errorSummary: "Not found" });
    return respond(200, body);
  };
  return { fetchImpl, requests };
}

const RECORDING_CONFIG = { orgUrl: "https://tenant.example.okta.com", authMode: "SSWS", token: "okta-test-token", scopes: [], sourceChain: ["tests"] };

/** Every top-level Okta dataset: the request that produces it, its core_data file, the per-parent files that are never requested when it is denied, the assess category that reads it, the snapshot counters that must render null, the access probe that reads the same surface, and the multi-inventory findings that must not pass while it is unreadable (the found item they keep in evidence). */
const OKTA_DATASETS = [
  { name: "sign-on policies", pattern: /^\/api\/v1\/policies\?type=OKTA_SIGN_ON&limit=\d+$/, file: "core_data/sign_on_policies.json", skipped: ["core_data/sign_on_policy_rules.json"], category: "authentication", nullCounters: ["sign_on_policies", "admin_dashboard_policies", "admin_mfa_rules"], probe: "policies" },
  { name: "password policies", pattern: /^\/api\/v1\/policies\?type=PASSWORD&limit=\d+$/, file: "core_data/password_policies.json", skipped: ["core_data/password_policy_rules.json"], category: "authentication", nullCounters: ["password_policies"] },
  { name: "MFA enrollment policies", pattern: /^\/api\/v1\/policies\?type=MFA_ENROLL&limit=\d+$/, file: "core_data/mfa_enrollment_policies.json", skipped: [], category: "authentication", nullCounters: [] },
  { name: "access policies", pattern: /^\/api\/v1\/policies\?type=ACCESS_POLICY&limit=\d+$/, file: "core_data/access_policies.json", skipped: ["core_data/access_policy_rules.json"], category: "authentication", nullCounters: ["access_policies", "admin_dashboard_policies", "admin_mfa_rules"] },
  { name: "authenticators", pattern: /^\/api\/v1\/authenticators$/, file: "core_data/authenticators.json", skipped: [], category: "authentication", nullCounters: ["active_authenticators", "strong_authenticators", "phishing_resistant_authenticators", "restricted_authenticators"], nullLabels: ["okta_verify_fips_mode"], notPass: [{ id: "OKTA-AUTH-008", summary: /, but the authenticator list was unreadable, so the other half of the certificate inventory could not be verified\.$/, found: "IdP: PIV Smart Card (ACTIVE)" }] },
  { name: "identity providers", pattern: /^\/api\/v1\/idps\?limit=\d+$/, file: "core_data/idps.json", skipped: [], category: "authentication", nullCounters: [], notPass: [{ id: "OKTA-AUTH-008", summary: /, but the identity provider list was unreadable, so the other half of the certificate inventory could not be verified\.$/, found: "Authenticator: smart_card_idp / Smart Card" }] },
  { name: "authorization servers", pattern: /^\/api\/v1\/authorizationServers\?limit=\d+$/, file: "core_data/authorization_servers.json", skipped: [], category: "authentication", nullCounters: [] },
  { name: "default authorization server", pattern: /^\/api\/v1\/authorizationServers\/default$/, file: "core_data/default_authorization_server.json", skipped: [], category: "authentication", nullCounters: [] },
  { name: "org factors", pattern: /^\/api\/v1\/org\/factors\?limit=\d+$/, file: "core_data/org_factors.json", skipped: [], category: "authentication", nullCounters: [] },
  { name: "role assignees", pattern: /^\/api\/v1\/iam\/assignees\/users\?limit=\d+$/, file: "core_data/users_with_role_assignments.json", skipped: ["core_data/user_roles.json", "core_data/privileged_user_factors.json"], category: "admin", nullCounters: ["privileged_users", "super_admins", "stale_privileged_users", "privileged_users_without_last_login", "privileged_users_factor_checked"], probe: "roles" },
  { name: "groups", pattern: /^\/api\/v1\/groups\?limit=\d+$/, file: "core_data/groups.json", skipped: ["core_data/privileged_group_roles.json", "core_data/privileged_group_members.json"], category: "admin", nullCounters: ["privileged_groups_reviewed"] },
  { name: "users", pattern: /^\/api\/v1\/users\?limit=\d+$/, file: "core_data/users.json", skipped: [], category: "admin", nullCounters: ["users_listed", "stale_active_users", "never_activated_users"], nullLabels: ["users_listing_truncated"], probe: "users" },
  { name: "Okta Support access", pattern: /^\/api\/v1\/org\/privacy\/oktaSupport$/, file: "core_data/okta_support_access.json", skipped: [], category: "admin", nullCounters: [], nullLabels: ["okta_support_access"] },
  { name: "third-party admin setting", pattern: /^\/api\/v1\/org\/orgSettings\/thirdPartyAdminSetting$/, file: "core_data/third_party_admin_setting.json", skipped: [], category: "admin", nullCounters: [] },
  { name: "apps", pattern: /^\/api\/v1\/apps\?limit=\d+$/, file: "core_data/apps.json", skipped: [], category: "integrations", nullCounters: ["applications", "active_applications", "risky_oidc_apps", "inactive_apps", "provisioning_apps", "deactivation_push_apps"] },
  { name: "trusted origins", pattern: /^\/api\/v1\/trustedOrigins\?limit=\d+$/, file: "core_data/trusted_origins.json", skipped: [], category: "integrations", nullCounters: ["trusted_origins", "insecure_trusted_origins"] },
  { name: "network zones", pattern: /^\/api\/v1\/zones\?limit=\d+$/, file: "core_data/network_zones.json", skipped: [], category: "integrations", nullCounters: ["custom_network_zones"] },
  { name: "group rules", pattern: /^\/api\/v1\/groups\/rules\?limit=\d+$/, file: "core_data/group_rules.json", skipped: [], category: "integrations", nullCounters: ["active_group_rules"] },
  { name: "event hooks", pattern: /^\/api\/v1\/eventHooks\?limit=\d+$/, file: "core_data/event_hooks.json", skipped: [], category: "monitoring", nullCounters: ["active_event_hooks"] },
  { name: "log streams", pattern: /^\/api\/v1\/logStreams\?limit=\d+$/, file: "core_data/log_streams.json", skipped: [], category: "monitoring", nullCounters: ["active_log_streams"] },
  { name: "system logs", pattern: /^\/api\/v1\/logs\?/, file: "core_data/system_logs_recent.json", skipped: [], category: "monitoring", nullCounters: ["system_log_events"], probe: "logs" },
  { name: "behaviors", pattern: /^\/api\/v1\/behaviors\?limit=\d+$/, file: "core_data/behaviors.json", skipped: [], category: "monitoring", nullCounters: ["behaviors"] },
  { name: "ThreatInsight", pattern: /^\/api\/v1\/threats\/configuration$/, file: "core_data/threat_insight.json", skipped: [], category: "monitoring", nullCounters: [], nullLabels: ["threat_insight_mode"] },
  { name: "API tokens", pattern: /^\/api\/v1\/api-tokens$/, file: "core_data/api_tokens.json", skipped: [], category: "monitoring", nullCounters: ["api_tokens", "stale_api_tokens", "undated_api_tokens", "unrestricted_api_tokens", "expired_api_tokens"], probe: "api_tokens" },
  { name: "device assurance", pattern: /^\/api\/v1\/device-assurances\?limit=\d+$/, file: "core_data/device_assurance.json", skipped: [], category: "monitoring", nullCounters: ["device_assurance_policies"] },
  { name: "org contacts", pattern: /^\/api\/v1\/org\/contacts$/, file: "core_data/org_contacts.json", skipped: [], category: "monitoring", nullCounters: ["org_contacts_resolved"] },
];

/**
 * Per-parent child requests. The recording fixture has one parent per map
 * (signon-1, pwd-1, access-1, user-1, group-1) and two org contact types, so
 * denying the single child of a map denies every child of that list, while
 * denying the TECHNICAL contact alone leaves the BILLING sibling readable.
 */
const OKTA_ALL_CHILDREN_DENIED = [
  { name: "sign-on policy rules", pattern: /^\/api\/v1\/policies\/signon-1\/rules\?limit=\d+$/, file: "core_data/sign_on_policy_rules.json", keys: ["signon-1"], shape: "map", nullCounters: [["authentication", "admin_mfa_rules"], ["integrations", "contextual_rules"]] },
  { name: "password policy rules", pattern: /^\/api\/v1\/policies\/pwd-1\/rules\?limit=\d+$/, file: "core_data/password_policy_rules.json", keys: ["pwd-1"], shape: "map", nullCounters: [] },
  { name: "access policy rules", pattern: /^\/api\/v1\/policies\/access-1\/rules\?limit=\d+$/, file: "core_data/access_policy_rules.json", keys: ["access-1"], shape: "map", nullCounters: [["authentication", "admin_mfa_rules"], ["integrations", "contextual_rules"]] },
  { name: "per-user role lists", pattern: /^\/api\/v1\/users\/user-1\/roles\?limit=\d+$/, file: "core_data/user_roles.json", keys: ["user-1"], shape: "map", nullCounters: [["admin", "super_admins"]], manual: { id: "OKTA-ADMIN-001", category: "admin", summary: /^Super admin concentration could not be evaluated because every lookup of the per-user role lists failed \(1 of 1\): the endpoint returned 403 Forbidden \(missing scope or admin role\)\.$/ } },
  { name: "privileged user factor lists", pattern: /^\/api\/v1\/users\/user-1\/factors$/, file: "core_data/privileged_user_factors.json", keys: ["user-1"], shape: "map", nullCounters: [["admin", "privileged_users_factor_checked"]], manual: { id: "OKTA-ADMIN-004", category: "admin", summary: /^Privileged user MFA enrollment could not be evaluated because every lookup of the privileged user factor lists failed \(1 of 1\): the endpoint returned 403 Forbidden/ } },
  { name: "privileged group role lists", pattern: /^\/api\/v1\/groups\/group-1\/roles\?limit=\d+$/, file: "core_data/privileged_group_roles.json", keys: ["group-1"], shape: "map", nullCounters: [] },
  { name: "privileged group member lists", pattern: /^\/api\/v1\/groups\/group-1\/users\?limit=\d+$/, file: "core_data/privileged_group_members.json", keys: ["group-1"], shape: "map", nullCounters: [] },
  { name: "org contact assignments", pattern: /^\/api\/v1\/org\/contacts\/[A-Z]+$/, file: "core_data/org_contacts.json", keys: ["BILLING", "TECHNICAL"], shape: "list", nullCounters: [["monitoring", "org_contacts_resolved"]], manual: { id: "OKTA-MON-008", category: "monitoring", summary: /^Security contact routing could not be evaluated because every lookup of the org contact assignments failed \(2 of 2\): the endpoint returned 403 Forbidden/ } },
  { name: "org contact users", pattern: /^\/api\/v1\/users\/user-\d+$/, file: "core_data/org_contacts.json", keys: ["BILLING", "TECHNICAL"], shape: "list", nullCounters: [["monitoring", "org_contacts_resolved"]], manual: { id: "OKTA-MON-008", category: "monitoring", summary: /every lookup of the org contact assignments failed \(2 of 2\)/ } },
];

const OKTA_PARTIAL_CHILD_DENIAL = { name: "technical contact assignment", pattern: /^\/api\/v1\/org\/contacts\/TECHNICAL$/, file: "core_data/org_contacts.json", key: "TECHNICAL" };

const OKTA_MENTIONED_STATUS_PATTERNS = [
  /\((\d{3}) [A-Z]/g,
  /\breturned (\d{3})\b/g,
  /"(?:status|httpStatus)":\s*(\d{3})\b/g,
];
const OKTA_MENTIONED_ENDPOINT_PATTERN = /\/api\/v1\/[A-Za-z0-9_\-./]+(?:\?[A-Za-z0-9_=&%\-.:+]*)?/g;

/**
 * Every 4xx or 5xx status code and every Management API path named anywhere
 * in the outputs must belong to a request the fixture actually served: a code
 * or endpoint that never appears in the request log is a claim the run did
 * not observe.
 */
function assertOktaOutputsNameOnlyObservedRequests(outputs, requests, label) {
  const observedStatuses = new Set(requests.map((request) => request.status));
  const observedPaths = new Set(requests.map((request) => request.path));
  const mentions = { statuses: 0, endpoints: 0 };
  for (const [name, text] of outputs) {
    for (const pattern of OKTA_MENTIONED_STATUS_PATTERNS) {
      for (const match of text.matchAll(pattern)) {
        const status = Number(match[1]);
        if (status < 400 || status > 599) continue;
        mentions.statuses += 1;
        assert.ok(observedStatuses.has(status), `${label} ${name}: mentions status ${status} but the run observed only ${[...observedStatuses].join(", ")} (in: ${match[0]})`);
      }
    }
    for (const match of text.matchAll(OKTA_MENTIONED_ENDPOINT_PATTERN)) {
      const mention = match[0].replace(/[.,;:)]+$/, "");
      mentions.endpoints += 1;
      assert.ok(observedPaths.has(mention), `${label} ${name}: names endpoint ${mention} but the run requested only ${[...observedPaths].join(", ")}`);
    }
  }
  return mentions;
}

function oktaOutputs(access, results, exported) {
  return new Map([
    ["check_access", JSON.stringify(access)],
    ...Object.entries(results).map(([category, result]) => [`assess ${category}`, JSON.stringify(result)]),
    ...[...readBundleFiles(exported.outputDir)].map(([name, content]) => [`bundle ${name}`, content]),
  ]);
}

function assertOktaNotCollectedMarker(entry, label, expected) {
  assert.ok(entry && typeof entry === "object" && !Array.isArray(entry), `${label}: a dataset that was not collected is never written as an array or scalar, got ${JSON.stringify(entry)}`);
  assert.equal(entry.collected, false, `${label}: carries collected: false`);
  assert.equal(entry.status, expected.status, `${label}: status is the observed HTTP status or null`);
  if (expected.endpoint) assert.match(entry.endpoint, expected.endpoint, `${label}: names the endpoint whose request failed, got ${entry.endpoint}`);
  else assert.equal(entry.endpoint, null, `${label}: names no endpoint when no request was issued`);
  assert.match(entry.error, expected.error, `${label}: carries the recorded error`);
}

async function runRecordedOkta(denied, outputRoot) {
  const { fetchImpl, requests } = recordingOktaFetch({ denied });
  const client = new OktaAuditorClient(RECORDING_CONFIG, { fetchImpl });
  const access = await runOktaAccessCheck(client, RECORDING_CONFIG);
  const results = await runAllAssessments(client, RECORDING_CONFIG);
  const exported = await exportOktaAuditBundle(client, RECORDING_CONFIG, outputRoot);
  const files = readBundleFiles(exported.outputDir);
  const collectionStatus = JSON.parse(files.get("core_data/collection_status.json"));
  return { requests, access, results, exported, files, collectionStatus, statusOf: (file) => collectionStatus.datasets.find((entry) => entry.file === file) };
}

test("collection status: a fully readable org records every dataset as collected, keeps readable-but-empty lists as [], and names only requested endpoints", async () => {
  const run = await runRecordedOkta([], createTempBase("grclanker-okta-collected-"));

  assert.deepEqual(run.collectionStatus.not_collected, []);
  assert.deepEqual(run.collectionStatus.truncated, []);
  assert.equal(run.collectionStatus.datasets.length, 33);
  for (const entry of run.collectionStatus.datasets) {
    assert.equal(entry.collected, true, entry.file);
    assert.equal(entry.complete, true, entry.file);
    assert.equal(entry.error, null, entry.file);
    assert.equal(entry.status, null, entry.file);
    assert.equal(entry.endpoint, null, entry.file);
    if (entry.shape === "object") {
      assert.equal(entry.count, null, `${entry.file}: a single object has no item count`);
      assert.equal(entry.truncated, null, `${entry.file}: a single object is never paginated`);
    } else {
      assert.equal(typeof entry.count, "number", entry.file);
      assert.equal(entry.truncated, false, entry.file);
    }
  }
  assert.deepEqual(JSON.parse(run.files.get("core_data/authorization_servers.json")), [], "a readable list with no records stays []");
  assert.deepEqual(JSON.parse(run.files.get("core_data/org_factors.json")), []);
  assert.equal(run.statusOf("core_data/authorization_servers.json").count, 0);
  assert.equal(run.statusOf("core_data/user_roles.json").count, 1, "a per-parent map counts the parents read");
  assert.equal(JSON.parse(run.files.get("core_data/default_authorization_server.json")), null, "an absent (404) single object is written as null, not as a denial");
  assert.equal(run.exported.errorCount, 0);
  assert.ok(run.access.probes.every((probe) => probe.status === "ok" && probe.httpStatus === null), "readable probes carry no HTTP status");
  for (const result of Object.values(run.results)) {
    assert.equal(result.snapshotSummary.datasets_not_collected, 0, result.category);
    assert.equal(result.snapshotSummary.dataset_errors, 0, result.category);
    assert.ok(Object.values(result.snapshotSummary).every((value) => value !== null), `${result.category}: every counter is real when every dataset was collected`);
  }
  assertOktaOutputsNameOnlyObservedRequests(oktaOutputs(run.access, run.results, run.exported), run.requests, "all readable");
});

test("collection status: a denied dataset is written to core_data as a not-collected marker, never-requested per-parent files carry a not-requested marker, its counters render null, and every status code and endpoint named in any output was actually observed", async () => {
  const base = createTempBase("grclanker-okta-denied-markers-");

  for (const dataset of OKTA_DATASETS) {
    const run = await runRecordedOkta([dataset.pattern], join(base, dataset.name.replace(/[^a-z0-9]+/gi, "-")));
    const label = `${dataset.name} denied`;

    const snapshot = JSON.parse(run.files.get(dataset.file));
    assertOktaNotCollectedMarker(snapshot, `${label} ${dataset.file}`, { status: 403, endpoint: dataset.pattern, error: /^Okta API request failed for \/api\/v1\/.* \(403 Forbidden\): You do not have permission/ });
    assert.ok(run.requests.some((request) => dataset.pattern.test(request.path) && request.status === 403), `${label}: the denied request was actually issued`);

    const status = run.statusOf(dataset.file);
    assert.equal(status.collected, false, label);
    for (const flag of ["complete", "count", "truncated", "truncation_note"]) {
      assert.equal(status[flag], null, `${label}: collection_status ${flag} is null, not a default`);
    }
    assert.equal(status.status, 403, label);
    assert.match(status.endpoint, dataset.pattern, label);
    assert.match(status.error, /403 Forbidden/, label);
    assert.ok(run.collectionStatus.not_collected.includes(dataset.file), label);

    for (const skippedFile of dataset.skipped) {
      const skipped = JSON.parse(run.files.get(skippedFile));
      assertOktaNotCollectedMarker(skipped, `${label} never-requested ${skippedFile}`, { status: null, endpoint: null, error: /^Not requested: no [a-z -]+ were requested because the parent list was not collected \(Okta API request failed for \/api\/v1\/.* \(403 Forbidden\)/ });
      const skippedStatus = run.statusOf(skippedFile);
      assert.equal(skippedStatus.collected, false, `${label}: ${skippedFile}`);
      assert.equal(skippedStatus.count, null, `${label}: ${skippedFile}`);
      assert.equal(skippedStatus.status, null, `${label}: ${skippedFile} invents no HTTP status`);
      assert.equal(skippedStatus.endpoint, null, `${label}: ${skippedFile} invents no endpoint`);
      assert.ok(run.collectionStatus.not_collected.includes(skippedFile), label);
    }
    assert.equal(run.collectionStatus.not_collected.length, 1 + dataset.skipped.length, `${label}: only the denied dataset and the files it gates are not collected`);

    const emptyFile = dataset.file === "core_data/authorization_servers.json" ? "core_data/org_factors.json" : "core_data/authorization_servers.json";
    assert.deepEqual(JSON.parse(run.files.get(emptyFile)), [], `${label}: a readable list with no records stays []`);
    assert.equal(run.statusOf(emptyFile).collected, true, label);
    assert.equal(run.statusOf(emptyFile).count, 0, label);

    const summary = run.results[dataset.category].snapshotSummary;
    assert.ok(summary.datasets_not_collected >= 1, `${label}: ${dataset.category} counts the dataset as not collected`);
    for (const counter of dataset.nullCounters) {
      assert.equal(summary[counter], null, `${label}: ${dataset.category} snapshot ${counter} renders null, not 0`);
    }
    for (const key of dataset.nullLabels ?? []) {
      assert.equal(summary[key], "not collected", `${label}: ${dataset.category} snapshot ${key}`);
    }
    assert.match(run.results[dataset.category].text, /not collected/, `${label}: the assessment text says so`);

    for (const expectation of dataset.notPass ?? []) {
      const finding = findingById(run.results[dataset.category], expectation.id);
      assert.notEqual(finding.status, "Pass", `${label}: ${expectation.id} reads this list and never passes while it is unreadable`);
      assert.match(finding.summary, expectation.summary, `${label}: ${expectation.id} names the unread list`);
      assert.ok(finding.evidence.includes(expectation.found), `${label}: ${expectation.id} keeps the found item in evidence: ${finding.evidence.join(" | ")}`);
    }

    if (dataset.probe) {
      const probe = run.access.probes.find((item) => item.key === dataset.probe);
      assert.equal(probe.status, "forbidden", label);
      assert.equal(probe.httpStatus, 403, `${label}: the probe carries the observed HTTP status`);
      assert.match(probe.path, dataset.pattern, label);
      assert.match(probe.detail, /\(403 Forbidden\)/, label);
      assert.ok(run.access.probes.filter((item) => item.key !== dataset.probe).every((item) => item.httpStatus === null), `${label}: readable probes carry no HTTP status`);
    }

    assert.match(run.files.get("_errors.log"), /\(403 Forbidden\)/, label);
    const mentions = assertOktaOutputsNameOnlyObservedRequests(oktaOutputs(run.access, run.results, run.exported), run.requests, label);
    assert.ok(mentions.statuses > 0 && mentions.endpoints > 0, `${label}: the outputs name the failed status and endpoint (found ${mentions.statuses} statuses, ${mentions.endpoints} endpoints)`);
  }
});

test("collection status: when every child lookup of a per-parent list is denied the list is not collected (count and truncated null), the file holds only the per-child markers, its counters render null, and the findings say every lookup failed", async () => {
  const base = createTempBase("grclanker-okta-all-children-denied-");

  for (const lookup of OKTA_ALL_CHILDREN_DENIED) {
    const run = await runRecordedOkta([lookup.pattern], join(base, lookup.name.replace(/[^a-z0-9]+/gi, "-")));
    const label = `${lookup.name} all denied`;
    const denied = run.requests.filter((request) => lookup.pattern.test(request.path));
    assert.equal(new Set(denied.map((request) => request.path)).size, lookup.keys.length, `${label}: one child request per parent was issued and denied`);
    assert.ok(denied.every((request) => request.status === 403), label);

    const snapshot = JSON.parse(run.files.get(lookup.file));
    if (lookup.shape === "map") {
      assert.deepEqual(Object.keys(snapshot).sort(), [...lookup.keys].sort(), `${label}: the file holds one marker per parent and nothing else`);
      for (const key of lookup.keys) {
        assertOktaNotCollectedMarker(snapshot[key], `${label} ${lookup.file}[${key}]`, { status: 403, endpoint: lookup.pattern, error: /\(403 Forbidden\)/ });
      }
    } else {
      assert.deepEqual(snapshot.map((entry) => entry.id).sort(), [...lookup.keys].sort(), `${label}: the file holds one marker per contact type and no resolved contact`);
      for (const entry of snapshot) {
        assertOktaNotCollectedMarker(entry, `${label} ${lookup.file}[${entry.id}]`, { status: 403, endpoint: lookup.pattern, error: /\(403 Forbidden\)/ });
      }
    }

    const status = run.statusOf(lookup.file);
    assert.equal(status.collected, false, `${label}: a list none of whose lookups succeeded was not collected`);
    for (const flag of ["complete", "count", "truncated", "truncation_note"]) {
      assert.equal(status[flag], null, `${label}: collection_status ${flag} is null, never 0 or false, got ${status[flag]}`);
    }
    assert.equal(status.status, null, `${label}: no single status is invented for the whole list`);
    assert.equal(status.endpoint, null, `${label}: no single endpoint is invented for the whole list`);
    assert.match(status.error, new RegExp(`^every lookup of the .+ failed \\(${lookup.keys.length} of ${lookup.keys.length}\\): `), label);
    assert.match(status.error, /\(403 Forbidden\)/, `${label}: the error still names each failed request`);
    assert.deepEqual(run.collectionStatus.not_collected, [lookup.file], label);

    for (const [category, counter] of lookup.nullCounters) {
      assert.equal(run.results[category].snapshotSummary[counter], null, `${label}: ${category} snapshot ${counter} renders null, not 0`);
      assert.ok(run.results[category].snapshotSummary.datasets_not_collected >= 1, `${label}: ${category} counts the list as not collected`);
    }
    if (lookup.manual) {
      const finding = findingById(run.results[lookup.manual.category], lookup.manual.id);
      assert.equal(finding.status, "Manual", `${label}: ${lookup.manual.id} is Manual, never a verdict on a zero count: ${finding.summary}`);
      assert.match(finding.summary, lookup.manual.summary, label);
      assert.doesNotMatch(finding.summary, /\b0 of \d+\b|some .* lookups failed/, `${label}: no bare zero and no "some lookups failed" wording`);
    }

    const mentions = assertOktaOutputsNameOnlyObservedRequests(oktaOutputs(run.access, run.results, run.exported), run.requests, label);
    assert.ok(mentions.statuses > 0 && mentions.endpoints > 0, `${label}: the outputs name the failed status and endpoint`);
  }

  const groupRoles = await runRecordedOkta([OKTA_ALL_CHILDREN_DENIED[5].pattern], join(base, "group-roles-evidence"));
  const hygiene = findingById(groupRoles.results.admin, "OKTA-ADMIN-003");
  assert.equal(hygiene.status, "Partial");
  assert.ok(hygiene.evidence.some((line) => /^Admin Team: roles=unread, members=1$/.test(line)), `a denied child reads as unread, not 0: ${hygiene.evidence.join(" | ")}`);
  const adminData = await collectOktaAdminAccessData(new OktaAuditorClient(RECORDING_CONFIG, { fetchImpl: recordingOktaFetch({ denied: [OKTA_ALL_CHILDREN_DENIED[5].pattern] }).fetchImpl }));
  assert.deepEqual(Object.keys(adminData.privilegedGroupRoles.data), [], "the in-memory map omits the denied child instead of holding []");
  assert.equal(adminData.privilegedGroupRoles.truncated, null, "no walk ran, so truncated is null rather than false");
  assert.equal(adminData.privilegedGroupRoles.notCollected?.collected, false);

  const superAdmins = findingById((await runRecordedOkta([OKTA_ALL_CHILDREN_DENIED[3].pattern], join(base, "super-admin-evidence"))).results.admin, "OKTA-ADMIN-002");
  assert.equal(superAdmins.status, "Partial");
  assert.match(superAdmins.summary, /\(every role lookup failed\)\.$/);
});

test("collection status: denying one child of several keeps the parent collected and records that child as a marker under its id, never as an empty list", async () => {
  const base = createTempBase("grclanker-okta-denied-child-");
  const lookup = OKTA_PARTIAL_CHILD_DENIAL;
  const run = await runRecordedOkta([lookup.pattern], join(base, lookup.key.toLowerCase()));
  const label = `${lookup.name} denied`;
  const snapshot = JSON.parse(run.files.get(lookup.file));
  assertOktaNotCollectedMarker(snapshot.find((entry) => entry.id === lookup.key), `${label} ${lookup.file}[${lookup.key}]`, { status: 403, endpoint: lookup.pattern, error: /\(403 Forbidden\)/ });
  assert.ok(snapshot.some((entry) => entry.contactType === "BILLING" && entry.userId === "user-9"), `${label}: the readable sibling is still written`);

  const status = run.statusOf(lookup.file);
  assert.equal(status.collected, true, `${label}: the parent walk ran and one lookup succeeded`);
  assert.equal(status.complete, false, `${label}: a denied child makes the dataset incomplete`);
  assert.equal(status.count, 1, `${label}: the count is the contacts actually resolved`);
  assert.equal(status.truncated, false, label);
  assert.match(status.error, /^TECHNICAL: .*403 Forbidden/, label);
  assert.doesNotMatch(status.error, /^every lookup/, `${label}: one failure of two is not every lookup`);
  assert.equal(status.status, null, `${label}: the dataset's own request did not fail`);
  assert.deepEqual(run.collectionStatus.not_collected, [], label);
  assert.equal(run.results.monitoring.snapshotSummary.org_contacts_resolved, 1);
  const contact = findingById(run.results.monitoring, "OKTA-MON-008");
  assert.equal(contact.status, "Partial");
  assert.match(contact.summary, /technical contact lookup failed/);
  const mentions = assertOktaOutputsNameOnlyObservedRequests(oktaOutputs(run.access, run.results, run.exported), run.requests, label);
  assert.ok(mentions.statuses > 0 && mentions.endpoints > 0, `${label}: the outputs name the failed status and endpoint`);
});

test("rule 9: scrub boundary: a name-shaped value stays bare in prose and is removed inside every carrier, as a configured secret in every encoding, and whenever it has a real token shape", () => {
  const name = "prod-us-east-2026";
  const bare = `Okta request failed for tenant ${name} owned by sess-canary-COOKIE-31415926535897`;
  assert.equal(scrubErrorText(bare), bare, "a name-shaped value bare in prose is indistinguishable from a resource name");
  assert.equal(scrubErrorText(bare, [name]), "Okta request failed for tenant [REDACTED] owned by sess-canary-COOKIE-31415926535897", "the same value registered as a configured secret is removed");
  const carriers = [
    [`Cookie: sid=${name}; Path=/`, "Cookie: [REDACTED]"],
    [`Set-Cookie: session=${name}; HttpOnly`, "Set-Cookie: [REDACTED]"],
    [`X-Api-Key: ${name} rejected`, "X-Api-Key: [REDACTED] rejected"],
    [`Authorization: Basic ${name} rejected`, "Authorization: Basic [REDACTED] rejected"],
    [`token=${name} rejected`, "token=[REDACTED] rejected"],
    [`{"client_secret": "${name}"} rejected`, '{"client_secret": "[REDACTED]"} rejected'],
    [`(session_id: ${name}) rejected`, "(session_id: [REDACTED]) rejected"],
    [`https://svc:${name}@host/p?k=${name} rejected`, "https://host/p?[REDACTED] rejected"],
    [`Bearer ${name} rejected`, "Bearer [REDACTED] rejected"],
    [`SSWS ${name} rejected`, "SSWS [REDACTED] rejected"],
    ["Basic authentication is required", "Basic authentication is required"],
    // Reviewer C, item G: the word after a credential-named "key:" is the pair's value whatever its shape, prose included.
    ["InvalidAuthenticationToken: Access token has expired", "InvalidAuthenticationToken: [REDACTED] token has expired"],
  ];
  for (const [input, expected] of carriers) {
    const scrubbed = scrubErrorText(input);
    assert.equal(scrubbed, expected, input);
    if (input.includes(name) && !expected.includes(name)) assertNoWindowOf(scrubbed, name, `carrier ${input}`);
  }
  assertNoWindowOf(scrubErrorText(bare, [name]), name, "configured secret in prose");

  // Quoted header values (the Codex P1 carrier class): the value goes whatever its quote style (plain, single, JSON-escaped), separator, or frame; the quote and any scheme word stay; quoted non-credential headers come back unchanged.
  const quotedExpectations = [
    [`Cookie: sid="${name}"; Path=/`, "Cookie: [REDACTED]"],
    [`Cookie: sid=\\"${name}\\"`, "Cookie: [REDACTED]"],
    [`Set-Cookie: session='${name}'; HttpOnly`, "Set-Cookie: [REDACTED]"],
    [`Authorization: Bearer "${name}" rejected`, 'Authorization: Bearer "[REDACTED]" rejected'],
    [`Authorization: SSWS '${name}' rejected`, "Authorization: SSWS '[REDACTED]' rejected"],
    [`Authorization: "Bearer ${name}" rejected`, 'Authorization: "Bearer [REDACTED]" rejected'],
    [`\\"Authorization\\": \\"Bearer ${name}\\"`, '\\"Authorization\\": \\"Bearer [REDACTED]\\"'],
    [`X-Api-Key: \\"Ab3dEf9hIj2k\\", next`, 'X-Api-Key: \\"[REDACTED]\\", next'],
    [`X-Auth-Token: "Ab3dEf9hIj2k"`, 'X-Auth-Token: "[REDACTED]"'],
    [`Bearer "${name}" rejected`, 'Bearer "[REDACTED]" rejected'],
  ];
  for (const [input, expected] of quotedExpectations) assert.equal(scrubErrorText(input), expected, input);
  // Compound header lines (reviewer B's shape): a quoted value ends at its closing quote, an unquoted cookie or header value ends at ";" or "," before the next "Name:" token or at the end of the line, and the following header keeps its name and gets its own carrier treatment.
  const requestId = "3f2b6a1e-9c4d-4e8f-b1a2-6d7c8e9f0a1b";
  const compoundExpectations = [
    [`Cookie: sid="${name}"; X-Api-Key: "${name}"; Content-Type: "application/json"`, 'Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"'],
    [`Cookie: sid=${name}; X-Api-Key: ${name}; Content-Type: application/json`, "Cookie: [REDACTED]; X-Api-Key: [REDACTED]; Content-Type: application/json"],
    [`Cookie: "sid=${name}; Path=/"; X-Api-Key: "${name}"; Content-Type: "application/json"`, 'Cookie: "[REDACTED]"; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"'],
    [`Set-Cookie: session=${name}; Path=/; HttpOnly, X-Api-Key: ${name}, Content-Type: text/html`, "Set-Cookie: [REDACTED], X-Api-Key: [REDACTED], Content-Type: text/html"],
    [`X-Api-Key: "${name}"; X-Auth-Token: "${name}"`, 'X-Api-Key: "[REDACTED]"; X-Auth-Token: "[REDACTED]"'],
    [`X-Api-Key: ${name}; X-Auth-Token: ${name}; Content-Type: application/json`, "X-Api-Key: [REDACTED]; X-Auth-Token: [REDACTED]; Content-Type: application/json"],
    [`Authorization: Bearer "${name}", X-Api-Key: "${name}", Content-Type: "application/json"`, 'Authorization: Bearer "[REDACTED]", X-Api-Key: "[REDACTED]", Content-Type: "application/json"'],
    [`Cookie: sid=${name}; {"error": "invalid_token", "client_secret": "${name}", "request_id": "${requestId}"}`, `Cookie: [REDACTED]; {"error": "invalid_token", "client_secret": "[REDACTED]", "request_id": "${requestId}"}`],
    [`Cookie: sid="${name}" {"error": "invalid_token", "request_id": "${requestId}"}`, `Cookie: [REDACTED] {"error": "invalid_token", "request_id": "${requestId}"}`],
    [`Cookie: sid=\\"${name}\\"; X-Api-Key: \\"${name}\\"; Content-Type: \\"application/json\\"`, 'Cookie: [REDACTED]; X-Api-Key: \\"[REDACTED]\\"; Content-Type: \\"application/json\\"'],
    [`{\\"Cookie\\": \\"sid=${name}; Path=/\\", \\"X-Api-Key\\": \\"${name}\\", \\"Content-Type\\": \\"application/json\\"}`, '{\\"Cookie\\": \\"[REDACTED]\\", \\"X-Api-Key\\": \\"[REDACTED]\\", \\"Content-Type\\": \\"application/json\\"}'],
  ];
  const gatewayBody = (line) => `Okta API request failed for /api/v1/users (502 Bad Gateway): <html><body><h1>502 Bad Gateway</h1><p>upstream headers: ${line}</p></body></html>`;
  for (const [input, expected] of compoundExpectations) {
    for (const [label, rendered, expectedRendered] of [["bare", input, expected], ["502 body", gatewayBody(input), gatewayBody(expected)]]) {
      const scrubbed = scrubErrorText(rendered);
      assert.equal(scrubbed, expectedRendered, `${label}: ${rendered}`);
      assertNoWindowOf(scrubbed, name, `compound ${label} ${rendered}`);
      for (const following of ["X-Api-Key", "X-Auth-Token", "Content-Type"]) {
        if (rendered.includes(`${following}`)) assert.ok(scrubbed.includes(following), `${following} keeps its name in ${scrubbed}`);
      }
      if (rendered.includes("application/json")) assert.ok(scrubbed.includes("application/json"), `Content-Type keeps its value in ${scrubbed}`);
      if (rendered.includes(requestId)) assert.ok(scrubbed.includes(requestId), `the request id stays in ${scrubbed}`);
      assert.equal(scrubErrorText(scrubbed), scrubbed, `second pass over ${rendered}`);
    }
  }
  const quotedCarriers = [
    (value, separator) => `Cookie${separator}sid=${value}; Path=/`,
    (value, separator) => `Cookie${separator}sid = ${value}`,
    (value, separator) => `Set-Cookie${separator}session=${value}; HttpOnly`,
    (value, separator) => `X-Api-Key${separator}${value}`,
    (value, separator) => `X-Auth-Token${separator}${value}`,
    (value, separator) => `Authorization${separator}${value}`,
    (value, separator) => `Authorization${separator}Bearer ${value}`,
    (value, separator) => `Authorization${separator}Basic ${value}`,
    (value, separator) => `Authorization${separator}SSWS ${value}`,
    (value, separator) => `Proxy-Authorization${separator}Bearer ${value}`,
    (value, separator, raw, quote) => `Authorization${separator}${quote}Bearer ${raw}${quote}`,
  ];
  const quotedFrames = [
    (line) => line,
    (line) => `Okta API request failed for /api/v1/users (401 Unauthorized): the request carried ${line} and was rejected`,
    (line) => `{"errorCode":"E0000011","errorSummary":"Invalid header: ${line}","errorCauses":[]}`,
  ];
  for (const raw of [name, "Ab3dEf9hIj2k"]) {
    for (const carrier of quotedCarriers) {
      for (const separator of [": ", ":", " : ", " :"]) {
        for (const frame of quotedFrames) {
          for (const quote of ['"', "'", '\\"']) {
            const input = frame(carrier(`${quote}${raw}${quote}`, separator, raw, quote));
            assertNoWindowOf(scrubErrorText(input), raw, `quoted carrier ${input}`);
          }
          const control = frame(carrier(raw, separator, raw, ""));
          assertNoWindowOf(scrubErrorText(control), raw, `unquoted carrier ${control}`);
        }
      }
    }
  }
  for (const header of OKTA_QUOTED_HEADERS_KEPT) {
    assert.equal(scrubErrorText(header), header, `must keep quoted header: ${header}`);
    const sentence = `Okta API request failed for /api/v1/users (400 Bad Request): the response carried ${header}`;
    assert.equal(scrubErrorText(sentence), sentence, `must keep quoted header in a sentence: ${sentence}`);
  }
  const secret = 'top secret/value+1"x';
  const forms = {
    raw: secret,
    json: JSON.stringify(secret).slice(1, -1),
    url: encodeURIComponent(secret),
    base64: Buffer.from(secret).toString("base64"),
    base64url: Buffer.from(secret).toString("base64url"),
  };
  const encoded = Object.entries(forms).map(([label, form]) => `${label}=${form}`).join(" ");
  assert.equal(scrubErrorText(encoded, [secret]), "raw=[REDACTED] json=[REDACTED] url=[REDACTED] base64=[REDACTED] base64url=[REDACTED]");
  assert.equal(
    scrubErrorText("bare shapes eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2lnbmF0dXJl 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 QmFzZTY0K1N5bWJvbHM= aB3xZ9qL2mN8pR4tV7wY1 ABCD-EFGH-1234-5678 xKqZvBnMwLpRtYsHdG stay-01 name_with_words-2026 ERR_MODULE_NOT_FOUND"),
    "bare shapes [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED] stay-01 name_with_words-2026 ERR_MODULE_NOT_FOUND",
    "a JWT, a hex digest, a padded base64 run, scattered digits, a second numeric segment, and token casing are removed bare; short runs, names, and uppercase codes stay",
  );
  assert.equal(
    scrubErrorText("failed for /api/v1/users/aB3xZ9qL2mN8pR4tV7wY1/factors from /tmp/run-9b6rz9m4l55zg7/config.yaml and https://hooks.example.com/services/T0/aB3xZ9qL2mN8pR4tV7wY1"),
    "failed for /api/v1/users/aB3xZ9qL2mN8pR4tV7wY1/factors from /tmp/run-9b6rz9m4l55zg7/config.yaml and https://hooks.example.com/services/T0/[REDACTED]",
    "a token-shaped segment of a bare request target or file path is an identifier the run named; inside a URL it is a webhook token",
  );
  assert.equal(
    scrubErrorText("key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY beside /api/v1/users/00u1abcd2EFGH3ijk4x5/roles"),
    "key [REDACTED] beside /api/v1/users/00u1abcd2EFGH3ijk4x5/roles",
    "a random 40-character base64 run is an AWS secret access key; a 40-character bare path of word segments is a request target",
  );

  // Must-keep table (addendum 7): every identifying string a summary may carry survives alone and inside a realistic sentence.
  for (const value of OKTA_MUST_KEEP) {
    assert.equal(scrubErrorText(value), value, `must keep bare: ${value}`);
    for (const sentence of oktaSummarySentences(value)) assert.equal(scrubErrorText(sentence), sentence, `must keep in a sentence: ${sentence}`);
  }
});

/** Reviewer C's 15 value shape classes (item G): the plain words that no shape rule catches are the point of the pair rule. */
const PAIR_VALUE_SHAPES = [
  "hunter2", "Summer2026!", "correcthorsebatterystaple", "letmein2024", "monkey", "qwerty", "letmein", "iloveyou",
  "football", "Sunshine", "starwarsfan", "footballteam", "abc12", "p@ss", "guest",
];
/** The pair forms of item G: "=", ": ", ":", compact JSON, and spaced JSON. */
const PAIR_FORMS = [
  (key, value) => `${key}=${value}`,
  (key, value) => `${key}: ${value}`,
  (key, value) => `${key}:${value}`,
  (key, value) => `{"${key}":"${value}"}`,
  (key, value) => `{"${key}": "${value}"}`,
];
/** The frames of item G: a bare line, prose, a colon-terminated banner with the pair on the next line, a JSON string member, a 502 JSON body, and a double-escaped raw member. */
const PAIR_FRAMES = [
  ["line", (pair) => pair],
  ["sentence", (pair) => `Vendor request failed (502 Bad Gateway) for /api/v1/items: upstream echoed ${pair} while proxying`],
  ["502-text", (pair) => `Vendor request failed (502 Bad Gateway) for /api/v1/items: Environment as echoed by the proxy:\n${pair}`],
  ["json-escaped", (pair) => `{"message":${JSON.stringify(pair)}}`],
  ["502-json", (pair) => `{"status":502,"error":"Bad Gateway","message":${JSON.stringify(`The upstream rejected the request; environment: ${pair}`)},"request":{"env":${JSON.stringify(pair)}}}`],
  ["502-json-raw", (pair) => `{"status":502,"raw":${JSON.stringify(JSON.stringify({ env: [pair] }))}}`],
];
const SAMPLE_UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

test("reviewer C final verdict, item G: the value under a credential-named key is removed whatever its shape in every pair form and frame; settings, identifiers, bearer ids, and webhooks follow the key classes", () => {
  const credentialKeys = [
    "DB_PASSWORD", "API_KEY", "client_secret", "access_token", "password", "AUTH_TOKEN",
    "OKTA_CLIENT_TOKEN", "OKTA_CLIENT_PRIVATEKEY", "OKTA_CLIENT_CLIENTASSERTION", "SPLUNK_PASSWORD", "SUMOLOGIC_ACCESS_KEY", "VERACODE_API_KEY_SECRET", "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE",
  ];
  for (const key of credentialKeys) {
    for (const value of PAIR_VALUE_SHAPES) {
      for (const form of PAIR_FORMS) {
        const pair = form(key, value);
        for (const [frameName, frame] of PAIR_FRAMES) {
          const input = frame(pair);
          const scrubbed = scrubErrorText(input);
          const label = `${frameName}: ${input}`;
          assertNoWindowOf(scrubbed, value, label);
          assert.ok(scrubbed.includes(key), `the key name stays in ${label} -> ${scrubbed}`);
          assert.ok(scrubbed.includes("[REDACTED]"), `the value is replaced by the marker in ${label} -> ${scrubbed}`);
          if (frameName === "sentence") assert.ok(scrubbed.endsWith(" while proxying"), `the prose after the pair stays in ${label} -> ${scrubbed}`);
          assert.equal(scrubErrorText(scrubbed), scrubbed, `second pass over ${label}`);
        }
      }
      assert.equal(scrubErrorText(`${key}=${value}`), `${key}=[REDACTED]`);
      assert.equal(scrubErrorText(`${key}: ${value}`), `${key}: [REDACTED]`);
      assert.equal(scrubErrorText(`{"${key}": "${value}"}`), `{"${key}": "[REDACTED]"}`);
    }
  }

  // Bearer ids: a key ending in secret_id or naming a session id loses its value whatever the shape, a UUID included, in every form.
  for (const key of ["secret_id", "VAULT_SECRET_ID", "role_secret_id", "secretId", "secret-id", "session_id", "sessionId", "sid", "JSESSIONID", "PHPSESSID"]) {
    for (const value of [SAMPLE_UUID, "xKqZvBnMwLpRtYsHdG", "monkey", "hunter2"]) {
      for (const form of PAIR_FORMS) {
        const scrubbed = scrubErrorText(form(key, value));
        assertNoWindowOf(scrubbed, value, `bearer id ${form(key, value)}`);
        assert.ok(scrubbed.includes(key), `bearer id key stays: ${scrubbed}`);
      }
    }
  }

  // Identifiers: a key without a credential word is not a pair under the rule; its value is judged by shape alone, so a UUID or a name stays.
  for (const key of ["OKTA_CLIENT_ID", "OKTA_CLIENT_CLIENTID", "client_id", "SUMO_ACCESS_ID", "SUMOLOGIC_ACCESS_ID", "SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SPLUNK_USERNAME", "X-Request-Id", "request_id", "user_id", "kid"]) {
    for (const value of [SAMPLE_UUID, "acme-prod-2026", "audit.bot"]) {
      for (const form of PAIR_FORMS) assert.equal(scrubErrorText(form(key, value)), form(key, value), `identifier kept: ${form(key, value)}`);
    }
  }

  // Settings: a credential-named key whose final segment names a setting keeps a value that is not token-shaped, in every form; a token-shaped value still goes.
  const settingPairs = [
    ["token_endpoint", "https://example.okta.com/oauth2/v1/token"],
    ["token_uri", "https://example.okta.com/oauth2/v1/token"],
    ["auth_method", "private_key_jwt"],
    ["token_endpoint_auth_method", "private_key_jwt"],
    ["signing_algorithm", "RS256"],
    ["token_audience", "api://default"],
    ["token_issuer", "https://example.okta.com/oauth2/default"],
    ["key_shape", "rsa"],
    ["token_type", "Bearer"],
    ["SNOWFLAKE_TOKEN_TYPE", "KEYPAIR_JWT"],
    ["X-Snowflake-Authorization-Token-Type", "KEYPAIR_JWT"],
    ["credential_mode", "PrivateKey"],
    ["token_limit", "200"],
    ["token_count", "3"],
    ["api_key_id", SAMPLE_UUID],
    ["VERACODE_API_KEY_ID", SAMPLE_UUID],
    ["OKTA_CLIENT_PRIVATEKEYID", "kid-2026-primary"],
    ["token_name", "audit-token"],
    ["api_key_name", "primary-key-2026"],
  ];
  for (const [key, value] of settingPairs) {
    for (const form of PAIR_FORMS) assert.equal(scrubErrorText(form(key, value)), form(key, value), `setting kept: ${form(key, value)}`);
    for (const shape of PAIR_VALUE_SHAPES) assert.equal(scrubErrorText(`${key}=${shape}`), `${key}=${shape}`, `a plain setting value stays: ${key}=${shape}`);
  }
  for (const [key, value] of [["token_type", "QmFzZTY0K1N5bWJvbHM="], ["api_key_id", "xKqZvBnMwLpRtYsHdG"], ["token_name", "aB3xZ9qL2mN8pR4tV7wY1"]]) {
    for (const form of PAIR_FORMS) assertNoWindowOf(scrubErrorText(form(key, value)), value, `token-shaped setting value ${form(key, value)}`);
  }

  // Webhooks: webhook*, *hook_url, and callback_url keep the origin and lose the path and query; a webhook secret goes whole.
  const webhookPath = "services/T0AB12CD/B0EF34GH/xKqZvBnMwLpRtYsHdG";
  assert.equal(scrubErrorText(`webhook_url=https://hooks.example.com/${webhookPath}`), "webhook_url=https://hooks.example.com/[REDACTED]");
  assert.equal(scrubErrorText(`webhookUrl: https://hooks.example.com/${webhookPath}?token=abc`), "webhookUrl: https://hooks.example.com/[REDACTED]");
  assert.equal(scrubErrorText(`slack_hook_url: "https://hooks.example.com/${webhookPath}"`), 'slack_hook_url: "https://hooks.example.com/[REDACTED]"');
  assert.equal(scrubErrorText("callback_url: https://app.example.com/oauth/callback?code=abc123def456"), "callback_url: https://app.example.com/[REDACTED]");
  assert.equal(scrubErrorText("webhook_secret=monkey"), "webhook_secret=[REDACTED]");
  for (const line of ["webhook_url=https://hooks.example.com/[REDACTED]", "callback_url: https://app.example.com/[REDACTED]"]) assert.equal(scrubErrorText(line), line, `second pass over ${line}`);
});

/** Reviewer C's literal escapes (item H): the two- and six-character sequences as they sit inside error text, not the control characters. */
const LITERAL_ESCAPES = ["\\n", "\\r\\n", "\\t", "\\b", "\\f", "\\/", "\\u000a", "\\u0009", "\\u000d\\u000a"];
/** The header lines of rows (b) and (ii) glued to an escape; each gives the line and its expected rendering, or null where the scrubber's HMAC rendering differs by integration. */
const ESCAPED_HEADER_LINES = [
  (value) => [`api_key=${value}`, "api_key=[REDACTED]"],
  (value) => [`password: ${value}`, "password: [REDACTED]"],
  (value) => [`X-Api-Key: ${value}`, "X-Api-Key: [REDACTED]"],
  (value) => [`Cookie: sid=${value}`, "Cookie: [REDACTED]"],
  (value) => [`Authorization: Bearer ${value}`, "Authorization: Bearer [REDACTED]"],
  (value) => [`Authorization: SSWS ${value}`, "Authorization: SSWS [REDACTED]"],
  (value) => [`Authorization: Splunk ${value}`, "Authorization: Splunk [REDACTED]"],
  (value) => [`Authorization: Basic ${value}`, "Authorization: Basic [REDACTED]"],
  (value) => [`Authorization: VERACODE-HMAC-SHA-256 id=${value},ts=1758560000000,nonce=${value},sig=${value}`, null],
  (value) => [`X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT\\u000aAuthorization: Bearer ${value}`, "X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT\\u000aAuthorization: Bearer [REDACTED]"],
];
/** The text before the escape: a colon-terminated word is the case that used to swallow the header line as its value. */
const ESCAPE_PREFIXES = ["request failed", "request headers:"];
/** The frames of item H: a bare line, a 502 banner ending in a colon, a JSON string member holding the literal escapes, and a double-escaped raw member (each with the encoding the frame applies to its inner text). */
const ESCAPE_FRAMES = [
  ["line", (text) => text, (text) => text],
  ["502-text", (text) => `Vendor request failed (502 Bad Gateway) for /api/v1/items: Environment as echoed by the proxy:${text}`, (text) => text],
  ["json-member", (text) => `{"message":"${text}"}`, (text) => text],
  ["502-json-raw", (text) => `{"status":502,"raw":${JSON.stringify(JSON.stringify({ env: [text] }))}}`, (text) => JSON.stringify(JSON.stringify(text).slice(1, -1)).slice(1, -1)],
];

test("reviewer C final verdict, item H: a literal JSON escape is a boundary before every carrier opener, so a header line glued to an escape is scrubbed as a header line and never as the value of the word before it", () => {
  for (const escape of LITERAL_ESCAPES) {
    for (const prefix of ESCAPE_PREFIXES) {
      for (const value of PAIR_VALUE_SHAPES) {
        for (const headerLine of ESCAPED_HEADER_LINES) {
          const [line, expectedLine] = headerLine(value);
          for (const [frameName, frame, encode] of ESCAPE_FRAMES) {
            const input = frame(`${prefix}${escape}${line}`);
            const scrubbed = scrubErrorText(input);
            const label = `${frameName}: ${input}`;
            assertNoWindowOf(scrubbed, value, label);
            assert.ok(scrubbed.includes("[REDACTED]"), `the value is replaced by the marker in ${label} -> ${scrubbed}`);
            assert.ok(scrubbed.includes(encode(`${prefix}${escape}${line.split(/[ =]/)[0]}`)), `the prefix, the escape, and the header name stay in ${label} -> ${scrubbed}`);
            if (expectedLine !== null) assert.equal(scrubbed, frame(`${prefix}${escape}${expectedLine}`), label);
            else assert.ok(scrubbed.includes("Authorization: VERACODE-HMAC-SHA-256 "), `the HMAC scheme word stays in ${label} -> ${scrubbed}`);
            assert.equal(scrubErrorText(scrubbed), scrubbed, `second pass over ${label}`);
          }
        }
      }
    }
  }

  // The reviewer's literal rows (b) and (ii).
  assert.equal(scrubErrorText("request headers:\\u000aAuthorization: Splunk abcdefghijklmnop"), "request headers:\\u000aAuthorization: Splunk [REDACTED]");
  assert.equal(scrubErrorText('{"message":"request headers:\\u000aAuthorization: Splunk abcdefghijklmnop"}'), '{"message":"request headers:\\u000aAuthorization: Splunk [REDACTED]"}');
  assert.equal(scrubErrorText("request headers:\\u0009X-Api-Key: hunter2"), "request headers:\\u0009X-Api-Key: [REDACTED]");
  assert.equal(scrubErrorText("request headers:\\u000aAuthorization: SSWS p@ss"), "request headers:\\u000aAuthorization: SSWS [REDACTED]");
  assert.equal(scrubErrorText("request headers:\\u000d\\u000aAuthorization: Bearer abc12"), "request headers:\\u000d\\u000aAuthorization: Bearer [REDACTED]");
  assert.equal(
    scrubErrorText("Vendor request failed (502 Bad Gateway) for /api/v1/items: Environment as echoed by the proxy:\\tpassword: hunter2"),
    "Vendor request failed (502 Bad Gateway) for /api/v1/items: Environment as echoed by the proxy:\\tpassword: [REDACTED]",
  );
  for (const banner of ["proxy:", "proxy.", "proxy"]) assert.equal(scrubErrorText(`${banner}\\n\\nX-Api-Key: hunter2`), `${banner}\\n\\nX-Api-Key: [REDACTED]`);
  assert.equal(scrubErrorText("upstream said\\nAuthorization: Bearer hunter2"), "upstream said\\nAuthorization: Bearer [REDACTED]");
  assert.equal(scrubErrorText('{\\n  \\"password\\": \\"monkey\\"\\n}'), '{\\n  \\"password\\": \\"[REDACTED]\\"\\n}');

  // Every anchored token shape starts after the escape and never on its letter; a value, URL, or query pair ends at the backslash of the next escape.
  const shapes = [
    ["eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2lnbmF0dXJl", "a JWT"],
    ["AKIAIOSFODNN7EXAMPLE", "an AWS access key id"],
    ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "an AWS secret access key"],
    ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "a hex digest"],
    ["xKqZvBnMwLpRtYsHdG", "a run with token casing"],
    ["sk_live_abcdefghij1234567890", "a vendor-prefixed token"],
    ["ghp_abcdefghijklmnopqrstuvwxyz0123", "a GitHub token"],
  ];
  for (const escape of LITERAL_ESCAPES) {
    for (const [shape, description] of shapes) {
      assert.equal(scrubErrorText(`trace${escape}${shape} end`), `trace${escape}[REDACTED] end`, `${description} after ${escape}`);
      assert.equal(scrubErrorText(`{"message":"trace${escape}${shape}${escape}end"}`), `{"message":"trace${escape}[REDACTED]${escape}end"}`, `${description} between two ${escape}`);
    }
    assert.equal(scrubErrorText(`trace${escape}name_with_words-2026 and${escape}ERR_MODULE_NOT_FOUND`), `trace${escape}name_with_words-2026 and${escape}ERR_MODULE_NOT_FOUND`, `a name after ${escape} stays whole`);
    assert.equal(scrubErrorText(`note${escape}https://example.com/a?token=abc123def456${escape}next`), `note${escape}https://example.com/a?[REDACTED]${escape}next`, `a URL after ${escape}`);
    assert.equal(scrubErrorText(`Bearer abcdefghijklmnop${escape}X-Api-Key: guest`), `Bearer [REDACTED]${escape}X-Api-Key: [REDACTED]`, `a scheme value ends at ${escape}`);
    assert.equal(scrubErrorText(`Cookie: sid=hunter2${escape}X-Api-Key: guest`), `Cookie: [REDACTED]${escape}X-Api-Key: [REDACTED]`, `a cookie value ends at ${escape}`);
  }
  // A "\/" escape is a boundary rather than a path separator: a key or token after it is judged on its own, while a plain "/" still names a bare path segment.
  assert.equal(scrubErrorText("path \\/api\\/v1\\/users\\/00u1abcd2EFGH3ijk4x5\\/factors"), "path \\/api\\/v1\\/users\\/[REDACTED]\\/factors");
  assert.equal(scrubErrorText("path /api/v1/users/00u1abcd2EFGH3ijk4x5/factors"), "path /api/v1/users/00u1abcd2EFGH3ijk4x5/factors");
  // A lone backslash is not an opening quote and does not hide the value after it.
  assert.equal(scrubErrorText("password: \\hunter2"), "password: [REDACTED]");
  assert.equal(scrubErrorText("Authorization: Bearer \\hunter2"), "Authorization: Bearer [REDACTED]");
});

/** Reviewer C's compound header lines (items F and L): several carriers on one line. Each builder takes distinct planted values and gives the line, its credential slots, the header names that must survive as often as they appeared, and the fragments that must survive verbatim. */
const COMPOUND_HEADER_LINES = [
  (a, b) => [`Cookie: sid="${a}"; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Cookie: sid=${a}; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Cookie: sid="${a}", X-Api-Key: "${b}", Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Cookie: sid=${a}, X-Api-Key: "${b}", Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Cookie: theme=light; sid=${a}; lang=en; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Set-Cookie: sid="${a}"; Path=/; HttpOnly, X-Api-Key: "${b}", Content-Type: "application/json"`, [a, b], ["Set-Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Cookie: sid='${a}'; X-Api-Key: '${b}'; Content-Type: 'application/json'`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Authorization: Bearer "${a}"; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Authorization", "X-Api-Key", "Content-Type"], ["Bearer", "application/json"]],
  (a, b) => [`X-Api-Key: "${a}", Authorization: "Bearer ${b}", Content-Type: "application/json"`, [a, b], ["X-Api-Key", "Authorization", "Content-Type"], ["Bearer", "application/json"]],
  (a, b) => [`X-Api-Key: "${a}"; Cookie: sid="${b}"; Content-Type: "application/json"`, [a, b], ["X-Api-Key", "Cookie", "Content-Type"], ["application/json"]],
  (a, b, c) => [`Cookie: sid="${a}", Authorization: Bearer "${b}", X-Api-Key: "${c}", Content-Type: "application/json"`, [a, b, c], ["Cookie", "Authorization", "X-Api-Key", "Content-Type"], ["Bearer", "application/json"]],
  (a, b) => [`Cookie: sid="${a}" {"X-Api-Key": "${b}", "Content-Type": "application/json"}`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Authorization: Bearer "${a}" {"Cookie": "sid=${b}", "Content-Type": "application/json"}`, [a, b], ["Authorization", "Cookie", "Content-Type"], ["Bearer", "application/json"]],
  (a, b) => [`{"Cookie": "sid=${a}"} X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Authorization: SSWS "${a}"; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Authorization", "X-Api-Key", "Content-Type"], ["SSWS", "application/json"]],
  (a, b) => [`Authorization: Splunk "${a}"; Cookie: sid=${b}; Content-Type: "application/json"`, [a, b], ["Authorization", "Cookie", "Content-Type"], ["Splunk", "application/json"]],
  (a, b) => [`Authorization: Snowflake Token="${a}", X-Api-Key: "${b}", Content-Type: "application/json"`, [a, b], ["Authorization", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b, c) => [`Authorization: VERACODE-HMAC-SHA-256 id=${a},ts=1700000000,nonce=${b},sig=${c}; Content-Type: "application/json"`, [a, b, c], ["Authorization", "Content-Type"], ["VERACODE-HMAC-SHA-256", "ts=1700000000", "application/json"]],
  (a, b) => [`Authorization: Basic "${a}"; Cookie: AWSALB="${b}"; Content-Type: "application/json"`, [a, b], ["Authorization", "Cookie", "Content-Type"], ["Basic", "application/json"]],
  // An unterminated quote ends before the next "Name:" token, which keeps its name (item F).
  (a, b) => [`Cookie: sid="${a}; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`X-Api-Key: "${a}; Cookie: sid=${b}; Content-Type: "application/json"`, [a, b], ["X-Api-Key", "Cookie", "Content-Type"], ["application/json"]],
  // A JSON-object header whose value carries escaped inner quotes (item F).
  (a, b) => [`{"Cookie": "sid=\\"${a}\\"", "X-Api-Key": "${b}", "Content-Type": "application/json"}`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`{"X-Api-Key": "\\"${a}\\"", "Cookie": "sid=${b}", "Content-Type": "application/json"}`, [a, b], ["X-Api-Key", "Cookie", "Content-Type"], ["application/json"]],
  (a, b) => [`{"Authorization": "Bearer \\"${a}\\"", "X-Api-Key": "${b}", "Content-Type": "application/json"}`, [a, b], ["Authorization", "X-Api-Key", "Content-Type"], ["Bearer", "application/json"]],
  // A following header whose name carries RFC 7230 token punctuation is recognised as the next header (item L).
  (a, b) => [`Cookie: theme=dark; my.sid=${a}; X.Api.Key: "${b}"`, [a, b], ["Cookie", "X.Api.Key"], []],
  (a, b) => [`Cookie: sid=${a}; X_Api_Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X_Api_Key", "Content-Type"], ["application/json"]],
];
/** The two value shapes of the compound matrix: pairwise distinct canaries sharing no 6-character window with any line or frame text. */
const COMPOUND_VALUE_SHAPES = [
  ["name-shaped", ["prod-iidsre-itdpqey", "prod-yzrupn-efussqe", "prod-hnxttf-anwlqzo"]],
  ["token-shaped", ["K7pQz2VxN9mR4tYw8LbC1dFgH6jS==", "Wq3Zt8Hv5Nc2Xf9Lm4Rp7Bd1Gk6Ty==", "Jx5Cn2Vb8Mq4Wz7Rt1Hp9Kf3Ld6Sg=="]],
];
/** The frames of the compound matrix: a bare line, a sentence, a 502 banner, a JSON string member, a 502 JSON body, and a double-escaped raw member. */
const COMPOUND_FRAMES = [
  ["line", (text) => text],
  ["sentence", (text) => `Vendor request failed (502 Bad Gateway) for /api/v1/items: ${text} while proxying`],
  ["502-text", (text) => `Vendor request failed (502 Bad Gateway) for /api/v1/items: Environment as echoed by the proxy:\n${text}`],
  ["json-escaped", (text) => `{"message":${JSON.stringify(text)}}`],
  ["502-json", (text) => `{"status":502,"error":"Bad Gateway","message":${JSON.stringify(`The upstream rejected the request; ${text}`)}}`],
  ["502-json-raw", (text) => `{"status":502,"raw":${JSON.stringify(JSON.stringify({ headers: text }))}}`],
];

/** How often `fragment` occurs in `text`. */
function occurrencesOf(text, fragment) {
  return text.split(fragment).length - 1;
}

test("reviewer C final verdict, items F and L: on a compound header line every carrier value goes at every JSON depth, an escaped inner quote is inner content, an unterminated quote ends before the next header token, and every following header keeps its name", () => {
  for (const [shapeName, values] of COMPOUND_VALUE_SHAPES) {
    for (const build of COMPOUND_HEADER_LINES) {
      const [line, credentials, names, keeps] = build(...values);
      for (const [frameName, frame] of COMPOUND_FRAMES) {
        const input = frame(line);
        const scrubbed = scrubErrorText(input);
        const label = `${shapeName} ${frameName}: ${input}`;
        for (const credential of credentials) assertNoWindowOf(scrubbed, credential, label);
        for (const name of names) assert.ok(occurrencesOf(scrubbed, name) >= occurrencesOf(input, name), `the header name ${name} survives in ${label} -> ${scrubbed}`);
        for (const keep of keeps) assert.ok(occurrencesOf(scrubbed, keep) >= occurrencesOf(input, keep), `${keep} survives in ${label} -> ${scrubbed}`);
        assert.equal(scrubErrorText(scrubbed), scrubbed, `second pass over ${label}`);
      }
    }
  }

  // The reviewer's edge rows, rendered: the following header keeps its name and its own carrier treatment.
  assert.equal(scrubErrorText('Cookie: sid="prod-iidsre-itdpqey; X-Api-Key: "prod-yzrupn-efussqe"; Content-Type: "application/json"'), 'Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"');
  assert.equal(scrubErrorText('X-Api-Key: "prod-iidsre-itdpqey; Cookie: sid=prod-yzrupn-efussqe; Content-Type: "application/json"'), 'X-Api-Key: "[REDACTED]; Cookie: [REDACTED]; Content-Type: "application/json"');
  assert.equal(scrubErrorText('{"Cookie": "sid=\\"prod-iidsre-itdpqey\\"", "X-Api-Key": "prod-yzrupn-efussqe", "Content-Type": "application/json"}'), '{"Cookie": "[REDACTED]", "X-Api-Key": "[REDACTED]", "Content-Type": "application/json"}');
  assert.equal(scrubErrorText('{"X-Api-Key": "\\"prod-iidsre-itdpqey\\"", "Cookie": "sid=prod-yzrupn-efussqe", "Content-Type": "application/json"}'), '{"X-Api-Key": "[REDACTED]", "Cookie": "[REDACTED]", "Content-Type": "application/json"}');
  assert.equal(scrubErrorText('{"Authorization": "Bearer \\"prod-iidsre-itdpqey\\"", "X-Api-Key": "prod-yzrupn-efussqe", "Content-Type": "application/json"}'), '{"Authorization": "Bearer [REDACTED]", "X-Api-Key": "[REDACTED]", "Content-Type": "application/json"}');
  assert.equal(scrubErrorText('Cookie: theme=dark; my.sid=prod-iidsre-itdpqey; X.Api.Key: "prod-yzrupn-efussqe"'), 'Cookie: [REDACTED]; X.Api.Key: "[REDACTED]"');
  // Inside a double-escaped raw JSON string every quoted carrier goes and the quote units at that depth stay.
  const rawMember = (headers) => `{"status":502,"raw":${JSON.stringify(JSON.stringify({ headers }))}}`;
  assert.equal(
    scrubErrorText(rawMember('Cookie: sid="prod-iidsre-itdpqey"; X-Api-Key: "prod-yzrupn-efussqe"; Content-Type: "application/json"')),
    rawMember('Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"'),
  );
  assert.equal(
    scrubErrorText(rawMember('{"Cookie": "sid=\\"prod-iidsre-itdpqey\\"", "X-Api-Key": "\\"prod-yzrupn-efussqe\\""}')),
    rawMember('{"Cookie": "[REDACTED]", "X-Api-Key": "[REDACTED]"}'),
  );
  // Reading to the matching closer keeps a quoted value whole: spaces, "=", and ";" inside the quotes go with it.
  assert.equal(scrubErrorText('"password": "correct horse battery staple"'), '"password": "[REDACTED]"');
  assert.equal(scrubErrorText('Cookie: "sid=a=b; theme=dark"; X-Api-Key: guest'), 'Cookie: "[REDACTED]"; X-Api-Key: [REDACTED]');
});

/** Every endpoint the Okta collectors request (sample ids in the per-parent paths), tenant names, principals, status text, finding ids. */
const OKTA_REQUESTED_PATHS = [
  "/api/v1/api-tokens",
  "/api/v1/apps?limit=200",
  "/api/v1/authenticators",
  "/api/v1/authorizationServers/default",
  "/api/v1/authorizationServers?limit=200",
  "/api/v1/behaviors?limit=200",
  "/api/v1/device-assurances?limit=200",
  "/api/v1/eventHooks?limit=200",
  "/api/v1/groups/00g1abcd2EFGH3ijk4x5/roles?limit=200",
  "/api/v1/groups/00g1abcd2EFGH3ijk4x5/users?limit=200",
  "/api/v1/groups?limit=200",
  "/api/v1/groups/rules?limit=200",
  "/api/v1/iam/assignees/users?limit=200",
  "/api/v1/iam/assignees/users?limit=1",
  "/api/v1/idps?limit=200",
  "/api/v1/logs?limit=1",
  "/api/v1/logs?since=2026-08-23T00:00:00.000Z&until=2026-09-22T00:00:00.000Z&limit=200",
  "/api/v1/logStreams?limit=200",
  "/api/v1/org/contacts",
  "/api/v1/org/contacts/TECHNICAL",
  "/api/v1/org/factors?limit=200",
  "/api/v1/org/orgSettings/thirdPartyAdminSetting",
  "/api/v1/org/privacy/oktaSupport",
  "/api/v1/policies/00p1abcd2EFGH3ijk4x5/rules?limit=200",
  "/api/v1/policies?type=PASSWORD&limit=200",
  "/api/v1/policies?type=OKTA_SIGN_ON&limit=1",
  "/api/v1/threats/configuration",
  "/api/v1/trustedOrigins?limit=200",
  "/api/v1/users/00u1abcd2EFGH3ijk4x5",
  "/api/v1/users/00u1abcd2EFGH3ijk4x5/factors",
  "/api/v1/users/00u1abcd2EFGH3ijk4x5/roles?limit=200",
  "/api/v1/users?limit=200",
  "/api/v1/users?limit=1",
  "/api/v1/zones?limit=200",
  "/oauth2/v1/token",
];
/** Quoted non-credential headers (the Codex P1 must-keep rows): a quote alone never makes a header value a credential. */
const OKTA_QUOTED_HEADERS_KEPT = [
  'Content-Type: "application/json"',
  'Content-Type:"application/json; charset=utf-8"',
  "Accept: 'application/json'",
  'Content-Length: "42"',
  'X-Request-Id: "3f2b6a1e-9c4d-4e8f-b1a2-6d7c8e9f0a1b"',
  'X-Rate-Limit-Remaining: "599"',
  'User-Agent: "grclanker-cli/0.4.1"',
  'Cache-Control: "no-store"',
  'Location: "/api/v1/users"',
  '{"Content-Type": "application/json", "Accept": "application/json"}',
  '{\\"Content-Type\\": \\"application/json\\", \\"Accept\\": \\"application/json\\"}',
];

const OKTA_MUST_KEEP = [
  ...OKTA_REQUESTED_PATHS,
  ...OKTA_REQUESTED_PATHS.map((path) => `GET ${path}`),
  "tenant.okta.gov",
  "https://tenant.okta.gov",
  "acme-prod-2026.okta.com",
  "dev-123456.oktapreview.com",
  "prod-us-east-2026",
  "audit.bot@tenant.okta.gov",
  "jane.doe@acme-prod.example.gov",
  "SUPER_ADMIN",
  "ORG_ADMIN",
  "READ_ONLY_ADMIN",
  "OKTA_SIGN_ON",
  "ACCESS_POLICY",
  "401 Unauthorized",
  "403 Forbidden",
  "404 Not Found",
  "429 Too Many Requests",
  "500 Internal Server Error",
  "502 Bad Gateway",
  "503 Service Unavailable",
  ...OKTA_CHECK_IDS,
  "home:.okta/okta.yaml",
  "project:.okta.yaml",
  "/home/auditor/.okta/okta.yaml",
  "SSWS",
  "PrivateKey",
  "ERR_OSSL_UNSUPPORTED",
  "INVALID_PRIVATE_KEY",
  "BLOCK_AS_IMPLICIT_KEY",
];

/** Realistic Okta summary and error sentences with an identifying value in the slot such a value occupies. */
function oktaSummarySentences(value) {
  return [
    `Certificate-based authentication could not be evaluated because the endpoint returned 403 Forbidden (missing scope or admin role): Okta API request failed for ${value} (403 Forbidden). Collect manually: export ${value} from the Okta admin console.`,
    `- Auth mode: ${value}\n- API token inventory: empty with no error\n- Organization: ${value}`,
    `Okta API request failed for ${value} (403 Forbidden): the endpoint returned 403 Forbidden (missing scope or admin role)`,
    `Not requested: no role lookups were requested because the parent list ${value} was not collected (Okta API request failed for ${value} (403 Forbidden)).`,
    `IdP data unavailable: ${value} (403 Forbidden)`,
  ];
}

/** Every fixed text the Okta integration emits, with sample paths and names, passes its scrubber unchanged (GWS note 1). */
const OKTA_FIXED_TEXTS = [
  "Unable to read Okta config file /home/auditor/.okta/okta.yaml (EACCES)",
  "Unable to read Okta config file /workspace/audit/.okta.yaml (UNREADABLE)",
  "Unable to parse Okta config file: invalid YAML in /home/auditor/.okta/okta.yaml at line 4, column 12 (BLOCK_AS_IMPLICIT_KEY)",
  "Unable to parse Okta config file: invalid YAML in /workspace/audit/.okta.yaml (INVALID_YAML)",
  "Okta org URL is required. Set OKTA_CLIENT_ORGURL, configure .okta.yaml, or pass org_url explicitly.",
  "Okta SSWS auth requires an API token. Set OKTA_CLIENT_TOKEN, configure token in .okta.yaml, or pass api_token explicitly.",
  "Okta PrivateKey auth requires client_id. Set OKTA_CLIENT_CLIENTID, configure clientId in .okta.yaml, or pass client_id explicitly.",
  "Okta PrivateKey auth requires private_key or client_assertion. Set OKTA_CLIENT_PRIVATEKEY, configure privateKey in .okta.yaml, or pass private_key explicitly.",
  "Okta PrivateKey auth requires client_id plus either private_key or client_assertion.",
  "Okta PrivateKey auth currently supports RSA private keys directly. For other key types, pass client_assertion explicitly.",
  "Bearer access tokens are only used for PrivateKey mode.",
  "the token listing returned zero tokens although the SSWS audit token itself should appear, so the inventory is incomplete",
  "Zero SSWS API tokens exist while auditing through an OAuth service app; an empty token inventory is compliant by intent because no long-lived static tokens remain.",
  "Rotate long-lived SSWS tokens and prefer OAuth service apps with scoped short-lived access tokens where possible.",
  "Auth mode: SSWS",
  "Auth mode: PrivateKey",
  "API token inventory: empty with no error",
  "Okta PrivateKey auth could not load the configured private key (ERR_OSSL_UNSUPPORTED). Provide an unencrypted RSA private key in PEM form.",
  "Okta PrivateKey auth could not load the configured private key (INVALID_PRIVATE_KEY). Provide an unencrypted RSA private key in PEM form.",
  "Okta API request failed for /api/v1/apps?limit=200 (502 Bad Gateway): non-JSON body (text/html, 5120 bytes)",
  "Okta API request failed for /api/v1/zones?limit=200 (500 Internal Server Error): JSON error body without errorSummary (37 bytes)",
  "Okta API request failed for /api/v1/idps?limit=200 (403 Forbidden): You do not have permission to perform the requested action",
  "Okta API request failed for /api/v1/logs?limit=1 (429 Too Many Requests)",
  "Okta API response from /api/v1/users?limit=200 (200) was unreadable: non-JSON body (text/html, 5120 bytes)",
  "Okta OAuth token request failed (401 Unauthorized): invalid_client",
  "Okta API request refused: the request URL is on origin https://collector.evil-example.net, not the configured org origin https://tenant.example.okta.com, so no request was sent.",
  "Okta API request refused: the request URL carries userinfo for origin https://tenant.example.okta.com (configured org origin https://tenant.example.okta.com), so no request was sent.",
  "Okta API request refused: the request URL is on origin javascript:, not the configured org origin https://tenant.example.okta.com, so no request was sent.",
  'GET /api/v1/apps?limit=200 stopped after 1 pages (1 items): the Link rel="next" URL is on origin data:, not the configured org origin https://tenant.example.okta.com and was not followed, total unknown.',
  'GET /api/v1/apps?limit=200 stopped after 1 pages (1 items): the Link rel="next" URL is on origin blob:, not the configured org origin https://tenant.example.okta.com and was not followed, total unknown.',
  'GET /api/v1/apps?limit=200 stopped after 1 pages (1 items): the Link rel="next" URL is a protocol-relative or relative reference rather than a root path on the configured org origin https://tenant.example.okta.com or an absolute URL on it and was not followed, total unknown.',
  'GET /api/v1/apps?limit=200 stopped after 1 pages (1 items): the Link rel="next" URL could not be parsed against the configured org origin https://tenant.example.okta.com and was not followed, total unknown.',
  "Not requested: no role lookups were requested because the parent list was not collected (Okta API request failed for /api/v1/iam/assignees/users?limit=200 (403 Forbidden)).",
  "every lookup of the role assignments failed (3 of 3): the endpoint returned 403 Forbidden (missing scope or admin role)",
  "User population listing is not available on this client.",
  "Per-user factor listing is not available on this client.",
  "Certificate-based authentication could not be evaluated because the endpoint returned 403 Forbidden (missing scope or admin role).",
  "Privileged role assignments could not be evaluated because the endpoint returned 401 Unauthorized (credential rejected).",
  "ThreatInsight could not be evaluated because the endpoint returned 404 Not Found (feature not enabled on this org edition).",
  "Log streaming could not be evaluated because the collector did not expose this endpoint.",
  "Event hooks could not be evaluated because the endpoint request failed.",
  "Group rules could not be evaluated because the inventory it depends on was not collected, so its request was never issued.",
  "Collect manually: export the identity providers list from Security > Identity Providers and the authenticators list from Security > Authenticators.",
  "Cause: the endpoint returned 403 Forbidden (missing scope or admin role).",
  "Error: Okta API request failed for /api/v1/idps?limit=200 (403 Forbidden): denied",
  "IdP data unavailable: Okta API request failed for /api/v1/idps?limit=200 (403 Forbidden)",
  "Org factors were unreadable (not consulted because authenticators were returned): Okta API request failed for /api/v1/org/factors?limit=200 (403 Forbidden)",
  "Network zones unreadable (custom zone count unknown): Okta API request failed for /api/v1/zones?limit=200 (403 Forbidden)",
  "sign-on and access policies were unreadable (the endpoint returned 403 Forbidden (missing scope or admin role))",
  "identity providers and authenticators were unreadable (the endpoint returned 403 Forbidden (missing scope or admin role))",
  "log streams and event hooks were unreadable (the endpoint returned 403 Forbidden (missing scope or admin role))",
  "A certificate IdP was found, but the authenticator list was unreadable, so the other half of the certificate inventory could not be verified.",
  "no ACTIVE certificate-oriented entry was found in the authenticator list while the identity provider list was unreadable (the endpoint returned 403 Forbidden (missing scope or admin role)), so this federal-domain tenant cannot be judged on half of the inventory",
  "Okta Support access is DISABLED, but the third-party admin setting could not be read because the endpoint returned 404 Not Found (feature not enabled on this org edition).",
  "Strong authenticators: unknown (authenticator list unreadable)",
  "Config precedence resolved from: home:.okta/okta.yaml -> project:.okta.yaml -> environment -> arguments",
  "Credential sources: environment, arguments.",
  "Unable to allocate output directory under /tmp/okta-export",
];

const OKTA_SOURCE_URL = new URL("../extensions/grc-tools/okta.ts", import.meta.url);

/**
 * The static segments of every `new Error(...)` template inside the named top-level functions of
 * the integration source, so a reworded or added resolver message fails the fixed-text test until a
 * fixed text or a live rendering covers it.
 */
function errorTemplateSegments(sourceUrl, functionNames) {
  const source = readFileSync(sourceUrl, "utf8");
  const segments = [];
  for (const name of functionNames) {
    const start = source.search(new RegExp(`^(?:export )?(?:async )?function ${name}\\(`, "m"));
    assert.notEqual(start, -1, `${name} is a top-level function of the integration source`);
    const body = source.slice(start, source.indexOf("\n}\n", start) + 2);
    for (const match of body.matchAll(/new Error\(/g)) {
      let depth = 1;
      let end = match.index + match[0].length;
      while (depth > 0 && end < body.length) {
        if (body[end] === "(") depth += 1;
        else if (body[end] === ")") depth -= 1;
        end += 1;
      }
      const argument = body.slice(match.index + match[0].length, end - 1);
      for (const literal of argument.matchAll(/"((?:[^"\\]|\\.)*)"/g)) segments.push(literal[1].replace(/\\"/g, '"'));
      for (const template of argument.matchAll(/`((?:[^`\\]|\\.)*)`/g)) segments.push(...template[1].split(/\$\{(?:[^{}]|\{[^{}]*\})*\}/));
    }
  }
  return [...new Set(segments.map((segment) => segment.trim()).filter((segment) => segment.length >= 8))];
}

/**
 * The resolver messages rendered live for the no credentials, partial credentials, bad auth mode,
 * and config file failure cases, each against a real temp path; the malformed file carries a config
 * canary so the message proves it holds the path, position, and code only.
 */
async function liveOktaResolverMessages() {
  const base = createTempBase("grclanker-okta-live-resolver-");
  const cwd = join(base, "cwd");
  const homeDir = join(base, "home");
  mkdirSync(cwd);
  mkdirSync(homeDir);
  const directoryConfig = join(base, "directory.yaml");
  mkdirSync(directoryConfig);
  const malformedConfig = join(base, "malformed.yaml");
  writeFileSync(malformedConfig, `okta:\n  client:\n    orgUrl: https://tenant.example.okta.com\n    token: "${CONFIG_CANARIES.unterminated}\n`);
  const orgUrl = { OKTA_CLIENT_ORGURL: "https://tenant.example.okta.com" };
  const privateKeyMode = { ...orgUrl, OKTA_CLIENT_AUTHORIZATIONMODE: "PrivateKey" };
  const resolve = async (args, env) => (await rejectionOf(resolveOktaConfiguration(args, env, cwd, homeDir))).message;
  return {
    paths: { directoryConfig, malformedConfig },
    messages: {
      "no credentials": await resolve({}, {}),
      "partial credentials: org URL without a token": await resolve({}, orgUrl),
      "bad auth mode: PrivateKey without client_id": await resolve({}, privateKeyMode),
      "bad auth mode: PrivateKey without a private key or client assertion": await resolve({}, { ...privateKeyMode, OKTA_CLIENT_CLIENTID: "0oa1clientid" }),
      "config file failure: directory at the path": await resolve({ config_file: directoryConfig }, {}),
      "config file failure: malformed YAML": await resolve({ config_file: malformedConfig }, {}),
    },
  };
}

test("rule 9: every fixed text the Okta integration emits, including the live resolver messages, passes its scrubber unchanged", async () => {
  const live = await liveOktaResolverMessages();
  const expected = {
    "no credentials": "Okta org URL is required. Set OKTA_CLIENT_ORGURL, configure .okta.yaml, or pass org_url explicitly.",
    "partial credentials: org URL without a token": "Okta SSWS auth requires an API token. Set OKTA_CLIENT_TOKEN, configure token in .okta.yaml, or pass api_token explicitly.",
    "bad auth mode: PrivateKey without client_id": "Okta PrivateKey auth requires client_id. Set OKTA_CLIENT_CLIENTID, configure clientId in .okta.yaml, or pass client_id explicitly.",
    "bad auth mode: PrivateKey without a private key or client assertion": "Okta PrivateKey auth requires private_key or client_assertion. Set OKTA_CLIENT_PRIVATEKEY, configure privateKey in .okta.yaml, or pass private_key explicitly.",
    "config file failure: directory at the path": `Unable to read Okta config file ${live.paths.directoryConfig} (EISDIR)`,
    "config file failure: malformed YAML": new RegExp(`^Unable to parse Okta config file: invalid YAML in ${live.paths.malformedConfig.replace(/[.*+?^$()|[\]\\]/g, "\\$&")} at line \\d+(?:, column \\d+)? \\([A-Z_]+\\)$`),
  };
  assert.deepEqual(Object.keys(live.messages), Object.keys(expected));
  const configuredSecret = "00QbNhmq3FzXaXEDy3zZU5fS2EepAmFzLGFkGmhBeB";
  for (const [label, message] of Object.entries(live.messages)) {
    if (expected[label] instanceof RegExp) assert.match(message, expected[label], label);
    else assert.equal(message, expected[label], label);
    for (const canary of Object.values(CONFIG_CANARIES)) assertNoWindowOf(message, canary, `live resolver message (${label})`);
    for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!message.includes(wording), `${label} repeats library wording "${wording}": ${message}`);
    assert.equal(scrubErrorText(message), message, `live resolver message survives the scrubber (${label})`);
    assert.equal(scrubErrorText(message, [configuredSecret]), message, `live resolver message survives with a configured secret registered (${label})`);
  }

  // Every message template the resolver and its loaders can throw is pinned by a fixed text or a live rendering, so a reworded message fails here until the set is updated.
  const corpus = [...OKTA_FIXED_TEXTS, ...Object.values(live.messages)];
  const segments = errorTemplateSegments(OKTA_SOURCE_URL, ["resolveOktaConfiguration", "readConfigFileText", "configFileParseError"]);
  assert.ok(segments.length >= 6, `the template scan found the four resolver messages and the two loader messages (${segments.length})`);
  for (const segment of segments) assert.ok(corpus.some((text) => text.includes(segment)), `resolver template segment is pinned by a fixed text or a live rendering: ${segment}`);

  for (const text of OKTA_FIXED_TEXTS) assert.equal(scrubErrorText(text), text, text);
  for (const text of OKTA_FIXED_TEXTS) assert.equal(scrubErrorText(text, [configuredSecret]), text, `${text} (with a configured secret registered)`);
});

test("resolveOktaConfiguration keeps environment credentials when an unrelated argument is passed (GWS note 2)", async () => {
  const dir = createTempBase("grclanker-okta-env-args-");
  const homeDir = createTempBase("grclanker-okta-env-args-home-");
  const env = { OKTA_CLIENT_ORGURL: "https://tenant.okta.gov", OKTA_CLIENT_TOKEN: "00QbNhmq3FzXaXEDy3zZU5fS2EepAmFzLGFkGmhBeB" };

  const ssws = await resolveOktaConfiguration({ scopes: ["okta.users.read"] }, env, dir, homeDir);
  assert.equal(ssws.token, env.OKTA_CLIENT_TOKEN, "the environment token survives an argument overlay that names no credential");
  assert.equal(ssws.orgUrl, "https://tenant.okta.gov");
  assert.deepEqual(ssws.sourceChain, ["environment", "arguments"]);

  const privateKeyEnv = {
    OKTA_CLIENT_ORGURL: "https://tenant.okta.gov",
    OKTA_CLIENT_AUTHORIZATIONMODE: "PrivateKey",
    OKTA_CLIENT_CLIENTID: "0oa1abcd2EFGH3ijk4x5",
    OKTA_CLIENT_PRIVATEKEY: "-----BEGIN PRIVATE KEY-----\nQbNhmq3FzXaXEDy3zZU5fS2EepAmFzLGFkGmhBeB\n-----END PRIVATE KEY-----",
  };
  const privateKey = await resolveOktaConfiguration({ org_url: "https://tenant.okta.gov" }, privateKeyEnv, dir, homeDir);
  assert.equal(privateKey.privateKey, privateKeyEnv.OKTA_CLIENT_PRIVATEKEY, "the environment private key survives an unrelated org_url argument");
  assert.equal(privateKey.clientId, "0oa1abcd2EFGH3ijk4x5");
  assert.equal(privateKey.authMode, "PrivateKey");
  assert.deepEqual(privateKey.sourceChain, ["environment", "arguments"]);
});

/** A 32-character random run: any 6 to 24 character window of it in an output is a leak. */
const PLANTED_TOKEN = "Xq7Vw2Lm9Tp4Rb8Kd3Fh6Jn1Zs5Yc0Ag";
/** A Stripe-shaped live key: the vendor prefix makes it an unambiguous credential shape on both sides. */
const PLANTED_STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
/** The distinctive segments of the planted JWT; the header is the common RS256 prefix and is not a canary. */
const PLANTED_JWT_PAYLOAD = "Zm9vYmFyLXByb2JlLXBheWxvYWQtOTgxMjM0NTY3ODkw";
const PLANTED_JWT_SIGNATURE = "c2lnbmF0dXJlLXBhcnQtb2YtdGhlLWpvdC1nb2VzLWhlcmU";
const PLANTED_JWT = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.${PLANTED_JWT_PAYLOAD}.${PLANTED_JWT_SIGNATURE}`;
const PLANTED_PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----";
const PLANTED_CANARIES = [PLANTED_TOKEN, PLANTED_STRIPE_KEY, PLANTED_JWT_PAYLOAD, PLANTED_JWT_SIGNATURE];
const BEARER_ID_UUID = "6f1c2b3a-4d5e-4f60-8a9b-0c1d2e3f4a5b";
/** The free-text note planted in the export probe: two unambiguous shapes, a header carrier, and an identifier that must survive. */
const PLANTED_NOTE = `Runbook: key ${PLANTED_STRIPE_KEY} end; bearer ${PLANTED_JWT}; Authorization: Bearer ${PLANTED_TOKEN}; cluster prod-us-east-2026-cluster was read`;
const REDACTED_NOTE = "Runbook: key [REDACTED] end; bearer [REDACTED]; Authorization: Bearer [REDACTED]; cluster prod-us-east-2026-cluster was read";

/**
 * Scheme-word order (CodeRabbit r4078025849): a credential-named key loses its value before any
 * scheme word is read, so "OKTA_CLIENT_SECRET=SSWS rejected" is a secret whose value starts with a
 * scheme name, not an Okta header. Scheme words act under Authorization-style keys and bare in
 * prose; auth-params and prose mentions of a scheme stay.
 */
const SCHEME_ORDER_ROWS = [
  ["sslPassword=splunk rejected", "sslPassword=[REDACTED] rejected"],
  ["db_password: token", "db_password: [REDACTED]"],
  ['sslPassword="splunk rejected"', 'sslPassword="[REDACTED]"'],
  ['"db_password": "token"', '"db_password": "[REDACTED]"'],
  ["SPLUNK_PASSWORD=bearer expired", "SPLUNK_PASSWORD=[REDACTED] expired"],
  ["OKTA_CLIENT_SECRET=SSWS rejected", "OKTA_CLIENT_SECRET=[REDACTED] rejected"],
  ["OKTA_CLIENT_SECRET: SSWS rejected", "OKTA_CLIENT_SECRET: [REDACTED] rejected"],
  ['OKTA_CLIENT_SECRET="SSWS rejected"', 'OKTA_CLIENT_SECRET="[REDACTED]"'],
  ['"OKTA_CLIENT_SECRET": "SSWS"', '"OKTA_CLIENT_SECRET": "[REDACTED]"'],
  [`Authorization: SSWS ${PLANTED_TOKEN}`, "Authorization: SSWS [REDACTED]"],
  ["Authorization: Splunk 4eC39HqLyjWDarjtT1zdp7dc", "Authorization: Splunk [REDACTED]"],
  [`Proxy-Authorization: Basic ${PLANTED_TOKEN}==`, "Proxy-Authorization: Basic [REDACTED]"],
  [`Authorization: bearer ${PLANTED_TOKEN}`, "Authorization: bearer [REDACTED]"],
  [`Authorization: sNoWfLaKe ${PLANTED_TOKEN}`, "Authorization: sNoWfLaKe [REDACTED]"],
  ["Authorization: SSWS prod-us-east-2026", "Authorization: SSWS [REDACTED]"],
  [`replayed BASIC ${PLANTED_TOKEN} upstream`, "replayed BASIC [REDACTED] upstream"],
  [`replayed splunk ${PLANTED_TOKEN} upstream`, "replayed splunk [REDACTED] upstream"],
  ["Bearer abcdefghijkl rejected", "Bearer [REDACTED] rejected"],
  ['WWW-Authenticate: Bearer realm="api"', 'WWW-Authenticate: Bearer realm="api"'],
  ['Bearer realm="api", error="invalid_token"', 'Bearer realm="api", error="invalid_token"'],
  ["Snowflake statement failed", "Snowflake statement failed"],
  ["Splunk Enterprise rejected the request", "Splunk Enterprise rejected the request"],
  ["the bearer presented an expired token", "the bearer presented an expired token"],
  ["Basic authentication failed", "Basic authentication failed"],
  ["OAuth 2.0 introspection", "OAuth 2.0 introspection"],
  ["token_type=Bearer", "token_type=Bearer"],
];

/** The key audit: bearer ids go whatever their shape, setting suffixes and URL-valued webhook keys keep their values, identifiers are judged by shape. */
const KEY_AUDIT_ROWS = [
  [`token_id=${BEARER_ID_UUID}`, "token_id=[REDACTED]"],
  [`tokenId: ${BEARER_ID_UUID}`, "tokenId: [REDACTED]"],
  [`role_secret_id=${BEARER_ID_UUID}`, "role_secret_id=[REDACTED]"],
  ["secret_id_ttl=3600 secret_id_num_uses=5 token_max_ttl=7200 token_bound_cidrs=10.0.0.0/8", "secret_id_ttl=3600 secret_id_num_uses=5 token_max_ttl=7200 token_bound_cidrs=10.0.0.0/8"],
  [`secret_id_accessor=${BEARER_ID_UUID}`, `secret_id_accessor=${BEARER_ID_UUID}`],
  ["webhook_count=3", "webhook_count=3"],
  [`webhook_url=https://hooks.example.com/services/T/B/${PLANTED_TOKEN}?ts=1`, "webhook_url=https://hooks.example.com/[REDACTED]"],
  [`client_id=svc-audit-2026 tenant_id=${BEARER_ID_UUID}`, `client_id=svc-audit-2026 tenant_id=${BEARER_ID_UUID}`],
  ["access_key_id=svc-audit-2026 key_id=kid-primary private_key_id=kid-primary secret_name=db-credentials-prod", "access_key_id=svc-audit-2026 key_id=kid-primary private_key_id=kid-primary secret_name=db-credentials-prod"],
  [`token_type=${PLANTED_TOKEN}`, "token_type=[REDACTED]"],
  ["client_id=0oa1audit key_id=key-2024-01 api_key_id=a1b2c3d4 private_key_id=kid-2026-01", "client_id=0oa1audit key_id=key-2024-01 api_key_id=a1b2c3d4 private_key_id=kid-2026-01"],
  [`api_key_id=${PLANTED_TOKEN}`, "api_key_id=[REDACTED]"],
  ["OKTA_CLIENT_AUTHORIZATIONMODE=ccg", "OKTA_CLIENT_AUTHORIZATIONMODE=ccg"],
  ["OKTA_CLIENT_AUTHORIZATIONMODE: RS256", "OKTA_CLIENT_AUTHORIZATIONMODE: RS256"],
  ['{"OKTA_CLIENT_AUTHORIZATIONMODE":"https://api.example.com/oauth2/token"}', '{"OKTA_CLIENT_AUTHORIZATIONMODE":"https://api.example.com/oauth2/token"}'],
  ["export OKTA_CLIENT_AUTHORIZATIONMODE=privatekey", "export OKTA_CLIENT_AUTHORIZATIONMODE=privatekey"],
  [`OKTA_CLIENT_AUTHORIZATIONMODE=${PLANTED_TOKEN}`, "OKTA_CLIENT_AUTHORIZATIONMODE=[REDACTED]"],
  ["private_key_file=/x/y.pem credentials_file=/x/c.json --private-key-file=/x", "private_key_file=/x/y.pem credentials_file=/x/c.json --private-key-file=/x"],
  ["OKTA_CLIENT_ORGURL= https://tenant.okta.gov", "OKTA_CLIENT_ORGURL= https://tenant.okta.gov"],
  ["SPLUNK_BASE_URL_OVERRIDE=/opt/splunk", "SPLUNK_BASE_URL_OVERRIDE=/opt/splunk"],
  ["export_output_dir=./export snowflake_account_name=", "export_output_dir=./export snowflake_account_name="],
  ["QmFzZTY0K1N5bWJvbHM= stays a token", "[REDACTED] stays a token"],
];

/** Flag, path-label, slash-escaped URL, and cookie carriers: the value goes and the prose around it stays. */
const CARRIER_ROWS = [
  [`psql --password ${PLANTED_TOKEN} -h db`, "psql --password [REDACTED] -h db"],
  [`mysql --password=${PLANTED_TOKEN} -h db`, "mysql --password=[REDACTED] -h db"],
  [`java -Dspring.datasource.password=${PLANTED_TOKEN} -jar app.jar`, "java -Dspring.datasource.password=[REDACTED] -jar app.jar"],
  [`helm --set db.password=${PLANTED_TOKEN} upgrade`, "helm --set db.password=[REDACTED] upgrade"],
  [`kv/password: ${PLANTED_TOKEN}`, "kv/password: [REDACTED]"],
  ["/oauth/token-request: invalid_client", "/oauth/token-request: invalid_client"],
  ["/api/v1/api-tokens: request failed with 403", "/api/v1/api-tokens: request failed with 403"],
  [`kv/password: ${PLANTED_TOKEN} [code 003001, sqlState 42501]`, "kv/password: [REDACTED] [code 003001, sqlState 42501]"],
  [`kv/password: ${PLANTED_TOKEN} (requestId abc-123)`, "kv/password: [REDACTED] (requestId abc-123)"],
  ["config/prod/password: hunter2 was echoed by the proxy", "config/prod/password: [REDACTED] was echoed by the proxy"],
  [`secrets/data/api_key: ${PLANTED_TOKEN}, then retried`, "secrets/data/api_key: [REDACTED], then retried"],
  ["/api/v1/secrets: request failed with 403", "/api/v1/secrets: request failed with 403"],
  ["/v1/auth/approle/passwords: listing denied", "/v1/auth/approle/passwords: listing denied"],
  [`kv/client_assertion: ${PLANTED_TOKEN}`, "kv/client_assertion: [REDACTED]"],
  ["kv/client_assertion: svc-reporting-2026 rejected", "kv/client_assertion: [REDACTED] rejected"],
  [`kv/OKTA_CLIENT_CLIENTASSERTION: ${PLANTED_TOKEN}`, "kv/OKTA_CLIENT_CLIENTASSERTION: [REDACTED]"],
  ["kv/OKTA_CLIENT_CLIENTASSERTION: svc-reporting-2026", "kv/OKTA_CLIENT_CLIENTASSERTION: [REDACTED]"],
  [`client_assertion=${PLANTED_JWT}`, "client_assertion=[REDACTED]"],
  ["OKTA_CLIENT_CLIENTASSERTION: svc-reporting-2026", "OKTA_CLIENT_CLIENTASSERTION: [REDACTED]"],
  ['{"client_assertion":"svc-reporting-2026"}', '{"client_assertion":"[REDACTED]"}'],
  ["client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
  [`/api_key=${PLANTED_TOKEN}`, "/api_key=[REDACTED]"],
  [`SPLUNK_ACS_TOKEN='${PLANTED_TOKEN}'`, "SPLUNK_ACS_TOKEN='[REDACTED]'"],
  [`httpEventCollectorToken="${PLANTED_TOKEN}"`, 'httpEventCollectorToken="[REDACTED]"'],
  [`X-Api-Key: "${PLANTED_TOKEN}"`, 'X-Api-Key: "[REDACTED]"'],
  [`note https:\\/\\/hooks.example.com\\/a?token=${PLANTED_TOKEN} next`, "note https:\\/\\/hooks.example.com\\/a?[REDACTED] next"],
  [`Cookie: theme=dark; my'pref=${PLANTED_TOKEN}`, "Cookie: [REDACTED]"],
  [`Cookie: sid=O'${PLANTED_TOKEN}; X-Api-Key: ${PLANTED_TOKEN}`, "Cookie: [REDACTED]; X-Api-Key: [REDACTED]"],
  [`Cookie: my&sid=${PLANTED_TOKEN}; Content-Type: application/json`, "Cookie: [REDACTED]; Content-Type: application/json"],
];

/** The data side: unambiguous shapes and carriers go, identifiers and bare runs survive (the generic long-run rule is off there). */
const DATA_SIDE_ROWS = [
  [`key ${PLANTED_STRIPE_KEY} end`, "key [REDACTED] end"],
  [`note ${PLANTED_JWT} end`, "note [REDACTED] end"],
  [`Authorization: Bearer ${PLANTED_TOKEN}`, "Authorization: Bearer [REDACTED]"],
  [`pem ${PLANTED_PEM} end`, "pem [REDACTED] end"],
  ["xoxb-1234567890-abcdefghijklmnop", "[REDACTED]"],
  ["AKIAIOSFODNN7EXAMPLE", "[REDACTED]"],
  ["ghp_16C7e42F292c6912E7710c838347Ae178B4a", "[REDACTED]"],
  ["cluster prod-us-east-2026-cluster was read", "cluster prod-us-east-2026-cluster was read"],
  [`run ${PLANTED_TOKEN} end`, `run ${PLANTED_TOKEN} end`],
];

function assertRows(scrub, rows, label) {
  for (const [input, expected] of rows) {
    const scrubbed = scrub(input);
    assert.equal(scrubbed, expected, `${label}: ${input}`);
    assert.equal(scrub(scrubbed), scrubbed, `${label}, second pass: ${input}`);
    for (const canary of PLANTED_CANARIES) {
      if (input.includes(canary) && !expected.includes(canary)) assertNoWindowOf(scrubbed, canary, `${label}: ${input}`);
    }
  }
}

test("reviewer C final verdict, scheme-word order (r4078025849) and the key audit: a credential-named key loses its value before any scheme word is read in both spellings, scheme words act only under Authorization-style keys and bare in prose, bearer ids go, setting suffixes and URL-valued webhook keys keep their values, and the flag, path, escaped-URL, and cookie carriers are read", () => {
  assertRows(scrubErrorText, SCHEME_ORDER_ROWS, "scheme-word order");
  assertRows(scrubErrorText, KEY_AUDIT_ROWS, "key audit");
  assertRows(scrubErrorText, CARRIER_ROWS, "carrier");
  assert.equal(scrubErrorText(`run ${PLANTED_TOKEN} end`), "run [REDACTED] end", "the error side keeps the generic long-run rule");
});

test("data-side ruling: vendor-prefixed tokens, JWTs, PEM blocks, and credential carriers are removed on the data side while identifiers and bare runs survive, in scrubDataText, in redactSnapshot, and in the exported Okta bundle", async () => {
  assertRows(scrubDataText, DATA_SIDE_ROWS, "data side");

  const record = {
    id: "rec-1",
    description: `note: key ${PLANTED_STRIPE_KEY} end`,
    tags: [{ notes: [`also ${PLANTED_JWT}`] }],
    webhook_url: `https://hooks.example.com/services/T/B/${PLANTED_TOKEN}?ts=1`,
    password: PLANTED_TOKEN,
    name: "benign",
    count: 3,
    enabled: true,
    empty: null,
  };
  const walked = redactSnapshot(record);
  assert.deepEqual(walked, {
    id: "rec-1",
    description: "note: key [REDACTED] end",
    tags: [{ notes: ["also [REDACTED]"] }],
    webhook_url: "https://hooks.example.com/[REDACTED]",
    password: "[REDACTED]",
    name: "benign",
    count: 3,
    enabled: true,
    empty: null,
  }, "the walker reaches every string leaf and keeps the origin of a webhook URL");
  assert.deepEqual(redactSnapshot(walked), walked, "second pass over the walked record");

  const sample = createSampleClient();
  const client = {
    ...sample,
    async listApps() {
      const [first, ...rest] = await sample.listApps();
      return [{ ...first, description: PLANTED_NOTE, settings: { ...first.settings, notes: { enduser: PLANTED_NOTE } } }, ...rest];
    },
  };
  const config = createSampleConfig();
  assertFixtureFreeOfCanaryWindows(JSON.stringify({ apps: await client.listApps(), config }), PLANTED_CANARIES, "data-side probe fixture");
  const secrets = leakWindows(PLANTED_CANARIES);
  const outputRoot = createTempBase("grclanker-okta-data-side-");
  const result = await exportOktaAuditBundle(client, config, outputRoot);
  const files = readBundleFiles(result.outputDir);
  assertSecretsAbsent(assert, files, secrets, "bundle directory");
  assertSecretsAbsent(assert, readZipEntries(result.zipPath), secrets, "zip archive");
  assertSecretsAbsent(assert, new Map([["assess results", JSON.stringify(await runAllAssessments(client, config))]]), secrets, "tool payloads");
  const [app] = JSON.parse(files.get("core_data/apps.json"));
  assert.equal(app.description, REDACTED_NOTE, "the app description keeps its prose and the cluster name around the removed shapes");
  assert.equal(app.settings.notes.enduser, REDACTED_NOTE, "the end-user note is walked the same way");
});

const REGISTERED_SECRET = "registry-passphrase-2026-echo";
const MINTED_ACCESS_TOKEN = "Mk2Pq8Rt4Vw6Xy1Zb3Cd5Fg7Hj9Ln0Ns";

test("item 7: once a client is constructed its configured credential is removed by redactSnapshot on a string leaf and by scrubDataText and scrubErrorText called without it, in every encoded form, and the access token the client mints joins it", async () => {
  const leaf = `the value ${REGISTERED_SECRET} was echoed by the proxy`;
  assert.equal(redactSnapshot(leaf), leaf, "before any client carries the value, the data side keeps a word-shaped run");
  assert.equal(scrubErrorText(`auth_method=${REGISTERED_SECRET}`), `auth_method=${REGISTERED_SECRET}`, "before any client carries the value, a setting keeps a word-shaped run");

  new OktaAuditorClient({ orgUrl: "https://registry.example.okta.com", authMode: "SSWS", token: REGISTERED_SECRET, scopes: [], sourceChain: ["tests"] });
  assert.equal(redactSnapshot(leaf), "the value [REDACTED] was echoed by the proxy");
  assert.equal(scrubDataText(`{"detail":"${REGISTERED_SECRET}"}`), '{"detail":"[REDACTED]"}');
  assert.equal(scrubErrorText(`auth_method=${REGISTERED_SECRET}`), "auth_method=[REDACTED]");
  assert.deepEqual(
    redactSnapshot({ note: leaf, nested: [{ text: `b64 ${Buffer.from(REGISTERED_SECRET).toString("base64")} end` }], count: 2 }),
    { note: "the value [REDACTED] was echoed by the proxy", nested: [{ text: "b64 [REDACTED] end" }], count: 2 },
  );

  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    if (url.pathname === "/oauth2/v1/token") return new Response(JSON.stringify({ access_token: MINTED_ACCESS_TOKEN, expires_in: 3600 }), { status: 200, headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify([]), { status: 200, headers: { "content-type": "application/json" } });
  };
  const client = new OktaAuditorClient(
    { orgUrl: "https://registry.example.okta.com", authMode: "PrivateKey", clientId: "registry-client", clientAssertion: "registry-assertion-jwt", scopes: ["okta.users.read"], sourceChain: ["tests"] },
    { fetchImpl },
  );
  assert.equal(redactSnapshot(`minted ${MINTED_ACCESS_TOKEN} echoed`), `minted ${MINTED_ACCESS_TOKEN} echoed`, "the data side keeps a bare run it has not been told about");
  await client.getJson("/api/v1/users");
  assert.equal(redactSnapshot(`minted ${MINTED_ACCESS_TOKEN} echoed`), "minted [REDACTED] echoed", "the minted access token is registered when it is obtained");
});

const FOREIGN_BODY_CANARY = "yln2bVNl4tE9Cyp1B18V2mX7";
const FOREIGN_BEARER_CANARY = "Qw8Zr2Lm5Pk1Vt7Xy3Nb6Hd9";
const FOREIGN_JSON_BODY = { foo: FOREIGN_BODY_CANARY, items: [{ password: FOREIGN_BODY_CANARY, description: `Authorization: Bearer ${FOREIGN_BEARER_CANARY}` }] };
/** The single-object endpoints whose 200 body is recorded whole; each has a documented member the verdicts read. */
const FOREIGN_OBJECT_TARGETS = {
  "core_data/okta_support_access.json": "/api/v1/org/privacy/oktaSupport",
  "core_data/third_party_admin_setting.json": "/api/v1/org/orgSettings/thirdPartyAdminSetting",
  "core_data/default_authorization_server.json": "/api/v1/authorizationServers/default",
  "core_data/threat_insight.json": "/api/v1/threats/configuration",
};
const FOREIGN_CONTACT_TARGET = "/api/v1/org/contacts/TECHNICAL";

/** Serves the foreign JSON document at the given paths with a 200 and the fixtures everywhere else. */
function foreignJsonOktaFetch(paths) {
  const recorder = recordingOktaFetch();
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input.toString());
    if (!paths.includes(url.pathname)) return recorder.fetchImpl(input, init);
    recorder.requests.push({ method: init.method ?? "GET", path: url.pathname, status: 200 });
    return new Response(JSON.stringify(FOREIGN_JSON_BODY), { status: 200, statusText: "OK", headers: { "content-type": "application/json" } });
  };
  return { fetchImpl, requests: recorder.requests };
}

test("class 10: a 200 body that is not the expected object is a not-collected marker, its findings demote, and no part of the body reaches the bundle, the zip, the assess payloads, or the access check", async () => {
  const { fetchImpl, requests } = foreignJsonOktaFetch([...Object.values(FOREIGN_OBJECT_TARGETS), FOREIGN_CONTACT_TARGET]);
  const client = new OktaAuditorClient(RECORDING_CONFIG, { fetchImpl });
  const access = await runOktaAccessCheck(client, RECORDING_CONFIG);
  const results = await runAllAssessments(client, RECORDING_CONFIG);
  const exported = await exportOktaAuditBundle(client, RECORDING_CONFIG, createTempBase("grclanker-okta-foreign-"));
  const files = readBundleFiles(exported.outputDir);
  const collectionStatus = JSON.parse(files.get("core_data/collection_status.json"));
  const outputs = oktaOutputs(access, results, exported);
  for (const [name, text] of readZipEntries(exported.zipPath)) outputs.set(`zip ${name}`, text);

  const shapeError = /^GET \/api\/v1\/[A-Za-z/]+ returned a 200 body that is not the expected object \(none of [A-Za-z, ]+ present\), so the response was not recorded$/;
  for (const [file, target] of Object.entries(FOREIGN_OBJECT_TARGETS)) {
    assertOktaNotCollectedMarker(JSON.parse(files.get(file)), file, { status: 200, endpoint: new RegExp(`^${target.replace(/[/.]/g, "\\$&")}$`), error: shapeError });
    assert.ok(collectionStatus.not_collected.includes(file), `${file} is listed as not collected`);
    const entry = collectionStatus.datasets.find((row) => row.file === file);
    assert.equal(entry.collected, false, file);
    assert.equal(entry.status, 200, `${file}: the marker keeps the observed status`);
    assert.equal(entry.endpoint, target, file);
  }

  const support = findingById(results.admin, "OKTA-ADMIN-006");
  assert.equal(support.status, "Manual", "the Okta Support verdict is manual, never pass or fail, over a body that is not the setting");
  assert.match(support.summary, /the endpoint returned a 200 body that is not the expected object \(unexpected response shape\) for Okta Support access/);
  assert.match(support.summary, /unexpected response shape\) for the third-party admin setting/);
  assert.equal(results.admin.snapshotSummary.okta_support_access, "not collected", "the support state label reads not collected, never unknown or a state");
  const threatInsight = findingById(results.monitoring, "OKTA-MON-003");
  assert.equal(threatInsight.status, "Manual");
  assert.match(threatInsight.summary, /unexpected response shape/);
  assert.equal(results.monitoring.snapshotSummary.threat_insight_mode, "not collected");
  const contact = findingById(results.monitoring, "OKTA-MON-008");
  assert.equal(contact.status, "Partial", "a contact assignment body without userId is a failed lookup, not an unassigned contact");
  assert.match(contact.summary, /technical contact lookup failed/);
  assert.doesNotMatch(contact.summary, /No technical contact user is assigned/);
  assert.ok(contact.evidence.some((line) => /TECHNICAL: GET \/api\/v1\/org\/contacts\/TECHNICAL returned a 200 body that is not the expected object/.test(line)));
  assert.equal(results.admin.snapshotSummary.datasets_not_collected, 2);
  assert.equal(results.authentication.snapshotSummary.datasets_not_collected, 1);
  assert.equal(results.monitoring.snapshotSummary.datasets_not_collected, 1);

  for (const [name, text] of outputs) {
    assert.ok(!text.includes(FOREIGN_BODY_CANARY), `${name}: the foreign body's member value never reaches an output`);
    assert.ok(!text.includes(FOREIGN_BEARER_CANARY), `${name}: the foreign body's bearer token never reaches an output`);
    assert.ok(!/TypeError|ReferenceError|Cannot read properties|is not a function/.test(text), `${name}: a foreign body never surfaces as a runtime error`);
  }
  assertOktaOutputsNameOnlyObservedRequests(outputs, requests, "foreign JSON");
  assert.ok(requests.some((request) => request.path === FOREIGN_CONTACT_TARGET && request.status === 200), "the fixture served the foreign contact body");
});

test("class 10: a single object carrying a documented member is kept whatever else it carries, and a 404 stays null", async () => {
  const supportOnly = { ...createSampleClient(), async getOktaSupportSettings() { return { support: "DISABLED", expiration: null, foo: FOREIGN_BODY_CANARY }; } };
  const kept = await collectOktaAdminAccessData(supportOnly);
  assert.equal(kept.oktaSupportAccess.notCollected, undefined, "a body with the documented member is the resource");
  assert.equal(kept.oktaSupportAccess.data.support, "DISABLED");
  assert.equal(statusOf(assessOktaAdminAccess(kept, createSampleConfig()), "OKTA-ADMIN-006"), "Pass");

  const foreign = { ...createSampleClient(), async getThreatInsight() { return FOREIGN_JSON_BODY; } };
  const monitoring = await collectOktaMonitoringData(foreign);
  assert.equal(monitoring.threatInsight.data, null, "the fallback stays in memory, never the body");
  assert.equal(monitoring.threatInsight.notCollected.status, 200);
  assert.equal(monitoring.threatInsight.notCollected.endpoint, "/api/v1/threats/configuration");
  assert.match(monitoring.threatInsight.error, /none of action, mode, settings, excludeZones present/);
  assert.ok(!JSON.stringify(monitoring).includes(FOREIGN_BODY_CANARY));

  const absent = await collectOktaMonitoringData({ ...createSampleClient(), async getThreatInsight() { return null; } });
  assert.equal(absent.threatInsight.data, null);
  assert.equal(absent.threatInsight.notCollected, undefined, "a 404 (null) is an absent feature, not a shape failure");
});
