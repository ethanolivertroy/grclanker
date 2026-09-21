import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
  resolveOktaConfiguration,
  resolveSecureOutputPath,
  runOktaAccessCheck,
} from "../dist/extensions/grc-tools/okta.js";

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
  assert.equal(policies.length, 2);
  assert.equal(state.tokenRequests, 2);
  clearOktaTokenCacheForTests();
});

test("Okta assessments generate mapped findings across authentication, admin, integration, and monitoring", async () => {
  const config = createSampleConfig();

  const access = await runOktaAccessCheck(
    {
      async getJson(pathname) {
        if (pathname.includes("api-tokens")) {
          throw new Error("Okta API request failed for /api/v1/api-tokens?limit=1 (403 Forbidden)");
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
  const oscalFindings = oscal["assessment-results"].results[0].findings;
  assert.ok(oscalFindings.some((finding) => finding.target["target-id"] === "ia-2.11_obj"));
  assert.ok(oscalFindings.every((finding) => ["satisfied", "not-satisfied"].includes(finding.target.status.state)));

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
