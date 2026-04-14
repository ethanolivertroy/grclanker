import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  OktaAuditorClient,
  assessOktaAdminAccess,
  assessOktaAuthentication,
  assessOktaIntegrations,
  assessOktaMonitoring,
  clearOktaTokenCacheForTests,
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

function createSampleConfig() {
  return {
    orgUrl: "https://tenant.okta.gov",
    authMode: "SSWS",
    token: "okta-token",
    scopes: [],
    sourceChain: ["tests"],
  };
}

function createSampleAuthenticationData() {
  return {
    signOnPolicies: dataset([
      { id: "signon-1", name: "Admin Console Policy" },
    ]),
    signOnPolicyRules: dataset({
      "signon-1": [
        {
          id: "signon-rule-1",
          name: "Admin console sign-on",
          actions: {
            signon: {
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
    mfaPolicies: dataset([{ id: "mfa-1", name: "MFA Enrollment" }]),
    accessPolicies: dataset([{ id: "access-1", name: "Workforce Access Policy" }]),
    accessPolicyRules: dataset({
      "access-1": [
        {
          id: "access-rule-1",
          name: "High risk step-up",
          conditions: {
            risk: { level: "HIGH" },
          },
        },
      ],
    }),
    authenticators: dataset([
      { id: "auth-1", key: "webauthn", status: "ACTIVE" },
      { id: "auth-2", key: "smart_card", status: "ACTIVE" },
    ]),
    idps: dataset([{ id: "idp-1", name: "PIV Smart Card", type: "SAML2" }]),
    authorizationServers: dataset([]),
    defaultAuthorizationServer: dataset(null),
    orgFactors: dataset([]),
  };
}

function createSampleAdminData() {
  return {
    usersWithRoleAssignments: dataset([
      {
        id: "user-1",
        status: "ACTIVE",
        lastLogin: new Date().toISOString(),
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
  };
}

function createSampleIntegrationData() {
  return {
    apps: dataset([
      {
        id: "app-1",
        label: "Core OIDC",
        status: "ACTIVE",
        settings: {
          oauthClient: {
            grant_types: ["authorization_code"],
          },
        },
      },
    ]),
    trustedOrigins: dataset([{ id: "origin-1", origin: "https://portal.example.gov" }]),
    networkZones: dataset([{ id: "zone-1", name: "Corporate HQ", system: false }]),
    accessPolicies: dataset([{ id: "access-1", name: "Workforce Access Policy" }]),
    accessPolicyRules: dataset({
      "access-1": [
        {
          id: "access-rule-1",
          name: "High risk step-up",
          conditions: {
            risk: { level: "HIGH" },
          },
        },
      ],
    }),
    signOnPolicies: dataset([{ id: "signon-1", name: "Admin Console Policy" }]),
    signOnPolicyRules: dataset({
      "signon-1": [
        {
          id: "signon-rule-1",
          name: "Admin console sign-on",
          conditions: {
            network: { connection: "ANYWHERE" },
          },
        },
      ],
    }),
    idps: dataset([]),
    authorizationServers: dataset([]),
  };
}

function createSampleMonitoringData() {
  return {
    eventHooks: dataset([{ id: "hook-1", name: "SIEM Forwarder", status: "ACTIVE" }]),
    logStreams: dataset([{ id: "stream-1", name: "Splunk HEC", status: "ACTIVE" }]),
    systemLogs: dataset([
      { published: new Date().toISOString(), eventType: "user.session.start" },
    ]),
    behaviors: dataset([{ id: "behavior-1", name: "New Device" }]),
    threatInsight: dataset({ action: "block" }),
    apiTokens: dataset([{ id: "token-1", name: "CI token", lastUpdated: new Date().toISOString() }]),
    deviceAssurance: dataset([{ id: "device-1", displayName: "Managed macOS" }]),
  };
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

  assert.equal(authentication.findings.find((finding) => finding.id === "OKTA-AUTH-001")?.status, "Pass");
  assert.ok(authentication.findings.find((finding) => finding.id === "OKTA-AUTH-001")?.frameworks.fedramp.length > 0);
  assert.equal(admin.findings.find((finding) => finding.id === "OKTA-ADMIN-001")?.status, "Pass");
  assert.equal(integrations.findings.find((finding) => finding.id === "OKTA-INTEG-003")?.status, "Pass");
  assert.equal(monitoring.findings.find((finding) => finding.id === "OKTA-MON-003")?.status, "Pass");
  assert.equal(monitoring.summary.Fail, 0);
});

test("exportOktaAuditBundle writes the expected package and secure paths stay rooted", async () => {
  const outputRoot = createTempBase("grclanker-okta-export-");
  const config = createSampleConfig();
  const authentication = createSampleAuthenticationData();
  const admin = createSampleAdminData();
  const integrations = createSampleIntegrationData();
  const monitoring = createSampleMonitoringData();

  const client = {
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
    async listApps() {
      return integrations.apps.data;
    },
    async listTrustedOrigins() {
      return integrations.trustedOrigins.data;
    },
    async listNetworkZones() {
      return integrations.networkZones.data;
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
  };

  const result = await exportOktaAuditBundle(client, config, outputRoot);
  assert.equal(result.errorCount, 0);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
  assert.ok(existsSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md")));
  assert.ok(existsSync(join(result.outputDir, "QUICK_REFERENCE.md")));

  const executiveSummary = readFileSync(
    join(result.outputDir, "compliance", "executive_summary.md"),
    "utf8",
  );
  assert.match(executiveSummary, /tenant\.okta\.gov/);
  assert.throws(
    () => resolveSecureOutputPath(outputRoot, "../escape"),
    /Refusing to write outside/,
  );
});
