import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  GWS_CHECK_IDS,
  GoogleWorkspaceAuditorClient,
  GwsApiError,
  assessGwsAdminAccess,
  assessGwsIdentity,
  assessGwsIntegrations,
  assessGwsMonitoring,
  buildTwoStepPolicyFilter,
  clearGwsTokenCacheForTests,
  collectGwsAuditData,
  exportGwsAuditBundle,
  normalizeFrameworkSelection,
  redactSecrets,
  resolveGwsConfiguration,
  resolveSecureOutputPath,
  runGwsAccessCheck,
} from "../dist/extensions/grc-tools/gws.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const RECENT_LOGIN = new Date(Date.now() - 2 * DAY_MS).toISOString();
const OLD_LOGIN = new Date(Date.now() - 400 * DAY_MS).toISOString();
const ENFORCED_FROM = new Date(Date.now() - 30 * DAY_MS).toISOString();

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function dataset(data, error) {
  return error ? { data, error } : { data };
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function createSampleConfig(overrides = {}) {
  return {
    authMode: "access_token",
    accessToken: "ya29.test",
    adminEmail: "admin@example.com",
    domain: "example.com",
    customerId: "my_customer",
    lookbackDays: 30,
    tokenUri: "https://oauth2.googleapis.com/token",
    sourceChain: ["tests"],
    ...overrides,
  };
}

function createUsers() {
  return [
    {
      id: "u-super",
      primaryEmail: "super@example.com",
      isAdmin: true,
      isDelegatedAdmin: false,
      suspended: false,
      archived: false,
      isEnforcedIn2Sv: true,
      isEnrolledIn2Sv: true,
      lastLoginTime: RECENT_LOGIN,
    },
    {
      id: "u-delegated",
      primaryEmail: "delegated@example.com",
      isAdmin: false,
      isDelegatedAdmin: true,
      suspended: false,
      archived: false,
      isEnforcedIn2Sv: false,
      isEnrolledIn2Sv: true,
      lastLoginTime: RECENT_LOGIN,
    },
    {
      id: "u-user",
      primaryEmail: "user@example.com",
      isAdmin: false,
      isDelegatedAdmin: false,
      suspended: false,
      archived: false,
      isEnforcedIn2Sv: true,
      isEnrolledIn2Sv: true,
      lastLoginTime: RECENT_LOGIN,
    },
    {
      id: "u-dormant",
      primaryEmail: "dormant@example.com",
      isAdmin: false,
      isDelegatedAdmin: false,
      suspended: false,
      archived: false,
      isEnforcedIn2Sv: false,
      isEnrolledIn2Sv: false,
      lastLoginTime: OLD_LOGIN,
    },
  ];
}

function createRoles() {
  return [
    {
      roleId: "1",
      roleName: "_SEED_ADMIN_ROLE",
      isSystemRole: true,
      isSuperAdminRole: true,
      rolePrivileges: [{ privilegeName: "SUPER_ADMIN", serviceId: "00haapch16h1ysv" }],
    },
    {
      roleId: "2",
      roleName: "_GROUPS_ADMIN_ROLE",
      isSystemRole: true,
      rolePrivileges: [{ privilegeName: "GROUPS_ALL", serviceId: "00haapch16h1ysv" }],
    },
  ];
}

function createRoleAssignments() {
  return [
    {
      roleAssignmentId: "ra-1",
      roleId: "2",
      assignedTo: "u-delegated",
      assigneeType: "USER",
      scopeType: "CUSTOMER",
    },
    {
      roleAssignmentId: "ra-2",
      roleId: "2",
      assignedTo: "group-1",
      assigneeType: "GROUP",
      scopeType: "CUSTOMER",
    },
  ];
}

function activity(applicationName, actorEmail, eventNames) {
  return {
    kind: "admin#reports#activity",
    id: {
      time: RECENT_LOGIN,
      uniqueQualifier: "1",
      applicationName,
      customerId: "C0123abcd",
    },
    actor: { email: actorEmail, profileId: "100", callerType: "USER" },
    events: eventNames.map((name) => ({ type: "login", name })),
  };
}

function createLoginActivities() {
  return [
    activity("login", "super@example.com", ["login_success", "suspicious_login"]),
    activity("login", "user@example.com", ["gov_attack_warning"]),
  ];
}

function createAdminActivities() {
  return [activity("admin", "super@example.com", ["CHANGE_APPLICATION_SETTING"])];
}

function createTokenActivities() {
  return [
    {
      ...activity("token", "delegated@example.com", ["authorize"]),
      actor: {
        email: "delegated@example.com",
        applicationInfo: { applicationName: "Example App", oAuthClientId: "client-1" },
      },
    },
  ];
}

/** Alert status lives in metadata.status (NOT_STARTED, IN_PROGRESS, CLOSED). */
function createAlerts() {
  return [
    {
      alertId: "a-1",
      customerId: "C0123abcd",
      createTime: RECENT_LOGIN,
      source: "Google Operations",
      type: "User reported phishing",
      metadata: { alertId: "a-1", status: "NOT_STARTED", severity: "HIGH" },
    },
    {
      alertId: "a-2",
      customerId: "C0123abcd",
      createTime: RECENT_LOGIN,
      source: "Google Operations",
      type: "Suspicious login",
      metadata: { alertId: "a-2", status: "CLOSED", severity: "MEDIUM" },
    },
  ];
}

function createTokens() {
  return {
    "delegated@example.com": [
      {
        kind: "admin#directory#token",
        clientId: "client-1",
        displayText: "Drive Syncer",
        anonymous: false,
        nativeApp: false,
        userKey: "u-delegated",
        scopes: [
          "https://www.googleapis.com/auth/drive",
          "https://www.googleapis.com/auth/admin.directory.user.readonly",
        ],
      },
    ],
    "user@example.com": [
      {
        kind: "admin#directory#token",
        clientId: "client-2",
        displayText: "Calendar Helper",
        anonymous: false,
        nativeApp: false,
        userKey: "u-user",
        scopes: ["https://www.googleapis.com/auth/calendar"],
      },
    ],
  };
}

function createTokenInventory() {
  const tokens = createTokens();
  return [
    { userId: "u-delegated", primaryEmail: "delegated@example.com", token: tokens["delegated@example.com"][0] },
    { userId: "u-user", primaryEmail: "user@example.com", token: tokens["user@example.com"][0] },
  ];
}

function inventoryDataset(records, overrides = {}) {
  return { data: records, seen: 4, total: 4, failed: 0, truncated: false, ...overrides };
}

/** Policy resource shape from the Cloud Identity policies reference and the settings catalog. */
function policy(settingType, value, query = { orgUnit: "orgUnits/03ph8a2z1root", sortOrder: 1 }) {
  return {
    name: `policies/${settingType.replace(/[^a-z_]/g, "")}`,
    customer: "customers/C0123abcd",
    type: "ADMIN",
    policyQuery: query,
    setting: { type: settingType, value },
  };
}

function createTwoStepPolicies() {
  return [
    policy("settings/security.two_step_verification_enforcement", { enforcedFrom: ENFORCED_FROM }),
    policy("settings/security.two_step_verification_enrollment", { allowEnrollment: true }),
    policy("settings/security.two_step_verification_enforcement_factor", { allowedSignInFactorSet: "NO_TELEPHONY" }),
  ];
}

function collection(items, overrides = {}) {
  return { items, truncated: false, pages: 1, ...overrides };
}

function createFakeCollector(overrides = {}) {
  const tokens = createTokens();
  return {
    collectUsers: async () => collection(createUsers()),
    collectRoles: async () => collection(createRoles()),
    collectRoleAssignments: async () => collection(createRoleAssignments()),
    collectActivities: async (applicationName) => {
      if (applicationName === "login") return collection(createLoginActivities());
      if (applicationName === "admin") return collection(createAdminActivities());
      return collection(createTokenActivities());
    },
    collectAlerts: async () => collection(createAlerts()),
    collectTwoStepPolicies: async () => collection(createTwoStepPolicies()),
    listUserTokens: async (userKey) => tokens[userKey] ?? [],
    ...overrides,
  };
}

function findingById(assessment, id) {
  const finding = assessment.findings.find((entry) => entry.id === id);
  assert.ok(finding, `missing finding ${id}`);
  return finding;
}

function assessAll(data, config) {
  return [
    assessGwsIdentity(data.identity, config),
    assessGwsAdminAccess(data.adminAccess, config),
    assessGwsIntegrations(data.integrations, config),
    assessGwsMonitoring(data.monitoring, config),
  ];
}

function statusMap(assessments) {
  return Object.fromEntries(assessments.flatMap((assessment) => assessment.findings.map((finding) => [finding.id, finding.status])));
}

test("resolveGwsConfiguration prefers explicit args over environment values and loads service account JSON", async () => {
  const base = createTempBase("grclanker-gws-config-");
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const credentialsPath = join(base, "sa.json");
  writeFileSync(
    credentialsPath,
    JSON.stringify({
      client_email: "svc@example-project.iam.gserviceaccount.com",
      private_key: privateKeyPem,
      token_uri: "https://oauth2.googleapis.com/token",
    }),
  );

  const resolved = await resolveGwsConfiguration(
    {
      auth_mode: "service_account",
      credentials_file: credentialsPath,
      admin_email: "admin@example.com",
      domain: "arg.example.com",
      lookback_days: 45,
    },
    {
      GWS_AUTH_MODE: "access_token",
      GWS_ACCESS_TOKEN: "env-token",
      GWS_ADMIN_EMAIL: "env-admin@example.com",
      GWS_DOMAIN: "env.example.com",
      GWS_LOOKBACK_DAYS: "7",
    },
  );

  assert.equal(resolved.authMode, "service_account");
  assert.equal(resolved.adminEmail, "admin@example.com");
  assert.equal(resolved.domain, "arg.example.com");
  assert.equal(resolved.lookbackDays, 45);
  assert.equal(resolved.serviceAccountEmail, "svc@example-project.iam.gserviceaccount.com");
  assert.match(resolved.serviceAccountPrivateKey, /BEGIN PRIVATE KEY/);
  assert.deepEqual(resolved.sourceChain, ["environment", "arguments"]);
});

test("GoogleWorkspaceAuditorClient refreshes service-account tokens and handles pagination", async () => {
  clearGwsTokenCacheForTests();
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const state = {
    tokenRequests: 0,
    firstUsers401: true,
  };

  const config = createSampleConfig({
    authMode: "service_account",
    accessToken: undefined,
    adminEmail: "admin@example.com",
    serviceAccountEmail: "svc@example-project.iam.gserviceaccount.com",
    serviceAccountPrivateKey: privateKeyPem,
  });

  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());

    if (url.origin === "https://oauth2.googleapis.com" && url.pathname === "/token") {
      state.tokenRequests += 1;
      return jsonResponse({
        access_token: `ya29.token.${state.tokenRequests}`,
        expires_in: 3600,
        token_type: "Bearer",
      });
    }

    if (url.pathname === "/admin/directory/v1/users") {
      if (state.firstUsers401) {
        state.firstUsers401 = false;
        return jsonResponse({ error: { message: "expired token" } }, 401);
      }
      const pageToken = url.searchParams.get("pageToken");
      return jsonResponse(
        pageToken
          ? { users: [{ id: "u-2", primaryEmail: "user2@example.com" }] }
          : { users: [{ id: "u-1", primaryEmail: "user1@example.com" }], nextPageToken: "page-2" },
      );
    }

    if (url.pathname === "/admin/directory/v1/customer/my_customer/roles") {
      return jsonResponse({ items: [{ roleId: "1", roleName: "_SEED_ADMIN_ROLE", isSuperAdminRole: true }] });
    }

    if (url.pathname === "/admin/directory/v1/customer/my_customer/roleassignments") {
      return jsonResponse({ items: [{ roleId: "1", assignedTo: "u-1", assigneeType: "USER" }] });
    }

    if (url.pathname === "/admin/reports/v1/activity/users/all/applications/login") {
      return jsonResponse({ items: [{ events: [{ name: "login_success" }] }] });
    }

    if (url.pathname === "/v1beta1/alerts") {
      return jsonResponse({ alerts: [{ alertId: "a-1", metadata: { status: "CLOSED" } }] });
    }

    if (url.origin === "https://cloudidentity.googleapis.com" && url.pathname === "/v1/policies") {
      return jsonResponse({ error: { message: "policy scope not delegated" } }, 403);
    }

    return jsonResponse({ error: { message: `unexpected URL ${url}` } }, 404);
  };

  const client = new GoogleWorkspaceAuditorClient(config, fetchImpl);
  const users = await client.collectUsers();
  assert.equal(users.items.length, 2);
  assert.equal(users.pages, 2);
  assert.equal(users.truncated, false);
  assert.equal(state.tokenRequests, 2);

  const access = await runGwsAccessCheck(client, config);
  assert.equal(access.status, "healthy");
  assert.equal(access.probes.find((probe) => probe.key === "policies").status, "forbidden");
  assert.ok(access.notes.some((note) => /GWS-ID-005 will render Manual/.test(note)));
});

test("Directory, Reports, and Policy requests encode the documented query parameters exactly", async () => {
  const config = createSampleConfig({ lookbackDays: 7 });
  const seen = [];
  const before = Date.now();
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push(url);
    if (url.pathname === "/admin/directory/v1/users") return jsonResponse({ users: [] });
    if (url.pathname.endsWith("/roles")) return jsonResponse({ items: [] });
    if (url.pathname.endsWith("/roleassignments")) return jsonResponse({ items: [] });
    if (url.pathname.startsWith("/admin/reports/v1/activity/")) return jsonResponse({ items: [] });
    if (url.pathname === "/v1beta1/alerts") return jsonResponse({ alerts: [] });
    if (url.pathname === "/v1/policies") return jsonResponse({ policies: [] });
    if (url.pathname.endsWith("/tokens")) return jsonResponse({ items: [] });
    return jsonResponse({ error: { message: `unexpected URL ${url}` } }, 404);
  };
  const client = new GoogleWorkspaceAuditorClient(config, fetchImpl);

  await client.collectUsers();
  const users = seen.pop();
  assert.equal(users.origin, "https://admin.googleapis.com");
  assert.equal(users.searchParams.get("customer"), "my_customer");
  assert.equal(users.searchParams.get("maxResults"), "500");
  assert.equal(users.searchParams.get("orderBy"), "email");
  assert.equal(users.searchParams.get("sortOrder"), "ASCENDING");
  assert.equal(users.searchParams.get("projection"), "basic");
  assert.equal(users.searchParams.get("showDeleted"), "false");
  assert.equal(
    users.searchParams.get("fields"),
    "users(id,primaryEmail,isAdmin,isDelegatedAdmin,suspended,archived,lastLoginTime,isEnrolledIn2Sv,isEnforcedIn2Sv,orgUnitPath),nextPageToken",
  );
  assert.equal(users.searchParams.has("pageToken"), false);

  await client.collectRoles();
  const roles = seen.pop();
  assert.equal(roles.pathname, "/admin/directory/v1/customer/my_customer/roles");
  assert.equal(roles.searchParams.get("maxResults"), "100");

  await client.collectRoleAssignments();
  const assignments = seen.pop();
  assert.equal(assignments.pathname, "/admin/directory/v1/customer/my_customer/roleassignments");
  assert.equal(assignments.searchParams.get("maxResults"), "200");

  await client.collectActivities("login");
  const login = seen.pop();
  assert.equal(login.pathname, "/admin/reports/v1/activity/users/all/applications/login");
  assert.equal(login.searchParams.get("maxResults"), "1000");
  const startTime = Date.parse(login.searchParams.get("startTime"));
  assert.match(login.searchParams.get("startTime"), /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  assert.ok(Math.abs(before - 7 * DAY_MS - startTime) < 5000);

  await client.collectAlerts();
  const alerts = seen.pop();
  assert.equal(alerts.origin, "https://alertcenter.googleapis.com");
  assert.equal(alerts.pathname, "/v1beta1/alerts");
  assert.equal(alerts.searchParams.get("pageSize"), "100");

  await client.collectTwoStepPolicies();
  const policies = seen.pop();
  assert.equal(policies.origin, "https://cloudidentity.googleapis.com");
  assert.equal(policies.pathname, "/v1/policies");
  assert.equal(policies.searchParams.get("pageSize"), "100");
  assert.equal(
    policies.searchParams.get("filter"),
    "customer == \"customers/my_customer\" && setting.type.matches('^settings/security\\\\.two_step_verification.*$')",
  );
  assert.equal(buildTwoStepPolicyFilter("C0123abcd"), "customer == \"customers/C0123abcd\" && setting.type.matches('^settings/security\\\\.two_step_verification.*$')");
  assert.ok(policies.search.includes("filter=customer+%3D%3D+%22customers%2Fmy_customer%22+%26%26+setting.type.matches"));

  await client.listUserTokens("user@example.com");
  const tokens = seen.pop();
  assert.equal(tokens.pathname, "/admin/directory/v1/users/user%40example.com/tokens");
});

test("verdict rule 7: pagination follows nextPageToken to the end and records truncation at the collection cap", async () => {
  const config = createSampleConfig();
  let activityPages = 0;
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname.startsWith("/admin/reports/v1/activity/")) {
      activityPages += 1;
      const count = Number(url.searchParams.get("maxResults"));
      return jsonResponse({
        items: Array.from({ length: count }, (_, index) => ({ id: { uniqueQualifier: `${activityPages}-${index}` }, events: [] })),
        nextPageToken: `page-${activityPages + 1}`,
      });
    }
    if (url.pathname === "/v1beta1/alerts") {
      const token = url.searchParams.get("pageToken");
      return jsonResponse(token === "second" ? { alerts: [{ alertId: "a-2" }] } : { alerts: [{ alertId: "a-1" }], nextPageToken: "second" });
    }
    return jsonResponse({ error: { message: "unexpected" } }, 404);
  };
  const client = new GoogleWorkspaceAuditorClient(config, fetchImpl);

  const activities = await client.collectActivities("admin");
  assert.equal(activities.items.length, 5000);
  assert.equal(activities.pages, 5);
  assert.equal(activities.truncated, true);

  const alerts = await client.collectAlerts();
  assert.equal(alerts.items.length, 2);
  assert.equal(alerts.pages, 2);
  assert.equal(alerts.truncated, false);
});

test("GWS assessments produce stable findings across identity, admin, integrations, and monitoring", () => {
  const config = createSampleConfig();
  const identity = assessGwsIdentity({
    users: dataset(createUsers()),
    roles: dataset(createRoles()),
    roleAssignments: dataset(createRoleAssignments()),
    loginActivities: dataset(createLoginActivities()),
    twoStepPolicies: dataset(createTwoStepPolicies()),
  }, config);
  const admin = assessGwsAdminAccess({
    users: dataset(createUsers()),
    roles: dataset(createRoles()),
    roleAssignments: dataset(createRoleAssignments()),
    adminActivities: dataset(createAdminActivities()),
  }, config);
  const integrations = assessGwsIntegrations({
    users: dataset(createUsers()),
    roles: dataset(createRoles()),
    roleAssignments: dataset(createRoleAssignments()),
    tokenInventory: inventoryDataset(createTokenInventory()),
    tokenActivities: dataset(createTokenActivities()),
  }, config);
  const monitoring = assessGwsMonitoring({
    loginActivities: dataset(createLoginActivities()),
    adminActivities: dataset(createAdminActivities()),
    tokenActivities: dataset(createTokenActivities()),
    alerts: dataset(createAlerts()),
  }, config);

  assert.equal(identity.findings.length, 5);
  assert.equal(admin.findings.length, 5);
  assert.equal(integrations.findings.length, 4);
  assert.equal(monitoring.findings.length, 5);
  assert.equal(GWS_CHECK_IDS.length, 19);
  assert.equal(findingById(identity, "GWS-ID-001").status, "Fail");
  assert.equal(findingById(identity, "GWS-ID-005").status, "Pass");
  assert.equal(findingById(admin, "GWS-ADMIN-005").status, "Manual");
  assert.equal(findingById(integrations, "GWS-INTEG-002").status, "Partial");
  assert.equal(findingById(monitoring, "GWS-MON-002").status, "Partial");
  assert.equal(findingById(monitoring, "GWS-MON-005").status, "Pass");
});

test("verdict rule 1: forbidden endpoints render Manual and name the endpoint, scope, and manual evidence", () => {
  const config = createSampleConfig();
  const forbidden = (endpoint) => ({ data: [], error: `403 Forbidden: ${endpoint}`, errorKind: "forbidden", seen: 0 });
  const identity = assessGwsIdentity({
    users: forbidden("users"),
    roles: dataset(createRoles()),
    roleAssignments: dataset(createRoleAssignments()),
    loginActivities: dataset(createLoginActivities()),
    twoStepPolicies: forbidden("policies"),
  }, config);
  for (const finding of identity.findings) {
    assert.equal(finding.status, "Manual", finding.id);
    assert.match(finding.summary, /HTTP 403/);
    assert.match(finding.summary, /missing scope/);
    assert.match(finding.manualNote, /^Collect manually:/);
  }
  assert.match(findingById(identity, "GWS-ID-001").summary, /Directory users\.list/);
  assert.match(findingById(identity, "GWS-ID-005").summary, /Cloud Identity policies\.list/);
  assert.match(findingById(identity, "GWS-ID-005").summary, /cloud-identity\.policies\.readonly/);

  const unauthorized = { data: [], error: "401 Unauthorized", errorKind: "unauthorized", seen: 0 };
  const monitoring = assessGwsMonitoring({
    loginActivities: unauthorized,
    adminActivities: dataset(createAdminActivities()),
    tokenActivities: dataset(createTokenActivities()),
    alerts: dataset(createAlerts()),
  }, config);
  assert.equal(findingById(monitoring, "GWS-MON-002").status, "Manual");
  assert.match(findingById(monitoring, "GWS-MON-002").summary, /HTTP 401/);
});

test("verdict rule 2: empty inventories never pass and each summary states how emptiness is treated", () => {
  const config = createSampleConfig();
  const empty = () => ({ data: [], seen: 0, truncated: false, pages: 1 });
  const identity = assessGwsIdentity({
    users: empty(),
    roles: empty(),
    roleAssignments: empty(),
    loginActivities: empty(),
    twoStepPolicies: empty(),
  }, config);
  const admin = assessGwsAdminAccess({ users: empty(), roles: empty(), roleAssignments: empty(), adminActivities: empty() }, config);
  const integrations = assessGwsIntegrations({
    users: empty(),
    roles: empty(),
    roleAssignments: empty(),
    tokenInventory: { data: [], seen: 0, total: 0, failed: 0, truncated: false },
    tokenActivities: empty(),
  }, config);
  const monitoring = assessGwsMonitoring({ loginActivities: empty(), adminActivities: empty(), tokenActivities: empty(), alerts: empty() }, config);

  for (const finding of [...identity.findings, ...admin.findings, ...integrations.findings, ...monitoring.findings]) {
    assert.equal(finding.status, "Manual", `${finding.id} must not pass on an empty inventory`);
    assert.match(finding.summary, /empt|zero|No |not collected|none of type/i, finding.id);
  }
  assert.match(findingById(identity, "GWS-ID-002").summary, /cannot be compliant/);
  assert.match(findingById(admin, "GWS-ADMIN-005").summary, /incomplete read/);
  assert.match(findingById(integrations, "GWS-INTEG-001").summary, /could not be demonstrated/);
});

test("verdict rule 2 (by intent): an empty sub-population inside a non-empty inventory may pass and says so", () => {
  const config = createSampleConfig();
  const admin = assessGwsAdminAccess({
    users: dataset(createUsers()),
    roles: dataset(createRoles()),
    roleAssignments: dataset([createRoleAssignments()[0]]),
    adminActivities: dataset(createAdminActivities()),
  }, config);
  const groupFinding = findingById(admin, "GWS-ADMIN-005");
  assert.equal(groupFinding.status, "Pass");
  assert.match(groupFinding.summary, /compliant by intent/);
  assert.match(groupFinding.summary, /non-empty assignment inventory/);
});

test("verdict rule 3: surfaces not collected in this run render Manual instead of passing", () => {
  const config = createSampleConfig();
  const identity = assessGwsIdentity({
    users: dataset(createUsers()),
    roles: dataset(createRoles()),
    roleAssignments: dataset(createRoleAssignments()),
    loginActivities: dataset(createLoginActivities()),
  }, config);
  const finding = findingById(identity, "GWS-ID-005");
  assert.equal(finding.status, "Manual");
  assert.match(finding.summary, /not collected in this run/);
  assert.equal(identity.snapshotSummary.two_step_policies, "not collected");

  const noEnforcement = assessGwsIdentity({
    users: dataset(createUsers()),
    roles: dataset(createRoles()),
    roleAssignments: dataset(createRoleAssignments()),
    loginActivities: dataset(createLoginActivities()),
    twoStepPolicies: dataset([policy("settings/security.two_step_verification_enrollment", { allowEnrollment: true })]),
  }, config);
  assert.equal(findingById(noEnforcement, "GWS-ID-005").status, "Manual");
  assert.match(findingById(noEnforcement, "GWS-ID-005").summary, /none of type settings\/security\.two_step_verification_enforcement/);
});

test("verdict rule 4: items without dates are bucketed separately and cap the verdict at Partial", () => {
  const config = createSampleConfig();
  const users = createUsers().filter((user) => user.id !== "u-dormant").map((user) => ({ ...user, isEnforcedIn2Sv: true }));
  const undated = { ...users[2], id: "u-undated", primaryEmail: "undated@example.com" };
  delete undated.lastLoginTime;
  const identity = assessGwsIdentity({
    users: dataset([...users, undated]),
    roles: dataset(createRoles()),
    roleAssignments: dataset([createRoleAssignments()[0]]),
    loginActivities: dataset(createLoginActivities()),
    twoStepPolicies: dataset(createTwoStepPolicies()),
  }, config);
  const dormancy = findingById(identity, "GWS-ID-003");
  assert.equal(dormancy.status, "Partial");
  assert.ok(dormancy.evidence.some((line) => /no parseable lastLoginTime \(reported separately, never counted as fresh\): 1/.test(line)));
  assert.equal(identity.snapshotSummary.users_without_last_login, 1);

  const monitoring = assessGwsMonitoring({
    loginActivities: dataset(createLoginActivities()),
    adminActivities: dataset(createAdminActivities()),
    tokenActivities: dataset(createTokenActivities()),
    alerts: dataset([{ alertId: "a-3", source: "Google Operations", type: "Suspicious login" }]),
  }, config);
  const backlog = findingById(monitoring, "GWS-MON-005");
  assert.equal(backlog.status, "Partial");
  assert.ok(backlog.evidence.some((line) => /without metadata\.status \(reported separately, never counted as closed\): 1/.test(line)));
});

test("verdict rule 5: a truncated or capped inventory flags seen counts and never passes", () => {
  const config = createSampleConfig();
  const compliantUsers = createUsers().filter((user) => user.id !== "u-dormant").map((user) => ({ ...user, isEnforcedIn2Sv: true }));
  const truncatedUsers = { data: compliantUsers, truncated: true, pages: 10, seen: compliantUsers.length };
  const identity = assessGwsIdentity({
    users: truncatedUsers,
    roles: dataset(createRoles()),
    roleAssignments: dataset([createRoleAssignments()[0]]),
    loginActivities: dataset(createLoginActivities()),
    twoStepPolicies: { data: createTwoStepPolicies(), truncated: true, pages: 10, seen: 3 },
  }, config);
  for (const finding of identity.findings) {
    assert.equal(finding.status, "Partial", finding.id);
    assert.match(finding.summary, /partial inventory/, finding.id);
    assert.ok(finding.evidence.some((line) => /partial view, seen \d+ across 10 page\(s\)/.test(line)), finding.id);
  }
  assert.equal(identity.snapshotSummary.users_seen_partial_view, "yes");

  const integrations = assessGwsIntegrations({
    users: dataset(compliantUsers),
    roles: dataset(createRoles()),
    roleAssignments: dataset([createRoleAssignments()[0]]),
    tokenInventory: inventoryDataset([createTokenInventory()[1]], { seen: 3, total: 120, truncated: true }),
    tokenActivities: dataset(createTokenActivities()),
  }, config);
  const inventory = findingById(integrations, "GWS-INTEG-001");
  assert.equal(inventory.status, "Partial");
  assert.ok(inventory.evidence.some((line) => /seen 3 of 120 active users/.test(line)));
});

test("verdict rule 6: absent or false enabling flags never count toward a pass", () => {
  const config = createSampleConfig();
  const enrolledOnly = createUsers().filter((user) => user.id !== "u-dormant").map((user) => {
    const copy = { ...user, isEnrolledIn2Sv: true };
    delete copy.isEnforcedIn2Sv;
    return copy;
  });
  const identity = assessGwsIdentity({
    users: dataset(enrolledOnly),
    roles: dataset(createRoles()),
    roleAssignments: dataset([createRoleAssignments()[0]]),
    loginActivities: dataset(createLoginActivities()),
    twoStepPolicies: dataset([
      policy("settings/security.two_step_verification_enforcement", {}),
      policy("settings/security.two_step_verification_enforcement", { enforcedFrom: new Date(Date.now() + 30 * DAY_MS).toISOString() }, { group: "groups/abc" }),
    ]),
  }, config);
  assert.equal(findingById(identity, "GWS-ID-001").status, "Fail");
  assert.equal(findingById(identity, "GWS-ID-002").status, "Fail");
  assert.equal(findingById(identity, "GWS-ID-004").status, "Fail");
  const policyFinding = findingById(identity, "GWS-ID-005");
  assert.equal(policyFinding.status, "Fail");
  assert.ok(policyFinding.evidence.some((line) => /enforcedFrom at or before now: 0/.test(line)));

  const blockedEnrollment = assessGwsIdentity({
    users: dataset(enrolledOnly),
    roles: dataset(createRoles()),
    roleAssignments: dataset([createRoleAssignments()[0]]),
    loginActivities: dataset(createLoginActivities()),
    twoStepPolicies: dataset([
      policy("settings/security.two_step_verification_enforcement", { enforcedFrom: ENFORCED_FROM }),
      policy("settings/security.two_step_verification_enrollment", { allowEnrollment: false }, { group: "groups/contractors" }),
    ]),
  }, config);
  assert.equal(findingById(blockedEnrollment, "GWS-ID-005").status, "Partial");
});

test("collectGwsAuditData records per-user token failures and privileged-first sampling", async () => {
  const collector = createFakeCollector({
    listUserTokens: async (userKey) => {
      if (userKey === "super@example.com") throw new GwsApiError(403, "403 Forbidden: insufficient scope", "https://admin.googleapis.com/x");
      return createTokens()[userKey] ?? [];
    },
  });
  const data = await collectGwsAuditData(collector);
  assert.equal(data.integrations.tokenInventory.failed, 1);
  assert.equal(data.integrations.tokenInventory.errorKind, "forbidden");
  assert.equal(data.integrations.tokenInventory.seen, 4);
  assert.equal(data.integrations.tokenInventory.total, 4);
  assert.equal(data.integrations.tokenInventory.data.length, 2);
  assert.equal(data.identity.twoStepPolicies.data.length, 3);
});

test("false-pass self-check (a): every endpoint returns 403 and no finding passes", async () => {
  const config = createSampleConfig();
  const deny = async () => {
    throw new GwsApiError(403, "403 Forbidden: Request had insufficient authentication scopes.", "https://admin.googleapis.com/denied");
  };
  const collector = createFakeCollector({
    collectUsers: deny,
    collectRoles: deny,
    collectRoleAssignments: deny,
    collectActivities: deny,
    collectAlerts: deny,
    collectTwoStepPolicies: deny,
    listUserTokens: deny,
  });
  const statuses = statusMap(assessAll(await collectGwsAuditData(collector), config));
  assert.equal(Object.keys(statuses).length, 19);
  for (const [id, status] of Object.entries(statuses)) {
    assert.equal(status, "Manual", `${id} must be Manual when every endpoint is forbidden`);
  }
});

test("false-pass self-check (b): every list is empty and nothing passes; emptiness is compliant only inside a non-empty parent inventory", async () => {
  const config = createSampleConfig();
  const empty = async () => collection([]);
  const collector = createFakeCollector({
    collectUsers: empty,
    collectRoles: empty,
    collectRoleAssignments: empty,
    collectActivities: empty,
    collectAlerts: empty,
    collectTwoStepPolicies: empty,
    listUserTokens: async () => [],
  });
  const statuses = statusMap(assessAll(await collectGwsAuditData(collector), config));
  assert.equal(Object.keys(statuses).length, 19);
  for (const [id, status] of Object.entries(statuses)) {
    assert.equal(status, "Manual", `${id} must be Manual when every list is empty`);
  }
});

test("false-pass self-check (c): a partial inventory never passes and flags the partial view", async () => {
  const config = createSampleConfig();
  const compliantUsers = createUsers().filter((user) => user.id !== "u-dormant").map((user) => ({ ...user, isEnforcedIn2Sv: true }));
  const truncated = (items) => collection(items, { truncated: true, pages: 3 });
  const collector = createFakeCollector({
    collectUsers: async () => truncated(compliantUsers),
    collectRoleAssignments: async () => truncated([createRoleAssignments()[0]]),
    collectActivities: async (applicationName) => {
      if (applicationName === "login") return truncated([activity("login", "user@example.com", ["login_success"])]);
      if (applicationName === "admin") return truncated(createAdminActivities());
      return truncated(createTokenActivities());
    },
    collectAlerts: async () => {
      throw new GwsApiError(403, "403 Forbidden: apps.alerts scope missing", "https://alertcenter.googleapis.com/v1beta1/alerts");
    },
    collectTwoStepPolicies: async () => truncated(createTwoStepPolicies()),
    listUserTokens: async (userKey) => {
      if (userKey === "super@example.com") throw new GwsApiError(403, "403 Forbidden: user.security scope missing", "https://admin.googleapis.com/tokens");
      return userKey === "user@example.com" ? createTokens()[userKey] : [];
    },
  });
  const assessments = assessAll(await collectGwsAuditData(collector), config);
  const statuses = statusMap(assessments);
  assert.equal(Object.keys(statuses).length, 19);
  for (const [id, status] of Object.entries(statuses)) {
    assert.notEqual(status, "Pass", `${id} must not pass on a partial inventory`);
  }
  const findings = assessments.flatMap((assessment) => assessment.findings);
  for (const id of ["GWS-ID-001", "GWS-ID-002", "GWS-ID-004", "GWS-ID-005", "GWS-ADMIN-001", "GWS-ADMIN-005", "GWS-MON-002"]) {
    const finding = findings.find((entry) => entry.id === id);
    assert.equal(finding.status, "Partial", id);
    assert.ok(finding.evidence.some((line) => /partial view, seen \d+ across 3 page\(s\)/.test(line)), id);
  }
  assert.equal(statuses["GWS-MON-001"], "Manual");
  assert.equal(statuses["GWS-MON-005"], "Manual");
  assert.equal(statuses["GWS-INTEG-001"], "Partial");
});

test("false-pass self-check (d): a fully compliant tenant built from documented shapes passes every automatable control", async () => {
  const config = createSampleConfig();
  const users = [
    { ...createUsers()[0] },
    { ...createUsers()[1], isEnforcedIn2Sv: true },
    { ...createUsers()[2] },
    { ...createUsers()[3], isEnforcedIn2Sv: true, isEnrolledIn2Sv: true, lastLoginTime: RECENT_LOGIN },
  ];
  const collector = createFakeCollector({
    collectUsers: async () => collection(users),
    collectRoleAssignments: async () => collection([
      { roleAssignmentId: "ra-0", roleId: "1", assignedTo: "u-super", assigneeType: "USER", scopeType: "CUSTOMER" },
      { roleAssignmentId: "ra-1", roleId: "2", assignedTo: "u-delegated", assigneeType: "USER", scopeType: "CUSTOMER" },
    ]),
    collectActivities: async (applicationName) => {
      if (applicationName === "login") return collection([activity("login", "user@example.com", ["login_success"])]);
      if (applicationName === "admin") return collection(createAdminActivities());
      return collection(createTokenActivities());
    },
    collectAlerts: async () => collection([createAlerts()[1]]),
    listUserTokens: async (userKey) => (userKey === "user@example.com" ? createTokens()[userKey] : []),
  });
  const assessments = assessAll(await collectGwsAuditData(collector), config);
  const statuses = statusMap(assessments);
  assert.deepEqual(Object.keys(statuses).sort(), [...GWS_CHECK_IDS].sort());
  for (const [id, status] of Object.entries(statuses)) {
    assert.equal(status, "Pass", `${id} must pass on the compliant tenant fixture`);
  }
});

test("exportGwsAuditBundle writes the shared bundle layout and a zip named after the allocated directory", async () => {
  const base = createTempBase("grclanker-gws-export-");
  const config = createSampleConfig();
  const result = await exportGwsAuditBundle(createFakeCollector(), config, base);

  assert.ok(existsSync(result.outputDir));
  assert.equal(basename(result.outputDir), "example.com-gws-audit");
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.findingCount, 19);
  assert.equal(result.errorCount, 0);
  assert.deepEqual(result.frameworks, ["fedramp", "cmmc", "soc2", "disa_stig", "irap", "ismap", "pci_dss", "cis"]);

  // The legacy summary.md and reports/ tree moved into the shared layout below.
  assert.equal(existsSync(join(result.outputDir, "summary.md")), false);
  assert.equal(existsSync(join(result.outputDir, "reports")), false);
  for (const file of [
    "core_data/users.json",
    "core_data/roles.json",
    "core_data/role_assignments.json",
    "core_data/login_activities.json",
    "core_data/admin_activities.json",
    "core_data/token_activities.json",
    "core_data/token_inventory.json",
    "core_data/alerts.json",
    "core_data/two_step_verification_policies.json",
    "analysis/findings.json",
    "analysis/identity.json",
    "analysis/identity.md",
    "analysis/admin_access.json",
    "analysis/integrations.json",
    "analysis/monitoring.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp/fedramp_compliance_report.md",
    "compliance/cmmc/cmmc_compliance_report.md",
    "compliance/soc2/soc2_compliance_report.md",
    "compliance/disa_stig/stig_compliance_checklist.md",
    "compliance/irap/irap_compliance_report.md",
    "compliance/ismap/ismap_compliance_report.md",
    "compliance/pci_dss/pci_dss_compliance_report.md",
    "compliance/cis/cis_compliance_report.md",
    "QUICK_REFERENCE.md",
  ]) {
    assert.ok(existsSync(join(result.outputDir, file)), file);
  }
  assert.equal(existsSync(join(result.outputDir, "_errors.log")), false);

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 19);
  assert.match(readFileSync(join(result.outputDir, "analysis", "identity.md"), "utf8"), /Google Workspace identity assessment/);
  assert.match(readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8"), /Controls evaluated: 19 of 19/);
  assert.match(readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8"), /GWS-ID-005/);
  assert.match(readFileSync(join(result.outputDir, "compliance", "cis", "cis_compliance_report.md"), "utf8"), /CIS Google Workspace Benchmark/);
});

test("verdict rule 8: re-running the export allocates -2 and never overwrites the earlier bundle or zip", async () => {
  const base = createTempBase("grclanker-gws-rerun-");
  const config = createSampleConfig();
  const first = await exportGwsAuditBundle(createFakeCollector(), config, base);
  const firstZipSize = readFileSync(first.zipPath).length;
  const second = await exportGwsAuditBundle(createFakeCollector(), config, base);
  const third = await exportGwsAuditBundle(createFakeCollector(), config, base);

  assert.equal(basename(second.outputDir), "example.com-gws-audit-2");
  assert.equal(basename(third.outputDir), "example.com-gws-audit-3");
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.zipPath));
  assert.ok(existsSync(third.zipPath));
  assert.equal(readFileSync(first.zipPath).length, firstZipSize);
  assert.deepEqual(
    readdirSync(base).sort(),
    [
      "example.com-gws-audit",
      "example.com-gws-audit-2",
      "example.com-gws-audit-2.zip",
      "example.com-gws-audit-3",
      "example.com-gws-audit-3.zip",
      "example.com-gws-audit.zip",
    ],
  );
});

test("exportGwsAuditBundle writes _errors.log only on partial collection and honors the frameworks filter", async () => {
  const base = createTempBase("grclanker-gws-errors-");
  const config = createSampleConfig();
  const collector = createFakeCollector({
    collectAlerts: async () => {
      throw new GwsApiError(403, "403 Forbidden: apps.alerts scope missing", "https://alertcenter.googleapis.com/v1beta1/alerts");
    },
  });
  const result = await exportGwsAuditBundle(collector, config, base, normalizeFrameworkSelection(["soc2", "CIS"]));

  assert.equal(result.errorCount, 1);
  assert.deepEqual(result.frameworks, ["soc2", "cis"]);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /apps\.alerts scope missing/);
  assert.ok(existsSync(join(result.outputDir, "compliance", "soc2", "soc2_compliance_report.md")));
  assert.ok(existsSync(join(result.outputDir, "compliance", "cis", "cis_compliance_report.md")));
  assert.equal(existsSync(join(result.outputDir, "compliance", "fedramp")), false);
  assert.match(readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8"), /Partial Collection Warnings/);
  const alerts = JSON.parse(readFileSync(join(result.outputDir, "core_data", "alerts.json"), "utf8"));
  assert.equal(alerts.errorKind, "forbidden");
  assert.throws(() => normalizeFrameworkSelection(["hipaa"]), /Unknown framework "hipaa"/);
});

test("redactSecrets strips credential-like keys from raw snapshots", () => {
  const redacted = redactSecrets({
    users: [{ primaryEmail: "user@example.com", password: "hunter2", hashFunction: "SHA-1" }],
    token: { access_token: "ya29.secret", clientId: "client-1" },
  });
  assert.equal(redacted.users[0].primaryEmail, "user@example.com");
  assert.equal(redacted.users[0].password, "[REDACTED]");
  assert.equal(redacted.users[0].hashFunction, "[REDACTED]");
  assert.equal(redacted.token.access_token, "[REDACTED]");
  assert.equal(redacted.token.clientId, "client-1");
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-gws-paths-");
  const outside = createTempBase("grclanker-gws-outside-");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);

  const symlinkTarget = join(base, "symlink-target");
  const symlinkParent = join(base, "symlink-parent");
  writeFileSync(symlinkTarget, "x");
  symlinkSync(outside, symlinkParent);

  assert.throws(() => resolveSecureOutputPath(base, "symlink-parent/file.txt"), /symlinked parent directory/);
});
