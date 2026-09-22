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
import { basename, join, relative } from "node:path";
import { inflateRawSync } from "node:zlib";

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
  describeErrorReasons,
  exportGwsAuditBundle,
  normalizeFrameworkSelection,
  projectActivitySnapshot,
  projectAlertSnapshot,
  redactKnownValues,
  redactSecrets,
  registerGwsTools,
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

function listFilesRecursively(root) {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const pathname = join(root, entry.name);
    if (entry.isDirectory()) files.push(...listFilesRecursively(pathname));
    else files.push(pathname);
  }
  return files;
}

/** Reads every entry of a zip through its central directory so the extracted text can be grepped. */
function readZipEntries(zipPath) {
  const buffer = readFileSync(zipPath);
  const eocd = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.ok(eocd >= 0, "zip end-of-central-directory record not found");
  const entryCount = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  const entries = new Map();
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50, "central directory header signature");
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString("utf8", offset + 46, offset + 46 + nameLength);
    const dataStart = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
    const data = buffer.subarray(dataStart, dataStart + compressedSize);
    if (!name.endsWith("/")) {
      entries.set(name, method === 8 ? inflateRawSync(data).toString("utf8") : data.toString("utf8"));
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

const PLANTED_SECRET = "FAKESECRET-9f8e7d6c";

function planted(carrier) {
  return `${PLANTED_SECRET}-${carrier}`;
}

/** Reports API parameters are {name, value} pairs; the secret sits under the generic value keys. */
function secretParameters(carrier) {
  return [
    { name: "oauth_token", value: planted(`${carrier}-oauth-token-param`) },
    { name: "accessToken", multiValue: [planted(`${carrier}-access-token-multivalue`)] },
    { name: "SETTING_NAME", value: planted(`${carrier}-benign-param`) },
  ];
}

/**
 * The run's own bearer credential in a shape no credential pattern recognizes (no ya29., AIza, GOCSPX-, or JWT form), so when the
 * server echoes it into a documented free-text field only the known-value scrub inside writeBundleFile can remove it.
 */
const RUN_TOKEN = planted("run-bearer-plain-0123456789abcdef");

/**
 * Every collected object type carries the planted secret in every carrier the reviewer used: camelCase keys, pair values, blobs, links,
 * plus the run credential echoed into two documented free-text fields (User.orgUnitPath, Alert.source) that projection keeps.
 */
function createSecretBearingCollector(runToken = RUN_TOKEN) {
  const withParameters = (item, carrier) => ({
    ...item,
    actor: { ...item.actor, key: planted(`${carrier}-actor-key`) },
    events: item.events.map((event) => ({ ...event, parameters: secretParameters(carrier) })),
  });
  const tokens = Object.fromEntries(Object.entries(createTokens()).map(([userKey, list]) => [
    userKey,
    list.map((token) => ({
      ...token,
      // displayText is third-party-controlled and is rendered into the GWS-INTEG-002 evidence line, so it carries a URL query token mid-prose.
      displayText: `${token.displayText} (callback https://app.test/callback?token=${planted("token-display-text-url")})`,
      refreshToken: planted("token-refresh-token"),
      etag: planted("token-etag"),
    })),
  ]));
  return createFakeCollector({
    collectUsers: async () => collection(createUsers().map((user) => ({
      ...user,
      orgUnitPath: `/Engineering/${runToken}`,
      privateKey: planted("user-private-key"),
      customSchemas: { hr: { badge: planted("user-benign-key") } },
    }))),
    collectRoles: async () => collection(createRoles().map((role) => ({
      ...role,
      clientSecret: planted("role-client-secret"),
      roleDescription: planted("role-description"),
    }))),
    collectRoleAssignments: async () => collection(createRoleAssignments().map((assignment) => ({
      ...assignment,
      refreshToken: planted("assignment-refresh-token"),
    }))),
    collectActivities: async (applicationName) => {
      if (applicationName === "login") return collection(createLoginActivities().map((item) => withParameters(item, "login")));
      if (applicationName === "admin") return collection(createAdminActivities().map((item) => withParameters(item, "admin")));
      return collection(createTokenActivities().map((item) => withParameters(item, "token-activity")));
    },
    collectAlerts: async () => collection(createAlerts().map((alert) => ({
      ...alert,
      source: `Google Operations ${runToken}`,
      etag: planted("alert-etag"),
      securityInvestigationToolLink: `https://admin.google.com/ac/sc/investigation?token=${planted("alert-link-query")}`,
      data: {
        "@type": "type.googleapis.com/google.apps.alertcenter.type.DeviceCompromised",
        rawConfig: `snmp community=${planted("alert-data-community")}`,
        note: planted("alert-data-benign-key"),
        accessToken: planted("alert-data-access-token"),
      },
    }))),
    collectTwoStepPolicies: async () => collection(createTwoStepPolicies().map((entry) => ({
      ...entry,
      setting: { ...entry.setting, value: { ...entry.setting.value, secretValue: planted("policy-secret-value"), note: planted("policy-benign-key") } },
    }))),
    listUserTokens: async (userKey) => tokens[userKey] ?? [],
  });
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

test("rule 10: a stalled or endless cursor is recorded as truncation and privileged verdicts stop passing", async () => {
  const config = createSampleConfig();
  let rolePages = 0;
  let assignmentPages = 0;
  const runawayCeiling = 1100;
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (rolePages > runawayCeiling || assignmentPages > runawayCeiling) {
      throw new Error(`pagination did not stop: ${rolePages} role pages, ${assignmentPages} role-assignment pages`);
    }
    if (url.pathname.endsWith("/roles")) {
      rolePages += 1;
      return jsonResponse({ items: rolePages === 1 ? createRoles() : [], nextPageToken: "same-cursor" });
    }
    if (url.pathname.endsWith("/roleassignments")) {
      assignmentPages += 1;
      return jsonResponse({ items: [], nextPageToken: `cursor-${assignmentPages}` });
    }
    return jsonResponse({ error: { message: "unexpected" } }, 404);
  };
  const client = new GoogleWorkspaceAuditorClient(config, fetchImpl);

  const roles = await client.collectRoles();
  assert.equal(roles.truncated, true);
  assert.equal(roles.pages, 2);
  assert.equal(rolePages, 2);
  assert.equal(roles.items.length, 2);

  const assignments = await client.collectRoleAssignments();
  assert.equal(assignments.truncated, true);
  assert.equal(assignments.pages, 1000);
  assert.equal(assignmentPages, 1000);

  const collector = createFakeCollector({
    collectUsers: async () => collection(createUsers().map((user) => ({ ...user, isEnforcedIn2Sv: true }))),
    collectRoles: async () => roles,
    collectRoleAssignments: async () => collection([createRoleAssignments()[0]]),
  });
  const assessments = assessAll(await collectGwsAuditData(collector), config);
  const findings = assessments.flatMap((assessment) => assessment.findings);
  for (const id of ["GWS-ID-001", "GWS-ID-004", "GWS-ADMIN-001", "GWS-ADMIN-002", "GWS-ADMIN-003", "GWS-ADMIN-005", "GWS-INTEG-002"]) {
    const finding = findings.find((entry) => entry.id === id);
    assert.notEqual(finding.status, "Pass", `${id} must not pass on a truncated roles listing`);
    assert.ok(finding.evidence.some((line) => /^Roles: partial view, seen 2 across 2 page\(s\)/.test(line)), `${id} must flag the truncated roles listing`);
  }
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
  assert.equal(identity.snapshotSummary.two_step_policies, null);
  assert.equal(identity.snapshotSummary.two_step_policies_status, "not collected: Cloud Identity policies.list was not queried in this run");
  assert.match(identity.text, /^- two_step_policies: not collected$/m);

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

test("rule 9: redactSecrets matches normalized key names, {name, value} pairs, and URL query strings", () => {
  const redacted = redactSecrets({
    users: [{ primaryEmail: "user@example.com", password: "hunter2", hashFunction: "SHA-1" }],
    token: { access_token: "ya29.secret", clientId: "client-1" },
    camel: { privateKey: "-----BEGIN", refreshToken: "1//abc", accessToken: "ya29.def", clientSecret: "GOCSPX-xyz", "API-Key": "k" },
    parameters: [
      { name: "oauth_token", value: "ya29.param" },
      { name: "accessToken", multiValue: ["ya29.multi"], intValue: "7" },
      { name: "SETTING_NAME", value: "ALLOW_LESS_SECURE_APPS" },
      { type: "USER_SETTINGS", name: "CHANGE_PASSWORD" },
    ],
    link: "https://admin.google.com/ac/sc/investigation?token=abc&x=1",
    embedded: "Notes App (callback https://app.test/cb?token=abc) and https://x.test/p?sig=1#frag then text",
    prose: "Invalid token: PLANTED-VALUE-0123, refresh 1//0gPLANTEDrefresh, key AIzaSyA-PLANTED_0123456789abcdefghijklm, Bearer PLANTEDbearer01, access_token=PLANTED-VALUE-0456, pageToken: CgoQabcdefgh stays",
    jwt: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLXNpZ25hdHVyZQ",
    pem: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----",
    counts: "Privileged third-party tokens: 3; token_records: 12345678; Auth mode: access_token",
    nextPageToken: "CgoQ",
    scopes: ["https://www.googleapis.com/auth/drive"],
  });
  assert.equal(redacted.users[0].primaryEmail, "user@example.com");
  assert.equal(redacted.users[0].password, "[REDACTED]");
  assert.equal(redacted.users[0].hashFunction, "[REDACTED]");
  assert.equal(redacted.token.access_token, "[REDACTED]");
  assert.equal(redacted.token.clientId, "client-1");
  assert.deepEqual(redacted.camel, {
    privateKey: "[REDACTED]",
    refreshToken: "[REDACTED]",
    accessToken: "[REDACTED]",
    clientSecret: "[REDACTED]",
    "API-Key": "[REDACTED]",
  });
  assert.deepEqual(redacted.parameters[0], { name: "oauth_token", value: "[REDACTED]" });
  assert.deepEqual(redacted.parameters[1], { name: "accessToken", multiValue: "[REDACTED]", intValue: "[REDACTED]" });
  assert.deepEqual(redacted.parameters[2], { name: "SETTING_NAME", value: "ALLOW_LESS_SECURE_APPS" });
  assert.deepEqual(redacted.parameters[3], { type: "USER_SETTINGS", name: "CHANGE_PASSWORD" });
  assert.equal(redacted.link, "https://admin.google.com/ac/sc/investigation");
  assert.equal(redacted.embedded, "Notes App (callback https://app.test/cb) and https://x.test/p then text");
  assert.equal(
    redacted.prose,
    "Invalid token: [REDACTED], refresh [REDACTED], key [REDACTED], Bearer [REDACTED], access_token=[REDACTED], pageToken: CgoQabcdefgh stays",
  );
  assert.equal(redacted.jwt, "[REDACTED]");
  assert.equal(redacted.pem, "[REDACTED]");
  assert.equal(redacted.counts, "Privileged third-party tokens: 3; token_records: 12345678; Auth mode: access_token");
  assert.equal(redacted.nextPageToken, "CgoQ");
  assert.deepEqual(redacted.scopes, ["https://www.googleapis.com/auth/drive"]);

  const scrubbed = redactKnownValues({ actor: "ya29.known-token-value", nested: ["prefix ya29.known-token-value suffix"], short: "abc" }, ["ya29.known-token-value", "abc"]);
  assert.deepEqual(scrubbed, { actor: "[REDACTED]", nested: ["prefix [REDACTED] suffix"], short: "abc" });
});

test("rule 9: API error bodies reduce to documented status and reason identifiers and the free-text message is never kept", async () => {
  const config = createSampleConfig();
  const body = {
    error: {
      code: 403,
      message: "Request had insufficient authentication scopes. token=ya29.PLANTED-VALUE-0123456789",
      status: "PERMISSION_DENIED",
      errors: [{ message: "Insufficient Permission: PLANTED-VALUE-0123456789", domain: "global", reason: "insufficientPermissions" }],
      details: [
        { "@type": "type.googleapis.com/google.rpc.ErrorInfo", reason: "ACCESS_TOKEN_SCOPE_INSUFFICIENT", domain: "googleapis.com", metadata: { service: "admin.googleapis.com" } },
        { "@type": "type.googleapis.com/google.rpc.ErrorInfo", reason: "not an identifier PLANTED-VALUE-0123456789", domain: "googleapis.com" },
      ],
    },
  };
  const jsonError = () => new Response(JSON.stringify(body), { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json" } });
  const client = new GoogleWorkspaceAuditorClient(config, async () => jsonError());
  await assert.rejects(client.collectAlerts(), (error) => {
    assert.ok(error instanceof GwsApiError);
    assert.equal(error.status, 403);
    assert.equal(error.message, "403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions, reason ACCESS_TOKEN_SCOPE_INSUFFICIENT)");
    return true;
  });

  const data = await collectGwsAuditData(createFakeCollector({ collectAlerts: () => client.collectAlerts() }));
  assert.equal(data.monitoring.alerts.errorKind, "forbidden");
  assert.equal(data.monitoring.alerts.error, "403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions, reason ACCESS_TOKEN_SCOPE_INSUFFICIENT)");

  assert.deepEqual(describeErrorReasons({ error: "invalid_grant", error_description: "Invalid JWT Signature. token=PLANTED-VALUE-0123456789" }), ["error invalid_grant"]);
  assert.deepEqual(describeErrorReasons({ error: { code: 400, message: "only a free-text message" } }), []);
  assert.deepEqual(describeErrorReasons({ message: "top-level message only" }), []);
  // Documented identifiers never carry `.`, `-`, or `/`, so dotted, hyphenated, and path-shaped values are dropped even when they look like identifiers.
  assert.deepEqual(describeErrorReasons({ error: { status: "PLANTED-SECRET_reason_plain_identifier_0123", errors: [{ reason: "ya29.PLANTEDvalue0123" }] } }), []);
  assert.deepEqual(describeErrorReasons({ error: { status: "1//0gPLANTEDrefresh", errors: [{ reason: "x".repeat(64) }] } }), []);
  assert.deepEqual(describeErrorReasons({ error: { status: "RESOURCE_EXHAUSTED", errors: [{ reason: "userRateLimitExceeded" }] } }), ["status RESOURCE_EXHAUSTED", "reason userRateLimitExceeded"]);

  // The server-supplied reason phrase is never rendered: the fixed RFC 9110 phrase table supplies it, and unknown codes render bare.
  const plain = new GoogleWorkspaceAuditorClient(config, async () => new Response("<html>denied PLANTED-VALUE-0123456789</html>", { status: 403, statusText: "Forbidden PLANTED-STATUS-TEXT-0123" }));
  await assert.rejects(plain.collectAlerts(), { message: "403 Forbidden" });
  const teapot = new GoogleWorkspaceAuditorClient(config, async () => new Response("", { status: 418, statusText: "PLANTED-STATUS-TEXT-0123" }));
  await assert.rejects(teapot.collectAlerts(), { message: "418" });
});

test("rule 9: snapshot projection keeps only documented fields, dropping alert data payloads and event parameters", () => {
  const alert = projectAlertSnapshot({
    alertId: "a-1",
    type: "Device compromised",
    source: "Mobile device management",
    createTime: RECENT_LOGIN,
    etag: "etag-1",
    securityInvestigationToolLink: "https://admin.google.com/ac/sc/investigation?token=abc",
    metadata: { alertId: "a-1", status: "NOT_STARTED", severity: "HIGH", etag: "etag-2" },
    data: { "@type": "type.googleapis.com/google.apps.alertcenter.type.DeviceCompromised", rawConfig: "community=public" },
  });
  assert.deepEqual(alert, {
    alertId: "a-1",
    type: "Device compromised",
    source: "Mobile device management",
    createTime: RECENT_LOGIN,
    metadata: { alertId: "a-1", status: "NOT_STARTED", severity: "HIGH" },
  });

  const item = projectActivitySnapshot({
    kind: "admin#reports#activity",
    id: { time: RECENT_LOGIN, uniqueQualifier: "1", applicationName: "admin", customerId: "C0123abcd" },
    actor: { email: "admin@example.com", profileId: "100", callerType: "USER", key: "consumer-key", applicationInfo: { applicationName: "App", oAuthClientId: "client-1" } },
    ipAddress: "203.0.113.1",
    events: [{ type: "USER_SETTINGS", name: "CHANGE_PASSWORD", parameters: [{ name: "oauth_token", value: "ya29" }] }],
  });
  assert.deepEqual(item, {
    id: { time: RECENT_LOGIN, uniqueQualifier: "1", applicationName: "admin", customerId: "C0123abcd" },
    actor: { email: "admin@example.com", profileId: "100", callerType: "USER", applicationInfo: { applicationName: "App" } },
    ipAddress: "203.0.113.1",
    events: [{ type: "USER_SETTINGS", name: "CHANGE_PASSWORD" }],
  });
});

test("rule 9 (end to end): a bundle exported from secret-bearing fixtures contains no planted value in any file or zip entry", async () => {
  const base = createTempBase("grclanker-gws-secrets-");
  // The run authenticates with RUN_TOKEN, and the fixtures echo that exact value back in documented fields (negative control for writeBundleFile).
  const config = createSampleConfig({ accessToken: RUN_TOKEN });
  const secretBearing = createSecretBearingCollector(RUN_TOKEN);
  // The token activity endpoint fails through the real client so the token-bearing error body travels the production readError path.
  const failingClient = new GoogleWorkspaceAuditorClient(config, async () => new Response(JSON.stringify({
    error: {
      code: 401,
      message: `Invalid Credentials: ${planted("error-message")}`,
      status: "UNAUTHENTICATED",
      errors: [{ message: planted("error-errors-message"), domain: "global", reason: "authError", location: "Authorization", locationType: "header" }],
      details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", reason: "ACCESS_TOKEN_TYPE_UNSUPPORTED", domain: "googleapis.com", metadata: { token: planted("error-details-metadata") } }],
    },
  }), { status: 401, statusText: "Unauthorized", headers: { "content-type": "application/json" } }));
  const collector = {
    ...secretBearing,
    collectActivities: async (applicationName) => (
      applicationName === "token" ? failingClient.collectActivities("token") : secretBearing.collectActivities(applicationName)
    ),
  };
  const result = await exportGwsAuditBundle(collector, config, base);

  assert.equal(result.findingCount, 19);
  assert.equal(result.errorCount, 1);
  const files = listFilesRecursively(result.outputDir);
  assert.ok(files.length >= 25, `expected the full bundle plus _errors.log, saw ${files.length} files`);
  const relativeFiles = files.map((file) => relative(result.outputDir, file));
  for (const expected of ["_errors.log", "analysis/findings.json", "analysis/integrations.json", "analysis/integrations.md", "analysis/monitoring.md", "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md"]) {
    assert.ok(relativeFiles.includes(expected), `bundle is missing ${expected}`);
  }
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    const leak = content.match(new RegExp(`${PLANTED_SECRET}-[a-z0-9-]+`));
    assert.equal(leak, null, `${relative(result.outputDir, file)} leaked ${leak?.[0]}`);
  }

  const entries = readZipEntries(result.zipPath);
  assert.equal(entries.size, files.length);
  for (const [name, content] of entries) {
    const leak = content.match(new RegExp(`${PLANTED_SECRET}-[a-z0-9-]+`));
    assert.equal(leak, null, `zip entry ${name} leaked ${leak?.[0]}`);
  }

  const users = JSON.parse(readFileSync(join(result.outputDir, "core_data", "users.json"), "utf8"));
  assert.deepEqual(Object.keys(users.data[0]).sort(), ["archived", "id", "isAdmin", "isDelegatedAdmin", "isEnforcedIn2Sv", "isEnrolledIn2Sv", "lastLoginTime", "orgUnitPath", "primaryEmail", "suspended"]);
  // Positive control for the writeBundleFile layer: the run credential survives projection and every pattern, so only redactKnownValues removes it.
  assert.equal(users.data[0].orgUnitPath, "/Engineering/[REDACTED]");
  const alerts = JSON.parse(readFileSync(join(result.outputDir, "core_data", "alerts.json"), "utf8"));
  assert.equal(alerts.data[0].metadata.status, "NOT_STARTED");
  assert.equal(alerts.data[0].source, "Google Operations [REDACTED]");
  assert.equal("data" in alerts.data[0], false);
  const logins = JSON.parse(readFileSync(join(result.outputDir, "core_data", "login_activities.json"), "utf8"));
  assert.deepEqual(logins.data[0].events, [{ type: "login", name: "login_success" }, { type: "login", name: "suspicious_login" }]);
  assert.equal("key" in logins.data[0].actor, false);
  const inventory = JSON.parse(readFileSync(join(result.outputDir, "core_data", "token_inventory.json"), "utf8"));
  assert.equal(inventory.data[0].token.clientId, "client-1");
  assert.equal("refreshToken" in inventory.data[0].token, false);
  const policies = JSON.parse(readFileSync(join(result.outputDir, "core_data", "two_step_verification_policies.json"), "utf8"));
  assert.deepEqual(policies.data[0].setting.value, { enforcedFrom: ENFORCED_FROM });
  assert.equal(inventory.data[0].token.displayText, "Drive Syncer (callback https://app.test/callback)");

  // The rendered surfaces (findings, per-category analysis, compliance, _errors.log) carry the scrubbed display name and the projected error.
  const clientLine = "Privileged token clients: Drive Syncer (callback https://app.test/callback) (client-1)";
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.ok(findings.find((finding) => finding.id === "GWS-INTEG-002").evidence.includes(clientLine));
  const integrations = JSON.parse(readFileSync(join(result.outputDir, "analysis", "integrations.json"), "utf8"));
  assert.ok(integrations.findings.find((finding) => finding.id === "GWS-INTEG-002").evidence.includes(clientLine));
  assert.match(readFileSync(join(result.outputDir, "analysis", "integrations.md"), "utf8"), /Drive Syncer \(callback https:\/\/app\.test\/callback\) \(client-1\)/);
  const projectedError = "401 Unauthorized (status UNAUTHENTICATED, reason authError, reason ACCESS_TOKEN_TYPE_UNSUPPORTED)";
  assert.equal(readFileSync(join(result.outputDir, "_errors.log"), "utf8"), `activities.list (token): ${projectedError}\n`);
  assert.match(readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8"), new RegExp(`## Partial Collection Warnings\\n\\n- activities\\.list \\(token\\): ${projectedError.replace(/[()]/g, "\\$&")}`));
  const tokenActivities = JSON.parse(readFileSync(join(result.outputDir, "core_data", "token_activities.json"), "utf8"));
  assert.equal(tokenActivities.error, projectedError);
  assert.equal(tokenActivities.errorKind, "unauthorized");
});

test("rule 1 corollary: a failed privileged tokens.list read is named in GWS-INTEG-002 and turns its counts into lower bounds", async () => {
  const config = createSampleConfig();
  const tokens = createTokens();
  const denied = (userKey) => new GwsApiError(
    403,
    "403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions)",
    `https://admin.googleapis.com/admin/directory/v1/users/${encodeURIComponent(userKey)}/tokens`,
  );
  const failedRead = "super@example.com (403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions))";
  const failedFor = (email) => `Directory tokens.list failed for 1 of 4 sampled users (${email}: 403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions))`;

  // Partial branch: super@example.com is denied while delegated@example.com (also privileged) holds one token.
  const partial = await collectGwsAuditData(createFakeCollector({
    listUserTokens: async (userKey) => {
      if (userKey === "super@example.com") throw denied(userKey);
      return tokens[userKey] ?? [];
    },
  }));
  assert.equal(partial.integrations.tokenInventory.failed, 1);
  assert.deepEqual(partial.integrations.tokenInventory.failures, [
    { userId: "u-super", primaryEmail: "super@example.com", error: "403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions)" },
  ]);
  const partialFindings = assessGwsIntegrations(partial.integrations, config);
  const exposure = findingById(partialFindings, "GWS-INTEG-002");
  assert.equal(exposure.status, "Partial");
  assert.match(exposure.summary, /Directory tokens\.list failed for 1 of the privileged users, so the privileged token count is a lower bound\.$/);
  assert.ok(exposure.evidence.includes("Privileged users with readable tokens.list: 1 of 2 (tokens.list failed: super@example.com)"), exposure.evidence.join("\n"));
  assert.ok(exposure.evidence.includes(`Privileged third-party tokens: at least 1 (${failedFor("super@example.com")})`), exposure.evidence.join("\n"));
  assert.ok(exposure.evidence.includes("Privileged token clients: Drive Syncer (client-1)"));
  assert.ok(exposure.evidence.includes("Per-user token reads that failed: 1 of 4 sampled users"));
  assert.ok(exposure.evidence.includes("Token inventory errors: super@example.com: 403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions)"));
  assert.ok(exposure.evidence.includes(`Directory tokens.list failed for privileged users: ${failedRead}`));
  assert.equal(exposure.evidence.some((line) => /^Privileged users sampled: 2 of 2$/.test(line)), false, "the sampled count must not claim both users were read");
  // The two neighbours that read the same inventory name the failed user as well.
  const inventoryErrorLine = "Token inventory errors: super@example.com: 403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions)";
  for (const id of ["GWS-INTEG-001", "GWS-INTEG-003"]) {
    const finding = findingById(partialFindings, id);
    assert.equal(finding.status, "Partial", id);
    assert.ok(finding.evidence.includes("Per-user token reads that failed: 1"), id);
    assert.ok(finding.evidence.includes(inventoryErrorLine), `${id}: ${finding.evidence.join("\n")}`);
  }

  // Fail branch: the same denied read while delegated@example.com holds four tokens keeps the lower-bound wording.
  const broad = await collectGwsAuditData(createFakeCollector({
    listUserTokens: async (userKey) => {
      if (userKey === "super@example.com") throw denied(userKey);
      if (userKey === "delegated@example.com") {
        return [1, 2, 3, 4].map((index) => ({ ...tokens[userKey][0], clientId: `client-${index}`, displayText: `App ${index}` }));
      }
      return tokens[userKey] ?? [];
    },
  }));
  const broadExposure = findingById(assessGwsIntegrations(broad.integrations, config), "GWS-INTEG-002");
  assert.equal(broadExposure.status, "Fail");
  assert.match(broadExposure.summary, /so the privileged token count is a lower bound\.$/);
  assert.ok(broadExposure.evidence.includes(`Privileged third-party tokens: at least 4 (${failedFor("super@example.com")})`), broadExposure.evidence.join("\n"));
  assert.ok(broadExposure.evidence.includes(`Directory tokens.list failed for privileged users: ${failedRead}`));

  // Manual branch: the denied privileged read with no privileged token in sight names the endpoint and the user in the summary.
  const quiet = await collectGwsAuditData(createFakeCollector({
    listUserTokens: async (userKey) => {
      if (userKey === "super@example.com") throw denied(userKey);
      return userKey === "user@example.com" ? tokens[userKey] : [];
    },
  }));
  const manual = findingById(assessGwsIntegrations(quiet.integrations, config), "GWS-INTEG-002");
  assert.equal(manual.status, "Manual");
  assert.match(manual.summary, /Directory tokens\.list failed for 1 of 4 sampled users including privileged super@example\.com, so zero privileged tokens is not treated as a pass\.$/);
  assert.ok(manual.evidence.includes(`Directory tokens.list failed for privileged users: ${failedRead}`));
  assert.ok(manual.evidence.includes("Per-user token reads that failed: 1 of 4 sampled users"));

  // A failure outside the privileged set is still named, every privileged read is shown as readable, and the counts stay lower bounds.
  const outsider = await collectGwsAuditData(createFakeCollector({
    listUserTokens: async (userKey) => {
      if (userKey === "dormant@example.com") throw denied(userKey);
      return tokens[userKey] ?? [];
    },
  }));
  const outsiderExposure = findingById(assessGwsIntegrations(outsider.integrations, config), "GWS-INTEG-002");
  assert.equal(outsiderExposure.status, "Partial");
  assert.ok(outsiderExposure.evidence.includes("Privileged users with readable tokens.list: 2 of 2"), outsiderExposure.evidence.join("\n"));
  assert.ok(outsiderExposure.evidence.includes(`Privileged third-party tokens: at least 1 (${failedFor("dormant@example.com")})`));
  assert.ok(outsiderExposure.evidence.includes("Token inventory errors: dormant@example.com: 403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions)"));
  assert.ok(outsiderExposure.evidence.includes("Directory tokens.list failed only for users outside the identified privileged set; every token count is still a lower bound"));
  assert.match(outsiderExposure.summary, /Directory tokens\.list failed for 1 of 4 sampled users, so the token counts are lower bounds\.$/);
  assert.equal(outsiderExposure.evidence.some((line) => /^Privileged third-party tokens: \d+$/.test(line)), false, "no exact privileged count beside a failed read");

  // A dataset that reports failures without naming users cannot attribute them, so every privileged count is a lower bound.
  const unattributed = assessGwsIntegrations({
    users: dataset(createUsers()),
    roles: dataset(createRoles()),
    roleAssignments: dataset(createRoleAssignments()),
    tokenInventory: inventoryDataset(createTokenInventory(), { failed: 1, error: "super@example.com: 403 Forbidden" }),
    tokenActivities: dataset(createTokenActivities()),
  }, config);
  const unattributedExposure = findingById(unattributed, "GWS-INTEG-002");
  assert.equal(unattributedExposure.status, "Partial");
  assert.ok(unattributedExposure.evidence.includes("Privileged users with readable tokens.list: at most 2 of 2 (1 tokens.list read(s) failed, users not recorded)"));
  assert.ok(unattributedExposure.evidence.includes("Directory tokens.list failures were not attributed to users, so every privileged count below is a lower bound"));
  assert.match(unattributedExposure.summary, /lower bound\.$/);
});

test("rule 1 corollary: GWS-INTEG-001 and GWS-INTEG-003 cap at Partial and name the endpoint when roles or role assignments are unreadable", async () => {
  const config = createSampleConfig();
  const denied = (path) => async () => {
    throw new GwsApiError(403, "403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions)", `https://admin.googleapis.com${path}`);
  };
  // Calendar-only tokens carry no broad scope, so with a readable directory both GWS-INTEG-001 and GWS-INTEG-003 pass on this fixture.
  const lowScopeTokens = async (userKey) => (createTokens()[userKey] ?? []).map((token) => ({ ...token, scopes: ["https://www.googleapis.com/auth/calendar"] }));
  const endpointNote = (endpoint) => `${endpoint} was not readable (403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions)), so the privileged-first token sample is not known to cover the privileged users`;
  const scenarios = [
    { overrides: { collectRoles: denied("/admin/directory/v1/customer/my_customer/roles") }, reason: "Directory roles.list was not readable" },
    { overrides: { collectRoleAssignments: denied("/admin/directory/v1/customer/my_customer/roleassignments") }, reason: "Directory roleAssignments.list was not readable" },
    {
      overrides: { collectRoles: denied("/roles"), collectRoleAssignments: denied("/roleassignments") },
      reason: "Directory roles.list and Directory roleAssignments.list were not readable",
    },
  ];
  for (const { overrides, reason } of scenarios) {
    const integrations = assessGwsIntegrations(
      (await collectGwsAuditData(createFakeCollector({ listUserTokens: lowScopeTokens, ...overrides }))).integrations,
      config,
    );
    for (const id of ["GWS-INTEG-001", "GWS-INTEG-003"]) {
      const finding = findingById(integrations, id);
      assert.equal(finding.status, "Partial", `${id}: ${reason}`);
      assert.ok(
        finding.summary.endsWith(`The verdict is capped at Partial because ${reason}, so the privileged-first token sample rests on an unreadable inventory.`),
        `${id} summary: ${finding.summary}`,
      );
      for (const endpoint of reason.replace(/ were not readable| was not readable/, "").split(" and ")) {
        assert.ok(finding.evidence.includes(endpointNote(endpoint)), `${id} evidence must name ${endpoint}: ${finding.evidence.join("\n")}`);
      }
    }
    assert.equal(findingById(integrations, "GWS-INTEG-002").status, "Manual");
  }

  // A finding that is already below Pass for its own reason keeps that summary and still names the unreadable endpoint in its evidence.
  const broadScope = assessGwsIntegrations(
    (await collectGwsAuditData(createFakeCollector({ collectRoles: denied("/roles") }))).integrations,
    config,
  );
  const sprawl = findingById(broadScope, "GWS-INTEG-003");
  assert.equal(sprawl.status, "Partial");
  assert.equal(sprawl.summary, "A limited set of third-party tokens carries broad scopes.");
  assert.ok(sprawl.evidence.includes(endpointNote("Directory roles.list")));

  // With both listings readable the same low-scope fixture passes both findings, so the demotion is tied to the unreadable inventory alone.
  const readable = assessGwsIntegrations((await collectGwsAuditData(createFakeCollector({ listUserTokens: lowScopeTokens }))).integrations, config);
  assert.equal(findingById(readable, "GWS-INTEG-001").status, "Pass");
  assert.equal(findingById(readable, "GWS-INTEG-003").status, "Pass");
});

test("rule 9: a service-account token evicted by a 401 mid-run is still scrubbed from the exported bundle", async () => {
  clearGwsTokenCacheForTests();
  const base = createTempBase("grclanker-gws-minted-");
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const config = createSampleConfig({
    authMode: "service_account",
    accessToken: undefined,
    adminEmail: "admin@example.com",
    serviceAccountEmail: "svc@example-project.iam.gserviceaccount.com",
    serviceAccountPrivateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  });
  const state = { minted: [], firstUsers401: true };
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.origin === "https://oauth2.googleapis.com" && url.pathname === "/token") {
      // Minted in a shape no credential pattern recognizes, so only the known-value layer can scrub an echo of it.
      const token = `MINTEDTOKEN-${state.minted.length + 1}-abcdefghijklmnopqrstuvwxyz0123456789`;
      state.minted.push(token);
      return jsonResponse({ access_token: token, expires_in: 3600, token_type: "Bearer" });
    }
    if (url.pathname === "/admin/directory/v1/users") {
      if (state.firstUsers401) {
        state.firstUsers401 = false;
        return jsonResponse({ error: { code: 401, message: "Invalid Credentials", status: "UNAUTHENTICATED" } }, 401);
      }
      // The directory echoes the first (now evicted) token into a documented free-text field.
      return jsonResponse({ users: createUsers().map((user) => ({ ...user, orgUnitPath: `/ou-${state.minted[0]}` })) });
    }
    if (url.pathname === "/admin/directory/v1/customer/my_customer/roles") return jsonResponse({ items: createRoles() });
    if (url.pathname === "/admin/directory/v1/customer/my_customer/roleassignments") return jsonResponse({ items: createRoleAssignments() });
    if (url.pathname.startsWith("/admin/reports/v1/activity/users/all/applications/")) return jsonResponse({ items: [] });
    if (url.pathname === "/v1beta1/alerts") return jsonResponse({ alerts: [] });
    if (url.origin === "https://cloudidentity.googleapis.com" && url.pathname === "/v1/policies") return jsonResponse({ policies: createTwoStepPolicies() });
    if (/^\/admin\/directory\/v1\/users\/[^/]+\/tokens$/.test(url.pathname)) return jsonResponse({ items: [] });
    return jsonResponse({ error: { code: 404, message: `unexpected URL ${url}`, status: "NOT_FOUND" } }, 404);
  };

  const client = new GoogleWorkspaceAuditorClient(config, fetchImpl);
  const result = await exportGwsAuditBundle(client, config, base);
  assert.ok(state.minted.length >= 2, `expected the 401 to force a second mint, saw ${state.minted.length}`);
  assert.equal(result.findingCount, 19);

  const files = listFilesRecursively(result.outputDir);
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    for (const token of state.minted) {
      assert.equal(content.includes(token), false, `${relative(result.outputDir, file)} leaked minted token ${token}`);
    }
  }
  const entries = readZipEntries(result.zipPath);
  assert.equal(entries.size, files.length);
  for (const [name, content] of entries) {
    for (const token of state.minted) {
      assert.equal(content.includes(token), false, `zip entry ${name} leaked minted token ${token}`);
    }
  }
  const users = JSON.parse(readFileSync(join(result.outputDir, "core_data", "users.json"), "utf8"));
  assert.equal(users.data[0].orgUnitPath, "/ou-[REDACTED]");
  clearGwsTokenCacheForTests();
});

/** Registers the inspector tools against a stand-in host and returns them keyed by name, applying prepareArguments the way the host does. */
function registeredTools() {
  const tools = new Map();
  registerGwsTools({ registerTool: (definition) => tools.set(definition.name, definition) });
  return {
    run: async (name, rawArgs) => {
      const definition = tools.get(name);
      assert.ok(definition, `tool ${name} is registered`);
      const result = await definition.execute("call-1", definition.prepareArguments(rawArgs));
      return { ...result, text: result.content.map((part) => part.text ?? "").join("\n"), json: JSON.stringify(result.details ?? {}) };
    },
  };
}

/** The registered tools build their client on the global fetch, so the route stands in for it for the duration of the callback. */
async function withRoutedFetch(route, callback) {
  const original = globalThis.fetch;
  globalThis.fetch = route;
  try {
    return await callback();
  } finally {
    globalThis.fetch = original;
  }
}

/** Every endpoint answers with an empty but well-formed page unless `overrides` supplies its own handler keyed by a pathname test. */
function routeEndpoints(overrides = []) {
  return async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    for (const [matches, handler] of overrides) {
      if (matches(url)) return handler(url);
    }
    if (url.pathname === "/admin/directory/v1/users") return jsonResponse({ users: createUsers() });
    if (url.pathname.endsWith("/roles")) return jsonResponse({ items: createRoles() });
    if (url.pathname.endsWith("/roleassignments")) return jsonResponse({ items: createRoleAssignments() });
    if (url.pathname.startsWith("/admin/reports/v1/activity/")) return jsonResponse({ items: [] });
    if (url.pathname === "/v1beta1/alerts") return jsonResponse({ alerts: [] });
    if (url.pathname === "/v1/policies") return jsonResponse({ policies: [] });
    if (url.pathname.endsWith("/tokens")) return jsonResponse({ items: [] });
    return jsonResponse({ error: { code: 404, message: `unexpected URL ${url}`, status: "NOT_FOUND" } }, 404);
  };
}

const INSPECTOR_TOOLS = ["gws_check_access", "gws_assess_identity", "gws_assess_admin_access", "gws_assess_integrations", "gws_assess_monitoring"];
/** The tools whose collection reads Directory roles.list, so a roles.list failure reaches their text and snapshot. */
const ROLE_READING_TOOLS = ["gws_check_access", "gws_assess_identity", "gws_assess_admin_access", "gws_assess_integrations"];

test("rule 9 (tool path): a transport error carrying credentials is scrubbed where the error is created, so every tool result and snapshot_summary reads [REDACTED]", async () => {
  clearGwsTokenCacheForTests();
  // The run credential has no Google shape, so only the known-value layer can remove it (negative control for that layer on the tool path).
  const runToken = "PLANTEDr5-run-token-0123456789abcdef";
  const thrown = `proxy CONNECT failed for Bearer ya29.PLANTEDr5bearer0123456789; access_token=PLANTEDr5pair0123456789; echo ${runToken}; see https://proxy.example/x?sig=PLANTEDr5sig0123`;
  const leak = /PLANTED/;
  const failRoles = [(url) => url.pathname.endsWith("/roles"), () => { throw new Error(thrown); }];
  const toolArgs = { auth_mode: "access_token", access_token: runToken, domain: "example.com" };
  const scrubbed = "proxy CONNECT failed for Bearer [REDACTED]; access_token=[REDACTED]; echo [REDACTED]; see https://proxy.example/x";
  const scrubbedPattern = new RegExp(scrubbed.replace(/[.()[\]]/g, "\\$&"));

  // The error class and summarizeError scrub at creation, so the library surfaces are already clean.
  const apiError = new GwsApiError(502, "upstream said Bearer ya29.PLANTEDr5ctor0123456789 at https://proxy.example/y?token=PLANTEDr5query0123", "https://admin.googleapis.com/x");
  assert.equal(apiError.message, "upstream said Bearer [REDACTED] at https://proxy.example/y");
  const data = await collectGwsAuditData(createFakeCollector({ collectRoles: async () => { throw new Error(thrown); } }));
  assert.equal(data.identity.roles.error, scrubbed.replace("echo [REDACTED]", `echo ${runToken}`), "a run that registered no configuration applies the shape scrub only");

  const tools = registeredTools();
  await withRoutedFetch(routeEndpoints([failRoles]), async () => {
    for (const name of INSPECTOR_TOOLS) {
      const result = await tools.run(name, toolArgs);
      assert.doesNotMatch(result.text, leak, `${name} text leaked`);
      assert.doesNotMatch(result.json, leak, `${name} details leaked`);
      if (ROLE_READING_TOOLS.includes(name)) {
        assert.match(result.text, scrubbedPattern, `${name} text must carry the scrubbed error`);
        assert.match(result.json, scrubbedPattern, `${name} details must carry the scrubbed error`);
      }
    }
    const adminAccess = await tools.run("gws_assess_admin_access", toolArgs);
    assert.match(adminAccess.text, new RegExp(`^- privileged_users_status: unreadable: Directory roles\\.list \\(${scrubbed.replace(/[.()[\]]/g, "\\$&")}\\)$`, "m"));
    assert.equal(adminAccess.details.snapshot_summary.privileged_users, null);
    assert.equal(adminAccess.details.snapshot_summary.privileged_users_status, `unreadable: Directory roles.list (${scrubbed})`);
    assert.ok(findingById(adminAccess.details, "GWS-ADMIN-001").evidence.some((line) => line.includes(scrubbed)), "the evidence names the scrubbed failure");
    const access = await tools.run("gws_check_access", toolArgs);
    const rolesProbe = access.details.probes.find((probe) => probe.key === "roles");
    assert.equal(rolesProbe.status, "error");
    assert.equal(rolesProbe.detail, scrubbed);
    assert.match(access.text, /roles\s+│\s+error\s+│\s+proxy CONNECT failed for Bearer \[REDACTED\]; access_token=\[REDACTED\]; echo \[REDACTED\]; see https:\/\/proxy\.example\/x/);
  });

  // A documented free-text field echoing credentials reaches INTEG-002 evidence only through the tool payload scrub (the bundle's redactSecrets layer).
  const displayToken = [(url) => url.pathname === "/admin/directory/v1/users/delegated%40example.com/tokens", () => jsonResponse({
    items: [{ clientId: "client-1", displayText: `Drive Syncer token=PLANTEDr5display0123456789 https://app.test/cb?code=PLANTEDr5code0123 ${runToken}`, scopes: ["https://www.googleapis.com/auth/drive"], userKey: "u-delegated" }],
  })];
  await withRoutedFetch(routeEndpoints([displayToken]), async () => {
    const integrations = await tools.run("gws_assess_integrations", toolArgs);
    assert.doesNotMatch(integrations.text, leak, integrations.text);
    assert.doesNotMatch(integrations.json, leak);
    assert.ok(findingById(integrations.details, "GWS-INTEG-002").evidence.includes("Privileged token clients: Drive Syncer token=[REDACTED] https://app.test/cb [REDACTED] (client-1)"), integrations.text);
  });

  // Every request throwing: all five tools render every unreadable read with the scrubbed message and nothing else.
  await withRoutedFetch(async () => { throw new Error(thrown); }, async () => {
    for (const name of INSPECTOR_TOOLS) {
      const result = await tools.run(name, toolArgs);
      assert.doesNotMatch(result.text, leak, `${name} text leaked`);
      assert.doesNotMatch(result.json, leak, `${name} details leaked`);
      assert.match(result.text, scrubbedPattern, `${name} text must carry the scrubbed error`);
      assert.equal(result.isError, undefined, `${name} reports unreadable reads as findings, not as a tool error`);
    }
  });

  // The tool catch block inherits the scrub, and the credentials parser never quotes its input.
  const badJson = await tools.run("gws_assess_identity", { auth_mode: "service_account", credentials_json: `ya29.PLANTEDr5notjson0123456789 ${"x".repeat(40)}`, admin_email: "admin@example.com" });
  assert.equal(badJson.isError, true);
  assert.doesNotMatch(badJson.text, leak, badJson.text);
  assert.equal(badJson.text, "Google Workspace identity assessment failed: Failed to parse service account JSON from credentials_json: the contents are not valid JSON (72 character(s); the contents are not repeated here).");
  clearGwsTokenCacheForTests();
});

test("rule 9 (tool path): a 200 body that is not JSON is described by content type and size, never quoted, in tool results and every bundle file", async () => {
  clearGwsTokenCacheForTests();
  const base = createTempBase("grclanker-gws-nonjson-");
  const bodyCanary = "ya29.PLANTEDr5okbody0123456789";
  const html = `<html><body>PLANTEDr5plainword ${bodyCanary} access_token=PLANTEDr5htmlpair0123</body></html>`;
  const leak = /PLANTED/;
  const htmlRoles = [(url) => url.pathname.endsWith("/roles"), () => new Response(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } })];
  const described = `200 OK with non-JSON text/html body (${Buffer.byteLength(html, "utf8")} bytes) withheld`;
  const toolArgs = { auth_mode: "access_token", access_token: "ya29.PLANTEDr5nonjsonrun0123456789", domain: "example.com" };

  // The client raises an explicit error naming status, content type, and size; the parser's quoting message never forms.
  const config = createSampleConfig();
  const client = new GoogleWorkspaceAuditorClient(config, routeEndpoints([htmlRoles]));
  await assert.rejects(client.collectRoles(), (error) => {
    assert.ok(error instanceof GwsApiError);
    assert.equal(error.status, 200);
    assert.equal(error.message, described);
    return true;
  });
  const untyped = new GoogleWorkspaceAuditorClient(config, async () => new Response(html, { status: 200 }));
  await assert.rejects(untyped.collectRoles(), (error) => {
    assert.equal(error.message, `200 OK with non-JSON text/plain body (${Buffer.byteLength(html, "utf8")} bytes) withheld`, "undici labels a string Response body text/plain");
    return true;
  });
  const empty = new GoogleWorkspaceAuditorClient(config, async () => new Response("", { status: 200, headers: { "content-type": "application/json" } }));
  await assert.rejects(empty.collectRoles(), { message: "200 OK with non-JSON application/json body (0 bytes) withheld" });

  const tools = registeredTools();
  await withRoutedFetch(routeEndpoints([htmlRoles]), async () => {
    for (const name of INSPECTOR_TOOLS) {
      const result = await tools.run(name, toolArgs);
      assert.doesNotMatch(result.text, leak, `${name} text quoted the body`);
      assert.doesNotMatch(result.json, leak, `${name} details quoted the body`);
      assert.doesNotMatch(result.text + result.json, /is not valid JSON|Unexpected token/, `${name} carries a parser message`);
    }
    const adminAccess = await tools.run("gws_assess_admin_access", toolArgs);
    assert.equal(adminAccess.details.snapshot_summary.privileged_users_status, `unreadable: Directory roles.list (${described})`);
    assert.equal(findingById(adminAccess.details, "GWS-ADMIN-001").status, "Manual");
  });

  // The bundle exported from the same client carries the description and nothing from the body, in the directory and the zip.
  const result = await exportGwsAuditBundle(client, config, base);
  assert.equal(result.errorCount, 1);
  const files = listFilesRecursively(result.outputDir);
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    assert.doesNotMatch(content, leak, `${relative(result.outputDir, file)} quoted the body`);
    assert.doesNotMatch(content, /is not valid JSON|Unexpected token/, `${relative(result.outputDir, file)} carries a parser message`);
  }
  for (const [name, content] of readZipEntries(result.zipPath)) {
    assert.doesNotMatch(content, leak, `zip entry ${name} quoted the body`);
  }
  assert.equal(readFileSync(join(result.outputDir, "_errors.log"), "utf8"), `roles.list: ${described}\n`);
  const roles = JSON.parse(readFileSync(join(result.outputDir, "core_data", "roles.json"), "utf8"));
  assert.equal(roles.error, described);
  assert.equal(roles.errorKind, "error");
  assert.equal(roles.data, null);

  // The token exchange applies the same rule to its own 200 body.
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const serviceAccount = createSampleConfig({
    authMode: "service_account",
    accessToken: undefined,
    serviceAccountEmail: "svc@example-project.iam.gserviceaccount.com",
    serviceAccountPrivateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  });
  const exchangeBody = `${bodyCanary} PLANTEDr5exchangebody`;
  const exchange = new GoogleWorkspaceAuditorClient(serviceAccount, async () => new Response(exchangeBody, { status: 200, headers: { "content-type": "text/plain" } }));
  await assert.rejects(exchange.collectRoles(), (error) => {
    assert.doesNotMatch(error.message, leak);
    assert.equal(error.message, `Google token exchange returned 200 OK with non-JSON text/plain body (${Buffer.byteLength(exchangeBody, "utf8")} bytes) withheld.`);
    return true;
  });
  clearGwsTokenCacheForTests();
});

const ENDPOINT = {
  users: "Directory users.list",
  roles: "Directory roles.list",
  roleAssignments: "Directory roleAssignments.list",
  tokens: "Directory tokens.list",
  alerts: "Alert Center alerts.list",
  policies: "Cloud Identity policies.list",
  activities: (applicationName) => `Reports activities.list (applicationName=${applicationName})`,
};
const FORBIDDEN_TEXT = "403 Forbidden (status PERMISSION_DENIED, reason insufficientPermissions)";
const UNAVAILABLE_STATUS = /^(unreadable|not collected|unknown)\b/;
const COLLECTED_STATUS = /^(complete|partial)\b/;
const ENDPOINT_MENTION = /\b(Directory (?:users|roles|roleAssignments|tokens)\.list|Reports activities\.list \(applicationName=(?:login|admin|token)\)|Alert Center alerts\.list|Cloud Identity policies\.list)/g;
/** An evidence line is `Label: value`; the value is a count, `at least N (...)`, or a status word naming the failed read. */
const EVIDENCE_LINE = /^([^:]+): (.*)$/;

/** Wraps the fake collector so every endpoint it is asked to read is recorded, the way the Slack fixture records requests. */
function recordingCollector(overrides = {}) {
  const requested = new Set();
  const inner = createFakeCollector(overrides);
  const record = (endpoint, call) => async (...args) => {
    requested.add(typeof endpoint === "function" ? endpoint(...args) : endpoint);
    return call(...args);
  };
  return {
    requested,
    collector: {
      collectUsers: record(ENDPOINT.users, inner.collectUsers),
      collectRoles: record(ENDPOINT.roles, inner.collectRoles),
      collectRoleAssignments: record(ENDPOINT.roleAssignments, inner.collectRoleAssignments),
      collectActivities: record(ENDPOINT.activities, inner.collectActivities),
      collectAlerts: record(ENDPOINT.alerts, inner.collectAlerts),
      collectTwoStepPolicies: record(ENDPOINT.policies, inner.collectTwoStepPolicies),
      listUserTokens: record(ENDPOINT.tokens, inner.listUserTokens),
    },
  };
}

/**
 * No count or list renders 0, [], or "unknown" beside a status that says the data was unreadable, not collected, or unknown.
 * Objects follow the `<key>` plus `<key>_status` and nested `status` conventions; evidence lines are checked as `Label: value`.
 */
function assertNoFabricatedValues(value, label, path = "") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoFabricatedValues(item, label, `${path}[${index}]`));
    return;
  }
  if (typeof value === "string") {
    const line = EVIDENCE_LINE.exec(value);
    if (!line) return;
    assert.notEqual(line[2], "unknown", `${label}: ${path} "${value}" is the "unknown" placeholder`);
    if (/\b(unreadable|not collected|unknown)\b/.test(line[2])) {
      assert.doesNotMatch(line[2], /^(\d+|\[\]|no|none|yes)\b/, `${label}: ${path} "${value}" renders a value beside an unavailable status`);
    }
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    assert.notEqual(entry, "unknown", `${label}: ${path}.${key} is the "unknown" placeholder`);
    if (typeof entry === "string" && UNAVAILABLE_STATUS.test(entry) && key.endsWith("_status")) {
      const base = key.slice(0, -"_status".length);
      if (base in value) assert.equal(value[base], null, `${label}: ${path}.${base} must be null beside status "${entry}"`);
    }
    if (key === "status" && typeof entry === "string" && UNAVAILABLE_STATUS.test(entry)) {
      for (const [sibling, siblingValue] of Object.entries(value)) {
        assert.ok(siblingValue !== 0 && !(Array.isArray(siblingValue) && siblingValue.length === 0), `${label}: ${path}.${sibling} renders ${JSON.stringify(siblingValue)} beside status "${entry}"`);
      }
    }
    assertNoFabricatedValues(entry, label, `${path}.${key}`);
  }
}

/** A status that says complete or partial (or an `at least N` evidence line) may only name endpoints that were actually requested. */
function assertStatusesMatchRequests(value, requested, label, path = "") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertStatusesMatchRequests(item, requested, label, `${path}[${index}]`));
    return;
  }
  if (typeof value === "string") {
    const line = EVIDENCE_LINE.exec(value);
    if (line && (COLLECTED_STATUS.test(line[2]) || /^at least \d+/.test(line[2]))) {
      for (const mention of line[2].match(ENDPOINT_MENTION) ?? []) {
        assert.ok(requested.has(mention), `${label}: ${path} "${value}" names ${mention}, which was never requested`);
      }
    }
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === "string" && (key.endsWith("_status") || key === "status") && COLLECTED_STATUS.test(entry)) {
      for (const mention of entry.match(ENDPOINT_MENTION) ?? []) {
        assert.ok(requested.has(mention), `${label}: ${path}.${key} says "${entry}" but ${mention} was never requested`);
      }
    }
    assertStatusesMatchRequests(entry, requested, label, `${path}.${key}`);
  }
}

/** Evidence labels whose count is derived from each inventory; when that inventory failed, none of them may render an exact number. */
const DIRECTORY_LABELS = [
  "Privileged users", "Privileged users with isEnforcedIn2Sv=true", "Super admins", "Super admins with isEnforcedIn2Sv=true", "Super admins identified",
  "Privileged users reviewed", "Suspended or archived privileged users", "Delegated admin users identified", "Total privileged users", "Privileged users identified",
];
const TOKEN_LABELS = ["Token records collected", "Privileged third-party tokens", "Third-party clients observed", "High-scope token records"];
const EVIDENCE_LABELS_BY_SOURCE = {
  users: [
    "Users collected", "Active users", "Active users reviewed", "Users with isEnforcedIn2Sv=true", "Users with isEnrolledIn2Sv=true", "Users with isAdmin=true",
    "Active users with no parseable lastLoginTime (reported separately, never counted as fresh)", "Users sampled for token inventory", ...DIRECTORY_LABELS, ...TOKEN_LABELS,
  ],
  roles: DIRECTORY_LABELS,
  roleAssignments: ["Role assignments collected", "Role assignments reviewed", "Group role assignments", ...DIRECTORY_LABELS],
  login: ["Login activity records collected", "Suspicious login signals"],
  admin: ["Admin activities collected", "Admin activity records collected"],
  token: ["Token activity records collected"],
  alerts: ["Alerts collected", "Open alerts (metadata.status NOT_STARTED or IN_PROGRESS)", "Closed alerts (metadata.status CLOSED)", "Alerts without metadata.status (reported separately, never counted as closed)"],
  policies: ["Policies returned", "Enforcement policies returned", "Enforcement policies with enforcedFrom at or before now", "Enrollment policies with allowEnrollment=false"],
  tokens: TOKEN_LABELS,
};

/** Every evidence line whose label depends on the failed inventory reads `at least N (...)`, `unreadable (...)`, or `not collected (...)`, never a bare number. */
function assertDependentLinesAreBounded(findings, source, label) {
  const labels = new Set(EVIDENCE_LABELS_BY_SOURCE[source]);
  for (const finding of findings) {
    for (const line of finding.evidence) {
      const match = EVIDENCE_LINE.exec(line);
      if (!match || !labels.has(match[1])) continue;
      assert.doesNotMatch(match[2], /^\d+(\s|$)/, `${label}: ${finding.id} renders "${line}" while ${source} failed`);
      assert.match(match[2], /^(at least \d+ \(|unreadable \(|not collected \()/, `${label}: ${finding.id} "${line}" must be a bound or a status naming the failed read`);
    }
  }
}

/** The snapshot fields the reviewer's field-by-endpoint table found rendered as 0 or `no`; each must now be null with a status naming the read. */
const NULL_SNAPSHOT_FIELDS_BY_SOURCE = {
  users: {
    identity: ["active_users", "privileged_users", "super_admins", "users_enforced_in_2sv", "dormant_active_users", "users_without_last_login"],
    admin_access: ["privileged_users", "super_admins", "delegated_admins", "stale_privileged_users", "privileged_users_without_last_login"],
    integrations: ["sampled_users", "active_user_population", "privileged_users", "token_records", "privileged_token_records", "high_scope_token_records", "token_read_failures"],
  },
  roles: {
    identity: ["privileged_users", "super_admins"],
    admin_access: ["privileged_users", "super_admins", "delegated_admins", "stale_privileged_users", "privileged_users_without_last_login"],
    integrations: ["privileged_users", "privileged_token_records"],
  },
  roleAssignments: {
    identity: ["privileged_users", "super_admins"],
    admin_access: ["privileged_users", "super_admins", "delegated_admins", "stale_privileged_users", "privileged_users_without_last_login", "group_role_assignments"],
    integrations: ["privileged_users", "privileged_token_records"],
  },
  login: { monitoring: ["login_activity_records", "suspicious_login_signals"] },
  admin: { monitoring: ["admin_activity_records"] },
  token: { integrations: ["token_activity_records"], monitoring: ["token_activity_records"] },
  alerts: { monitoring: ["alerts_collected", "open_alerts", "alerts_without_status"] },
  policies: { identity: ["two_step_policies"] },
  tokens: { integrations: ["token_records", "privileged_token_records", "high_scope_token_records"] },
};

function denialError(kind, endpoint) {
  switch (kind) {
    case "403":
      return new GwsApiError(403, FORBIDDEN_TEXT, `https://admin.googleapis.com/${endpoint}`);
    case "401":
      return new GwsApiError(401, "401 Unauthorized (status UNAUTHENTICATED, reason authError)", `https://admin.googleapis.com/${endpoint}`);
    case "error":
      return new Error("socket hang up");
    default:
      throw new Error(`unknown denial kind ${kind}`);
  }
}

/** Collector overrides that deny one surface with one failure kind; the token rows deny every user, the privileged user, or the token holder. */
function denyOverrides(source, kind) {
  const fail = () => { throw denialError(kind, source); };
  const tokens = createTokens();
  switch (source) {
    case "users": return { collectUsers: fail };
    case "roles": return { collectRoles: fail };
    case "roleAssignments": return { collectRoleAssignments: fail };
    case "alerts": return { collectAlerts: fail };
    case "policies": return { collectTwoStepPolicies: fail };
    case "login":
    case "admin":
    case "token":
      return { collectActivities: async (applicationName) => (applicationName === source ? fail() : createFakeCollector().collectActivities(applicationName)) };
    case "tokens": return { listUserTokens: fail };
    case "tokens-super": return { listUserTokens: async (userKey) => (userKey === "super@example.com" ? fail() : tokens[userKey] ?? []) };
    case "tokens-user": return { listUserTokens: async (userKey) => (userKey === "user@example.com" ? fail() : tokens[userKey] ?? []) };
    default: throw new Error(`unknown source ${source}`);
  }
}

function snapshotByCategory(assessments) {
  return Object.fromEntries(assessments.map((assessment) => [assessment.category, assessment]));
}

test("null standard: every snapshot count derived from a denied inventory renders null with a status naming the endpoint, and the partial-view flag reads from the collection status", async () => {
  const config = createSampleConfig();
  const endpointFor = { users: ENDPOINT.users, roles: ENDPOINT.roles, roleAssignments: ENDPOINT.roleAssignments, login: ENDPOINT.activities("login"), admin: ENDPOINT.activities("admin"), token: ENDPOINT.activities("token"), alerts: ENDPOINT.alerts, policies: ENDPOINT.policies, tokens: ENDPOINT.tokens };

  for (const [source, expectations] of Object.entries(NULL_SNAPSHOT_FIELDS_BY_SOURCE)) {
    const byCategory = snapshotByCategory(assessAll(await collectGwsAuditData(createFakeCollector(denyOverrides(source, "403"))), config));
    for (const [category, fields] of Object.entries(expectations)) {
      const { snapshotSummary, text } = byCategory[category];
      for (const field of fields) {
        const status = snapshotSummary[`${field}_status`];
        assert.equal(snapshotSummary[field], null, `${source} denied: ${category}.${field} = ${JSON.stringify(snapshotSummary[field])} (${status})`);
        assert.match(status, UNAVAILABLE_STATUS, `${source} denied: ${category}.${field}_status = ${status}`);
        assert.ok(status.includes(endpointFor[source]), `${source} denied: ${category}.${field}_status must name ${endpointFor[source]}: ${status}`);
        assert.ok(status.includes(source === "tokens" ? "failed for all 4 sampled users" : FORBIDDEN_TEXT), `${source} denied: ${category}.${field}_status must carry the projected error: ${status}`);
        assert.match(text, new RegExp(`^- ${field}: (unreadable|not collected)$`, "m"), `${source} denied: ${category} text must render ${field} as its status word`);
      }
    }
    if (source === "users") {
      for (const category of ["identity", "admin_access"]) {
        assert.match(byCategory[category].snapshotSummary.users_seen_partial_view, /^unreadable \(Directory users\.list \(403 Forbidden/, category);
        assert.doesNotMatch(byCategory[category].text, /^- users_seen_partial_view: no$/m, category);
      }
      // Reads that were never attempted because users.list failed say so instead of claiming an empty sample.
      assert.match(byCategory.integrations.snapshotSummary.sampled_users_status, /^not collected: Directory tokens\.list was not called because Directory users\.list was unreadable \(403 Forbidden/);
      assert.match(byCategory.integrations.snapshotSummary.token_read_failures_status, /^not collected: Directory tokens\.list was not called because/);
    }
  }

  // A tokens.list read that failed for one sampled user turns every token count into a lower bound naming that user.
  for (const [source, email] of [["tokens-super", "super@example.com"], ["tokens-user", "user@example.com"]]) {
    const { snapshotSummary, text } = snapshotByCategory(assessAll(await collectGwsAuditData(createFakeCollector(denyOverrides(source, "403"))), config)).integrations;
    for (const field of ["token_records", "privileged_token_records", "high_scope_token_records"]) {
      assert.equal(typeof snapshotSummary[field], "number", `${source}: ${field}`);
      assert.match(snapshotSummary[`${field}_status`], new RegExp(`^partial: at least ${snapshotSummary[field]}; Directory tokens\\.list failed for 1 of 4 sampled users \\(${email.replace(".", "\\.")}: 403 Forbidden`), `${source}: ${field}_status`);
      assert.match(text, new RegExp(`^- ${field}: at least ${snapshotSummary[field]}$`, "m"), `${source}: ${field} text`);
    }
    assert.equal(snapshotSummary.token_read_failures, 1, source);
    assert.match(snapshotSummary.token_read_failures_status, /^complete: Directory tokens\.list was attempted for 4 sampled user\(s\) of 4 active users$/, source);
  }

  // The readable baseline keeps exact counts, a complete status on every field, and `no` for the partial-view flag.
  // A status key is `<field>_status` for a field that exists; `alerts_without_status` is itself a count.
  const baseline = snapshotByCategory(assessAll(await collectGwsAuditData(createFakeCollector()), config));
  for (const [category, assessment] of Object.entries(baseline)) {
    for (const [key, value] of Object.entries(assessment.snapshotSummary)) {
      const isStatusKey = key.endsWith("_status") && key.slice(0, -"_status".length) in assessment.snapshotSummary;
      if (isStatusKey) assert.match(value, /^complete: /, `${category}.${key}`);
      else if (key === "users_seen_partial_view") assert.equal(value, "no", `${category}.${key}`);
      else assert.equal(typeof value, "number", `${category}.${key} = ${JSON.stringify(value)}`);
    }
  }
  assert.equal(baseline.monitoring.snapshotSummary.alerts_without_status, 0);
  assert.match(baseline.monitoring.snapshotSummary.alerts_without_status_status, /^complete: Alert Center alerts\.list returned/);
  assert.equal(baseline.identity.snapshotSummary.active_users, 4);
  assert.equal(baseline.identity.snapshotSummary.active_users_status, "complete: Directory users.list returned 4 record(s) across 1 page(s)");
  // A truncated users.list keeps its count as a lower bound and flags the partial view from the collection status.
  const truncated = snapshotByCategory(assessAll(await collectGwsAuditData(createFakeCollector({ collectUsers: async () => collection(createUsers(), { truncated: true, pages: 3 }) })), config));
  assert.equal(truncated.identity.snapshotSummary.users_seen_partial_view, "yes");
  assert.match(truncated.identity.snapshotSummary.active_users_status, /^partial: at least 4; Directory users\.list stopped at the collection cap after 3 page\(s\) with 4 seen, more pages exist$/);
  assert.match(truncated.identity.text, /^- active_users: at least 4$/m);
});

test("null standard: a denied core_data dataset writes a {status, endpoint, error} marker with null data, seen, pages, and truncated", async () => {
  const config = createSampleConfig();
  const readCore = (result, name) => JSON.parse(readFileSync(join(result.outputDir, "core_data", name), "utf8"));

  const usersDenied = await exportGwsAuditBundle(createFakeCollector(denyOverrides("users", "403")), config, createTempBase("grclanker-gws-core-users-"));
  const users = readCore(usersDenied, "users.json");
  assert.deepEqual(users, {
    status: `unreadable: Directory users.list (${FORBIDDEN_TEXT})`,
    endpoint: ENDPOINT.users,
    error: FORBIDDEN_TEXT,
    errorKind: "forbidden",
    data: null,
    seen: null,
    pages: null,
    truncated: null,
  });
  // The token sample is drawn from users.list, so it is recorded as never collected rather than as an empty inventory.
  const neverSampled = readCore(usersDenied, "token_inventory.json");
  assert.match(neverSampled.status, /^not collected: Directory tokens\.list was not called because Directory users\.list was unreadable \(403 Forbidden/);
  assert.equal(neverSampled.endpoint, ENDPOINT.tokens);
  for (const field of ["data", "seen", "total", "failed", "failures", "readable_users", "truncated", "error", "errorKind"]) {
    assert.equal(neverSampled[field], null, `token_inventory.json ${field}`);
  }
  const zipUsers = JSON.parse(readZipEntries(usersDenied.zipPath).get("core_data/users.json"));
  assert.equal(zipUsers.data, null);
  assert.equal(zipUsers.status, users.status);

  // Every dataset file carries the same marker shape when its own read is denied.
  const allDenied = await exportGwsAuditBundle(createFakeCollector({
    collectUsers: denyOverrides("users", "403").collectUsers,
    collectRoles: denyOverrides("roles", "401").collectRoles,
    collectRoleAssignments: denyOverrides("roleAssignments", "error").collectRoleAssignments,
    collectActivities: async () => { throw denialError("403", "activities"); },
    collectAlerts: denyOverrides("alerts", "403").collectAlerts,
    collectTwoStepPolicies: denyOverrides("policies", "401").collectTwoStepPolicies,
  }), config, createTempBase("grclanker-gws-core-all-"));
  const expectedEndpoints = {
    "users.json": ENDPOINT.users,
    "roles.json": ENDPOINT.roles,
    "role_assignments.json": ENDPOINT.roleAssignments,
    "login_activities.json": ENDPOINT.activities("login"),
    "admin_activities.json": ENDPOINT.activities("admin"),
    "token_activities.json": ENDPOINT.activities("token"),
    "alerts.json": ENDPOINT.alerts,
    "two_step_verification_policies.json": ENDPOINT.policies,
  };
  for (const [name, endpoint] of Object.entries(expectedEndpoints)) {
    const file = readCore(allDenied, name);
    assert.equal(file.endpoint, endpoint, name);
    assert.match(file.status, new RegExp(`^unreadable: ${endpoint.replace(/[.()]/g, "\\$&")} \\(`), name);
    assert.ok(typeof file.error === "string" && file.error.length > 0, `${name} keeps the projected error`);
    assert.equal(file.data, null, name);
    assert.equal(file.seen, null, name);
    assert.equal(file.truncated, null, name);
    assertNoFabricatedValues(file, `core_data/${name}`);
  }
  assert.equal(readCore(allDenied, "role_assignments.json").error, "socket hang up");
  assert.equal(readCore(allDenied, "roles.json").errorKind, "unauthorized");

  // token_inventory.json: null data when every read failed, and truncated is null whenever any read failed.
  const tokensDenied = await exportGwsAuditBundle(createFakeCollector(denyOverrides("tokens", "403")), config, createTempBase("grclanker-gws-core-tokens-"));
  const unreadable = readCore(tokensDenied, "token_inventory.json");
  assert.match(unreadable.status, /^unreadable: Directory tokens\.list failed for all 4 sampled users \(super@example\.com: 403 Forbidden/);
  assert.equal(unreadable.data, null);
  assert.equal(unreadable.truncated, null);
  assert.equal(unreadable.readable_users, "0 of 4");
  assert.equal(unreadable.failed, 4);
  assert.equal(unreadable.failures.length, 4);
  assertNoFabricatedValues(unreadable, "core_data/token_inventory.json (all denied)");

  const oneDenied = await exportGwsAuditBundle(createFakeCollector(denyOverrides("tokens-user", "403")), config, createTempBase("grclanker-gws-core-one-"));
  const partial = readCore(oneDenied, "token_inventory.json");
  assert.match(partial.status, /^partial: Directory tokens\.list failed for 1 of 4 sampled users \(user@example\.com: 403 Forbidden/);
  assert.equal(partial.truncated, null, "the sample cap no longer describes completeness once a read failed");
  assert.equal(partial.readable_users, "3 of 4");
  assert.equal(partial.data.length, 1, "the readable users' tokens are kept");
  assert.deepEqual(partial.failures.map((failure) => failure.primaryEmail), ["user@example.com"]);

  // A fully readable run keeps its records, a complete status, and a boolean truncated flag.
  const readable = await exportGwsAuditBundle(createFakeCollector(), config, createTempBase("grclanker-gws-core-readable-"));
  const complete = readCore(readable, "users.json");
  assert.equal(complete.status, "complete: Directory users.list returned 4 record(s) across 1 page(s)");
  assert.equal(complete.data.length, 4);
  assert.equal(complete.seen, 4);
  assert.equal(complete.truncated, false);
  const completeTokens = readCore(readable, "token_inventory.json");
  assert.equal(completeTokens.status, "complete: Directory tokens.list read for all 4 sampled user(s)");
  assert.equal(completeTokens.truncated, false);
  assert.equal(completeTokens.readable_users, "4 of 4");
});

test("null standard: GWS-INTEG-001, 002, and 003 token counts render at least N naming the failed reads, or unreadable when no read succeeded", async () => {
  const config = createSampleConfig();
  const integrationsFor = async (source) => assessGwsIntegrations((await collectGwsAuditData(createFakeCollector(denyOverrides(source, "403")))).integrations, config);
  const lines = (finding, label) => finding.evidence.filter((line) => line.startsWith(`${label}: `));

  // Every sampled read failed: the counts are unknown, and the status names the endpoint and every failed user.
  const allDenied = await integrationsFor("tokens");
  for (const id of ["GWS-INTEG-001", "GWS-INTEG-002", "GWS-INTEG-003"]) {
    const finding = findingById(allDenied, id);
    assert.equal(finding.status, "Manual", id);
    assert.equal(finding.evidence.some((line) => /^(Token records collected|Privileged third-party tokens|High-scope token records|Third-party clients observed): \d+$/.test(line)), false, `${id}: ${finding.evidence.join("\n")}`);
  }
  const allDeniedStatus = /^unreadable \(Directory tokens\.list failed for all 4 sampled users \(super@example\.com: 403 Forbidden.*dormant@example\.com: 403 Forbidden.*\)\)$/;
  assert.match(findingById(allDenied, "GWS-INTEG-002").evidence.find((line) => line.startsWith("Token records collected: ")).slice("Token records collected: ".length), allDeniedStatus);
  assert.match(findingById(allDenied, "GWS-INTEG-002").evidence.find((line) => line.startsWith("Privileged third-party tokens: ")).slice("Privileged third-party tokens: ".length), allDeniedStatus);
  assert.match(findingById(allDenied, "GWS-INTEG-003").evidence.find((line) => line.startsWith("Token records collected: ")).slice("Token records collected: ".length), allDeniedStatus);
  assert.match(findingById(allDenied, "GWS-INTEG-002").summary, /the token inventory is unreadable; Directory tokens\.list failed for 4 of 4 sampled users including privileged super@example\.com, delegated@example\.com/);
  assert.equal(findingById(allDenied, "GWS-INTEG-001").summary.startsWith("Directory tokens.list was not readable"), true);

  // Only the token holder's read failed: every token count is a lower bound that names that user and the endpoint.
  const holderDenied = await integrationsFor("tokens-user");
  const bound = (count) => `at least ${count} (Directory tokens.list failed for 1 of 4 sampled users (user@example.com: ${FORBIDDEN_TEXT}))`;
  assert.equal(findingById(holderDenied, "GWS-INTEG-001").status, "Partial");
  assert.deepEqual(lines(findingById(holderDenied, "GWS-INTEG-001"), "Token records collected"), [`Token records collected: ${bound(1)}`]);
  assert.equal(findingById(holderDenied, "GWS-INTEG-002").status, "Partial");
  assert.deepEqual(lines(findingById(holderDenied, "GWS-INTEG-002"), "Privileged third-party tokens"), [`Privileged third-party tokens: ${bound(1)}`]);
  assert.equal(findingById(holderDenied, "GWS-INTEG-003").status, "Partial");
  assert.deepEqual(lines(findingById(holderDenied, "GWS-INTEG-003"), "High-scope token records"), [`High-scope token records: ${bound(1)}`]);
  assert.deepEqual(lines(findingById(holderDenied, "GWS-INTEG-003"), "Third-party clients observed"), [`Third-party clients observed: ${bound(1)}`]);

  // Only the privileged user's read failed: the same lower-bound wording names super@example.com on every token line.
  const privilegedDenied = await integrationsFor("tokens-super");
  const privilegedBound = (count) => `at least ${count} (Directory tokens.list failed for 1 of 4 sampled users (super@example.com: ${FORBIDDEN_TEXT}))`;
  assert.deepEqual(lines(findingById(privilegedDenied, "GWS-INTEG-001"), "Token records collected"), [`Token records collected: ${privilegedBound(2)}`]);
  assert.deepEqual(lines(findingById(privilegedDenied, "GWS-INTEG-002"), "Privileged third-party tokens"), [`Privileged third-party tokens: ${privilegedBound(1)}`]);
  assert.deepEqual(lines(findingById(privilegedDenied, "GWS-INTEG-003"), "High-scope token records"), [`High-scope token records: ${privilegedBound(1)}`]);
  for (const assessment of [holderDenied, privilegedDenied]) {
    assertDependentLinesAreBounded(assessment.findings.filter((finding) => finding.id !== "GWS-INTEG-004"), "tokens", "one tokens.list read denied");
  }

  // With every read successful the same labels render exact counts.
  const readable = assessGwsIntegrations((await collectGwsAuditData(createFakeCollector())).integrations, config);
  assert.deepEqual(lines(findingById(readable, "GWS-INTEG-001"), "Token records collected"), ["Token records collected: 2"]);
  assert.deepEqual(lines(findingById(readable, "GWS-INTEG-002"), "Privileged third-party tokens"), ["Privileged third-party tokens: 1"]);
});

/**
 * The reviewer's 34-scenario matrix: eleven surfaces (eight inventories, tokens.list for every user, for the privileged user, and for the
 * token holder) by three failure kinds, plus the never-collected Policy API dataset. Every finding line, snapshot field, and core_data
 * file is checked with the two generic guards, and evidence lines derived from the failed read must be bounds, never exact counts.
 */
test("null standard sweep: 34 denial scenarios render no fabricated value and no status naming an unrequested endpoint", async () => {
  const config = createSampleConfig();
  // Each export gets its own base: the bundle allocator only tries nine suffixes under one root.
  const freshBase = () => createTempBase("grclanker-gws-sweep-");
  const coreDataFiles = (result) => listFilesRecursively(join(result.outputDir, "core_data")).map((file) => [relative(result.outputDir, file), JSON.parse(readFileSync(file, "utf8"))]);
  const checkAll = (label, assessments, requested, coreData) => {
    const findings = assessments.flatMap((assessment) => assessment.findings);
    assertNoFabricatedValues(assessments.map((assessment) => assessment.snapshotSummary), `${label}: snapshots`);
    assertNoFabricatedValues(findings.map((finding) => finding.evidence), `${label}: evidence`);
    assertStatusesMatchRequests(assessments.map((assessment) => assessment.snapshotSummary), requested, `${label}: snapshots`);
    assertStatusesMatchRequests(findings.map((finding) => finding.evidence), requested, `${label}: evidence`);
    for (const [name, file] of coreData) {
      assertNoFabricatedValues(file, `${label}: ${name}`);
      assertStatusesMatchRequests(file, requested, `${label}: ${name}`);
    }
    return findings;
  };

  const baseline = recordingCollector();
  const baselineData = await collectGwsAuditData(baseline.collector);
  const baselineAssessments = assessAll(baselineData, config);
  const baselineBundle = await exportGwsAuditBundle(baseline.collector, config, freshBase());
  const baselineFindings = checkAll("baseline", baselineAssessments, baseline.requested, coreDataFiles(baselineBundle));
  assert.equal(baselineFindings.length, 19);
  assert.equal(baseline.requested.size, 9, "every endpoint is requested on the baseline");
  for (const [name, file] of coreDataFiles(baselineBundle)) assert.match(file.status, /^complete: /, name);

  const sources = ["users", "roles", "roleAssignments", "login", "admin", "token", "alerts", "policies", "tokens", "tokens-super", "tokens-user"];
  let scenarios = 0;
  for (const source of sources) {
    for (const kind of ["403", "401", "error"]) {
      const label = `${source} (${kind})`;
      const recorder = recordingCollector(denyOverrides(source, kind));
      const data = await collectGwsAuditData(recorder.collector);
      const assessments = assessAll(data, config);
      const bundle = await exportGwsAuditBundle(recorder.collector, config, freshBase());
      const findings = checkAll(label, assessments, recorder.requested, coreDataFiles(bundle));
      assertDependentLinesAreBounded(findings, source.startsWith("tokens") ? "tokens" : source, label);
      const expected = NULL_SNAPSHOT_FIELDS_BY_SOURCE[source.startsWith("tokens") ? "tokens" : source];
      const byCategory = snapshotByCategory(assessments);
      for (const [category, fields] of Object.entries(expected)) {
        for (const field of fields) {
          if (source.startsWith("tokens-")) {
            assert.match(byCategory[category].snapshotSummary[`${field}_status`], /^partial: at least \d+; Directory tokens\.list failed for 1 of 4 sampled users/, `${label}: ${category}.${field}_status`);
          } else {
            assert.equal(byCategory[category].snapshotSummary[field], null, `${label}: ${category}.${field}`);
          }
        }
      }
      if (source === "users") {
        assert.equal(recorder.requested.has(ENDPOINT.tokens), false, `${label}: tokens.list is never requested without a user inventory`);
        for (const category of ["identity", "admin_access"]) {
          assert.match(byCategory[category].snapshotSummary.users_seen_partial_view, /^unreadable \(Directory users\.list \(/, `${label}: ${category}.users_seen_partial_view`);
        }
      }
      scenarios += 1;
    }
  }

  // The 34th scenario: the Policy API dataset was never part of the run.
  const withoutPolicies = assessGwsIdentity({ ...baselineData.identity, twoStepPolicies: undefined }, config);
  assertNoFabricatedValues([withoutPolicies.snapshotSummary], "policy dataset undefined: snapshot");
  assertNoFabricatedValues(withoutPolicies.findings.map((finding) => finding.evidence), "policy dataset undefined: evidence");
  assert.equal(withoutPolicies.snapshotSummary.two_step_policies, null);
  assert.equal(withoutPolicies.snapshotSummary.two_step_policies_status, "not collected: Cloud Identity policies.list was not queried in this run");
  assert.equal(findingById(withoutPolicies, "GWS-ID-005").status, "Manual");
  scenarios += 1;
  assert.equal(scenarios, 34);

  // The guards bite: a snapshot in the old shape (0 beside an unreadable status) and a complete status naming an unrequested read both fail.
  assert.throws(() => assertNoFabricatedValues([{ active_users: 0, active_users_status: `unreadable: ${ENDPOINT.users} (403)` }], "old shape"), /active_users must be null beside status/);
  assert.throws(() => assertNoFabricatedValues([{ status: `unreadable: ${ENDPOINT.users} (403)`, data: [], seen: 0 }], "old core_data shape"), /renders \[\] beside status/);
  assert.throws(() => assertNoFabricatedValues([["Token records collected: 0 (unreadable Directory tokens.list)"]], "old line shape"), /renders a value beside an unavailable status/);
  assert.throws(() => assertStatusesMatchRequests([{ sampled_users_status: `complete: ${ENDPOINT.tokens} was attempted for 4 sampled user(s)` }], new Set([ENDPOINT.users]), "unrequested"), /was never requested/);
  assert.throws(() => assertDependentLinesAreBounded([{ id: "X", evidence: ["Token records collected: 0"] }], "tokens", "bare zero"), /renders "Token records collected: 0" while tokens failed/);
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
