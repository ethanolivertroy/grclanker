import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  SUMOLOGIC_CONTROLS,
  SUMOLOGIC_DEPLOYMENTS,
  SumologicApiClient,
  assessSumologicAccessControl,
  assessSumologicContentSharing,
  assessSumologicDataGovernance,
  assessSumologicIdentity,
  checkSumologicAccess,
  collectionOf,
  exportSumologicAuditBundle,
  failedCollection,
  resolveSecureOutputPath,
  resolveSumologicBaseUrl,
  resolveSumologicConfiguration,
} from "../dist/extensions/grc-tools/sumologic.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const NOW = new Date("2026-09-21T00:00:00Z");
const FRESH = "2026-09-01T00:00:00Z";
const STALE = "2025-01-01T00:00:00Z";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    accessId: "suABCDEF",
    accessKey: "secret-access-key-value",
    baseUrl: "https://api.us2.sumologic.com/api",
    deployment: "us2",
    timeoutMs: 30000,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    headers: { "content-type": "application/json", ...(options.headers ?? {}) },
  });
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()];
}

function healthyData() {
  return {
    accountStatus: { planType: "Paid", pricingModel: "credits" },
    users: [
      { id: "u1", email: "admin@example.com", isActive: true, isMfaEnabled: true, lastLoginTimestamp: FRESH },
      { id: "u2", email: "analyst@example.com", isActive: true, isMfaEnabled: true, lastLoginTimestamp: FRESH },
    ],
    roles: [
      { id: "r1", name: "Administrator", systemDefined: true, capabilities: ["manageUsersAndRoles"], users: ["u1"], filterPredicate: "" },
      { id: "r2", name: "Analyst", systemDefined: true, capabilities: ["viewCollectors"], users: ["u2"], filterPredicate: "_sourceCategory=prod" },
    ],
    accessKeys: [
      { id: "k1", label: "ci-key", disabled: false, createdAt: FRESH, lastUsed: FRESH, corsHeaders: [] },
    ],
    identityProviders: [
      { id: "idp1", configurationName: "Okta", issuer: "okta", x509cert1: "CERT", signAuthnRequest: true, disableRequestedAuthnContext: false, debugMode: false, spInitiatedLoginEnabled: true },
    ],
    allowlistedUsers: [{ userId: "u1", email: "admin@example.com", isActive: true }],
    passwordPolicy: {
      minLength: 14,
      mustContainLowercase: true,
      mustContainUppercase: true,
      mustContainDigits: true,
      mustContainSpecialChars: true,
      maxPasswordAgeInDays: 60,
      accountLockoutThreshold: 5,
      requireMfa: true,
      disallowWeakPasswords: true,
    },
    allowlistStatus: { loginEnabled: true, contentEnabled: true },
    allowlistAddresses: [{ cidr: "203.0.113.0/24", description: "office" }],
    policies: {
      audit: { enabled: true },
      searchAudit: { enabled: true },
      shareDashboardsOutsideOrganization: { enabled: false },
      dataAccessLevel: { enabled: true },
      userConcurrentSessionsLimit: { enabled: true, maxConcurrentSessions: 2 },
      maxUserSessionTimeout: { maxUserSessionTimeout: "15m" },
      accessKeysLifetime: { accessKeysLifetimeInDays: "90" },
    },
    partitions: [
      { id: "p1", name: "sumologic_default", indexType: "DefaultIndex", isActive: true, retentionPeriod: 400 },
      { id: "p2", name: "sumologic_audit_events", indexType: "AuditIndex", isActive: true, retentionPeriod: 400 },
    ],
    scheduledViews: [{ id: "sv1", indexName: "errors", retentionPeriod: 400 }],
    ingestBudgets: [{ id: "b1", name: "prod-budget", action: "stopCollecting", usageStatus: "Normal" }],
    connections: [],
    collectors: [
      { id: 1, name: "web-1", collectorType: "Installable", alive: true, ephemeral: false, collectorVersion: "19.500-1" },
      { id: 2, name: "hosted", collectorType: "Hosted", alive: true, ephemeral: false },
    ],
    monitors: [
      {
        id: "m1",
        name: "Failed logins",
        isDisabled: false,
        runAs: { runAsId: "u2" },
        notifications: [{ notification: { connectionType: "Email", recipients: ["secops@example.com"] }, runForTriggerTypes: ["Critical"] }],
      },
    ],
    personalFolder: { id: "f1", children: [{ id: "c1", name: "Search A", itemType: "Search", isScheduled: false }] },
    dashboards: [{ id: "d1", title: "SOC", isPublic: false }],
    permissions: { explicitPermissions: [{ permissionName: "View", sourceType: "user", sourceId: "u1", contentId: "c1" }], implicitPermissions: [] },
  };
}

function readerFrom(data, overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    getAccountStatus: async () => collectionOf(data.accountStatus),
    listUsers: async () => collectionOf(data.users),
    listRoles: async () => collectionOf(data.roles),
    listAccessKeys: async () => collectionOf(data.accessKeys),
    listSamlIdentityProviders: async () => collectionOf(data.identityProviders),
    listSamlAllowlistedUsers: async () => collectionOf(data.allowlistedUsers),
    getPasswordPolicy: async () => collectionOf(data.passwordPolicy),
    getServiceAllowlistStatus: async () => collectionOf(data.allowlistStatus),
    listServiceAllowlistAddresses: async () => collectionOf(data.allowlistAddresses),
    getPolicy: async (name) => collectionOf(data.policies[name] ?? {}),
    listPartitions: async () => collectionOf(data.partitions),
    listScheduledViews: async () => collectionOf(data.scheduledViews),
    listIngestBudgets: async () => collectionOf(data.ingestBudgets),
    listConnections: async () => collectionOf(data.connections),
    listCollectors: async () => collectionOf(data.collectors),
    listMonitors: async () => collectionOf(data.monitors),
    getPersonalFolder: async () => collectionOf(data.personalFolder),
    listDashboards: async () => collectionOf(data.dashboards),
    getContentPermissions: async () => collectionOf(data.permissions),
    ...overrides,
  };
}

function forbiddenReader() {
  const forbidden = async () => failedCollection("Sumo Logic request failed (403 forbidden)", 403);
  return {
    getResolvedConfig: () => sampleConfig(),
    getAccountStatus: forbidden,
    listUsers: forbidden,
    listRoles: forbidden,
    listAccessKeys: forbidden,
    listSamlIdentityProviders: forbidden,
    listSamlAllowlistedUsers: forbidden,
    getPasswordPolicy: forbidden,
    getServiceAllowlistStatus: forbidden,
    listServiceAllowlistAddresses: forbidden,
    getPolicy: forbidden,
    listPartitions: forbidden,
    listScheduledViews: forbidden,
    listIngestBudgets: forbidden,
    listConnections: forbidden,
    listCollectors: forbidden,
    listMonitors: forbidden,
    getPersonalFolder: forbidden,
    listDashboards: forbidden,
    getContentPermissions: forbidden,
  };
}

function emptyReader() {
  return readerFrom({
    accountStatus: {},
    users: [],
    roles: [],
    accessKeys: [],
    identityProviders: [],
    allowlistedUsers: [],
    passwordPolicy: {},
    allowlistStatus: {},
    allowlistAddresses: [],
    policies: {},
    partitions: [],
    scheduledViews: [],
    ingestBudgets: [],
    connections: [],
    collectors: [],
    monitors: [],
    personalFolder: {},
    dashboards: [],
    permissions: {},
  });
}

function partialReader() {
  const data = healthyData();
  const partial = (items) => collectionOf(items, { complete: false });
  return readerFrom(data, {
    listUsers: async () => partial(data.users),
    listRoles: async () => partial(data.roles),
    listAccessKeys: async () => collectionOf(data.accessKeys, { scope: "personal" }),
    listPartitions: async () => partial(data.partitions),
    listIngestBudgets: async () => partial(data.ingestBudgets),
    listConnections: async () => partial(data.connections),
    listCollectors: async () => partial(data.collectors),
    listMonitors: async () => partial(data.monitors),
    listDashboards: async () => partial(data.dashboards),
  });
}

async function allAssessments(reader) {
  return [
    await assessSumologicIdentity(reader, { now: NOW }),
    await assessSumologicAccessControl(reader, { now: NOW }),
    await assessSumologicDataGovernance(reader, { now: NOW }),
    await assessSumologicContentSharing(reader, { now: NOW }),
  ];
}

function byId(result, id) {
  return result.findings.find((item) => item.id === id);
}

test("resolveSumologicConfiguration prefers args over env over config file and maps deployments", () => {
  const dir = createTempBase("grclanker-sumo-config-");
  const configFile = join(dir, "config.yaml");
  writeFileSync(configFile, "access_id: file-id\naccess_key: file-key\nendpoint: eu\n");

  const fromFile = resolveSumologicConfiguration({}, { SUMOLOGIC_CONFIG_FILE: configFile });
  assert.equal(fromFile.accessId, "file-id");
  assert.equal(fromFile.baseUrl, "https://api.eu.sumologic.com/api");
  assert.equal(fromFile.deployment, "eu");
  assert.ok(fromFile.sourceChain.includes("config-file-access-id"));

  const fromEnv = resolveSumologicConfiguration({}, {
    SUMOLOGIC_CONFIG_FILE: configFile,
    SUMOLOGIC_ACCESS_ID: "env-id",
    SUMOLOGIC_ACCESS_KEY: "env-key",
    SUMOLOGIC_ENDPOINT: "https://api.us2.sumologic.com/api",
  });
  assert.equal(fromEnv.accessId, "env-id");
  assert.equal(fromEnv.baseUrl, "https://api.us2.sumologic.com/api");
  assert.equal(fromEnv.deployment, "us2");

  const fromArgs = resolveSumologicConfiguration(
    { access_id: "arg-id", access_key: "arg-key", endpoint: "fed", timeout_seconds: 9 },
    { SUMOLOGIC_CONFIG_FILE: configFile, SUMOLOGIC_ACCESS_ID: "env-id", SUMOLOGIC_ACCESS_KEY: "env-key", SUMOLOGIC_ENDPOINT: "eu" },
  );
  assert.equal(fromArgs.accessId, "arg-id");
  assert.equal(fromArgs.accessKey, "arg-key");
  assert.equal(fromArgs.baseUrl, "https://api.fed.sumologic.com/api");
  assert.equal(fromArgs.timeoutMs, 9000);
  assert.ok(fromArgs.sourceChain.includes("arguments-access-id"));

  const defaulted = resolveSumologicConfiguration({ access_id: "a", access_key: "b" }, { SUMOLOGIC_CONFIG_FILE: join(dir, "missing.yaml") });
  assert.equal(defaulted.baseUrl, "https://api.sumologic.com/api");
  assert.equal(defaulted.deployment, "us1");

  assert.throws(() => resolveSumologicConfiguration({}, { SUMOLOGIC_CONFIG_FILE: join(dir, "missing.yaml") }), /SUMOLOGIC_ACCESS_ID/);
});

test("resolveSumologicBaseUrl maps every documented deployment and normalizes URLs", () => {
  const expected = {
    au: "https://api.au.sumologic.com/api",
    ca: "https://api.ca.sumologic.com/api",
    ch: "https://api.ch.sumologic.com/api",
    de: "https://api.de.sumologic.com/api",
    esc: "https://api.esc.sumologic.com/api",
    eu: "https://api.eu.sumologic.com/api",
    fed: "https://api.fed.sumologic.com/api",
    in: "https://api.in.sumologic.com/api",
    jp: "https://api.jp.sumologic.com/api",
    kr: "https://api.kr.sumologic.com/api",
    us1: "https://api.sumologic.com/api",
    us2: "https://api.us2.sumologic.com/api",
  };
  assert.deepEqual(SUMOLOGIC_DEPLOYMENTS, expected);
  for (const [code, url] of Object.entries(expected)) {
    assert.deepEqual(resolveSumologicBaseUrl(code), { baseUrl: url, deployment: code });
    assert.deepEqual(resolveSumologicBaseUrl(code.toUpperCase()), { baseUrl: url, deployment: code });
  }
  assert.equal(resolveSumologicBaseUrl("https://api.sumologic.com").baseUrl, "https://api.sumologic.com/api");
  assert.equal(resolveSumologicBaseUrl("https://api.jp.sumologic.com/api/v1/").baseUrl, "https://api.jp.sumologic.com/api");
  assert.throws(() => resolveSumologicBaseUrl("mars"), /Unknown Sumo Logic deployment/);
});

test("SumologicApiClient sends basic auth, follows token pagination, retries 429 and 5xx, and redacts the key", async () => {
  const seen = [];
  let usersAttempt = 0;
  const sleeps = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, search: url.search, auth: headerValue(init.headers, "authorization") });
    if (url.pathname === "/api/v1/users") {
      usersAttempt += 1;
      if (usersAttempt === 1) return jsonResponse({ errors: [{ code: "rate.limit.exceeded" }] }, { status: 429, headers: { "retry-after": "1" } });
      if (usersAttempt === 2) return jsonResponse({ message: "boom" }, { status: 503 });
      if (!url.searchParams.get("token")) return jsonResponse({ data: [{ id: "u1" }], next: "page-2" });
      return jsonResponse({ data: [{ id: "u2" }], next: null });
    }
    if (url.pathname === "/api/v1/roles") {
      return jsonResponse({ errors: [{ code: "forbidden", message: "secret-access-key-value should not leak" }] }, { status: 403 });
    }
    return jsonResponse({});
  };
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl, sleepImpl: async (ms) => { sleeps.push(ms); } });

  const users = await client.listUsers();
  assert.equal(users.ok, true);
  assert.equal(users.complete, true);
  assert.deepEqual(users.data.map((user) => user.id), ["u1", "u2"]);
  assert.equal(seen[0].auth, `Basic ${Buffer.from("suABCDEF:secret-access-key-value").toString("base64")}`);
  assert.deepEqual(sleeps.slice(0, 2), [1000, 500]);
  assert.ok(seen.some((item) => item.search.includes("token=page-2")));
  assert.ok(seen.every((item) => item.pathname !== "/api/v1/users" || item.search.includes("limit=1000")));

  const roles = await client.listRoles();
  assert.equal(roles.ok, false);
  assert.equal(roles.httpStatus, 403);
  assert.doesNotMatch(roles.error, /secret-access-key-value/);
  assert.match(roles.error, /\[REDACTED\]/);
});

test("SumologicApiClient marks capped pagination incomplete, paginates collectors and monitors by offset, and falls back to personal keys", async () => {
  const requests = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push(`${url.pathname}${url.search}`);
    if (url.pathname === "/api/v1/partitions") return jsonResponse({ data: [{ id: `p-${url.searchParams.get("token") ?? "0"}` }], next: "more" });
    if (url.pathname === "/api/v1/collectors") {
      const offset = Number(url.searchParams.get("offset"));
      return jsonResponse({ collectors: offset === 0 ? Array.from({ length: 1000 }, (_, index) => ({ id: index })) : [{ id: 1000 }] });
    }
    if (url.pathname === "/api/v1/monitors/search") return jsonResponse([{ item: { id: "m1", name: "Monitor" }, path: "/Monitor/m1" }]);
    if (url.pathname === "/api/v1/accessKeys") return jsonResponse({ errors: [{ code: "forbidden" }] }, { status: 403 });
    if (url.pathname === "/api/v1/accessKeys/personal") return jsonResponse({ data: [{ id: "k1", label: "mine" }] });
    return jsonResponse({});
  };
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl, maxPages: 2, maxRetries: 0 });

  const partitions = await client.listPartitions();
  assert.equal(partitions.ok, true);
  assert.equal(partitions.complete, false);
  assert.equal(partitions.data.length, 2);
  assert.ok(requests[0].includes("viewTypes=DefaultView%2CPartition%2CAuditIndex"));

  const collectors = await client.listCollectors();
  assert.equal(collectors.complete, true);
  assert.equal(collectors.data.length, 1001);
  assert.ok(requests.some((item) => item.includes("/api/v1/collectors?limit=1000&offset=1000")));

  const monitors = await client.listMonitors();
  assert.equal(monitors.data[0].name, "Monitor");
  assert.equal(monitors.data[0].path, "/Monitor/m1");
  assert.ok(requests.some((item) => item.includes("/api/v1/monitors/search?query=type%3Amonitor")));

  const keys = await client.listAccessKeys();
  assert.equal(keys.ok, true);
  assert.equal(keys.scope, "personal");
  assert.deepEqual(keys.data.map((key) => key.label), ["mine"]);
});

test("checkSumologicAccess reports healthy and degraded surfaces with capability hints", async () => {
  const healthy = await checkSumologicAccess(readerFrom(healthyData()));
  assert.equal(healthy.status, "healthy");
  assert.equal(healthy.surfaces.length, 18);
  assert.equal(healthy.missingCapabilities.length, 0);
  assert.match(healthy.recommendedNextStep, /sumologic_assess_identity/);
  const addresses = healthy.surfaces.find((surface) => surface.endpoint === "/v1/serviceAllowlist/addresses");
  assert.equal(addresses.name, "service_allowlist_addresses");
  assert.equal(addresses.status, "readable");
  assert.equal(addresses.count, 1);
  assert.equal(addresses.capabilityHint, "ipAllowlisting");

  const degraded = await checkSumologicAccess(readerFrom(healthyData(), {
    listUsers: async () => failedCollection("forbidden", 403),
    listCollectors: async () => failedCollection("forbidden", 403),
    listServiceAllowlistAddresses: async () => failedCollection("forbidden", 403),
  }));
  assert.equal(degraded.status, "limited");
  assert.ok(degraded.missingCapabilities.includes("manageUsersAndRoles"));
  assert.ok(degraded.missingCapabilities.includes("viewCollectors"));
  assert.ok(degraded.missingCapabilities.includes("ipAllowlisting"));
  assert.equal(degraded.surfaces.find((surface) => surface.name === "service_allowlist_addresses").status, "not_readable");
  assert.match(degraded.recommendedNextStep, /never as passes/);
});

test("all four assessments cover the 20 spec controls with framework mappings", async () => {
  const results = await allAssessments(readerFrom(healthyData()));
  const ids = results.flatMap((result) => result.findings.map((item) => item.id)).sort();
  assert.deepEqual(ids, SUMOLOGIC_CONTROLS.map((item) => item.id).sort());
  assert.equal(new Set(ids).size, 20);
  for (const item of results.flatMap((result) => result.findings)) {
    assert.equal(item.mappings.length, 8, `${item.id} mappings`);
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("FedRAMP ")));
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("ISMAP ")));
  }
  assert.equal(byId(results[0], "SUMO-01").mappings[0], "FedRAMP IA-2");
  assert.equal(byId(results[3], "SUMO-20").mappings[4], "PCI-DSS 10.6.1");
});

test("healthy fixtures pass where evidence is complete and stay manual where the API cannot verify", async () => {
  const [identity, access, data, content] = await allAssessments(readerFrom(healthyData()));
  assert.equal(byId(identity, "SUMO-01").status, "manual");
  assert.match(byId(identity, "SUMO-01").summary, /Require SAML sign-in/);
  assert.equal(byId(identity, "SUMO-02").status, "pass");
  assert.equal(byId(identity, "SUMO-03").status, "pass");
  assert.equal(byId(identity, "SUMO-04").status, "pass");
  assert.equal(byId(identity, "SUMO-05").status, "pass");
  assert.equal(byId(access, "SUMO-06").status, "pass");
  assert.equal(byId(access, "SUMO-07").status, "pass");
  assert.equal(byId(access, "SUMO-08").status, "pass");
  assert.equal(byId(access, "SUMO-13").status, "pass");
  assert.equal(byId(access, "SUMO-14").status, "pass");
  assert.equal(byId(data, "SUMO-09").status, "pass");
  assert.equal(byId(data, "SUMO-10").status, "pass");
  assert.equal(byId(data, "SUMO-12").status, "pass");
  assert.equal(byId(data, "SUMO-16").status, "pass");
  assert.equal(byId(data, "SUMO-17").status, "pass");
  assert.equal(byId(content, "SUMO-11").status, "pass");
  assert.equal(byId(content, "SUMO-15").status, "manual");
  assert.equal(byId(content, "SUMO-18").status, "manual");
  assert.match(byId(content, "SUMO-18").summary, /no lookup table listing endpoint/);
  assert.equal(byId(content, "SUMO-19").status, "pass");
  assert.equal(byId(content, "SUMO-20").status, "pass");
});

test("failing fixtures fail the corresponding controls", async () => {
  const data = healthyData();
  data.identityProviders = [];
  data.passwordPolicy = { ...data.passwordPolicy, minLength: 8, maxPasswordAgeInDays: 0, requireMfa: false };
  data.roles.push({ id: "r3", name: "Power", systemDefined: false, capabilities: ["manageUsersAndRoles"], users: ["u2", "u3", "u4", "u5", "u6", "u7"] });
  data.accessKeys = [{ id: "k2", label: "old", disabled: false, createdAt: STALE, lastUsed: STALE }];
  data.allowlistStatus = { loginEnabled: false, contentEnabled: false };
  data.policies.maxUserSessionTimeout = { maxUserSessionTimeout: "1d" };
  data.policies.audit = { enabled: false };
  data.ingestBudgets = [];
  data.partitions[1].retentionPeriod = 30;
  data.collectors = [{ id: 3, name: "dead", collectorType: "Installable", alive: false, ephemeral: false, lastSeenAlive: Date.parse(STALE), collectorVersion: "19.1" }];
  data.policies.dataAccessLevel = { enabled: false };
  data.policies.shareDashboardsOutsideOrganization = { enabled: true };
  data.monitors[0].notifications = [{ notification: { connectionType: "Email", recipients: ["someone@gmail.com"] }, runForTriggerTypes: ["Critical"] }];
  data.connections = [{ id: "c1", name: "hook", type: "WebhookConnection", url: "https://hooks.evil.example/x" }];

  const [identity, access, governance, content] = await allAssessments(readerFrom(data));
  assert.equal(byId(identity, "SUMO-01").status, "fail");
  assert.equal(byId(identity, "SUMO-02").status, "manual");
  assert.match(byId(identity, "SUMO-02").summary, /Not applicable/);
  assert.equal(byId(identity, "SUMO-03").status, "fail");
  assert.equal(byId(identity, "SUMO-04").status, "fail");
  assert.equal(byId(identity, "SUMO-05").status, "fail");
  assert.equal(byId(access, "SUMO-06").status, "fail");
  assert.equal(byId(access, "SUMO-07").status, "fail");
  assert.equal(byId(access, "SUMO-08").status, "fail");
  assert.equal(byId(access, "SUMO-13").status, "fail");
  assert.equal(byId(access, "SUMO-14").status, "fail");
  assert.equal(byId(governance, "SUMO-09").status, "fail");
  assert.equal(byId(governance, "SUMO-12").status, "fail");
  assert.equal(byId(governance, "SUMO-16").status, "fail");
  assert.equal(byId(governance, "SUMO-17").status, "fail");
  assert.equal(byId(governance, "SUMO-10").status, "manual");
  assert.equal(byId(content, "SUMO-11").status, "fail");
  assert.equal(byId(content, "SUMO-19").status, "fail");
  assert.equal(byId(content, "SUMO-20").status, "fail");

  const approved = await assessSumologicDataGovernance(readerFrom(data), { now: NOW, approvedDestinationDomains: ["example.com"] });
  assert.equal(byId(approved, "SUMO-10").status, "fail");
});

test("self-check (a): every endpoint forbidden yields only manual findings that name the cause", async () => {
  const results = await allAssessments(forbiddenReader());
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} must not pass on 403`);
    assert.equal(item.status, "manual", `${item.id} should be manual on 403`);
    assert.match(item.summary, /403|unreadable|not exposed|Collect manually|unknown error|human/i, `${item.id} summary names the cause`);
  }
  assert.match(byId(results[0], "SUMO-01").summary, /lacks the role capability \(403\)/);
  assert.ok(results.every((result) => result.errors.length > 0));
});

test("self-check (b): empty inventories never pass by default and state whether emptiness fails or needs review", async () => {
  const results = await allAssessments(emptyReader());
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  const passes = findings.filter((item) => item.status === "pass").map((item) => item.id);
  assert.deepEqual(passes, [], `unexpected passes on empty data: ${passes.join(", ")}`);
  const byIdMap = Object.fromEntries(findings.map((item) => [item.id, item]));
  assert.equal(byIdMap["SUMO-01"].status, "fail");
  assert.match(byIdMap["SUMO-01"].summary, /Zero SAML identity providers/);
  assert.equal(byIdMap["SUMO-02"].status, "manual");
  assert.equal(byIdMap["SUMO-06"].status, "manual");
  assert.equal(byIdMap["SUMO-13"].status, "fail");
  assert.equal(byIdMap["SUMO-16"].status, "fail");
  assert.match(byIdMap["SUMO-16"].summary, /Zero ingest budgets/);
  assert.equal(byIdMap["SUMO-17"].status, "manual");
  assert.equal(byIdMap["SUMO-12"].status, "manual");
  assert.equal(byIdMap["SUMO-20"].status, "manual");
  assert.equal(byIdMap["SUMO-09"].status, "fail");
  assert.equal(byIdMap["SUMO-11"].status, "fail");
  assert.equal(byIdMap["SUMO-05"].status, "fail");
  assert.match(byIdMap["SUMO-05"].summary, /requireMfa=absent/);
  assert.equal(byIdMap["SUMO-07"].status, "manual");
  assert.match(byIdMap["SUMO-07"].summary, /did not include accessKeysLifetimeInDays/);
});

test("self-check (b) exception: empty lists pass only where the control intent makes emptiness compliant and the endpoint was readable", async () => {
  const data = healthyData();
  data.allowlistedUsers = [];
  data.connections = [];
  const [identity, , governance] = await allAssessments(readerFrom(data));
  assert.equal(byId(identity, "SUMO-02").status, "pass");
  assert.match(byId(identity, "SUMO-02").summary, /0 SAML allowlisted user\(s\) \(endpoint readable/);
  assert.equal(byId(governance, "SUMO-10").status, "pass");
  assert.match(byId(governance, "SUMO-10").summary, /Zero outbound connections .* \(endpoints readable\)/);
});

test("self-check (c): partial inventories never pass", async () => {
  const results = await allAssessments(partialReader());
  const findings = results.flatMap((result) => result.findings);
  const passes = findings.filter((item) => item.status === "pass").map((item) => item.id);
  const allowedPasses = ["SUMO-02", "SUMO-03", "SUMO-04", "SUMO-13", "SUMO-14", "SUMO-09", "SUMO-11"];
  const unexpected = passes.filter((id) => !allowedPasses.includes(id));
  assert.deepEqual(unexpected, [], `partial inventories must not pass: ${unexpected.join(", ")}`);
  const byIdMap = Object.fromEntries(findings.map((item) => [item.id, item]));
  assert.equal(byIdMap["SUMO-05"].status, "warn");
  assert.match(byIdMap["SUMO-05"].summary, /Pagination stopped before the last page/);
  assert.equal(byIdMap["SUMO-06"].status, "warn");
  assert.equal(byIdMap["SUMO-07"].status, "manual");
  assert.match(byIdMap["SUMO-07"].summary, /Partial view: 1 personal access key/);
  assert.equal(byIdMap["SUMO-08"].status, "manual");
  assert.equal(byIdMap["SUMO-12"].status, "warn");
  assert.equal(byIdMap["SUMO-16"].status, "warn");
  assert.equal(byIdMap["SUMO-17"].status, "warn");
  assert.equal(byIdMap["SUMO-19"].status, "warn");
  assert.equal(byIdMap["SUMO-20"].status, "warn");
});

test("SumologicApiClient caps the dashboards page size at 100 and follows the dashboards cursor", async () => {
  const requests = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push({ pathname: url.pathname, limit: url.searchParams.get("limit"), token: url.searchParams.get("token"), mode: url.searchParams.get("mode") });
    if (url.pathname === "/api/v2/dashboards") {
      if (Number(url.searchParams.get("limit")) > 100) return jsonResponse({ errors: [{ code: "invalid.limit", message: "limit must be at most 100" }] }, { status: 400 });
      if (!url.searchParams.get("token")) return jsonResponse({ dashboards: Array.from({ length: 100 }, (_, index) => ({ id: `d${index}`, title: `Dashboard ${index}`, isPublic: false })), next: "page-2" });
      return jsonResponse({ dashboards: [{ id: "d100", title: "Last", isPublic: false }], next: null });
    }
    if (url.pathname === "/api/v1/users") return jsonResponse({ data: [{ id: "u1" }], next: null });
    return jsonResponse({});
  };
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl, maxRetries: 0 });

  const dashboards = await client.listDashboards();
  assert.equal(dashboards.ok, true, dashboards.error);
  assert.equal(dashboards.complete, true);
  assert.equal(dashboards.data.length, 101);
  const dashboardRequests = requests.filter((item) => item.pathname === "/api/v2/dashboards");
  assert.equal(dashboardRequests.length, 2);
  assert.ok(dashboardRequests.every((item) => item.limit === "100" && item.mode === "allViewableByUser"));
  assert.equal(dashboardRequests[1].token, "page-2");

  await client.listUsers();
  assert.equal(requests.find((item) => item.pathname === "/api/v1/users").limit, "1000");

  const access = await checkSumologicAccess(client);
  assert.equal(access.surfaces.find((surface) => surface.name === "dashboards").status, "readable");
});

test("control 11 downgrades when the personal folder holds more items than content_sample", async () => {
  const data = healthyData();
  data.personalFolder = { id: "f1", children: Array.from({ length: 40 }, (_, index) => ({ id: `c${index}`, name: `Search ${index}`, itemType: "Search" })) };
  let permissionLookups = 0;
  const reader = readerFrom(data, { getContentPermissions: async () => { permissionLookups += 1; return collectionOf(data.permissions); } });

  const sampled = await assessSumologicContentSharing(reader, { now: NOW });
  const sharing = byId(sampled, "SUMO-11");
  assert.equal(permissionLookups, 25);
  assert.equal(sharing.status, "warn");
  assert.match(sharing.summary, /Only 25 of 40 personal-folder items were sampled \(content_sample=25\); 15 were not evaluated/);
  assert.equal(sharing.evidence.personal_folder_items_total, 40);
  assert.equal(sharing.evidence.personal_folder_items_sampled, 25);
  assert.equal(sharing.evidence.personal_folder_items_unsampled, 15);
  assert.equal(sampled.summary.personal_folder_items_unsampled, 15);
  assert.equal(byId(sampled, "SUMO-15").evidence.personal_folder_items_total, 40);
  assert.equal(byId(sampled, "SUMO-18").evidence.personal_folder_items_total, 40);

  const full = await assessSumologicContentSharing(readerFrom(data), { now: NOW, contentSample: 40 });
  assert.equal(byId(full, "SUMO-11").status, "pass");
  assert.match(byId(full, "SUMO-11").summary, /all 40 items in the folder were evaluated/);
  assert.equal(byId(full, "SUMO-11").evidence.personal_folder_items_unsampled, 0);
});

test("control 7 treats an access key lifetime policy of 0 or absent as at most warn and always states the policy", async () => {
  const healthy = await assessSumologicAccessControl(readerFrom(healthyData()), { now: NOW });
  assert.equal(byId(healthy, "SUMO-07").status, "pass");
  assert.match(byId(healthy, "SUMO-07").summary, /The access key lifetime policy is 90 days\./);
  assert.equal(byId(healthy, "SUMO-07").evidence.access_keys_lifetime_policy_state, "enforced");

  const neverExpire = healthyData();
  neverExpire.policies.accessKeysLifetime = { accessKeysLifetimeInDays: "0" };
  const zero = await assessSumologicAccessControl(readerFrom(neverExpire), { now: NOW });
  assert.equal(byId(zero, "SUMO-07").status, "warn");
  assert.match(byId(zero, "SUMO-07").summary, /The access key lifetime policy is 0 \(keys never expire\)\./);
  assert.equal(byId(zero, "SUMO-07").evidence.access_keys_lifetime_policy_days, 0);
  assert.equal(byId(zero, "SUMO-07").evidence.access_keys_lifetime_policy_state, "never-expire");
  assert.equal(byId(zero, "SUMO-08").status, "pass");

  const absent = healthyData();
  absent.policies.accessKeysLifetime = {};
  const missing = await assessSumologicAccessControl(readerFrom(absent), { now: NOW });
  assert.equal(byId(missing, "SUMO-07").status, "warn");
  assert.match(byId(missing, "SUMO-07").summary, /did not include accessKeysLifetimeInDays/);
  assert.equal(byId(missing, "SUMO-07").evidence.access_keys_lifetime_policy_state, "absent");

  const unreadable = await assessSumologicAccessControl(readerFrom(healthyData(), {
    getPolicy: async (name) => (name === "accessKeysLifetime" ? failedCollection("forbidden", 403) : collectionOf(healthyData().policies[name] ?? {})),
  }), { now: NOW });
  assert.equal(byId(unreadable, "SUMO-07").status, "warn");
  assert.match(byId(unreadable, "SUMO-07").summary, /lifetime policy was unreadable/);

  const stale = healthyData();
  stale.policies.accessKeysLifetime = { accessKeysLifetimeInDays: "0" };
  stale.accessKeys = [{ id: "k2", label: "old", disabled: false, createdAt: STALE, lastUsed: FRESH }];
  const failed = await assessSumologicAccessControl(readerFrom(stale), { now: NOW });
  assert.equal(byId(failed, "SUMO-07").status, "fail");
  assert.match(byId(failed, "SUMO-07").summary, /have not been rotated\. The access key lifetime policy is 0 \(keys never expire\)\./);

  const personal = await assessSumologicAccessControl(readerFrom(stale, { listAccessKeys: async () => collectionOf(stale.accessKeys, { scope: "personal" }) }), { now: NOW });
  assert.equal(byId(personal, "SUMO-07").status, "manual");
  assert.match(byId(personal, "SUMO-07").summary, /The access key lifetime policy is 0/);
});

test("control 6 warns on custom roles without a filterPredicate and names them", async () => {
  const data = healthyData();
  data.roles.push({ id: "r4", name: "Wide Open", systemDefined: false, capabilities: ["viewCollectors"], users: ["u2"] });
  const unscoped = await assessSumologicAccessControl(readerFrom(data), { now: NOW });
  assert.equal(byId(unscoped, "SUMO-06").status, "warn");
  assert.match(byId(unscoped, "SUMO-06").summary, /1 custom role\(s\) have no filterPredicate and grant unrestricted search scope \(Wide Open\)/);
  assert.deepEqual(byId(unscoped, "SUMO-06").evidence.custom_roles_without_filter_predicate, ["Wide Open"]);

  data.roles[2].filterPredicate = "_sourceCategory=web";
  const scoped = await assessSumologicAccessControl(readerFrom(data), { now: NOW });
  assert.equal(byId(scoped, "SUMO-06").status, "pass");
  assert.match(byId(scoped, "SUMO-06").summary, /every custom role carries a filterPredicate/);

  const systemUnscoped = healthyData();
  systemUnscoped.roles.push({ id: "r5", name: "Analyst (system)", systemDefined: true, capabilities: ["viewCollectors"], users: [] });
  const system = await assessSumologicAccessControl(readerFrom(systemUnscoped), { now: NOW });
  assert.equal(byId(system, "SUMO-06").status, "pass");
});

test("controls 5 and 6 report locked and dormant users and keep undated logins out of the active bucket", async () => {
  const data = healthyData();
  data.users.push(
    { id: "u3", email: "locked@example.com", isActive: true, isMfaEnabled: true, isLocked: true, lastLoginTimestamp: FRESH },
    { id: "u4", email: "dormant@example.com", isActive: true, isMfaEnabled: true, isLocked: false, lastLoginTimestamp: STALE },
    { id: "u5", email: "never@example.com", isActive: true, isMfaEnabled: true, isLocked: false, lastLoginTimestamp: null },
  );
  const [identity, access] = await allAssessments(readerFrom(data));
  const mfa = byId(identity, "SUMO-05");
  assert.equal(mfa.status, "pass");
  assert.deepEqual(mfa.evidence.locked_users, ["locked@example.com"]);
  assert.deepEqual(mfa.evidence.dormant_active_users, ["dormant@example.com"]);
  assert.deepEqual(mfa.evidence.active_users_without_last_login, ["never@example.com"]);
  assert.equal(mfa.evidence.active_users_with_recent_login, 3);
  assert.equal(mfa.evidence.user_inactive_threshold_days, 90);
  assert.equal(identity.summary.locked_users, 1);
  assert.equal(identity.summary.dormant_active_users, 1);
  assert.equal(identity.summary.active_users_without_last_login, 1);

  const rbac = byId(access, "SUMO-06");
  assert.equal(rbac.status, "pass");
  assert.deepEqual(rbac.evidence.locked_users, ["locked@example.com"]);
  assert.deepEqual(rbac.evidence.dormant_active_users, ["dormant@example.com"]);
  assert.deepEqual(rbac.evidence.active_users_without_last_login, ["never@example.com"]);
  assert.deepEqual(rbac.evidence.dormant_admin_members, []);

  data.roles[0].users = ["u1", "u4"];
  const dormantAdmin = await assessSumologicAccessControl(readerFrom(data), { now: NOW });
  assert.equal(byId(dormantAdmin, "SUMO-06").status, "warn");
  assert.match(byId(dormantAdmin, "SUMO-06").summary, /1 admin role member\(s\) have not logged in for over 90 days \(dormant@example.com\)/);
  assert.deepEqual(byId(dormantAdmin, "SUMO-06").evidence.dormant_admin_members, ["dormant@example.com"]);

  data.roles[0].users = ["u1", "u5"];
  const undatedAdmin = await assessSumologicAccessControl(readerFrom(data), { now: NOW });
  assert.equal(byId(undatedAdmin, "SUMO-06").status, "warn");
  assert.match(byId(undatedAdmin, "SUMO-06").summary, /have no lastLoginTimestamp and are not counted as active/);
  assert.deepEqual(byId(undatedAdmin, "SUMO-06").evidence.admin_members_without_last_login, ["never@example.com"]);
  assert.deepEqual(byId(undatedAdmin, "SUMO-06").evidence.dormant_admin_members, []);

  data.roles[0].users = ["u1", "u4"];
  const relaxed = await assessSumologicAccessControl(readerFrom(data), { now: NOW, userInactiveDays: 3650 });
  assert.equal(byId(relaxed, "SUMO-06").status, "pass");
  assert.equal(byId(relaxed, "SUMO-06").evidence.user_inactive_threshold_days, 3650);
  assert.deepEqual(byId(relaxed, "SUMO-06").evidence.dormant_admin_members, []);

  data.roles[0].users = ["u1"];
  const usersUnreadable = await assessSumologicAccessControl(readerFrom(data, { listUsers: async () => failedCollection("forbidden", 403) }), { now: NOW });
  assert.equal(byId(usersUnreadable, "SUMO-06").status, "warn");
  assert.match(byId(usersUnreadable, "SUMO-06").summary, /user list was unreadable/);
});

test("control 5 reports an absent requireMfa flag as absent, not false", async () => {
  const data = healthyData();
  delete data.passwordPolicy.requireMfa;
  const identity = await assessSumologicIdentity(readerFrom(data), { now: NOW });
  assert.equal(byId(identity, "SUMO-05").status, "fail");
  assert.match(byId(identity, "SUMO-05").summary, /requireMfa=absent/);
  assert.doesNotMatch(byId(identity, "SUMO-05").summary, /requireMfa=false/);
  assert.equal(byId(identity, "SUMO-05").evidence.require_mfa_policy, "absent");

  data.passwordPolicy.requireMfa = false;
  const explicit = await assessSumologicIdentity(readerFrom(data), { now: NOW });
  assert.match(byId(explicit, "SUMO-05").summary, /requireMfa=false/);
  assert.equal(byId(explicit, "SUMO-05").evidence.require_mfa_policy, "false");
});

test("control 10 resolves connection hosts from url only and flags connections without a url", async () => {
  const data = healthyData();
  data.connections = [
    { id: "c1", name: "approved-hook", type: "WebhookConnection", url: "https://hooks.example.com/x", defaultPayload: "{\"url\":\"https://hooks.evil.example/decoy\"}" },
    { id: "c2", name: "payload-only", type: "WebhookConnection", defaultPayload: "{\"url\":\"https://hooks.example.com/decoy\"}" },
  ];
  const governance = await assessSumologicDataGovernance(readerFrom(data), { now: NOW, approvedDestinationDomains: ["example.com"] });
  const forwarding = byId(governance, "SUMO-10");
  assert.equal(forwarding.status, "fail");
  assert.deepEqual(forwarding.evidence.destinations.map((item) => item.host), ["hooks.example.com", null]);
  assert.deepEqual(forwarding.evidence.unapproved_destinations, ["payload-only"]);

  data.connections = [data.connections[0]];
  const approved = await assessSumologicDataGovernance(readerFrom(data), { now: NOW, approvedDestinationDomains: ["example.com"] });
  assert.equal(byId(approved, "SUMO-10").status, "pass");
});

test("approved_email_domains drives control 20 when org domains cannot be derived from the user list", async () => {
  const data = healthyData();
  data.monitors[0].notifications = [{ notification: { connectionType: "Email", recipients: ["soc@partner.example.org"] }, runForTriggerTypes: ["Critical"] }];
  const usersUnreadable = { listUsers: async () => failedCollection("forbidden", 403) };

  const noDomains = await assessSumologicContentSharing(readerFrom(data, usersUnreadable), { now: NOW });
  assert.equal(byId(noDomains, "SUMO-20").status, "manual");
  assert.match(byId(noDomains, "SUMO-20").summary, /no org email domains could be derived/);

  const approved = await assessSumologicContentSharing(readerFrom(data, usersUnreadable), { now: NOW, approvedEmailDomains: ["partner.example.org"] });
  assert.equal(byId(approved, "SUMO-20").status, "pass");
  assert.deepEqual(byId(approved, "SUMO-20").evidence.org_email_domains, ["partner.example.org"]);

  const mismatch = await assessSumologicContentSharing(readerFrom(data, usersUnreadable), { now: NOW, approvedEmailDomains: ["example.com"] });
  assert.equal(byId(mismatch, "SUMO-20").status, "fail");
  assert.deepEqual(byId(mismatch, "SUMO-20").evidence.external_email_recipients, ["soc@partner.example.org"]);

  const combined = await assessSumologicContentSharing(readerFrom(data), { now: NOW, approvedEmailDomains: ["Partner.Example.org"] });
  assert.equal(byId(combined, "SUMO-20").status, "pass");
  assert.ok(byId(combined, "SUMO-20").evidence.org_email_domains.includes("example.com"));
  assert.ok(byId(combined, "SUMO-20").evidence.org_email_domains.includes("partner.example.org"));
});

test("a 401 response is reported as rejected credentials, is not retried, and never falls back to personal keys", async () => {
  const requests = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push(url.pathname);
    return jsonResponse({ errors: [{ code: "unauthorized", message: "Full authentication is required" }] }, { status: 401 });
  };
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl, sleepImpl: async () => {} });

  const keys = await client.listAccessKeys();
  assert.equal(keys.ok, false);
  assert.equal(keys.httpStatus, 401);
  assert.match(keys.error, /\(401 unauthorized\)/);
  assert.deepEqual(requests, ["/api/v1/accessKeys"]);

  const access = await checkSumologicAccess(client);
  assert.equal(access.status, "limited");
  assert.equal(access.surfaces.filter((surface) => surface.status === "readable").length, 0);

  const unauthorized = async () => failedCollection("Sumo Logic request failed (401 unauthorized)", 401);
  const reader = { ...forbiddenReader() };
  for (const key of Object.keys(reader)) if (key !== "getResolvedConfig") reader[key] = unauthorized;
  const results = await allAssessments(reader);
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  for (const item of findings) {
    assert.equal(item.status, "manual", `${item.id} must be manual on 401`);
    assert.doesNotMatch(item.summary, /403/, `${item.id} must not describe a 401 as a 403`);
  }
  assert.match(byId(results[0], "SUMO-01").summary, /credentials were rejected \(401\)/);
  assert.equal(byId(results[0], "SUMO-01").evidence.http_status, 401);
  assert.match(byId(results[1], "SUMO-07").summary, /credentials were rejected \(401\)/);
});

test("undated items are never counted as fresh or active", async () => {
  const data = healthyData();
  data.accessKeys = [{ id: "k3", label: "undated", disabled: false, createdAt: null, lastUsed: null }];
  const access = await assessSumologicAccessControl(readerFrom(data), { now: NOW });
  assert.equal(byId(access, "SUMO-07").status, "warn");
  assert.match(byId(access, "SUMO-07").summary, /lack a createdAt timestamp/);
  assert.equal(byId(access, "SUMO-08").status, "warn");
  assert.match(byId(access, "SUMO-08").summary, /no lastUsed timestamp/);

  data.collectors = [{ id: 9, name: "ghost", collectorType: "Installable", alive: false, ephemeral: false, collectorVersion: "19.1" }];
  const governance = await assessSumologicDataGovernance(readerFrom(data), { now: NOW });
  assert.equal(byId(governance, "SUMO-12").status, "fail");
});

test("enabling flags that are false or absent do not support pass", async () => {
  const data = healthyData();
  data.policies.audit = {};
  data.policies.dataAccessLevel = {};
  data.allowlistStatus = { contentEnabled: true };
  data.identityProviders[0].debugMode = true;
  data.partitions = data.partitions.map((partition) => ({ ...partition, retentionPeriod: -1 }));
  const [identity, access, governance, content] = await allAssessments(readerFrom(data));
  assert.equal(byId(identity, "SUMO-01").status, "warn");
  assert.equal(byId(access, "SUMO-13").status, "fail");
  assert.equal(byId(governance, "SUMO-09").status, "fail");
  assert.match(byId(governance, "SUMO-09").summary, /enabled=absent/);
  assert.equal(byId(governance, "SUMO-17").status, "warn");
  assert.match(byId(governance, "SUMO-17").summary, /account default/);
  assert.equal(byId(content, "SUMO-11").status, "fail");
});

test("disabled monitors, org-wide shares, and plan-limited audit index downgrade verdicts", async () => {
  const data = healthyData();
  data.monitors[0].isDisabled = true;
  data.permissions = { explicitPermissions: [{ permissionName: "View", sourceType: "org", sourceId: "org", contentId: "c1" }] };
  data.personalFolder.children.push({ id: "c2", name: "Sensitive lookup", itemType: "Lookups" });
  data.partitions = [data.partitions[0]];
  data.accountStatus = { planType: "Free" };
  const [, , governance, content] = await allAssessments(readerFrom(data));
  assert.equal(byId(content, "SUMO-20").status, "warn");
  assert.equal(byId(content, "SUMO-11").status, "warn");
  assert.equal(byId(content, "SUMO-18").status, "warn");
  assert.equal(byId(governance, "SUMO-09").status, "manual");
  assert.match(byId(governance, "SUMO-09").summary, /plan Free/);
});

test("exportSumologicAuditBundle writes the bundle layout, zip, and error log, and never overwrites a prior bundle", async () => {
  const base = createTempBase("grclanker-sumo-export-");
  const reader = readerFrom(healthyData(), { listCollectors: async () => failedCollection("Sumo Logic request to /v1/collectors failed (403 forbidden)", 403) });

  const first = await exportSumologicAuditBundle(reader, sampleConfig(), base, { now: NOW });
  assert.ok(existsSync(first.outputDir));
  assert.ok(existsSync(first.zipPath));
  assert.equal(first.zipPath, `${first.outputDir}.zip`);
  assert.equal(first.findingCount, 20);
  assert.equal(first.errorCount, 1);
  assert.ok(first.fileCount >= 24);
  for (const relativePath of [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "_errors.log",
    "core_data/access_check.json",
    "core_data/identity.json",
    "core_data/access-control.json",
    "core_data/data-governance.json",
    "core_data/content-sharing.json",
    "analysis/findings.json",
    "analysis/identity.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp.md",
    "compliance/cmmc.md",
    "compliance/soc-2.md",
    "compliance/cis.md",
    "compliance/pci-dss.md",
    "compliance/stig.md",
    "compliance/irap.md",
    "compliance/ismap.md",
  ]) {
    assert.ok(existsSync(join(first.outputDir, relativePath)), `${relativePath} missing`);
  }
  const metadata = JSON.parse(readFileSync(join(first.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.deployment, "us2");
  assert.equal(metadata.access_id_prefix, "suAB");
  const bundleText = readFileSync(join(first.outputDir, "core_data", "access-control.json"), "utf8");
  assert.doesNotMatch(bundleText, /secret-access-key-value/);
  assert.match(readFileSync(join(first.outputDir, "_errors.log"), "utf8"), /collectors/);
  const findings = JSON.parse(readFileSync(join(first.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "SUMO-12").status, "manual");

  const second = await exportSumologicAuditBundle(readerFrom(healthyData()), sampleConfig(), base, { now: NOW });
  assert.notEqual(second.outputDir, first.outputDir);
  assert.notEqual(second.zipPath, first.zipPath);
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.equal(second.errorCount, 0);
  assert.ok(!existsSync(join(second.outputDir, "_errors.log")));
  assert.ok(existsSync(first.zipPath));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-sumo-path-");
  const outside = createTempBase("grclanker-sumo-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);
  const safe = resolveSecureOutputPath(base, join("compliance", "safe.md"));
  assert.match(safe, /compliance\/safe\.md$/);
});

test("Sumo Logic tools are registered in the tool catalog under the Sumo Logic group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("sumologic_"));
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [
    "sumologic_assess_access_control",
    "sumologic_assess_content_sharing",
    "sumologic_assess_data_governance",
    "sumologic_assess_identity",
    "sumologic_check_access",
    "sumologic_export_audit_bundle",
  ]);
  assert.ok(tools.every((tool) => tool.group === "Sumo Logic"));
  assert.ok(tools.every((tool) => tool.kind === "domain"));
  const exportTool = tools.find((tool) => tool.name === "sumologic_export_audit_bundle");
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "output_dir"));
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "endpoint"));
});
