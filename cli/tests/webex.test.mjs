import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  WebexApiClient,
  WebexApiError,
  assessWebexCollaborationGovernance,
  assessWebexIdentity,
  assessWebexMeetingHybridSecurity,
  checkWebexAccess,
  detectTokenType,
  exportWebexAuditBundle,
  parseLinkHeaderNext,
  redactSecrets,
  resolveSecureOutputPath,
  resolveWebexConfiguration,
} from "../dist/extensions/grc-tools/webex.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    token: "webex-token",
    orgId: "org-123",
    baseUrl: "https://webexapis.com/v1",
    timeoutMs: 30000,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    statusText: options.statusText ?? "OK",
    headers: {
      "content-type": "application/json",
      ...(options.headers ?? {}),
    },
  });
}

function page(items, truncated = false) {
  return { items, truncated, pageCount: 1 };
}

function forbidden(endpoint) {
  return new WebexApiError(`Webex request failed (403 Forbidden) for ${endpoint}`, 403, endpoint);
}

const CLIENT_METHODS = [
  "getMe", "listOrganizations", "getOrganization", "listPeople", "listRoles", "listLicenses", "listEvents",
  "listAdminAuditEvents", "listAdminRecordings", "listMeetings", "getMeetingPreferences", "listMeetingSites",
  "listHybridClusters", "listHybridConnectors", "listDevices", "listWorkspaces", "listRooms", "listWebhooks",
];
const OBJECT_METHODS = new Set(["getMe", "getOrganization", "getMeetingPreferences"]);

/** Fixture (a): every endpoint returns 403. */
function forbiddenClient() {
  const client = { getResolvedConfig: () => sampleConfig() };
  for (const method of CLIENT_METHODS) {
    client[method] = async () => { throw forbidden(`/${method}`); };
  }
  return client;
}

/** Fixture (b): every list is empty, objects are minimal. */
function emptyClient() {
  const client = { getResolvedConfig: () => sampleConfig() };
  for (const method of CLIENT_METHODS) {
    client[method] = OBJECT_METHODS.has(method)
      ? async () => ({ id: "me-1", type: "person" })
      : async () => page([]);
  }
  return client;
}

/** Fixture (d): a fully compliant organization built from documented field names. */
function compliantClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getMe() {
      return { id: "me-1", displayName: "Auditor", emails: ["auditor@example.com"], type: "person", roles: ["role-full-admin"] };
    },
    async listOrganizations() {
      return page([{ id: "org-123", displayName: "Example Org", created: "2020-01-01T00:00:00.000Z" }]);
    },
    async getOrganization() {
      return { id: "org-123", displayName: "Example Org", created: "2020-01-01T00:00:00.000Z" };
    },
    async listPeople() {
      return page([
        { id: "u1", displayName: "Full Admin", emails: ["admin@example.com"], type: "person", roles: ["role-full-admin"], created: "2021-01-01T00:00:00.000Z" },
        { id: "u2", displayName: "Compliance", emails: ["co@example.com"], type: "person", roles: ["role-compliance"], created: "2021-01-01T00:00:00.000Z" },
        { id: "u3", displayName: "User", emails: ["user@example.com"], type: "person", roles: [], created: "2021-01-01T00:00:00.000Z" },
        { id: "b1", displayName: "Approved Bot", emails: ["bot@webex.bot"], type: "bot", created: "2022-01-01T00:00:00.000Z" },
      ]);
    },
    async listRoles() {
      return page([
        { id: "role-full-admin", name: "Full Administrator" },
        { id: "role-compliance", name: "Compliance Officer" },
      ]);
    },
    async listLicenses() {
      return page([{ id: "lic-1", name: "Meetings", totalUnits: 100, consumedUnits: 90 }]);
    },
    async listEvents() {
      return page([{ id: "ev-1", resource: "messages", type: "created", actorId: "u3", orgId: "org-123", created: "2026-09-01T00:00:00.000Z", data: {} }]);
    },
    async listAdminAuditEvents() {
      return page([{ id: "audit-1", actorId: "u1", actorOrgId: "org-123", created: "2026-09-10T00:00:00.000Z", data: { eventCategory: "ROLES", actionText: "role added" } }]);
    },
    async listAdminRecordings() {
      return page([{ id: "rec-1", topic: "Board", createTime: "2026-09-01T00:00:00.000Z", status: "available", password: "p" }]);
    },
    async listMeetings() {
      return page([{ id: "m-1", title: "Weekly", password: "abc", unlockedMeetingJoinSecurity: "allowJoinWithLobby" }]);
    },
    async getMeetingPreferences() {
      return { personalMeetingRoom: { enabledAutoLock: true, autoLockMinutes: 5, hostPin: "1234" }, schedulingOptions: { enabledJoinBeforeHost: false }, sites: [{ siteUrl: "example.webex.com", default: true }] };
    },
    async listMeetingSites() {
      return page([{ siteUrl: "example.webex.com", default: true }]);
    },
    async listHybridClusters() {
      return page([{ id: "cluster-1", name: "Calendar", orgId: "org-123" }]);
    },
    async listHybridConnectors() {
      return page([{ id: "conn-1", clusterId: "cluster-1", type: "calendar", version: "1.0", status: "operational", createdAt: "2026-01-01T00:00:00.000Z" }]);
    },
    async listDevices() {
      return page([{ id: "dev-1", displayName: "Room Kit", workspaceId: "ws-1", software: "RoomOS 11.20", upgradeChannel: "stable", connectionStatus: "connected", managedBy: "CUSTOMER" }]);
    },
    async listWorkspaces() {
      return page([{ id: "ws-1", displayName: "Boardroom" }]);
    },
    async listRooms() {
      return page([{ id: "room-1", title: "General", type: "group", classificationId: "class-1" }]);
    },
    async listWebhooks() {
      return page([{ id: "hook-1", name: "Notifier", targetUrl: "https://example.com/hook", resource: "messages", event: "created", secret: "s3cret", status: "active" }]);
    },
    ...overrides,
  };
}

/** Fixture (c): partial inventory (people cap hit, truncated pages, one surface denied). */
function partialClient() {
  const base = compliantClient();
  return {
    ...base,
    async listPeople() {
      return page((await base.listPeople()).items, true);
    },
    async listRooms() {
      return page((await base.listRooms()).items, true);
    },
    async listWebhooks() {
      return page((await base.listWebhooks()).items, true);
    },
    async listHybridConnectors() {
      return page((await base.listHybridConnectors()).items, true);
    },
    async listLicenses() {
      return page((await base.listLicenses()).items, true);
    },
    async listAdminAuditEvents() {
      throw forbidden("/adminAudit/events");
    },
  };
}

/** Fixture (c) variant: a bot token. */
function botClient() {
  return compliantClient({
    async getMe() {
      return { id: "bot-1", displayName: "Bot", emails: ["bot@webex.bot"], type: "bot" };
    },
  });
}

async function allAssessments(client) {
  return [
    await assessWebexIdentity(client),
    await assessWebexCollaborationGovernance(client),
    await assessWebexMeetingHybridSecurity(client),
  ];
}

function findingsOf(assessments) {
  return assessments.flatMap((item) => item.findings);
}

const AUTOMATABLE = ["WEBEX-ID-03", "WEBEX-ID-04", "WEBEX-ID-05", "WEBEX-COLLAB-04", "WEBEX-COLLAB-05", "WEBEX-COLLAB-06", "WEBEX-COLLAB-07", "WEBEX-MTG-04"];

test("resolveWebexConfiguration prefers explicit args over environment values", () => {
  const resolved = resolveWebexConfiguration(
    {
      token: "arg-token",
      org_id: "org-explicit",
      base_url: "https://example.invalid/v1",
      timeout_seconds: 9,
    },
    {
      WEBEX_TOKEN: "env-token",
      WEBEX_ORG_ID: "org-env",
    },
    { homeDir: createTempBase("grclanker-webex-home-") },
  );

  assert.equal(resolved.token, "arg-token");
  assert.equal(resolved.orgId, "org-explicit");
  assert.equal(resolved.baseUrl, "https://example.invalid/v1");
  assert.equal(resolved.timeoutMs, 9000);
  assert.ok(resolved.sourceChain.includes("arguments-token"));
});

test("resolveWebexConfiguration accepts refresh credentials without a token", () => {
  const resolved = resolveWebexConfiguration({}, {
    WEBEX_CLIENT_ID: "client",
    WEBEX_CLIENT_SECRET: "secret",
    WEBEX_REFRESH_TOKEN: "refresh",
  }, { homeDir: createTempBase("grclanker-webex-home-") });

  assert.equal(resolved.token, undefined);
  assert.deepEqual(resolved.refresh, { clientId: "client", clientSecret: "secret", refreshToken: "refresh" });
  assert.throws(() => resolveWebexConfiguration({}, {}, { homeDir: createTempBase("grclanker-webex-home-") }), /WEBEX_TOKEN/);
});

test("resolveWebexConfiguration discovers JSON and YAML config files under ~/.config/webex-sec-inspector", () => {
  const jsonHome = createTempBase("grclanker-webex-home-");
  mkdirSync(join(jsonHome, ".config", "webex-sec-inspector"), { recursive: true });
  writeFileSync(join(jsonHome, ".config", "webex-sec-inspector", "config.json"), JSON.stringify({ token: "file-token", org_id: "org-file" }));
  const fromJson = resolveWebexConfiguration({}, {}, { homeDir: jsonHome });
  assert.equal(fromJson.token, "file-token");
  assert.equal(fromJson.orgId, "org-file");
  assert.ok(fromJson.sourceChain.includes("config-file:config.json"));

  const yamlHome = createTempBase("grclanker-webex-home-");
  mkdirSync(join(yamlHome, ".config", "webex-sec-inspector"), { recursive: true });
  writeFileSync(join(yamlHome, ".config", "webex-sec-inspector", "config.yaml"), "client_id: cid\nclient_secret: csecret\nrefresh_token: rtoken\n");
  const fromYaml = resolveWebexConfiguration({}, { WEBEX_ORG_ID: "org-env" }, { homeDir: yamlHome });
  assert.deepEqual(fromYaml.refresh, { clientId: "cid", clientSecret: "csecret", refreshToken: "rtoken" });
  assert.equal(fromYaml.orgId, "org-env");
});

test("WebexApiClient refreshes an access token through POST /access_token and redacts it", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, method: init.method, body: init.body, auth: init.headers?.authorization });
    if (url.pathname === "/v1/access_token") {
      return jsonResponse({ access_token: "fresh-token", expires_in: 1209600, refresh_token: "r2", token_type: "Bearer" });
    }
    return jsonResponse({ id: "me-1", type: "person" });
  };
  const config = resolveWebexConfiguration({ client_id: "cid", client_secret: "csecret", refresh_token: "rtoken" }, {}, { homeDir: createTempBase("grclanker-webex-home-") });
  const client = new WebexApiClient(config, { fetchImpl });
  const me = await client.getMe();

  assert.equal(me.id, "me-1");
  assert.equal(seen[0].method, "POST");
  const body = new URLSearchParams(seen[0].body);
  assert.equal(body.get("grant_type"), "refresh_token");
  assert.equal(body.get("client_id"), "cid");
  assert.equal(body.get("refresh_token"), "rtoken");
  assert.equal(seen[1].auth, "Bearer fresh-token");
  assert.deepEqual(redactSecrets({ access_token: "x", nested: { secret: "y", password: "z", ok: 1 }, list: [{ refresh_token: "r" }] }), {
    access_token: "[REDACTED]",
    nested: { secret: "[REDACTED]", password: "[REDACTED]", ok: 1 },
    list: [{ refresh_token: "[REDACTED]" }],
  });
});

test("WebexApiClient follows Link pagination to completion, reports truncation, and sends bearer auth", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, max: url.searchParams.get("max"), orgId: url.searchParams.get("orgId"), auth: init.headers?.authorization });
    if (seen.length === 1) {
      return jsonResponse(
        { items: [{ id: "person-1" }] },
        { headers: { link: '<https://webexapis.com/v1/people?max=100&orgId=org-123&after=cursor>; rel="next"' } },
      );
    }
    if (seen.length === 2) {
      return jsonResponse({ items: [] }, { headers: { link: '<https://webexapis.com/v1/people?max=100&orgId=org-123&after=cursor2>; rel="next"' } });
    }
    return jsonResponse({ items: [{ id: "person-2" }, { id: "person-3" }] });
  };

  const client = new WebexApiClient(sampleConfig({ token: "webex-test" }), { fetchImpl });
  const people = await client.listPeople(10);

  assert.deepEqual(people.items.map((person) => person.id), ["person-1", "person-2", "person-3"]);
  assert.equal(people.truncated, false);
  assert.equal(people.pageCount, 3);
  assert.deepEqual(seen.map((request) => request.auth), Array(3).fill("Bearer webex-test"));
  assert.equal(seen[0].max, "100");
  assert.equal(seen[0].orgId, "org-123");

  const capped = await new WebexApiClient(sampleConfig(), { fetchImpl: async () => jsonResponse({ items: [{ id: "a" }, { id: "b" }] }, { headers: { link: '<https://webexapis.com/v1/people?after=x>; rel="next"' } }) }).listPeople(1);
  assert.equal(capped.items.length, 1);
  assert.equal(capped.truncated, true);
  assert.equal(parseLinkHeaderNext('<https://a/first>; rel="first", <https://a/next>; rel="next"'), "https://a/next");
  assert.equal(parseLinkHeaderNext('<https://a/prev>; rel="prev"'), null);
});

test("WebexApiClient sends only documented query parameters per endpoint", async () => {
  const seen = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push(`${url.pathname}?${url.searchParams.toString()}`);
    return jsonResponse({ items: [] });
  };
  const now = () => new Date("2026-09-21T12:00:00.000Z");
  const client = new WebexApiClient(sampleConfig(), { fetchImpl, now });
  await client.listPeople();
  await client.listRoles();
  await client.listLicenses();
  await client.listEvents();
  await client.listAdminAuditEvents("org-123");
  await client.listAdminRecordings();
  await client.listMeetings();
  await client.listHybridClusters();
  await client.listDevices();
  await client.listRooms();
  await client.listWebhooks();

  assert.deepEqual(seen, [
    "/v1/people?max=100&orgId=org-123",
    "/v1/roles?max=100",
    "/v1/licenses?max=100&orgId=org-123",
    "/v1/events?max=100",
    "/v1/adminAudit/events?max=200&orgId=org-123&from=2026-08-22T12%3A00%3A00.000Z&to=2026-09-21T12%3A00%3A00.000Z",
    "/v1/admin/recordings?max=100",
    "/v1/meetings?max=100",
    "/v1/hybrid/clusters?max=100&orgId=org-123",
    "/v1/devices?max=100&orgId=org-123",
    "/v1/rooms?max=100",
    "/v1/webhooks?max=100",
  ]);
});

test("WebexApiClient honors 429 Retry-After and surfaces 403 as WebexApiError", async () => {
  const waits = [];
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    if (calls === 1) return jsonResponse({}, { status: 429, statusText: "Too Many Requests", headers: { "retry-after": "2" } });
    return jsonResponse({ items: [{ id: "role-1", name: "Full Administrator" }] });
  };
  const client = new WebexApiClient(sampleConfig(), { fetchImpl, sleep: async (ms) => { waits.push(ms); } });
  const roles = await client.listRoles();
  assert.deepEqual(waits, [2000]);
  assert.equal(roles.items.length, 1);

  const denied = new WebexApiClient(sampleConfig(), { fetchImpl: async () => jsonResponse({ message: "no scope" }, { status: 403, statusText: "Forbidden" }) });
  await assert.rejects(() => denied.listPeople(), (error) => error instanceof WebexApiError && error.status === 403 && /\/v1\/people/.test(error.message));
});

test("checkWebexAccess reports readable surfaces and token type for an admin token", async () => {
  const result = await checkWebexAccess(compliantClient());
  assert.equal(result.status, "healthy");
  assert.equal(result.tokenType, "person");
  assert.equal(result.adminCapable, true);
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 17);
  assert.ok(result.surfaces.some((surface) => surface.name === "organization" && surface.status === "readable"));
  assert.match(result.recommendedNextStep, /webex_assess_identity/);
  assert.equal(detectTokenType({ type: "appuser" }), "appuser");
  assert.equal(detectTokenType(undefined), "unknown");
});

test("checkWebexAccess renders admin surfaces manual for a bot token", async () => {
  const result = await checkWebexAccess(botClient());
  assert.equal(result.status, "limited");
  assert.equal(result.tokenType, "bot");
  assert.equal(result.adminCapable, false);
  const people = result.surfaces.find((surface) => surface.name === "people");
  assert.equal(people.status, "manual");
  assert.match(people.error, /Bot tokens/);
  assert.ok(result.notes.some((note) => /Bot tokens cannot read admin surfaces/.test(note)));
});

test("fixture (a): every endpoint 403 yields manual verdicts naming the cause, never pass", async () => {
  const findings = findingsOf(await allAssessments(forbiddenClient()));
  assert.equal(findings.length, 19);
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} passed under 403`);
    assert.equal(item.status, "manual", `${item.id} should be manual under 403`);
  }
  assert.match(findings.find((item) => item.id === "WEBEX-ID-03").summary, /403.*scope or admin role/);
  assert.match(findings.find((item) => item.id === "WEBEX-COLLAB-05").summary, /\/webhooks returned 403/);
});

test("fixture (b): empty inventories never pass by default", async () => {
  const findings = findingsOf(await allAssessments(emptyClient()));
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} passed on empty data`);
  }
  assert.equal(findings.find((item) => item.id === "WEBEX-ID-03").status, "manual");
  assert.equal(findings.find((item) => item.id === "WEBEX-COLLAB-04").status, "manual");
  assert.equal(findings.find((item) => item.id === "WEBEX-COLLAB-05").status, "manual");
  assert.equal(findings.find((item) => item.id === "WEBEX-COLLAB-06").status, "manual");
  assert.equal(findings.find((item) => item.id === "WEBEX-COLLAB-07").status, "warn");
  assert.equal(findings.find((item) => item.id === "WEBEX-MTG-04").status, "manual");
});

test("fixture (c): partial inventories flag the partial view instead of passing", async () => {
  const findings = findingsOf(await allAssessments(partialClient()));
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} passed on a partial inventory`);
  }
  const compliance = findings.find((item) => item.id === "WEBEX-ID-03");
  assert.equal(compliance.status, "warn");
  assert.match(compliance.summary, /truncated at 4 items/);
  assert.equal(compliance.evidence.people_truncated, true);
  const audit = findings.find((item) => item.id === "WEBEX-COLLAB-07");
  assert.equal(audit.status, "manual");
  assert.match(audit.summary, /audit:events_read/);

  const botFindings = findingsOf(await allAssessments(botClient()));
  for (const item of botFindings) {
    assert.notEqual(item.status, "pass", `${item.id} passed with a bot token`);
  }
  assert.match(botFindings.find((item) => item.id === "WEBEX-ID-05").summary, /bot token cannot read admin surfaces/);
  assert.match(botFindings.find((item) => item.id === "WEBEX-COLLAB-04").summary, /bot token sees only its own spaces/);
});

test("fixture (d): a compliant organization passes every automatable control", async () => {
  const assessments = await allAssessments(compliantClient());
  const findings = findingsOf(assessments);
  assert.equal(findings.length, 19);
  for (const id of AUTOMATABLE) {
    assert.equal(findings.find((item) => item.id === id)?.status, "pass", `${id} should pass on the compliant fixture`);
  }
  const manual = findings.filter((item) => item.status === "manual").map((item) => item.id);
  assert.deepEqual(manual, ["WEBEX-ID-01", "WEBEX-ID-02", "WEBEX-ID-06", "WEBEX-COLLAB-01", "WEBEX-COLLAB-02", "WEBEX-COLLAB-03", "WEBEX-COLLAB-08", "WEBEX-MTG-01", "WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-05"]);
  for (const item of findings.filter((entry) => entry.status === "manual")) {
    assert.match(item.summary, /^Manual:/);
    assert.match(item.summary, /developer\.webex\.com|Control Hub/);
  }
  const covered = new Set(findings.flatMap((item) => item.control));
  assert.equal(covered.size, 25);
  assert.ok(findings.every((item) => item.frameworks.fedramp.length > 0));
  assert.equal(findings.find((item) => item.id === "WEBEX-ID-05").evidence.bot_count, 1);
  assert.match(findings.find((item) => item.id === "WEBEX-MTG-01").summary, /SRTP .*folded/);
  for (const assessment of assessments) {
    assert.deepEqual(assessment.errors, []);
  }
});

test("assessWebexIdentity fails Compliance Officer assignment and warns on admin concentration", async () => {
  const client = compliantClient({
    async listPeople() {
      return page([
        { id: "u1", displayName: "A", type: "person", roles: ["role-full-admin"] },
        { id: "u2", displayName: "B", type: "person", roles: ["role-full-admin"] },
        { id: "u3", displayName: "C", type: "person", roles: ["role-full-admin"] },
      ]);
    },
  });
  const result = await assessWebexIdentity(client, { maxAdmins: 2 });
  assert.equal(result.findings.find((item) => item.id === "WEBEX-ID-03").status, "fail");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-ID-04").status, "warn");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-ID-05").status, "pass");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-ID-05").evidence.bot_count, 0);
});

test("assessWebexCollaborationGovernance fails unclassified spaces and insecure webhooks", async () => {
  const client = compliantClient({
    async listRooms() {
      return page([{ id: "room-1", title: "General", type: "group" }]);
    },
    async listWebhooks() {
      return page([{ id: "hook-1", name: "Legacy", targetUrl: "http://example.com", status: "active" }]);
    },
    async listLicenses() {
      return page([{ id: "lic-1", totalUnits: 10, consumedUnits: 4 }]);
    },
  });
  const result = await assessWebexCollaborationGovernance(client);
  assert.equal(result.findings.find((item) => item.id === "WEBEX-COLLAB-04").status, "fail");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-COLLAB-05").status, "fail");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-COLLAB-06").status, "warn");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-COLLAB-08").status, "manual");
  assert.match(result.findings.find((item) => item.id === "WEBEX-COLLAB-08").summary, /eDiscovery report is available through Control Hub/);
});

test("assessWebexMeetingHybridSecurity fails non-operational connectors and keeps org defaults manual", async () => {
  const client = compliantClient({
    async listHybridConnectors() {
      return page([{ id: "conn-1", type: "calendar", status: "impaired" }, { id: "conn-2", type: "calendar", status: "operational", createdAt: "2026-01-01T00:00:00.000Z" }]);
    },
    async listMeetings() {
      return page([{ id: "m-1", unlockedMeetingJoinSecurity: "allowJoin" }]);
    },
  });
  const result = await assessWebexMeetingHybridSecurity(client);
  const hybrid = result.findings.find((item) => item.id === "WEBEX-MTG-04");
  assert.equal(hybrid.status, "fail");
  assert.equal(hybrid.evidence.non_operational.length, 1);
  const lobby = result.findings.find((item) => item.id === "WEBEX-MTG-02");
  assert.equal(lobby.status, "manual");
  assert.equal(lobby.evidence.sampled_allow_join_without_lobby, 1);
  assert.equal(lobby.evidence.sampled_without_password, 1);
  assert.equal(result.findings.find((item) => item.id === "WEBEX-MTG-05").status, "manual");
});

test("exportWebexAuditBundle writes the shared layout, redacts secrets, and never overwrites a prior bundle", async () => {
  const base = createTempBase("grclanker-webex-export-");
  const first = await exportWebexAuditBundle(compliantClient(), sampleConfig(), base);
  assert.ok(existsSync(first.outputDir));
  assert.equal(first.zipPath, `${first.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath));
  assert.equal(first.findingCount, 19);
  assert.equal(first.errorCount, 0);
  assert.ok(!existsSync(join(first.outputDir, "_errors.log")));

  for (const relativePath of [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access.json",
    "core_data/identity/people.json",
    "core_data/collaboration-governance/webhooks.json",
    "core_data/meeting-hybrid-security/meeting_preferences.json",
    "analysis/findings.json",
    "analysis/identity.json",
    "analysis/collaboration-governance.json",
    "analysis/meeting-hybrid-security.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp/fedramp_compliance_report.md",
    "compliance/cmmc/cmmc_compliance_report.md",
    "compliance/soc2/soc2_compliance_report.md",
    "compliance/cis/cis_controls_report.md",
    "compliance/pci_dss/pci_dss_compliance_report.md",
    "compliance/disa_stig/stig_compliance_checklist.md",
    "compliance/irap/irap_compliance_report.md",
    "compliance/ismap/ismap_compliance_report.md",
  ]) {
    assert.ok(existsSync(join(first.outputDir, relativePath)), `missing ${relativePath}`);
  }
  const webhooks = readFileSync(join(first.outputDir, "core_data/collaboration-governance/webhooks.json"), "utf8");
  assert.match(webhooks, /\[REDACTED\]/);
  assert.doesNotMatch(webhooks, /s3cret/);
  const preferences = readFileSync(join(first.outputDir, "core_data/meeting-hybrid-security/meeting_preferences.json"), "utf8");
  assert.doesNotMatch(preferences, /1234/);
  const metadata = JSON.parse(readFileSync(join(first.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.org_id, "org-123");
  assert.equal(metadata.token_type, "person");

  const second = await exportWebexAuditBundle(partialClient(), sampleConfig(), base);
  assert.notEqual(second.outputDir, first.outputDir);
  assert.match(second.outputDir, /-audit-bundle-2$/);
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath));
  assert.ok(second.errorCount > 0);
  assert.match(readFileSync(join(second.outputDir, "_errors.log"), "utf8"), /adminAudit/);
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-webex-path-");
  const outside = createTempBase("grclanker-webex-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
});
