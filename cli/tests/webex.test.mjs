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
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  WEBEX_DOCS,
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

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(TEST_DIR, "..", "..");

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

function textResponse(body, options = {}) {
  return new Response(body, {
    status: options.status ?? 200,
    statusText: options.statusText ?? "OK",
    headers: { "content-type": "text/plain", ...(options.headers ?? {}) },
  });
}

function page(items, truncated = false) {
  return { items, truncated, pageCount: 1 };
}

function forbidden(endpoint) {
  return new WebexApiError(`Webex request failed (403 Forbidden) for ${endpoint}`, 403, endpoint);
}

const CLIENT_METHODS = [
  "getMe", "listOrganizations", "getOrganization", "listPeople", "listRoles", "listLicenses", "getGuestCount", "listEvents",
  "listAdminAuditEvents", "listAdminRecordings", "listMeetings", "getMeetingPreferences", "listMeetingSites",
  "getMeetingCommonSettings", "listHybridClusters", "listHybridConnectors", "listDevices", "listWorkspaces", "listRooms", "listWebhooks",
];
const OBJECT_METHODS = new Set(["getMe", "getOrganization", "getMeetingPreferences", "getGuestCount", "getMeetingCommonSettings"]);

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

/**
 * GetMeetingConfigurationCommonSettingObject from the site reference
 * (get-meeting-common-settings-configuration), securityOptions subtree only
 * where it matters, every key spelled as the embedded OpenAPI schema documents.
 */
function compliantCommonSettings(overrides = {}) {
  return {
    siteOptions: { allowCustomPersonalRoomURL: false },
    telephonyConfig: { allowCallIn: true, allowCallBack: false, VoIP: true },
    defaultSchedulerOptions: { entryAndExitTone: "NoTone", telephonySupport: "WebexTeleconferencing", tollFree: false, VoIP: true },
    scheduleMeetingOptions: { emailReminders: true },
    securityOptions: {
      joinBeforeHost: false,
      audioBeforeHost: false,
      firstAttendeeAsPresenter: false,
      unlistAllMeetings: true,
      requireLoginBeforeAccess: true,
      allowMobileScreenCapture: false,
      requireStrongPassword: true,
      passwordCriteria: {
        mixedCase: true,
        minLength: 8,
        minNumeric: 2,
        minAlpha: 4,
        minSpecial: 1,
        disallowDynamicWebText: true,
        disallowList: true,
        disallowValues: ["password"],
      },
      ...overrides,
    },
  };
}

/** Fixture (d): a fully compliant organization built strictly from documented response shapes. */
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
        { id: "g1", displayName: "Visitor", emails: ["visitor@example.net"], type: "appuser", created: "2026-09-01T00:00:00.000Z" },
      ]);
    },
    async listRoles() {
      return page([
        { id: "role-full-admin", name: "Full Administrator" },
        { id: "role-compliance", name: "Compliance Officer" },
      ]);
    },
    async listLicenses() {
      return page([{ id: "lic-1", name: "Meetings", totalUnits: 100, consumedUnits: 90, siteUrl: "example.webex.com" }]);
    },
    async getGuestCount() {
      return { count: 1 };
    },
    async listEvents() {
      return page([{ id: "ev-1", resource: "messages", type: "created", actorId: "u3", orgId: "org-123", created: "2026-09-01T00:00:00.000Z", data: {} }]);
    },
    async listAdminAuditEvents() {
      return page([{ id: "audit-1", actorId: "u1", actorOrgId: "org-123", created: "2026-09-10T00:00:00.000Z", data: { eventCategory: "ROLES", actionText: "role added" } }]);
    },
    async listAdminRecordings() {
      return page([{ id: "rec-1", topic: "Board", createTime: "2026-09-01T00:00:00.000Z", status: "available", siteUrl: "example.webex.com" }]);
    },
    async listMeetings() {
      return page([{ id: "m-1", title: "Weekly", password: "abc", unlockedMeetingJoinSecurity: "allowJoinWithLobby", siteUrl: "example.webex.com" }]);
    },
    async getMeetingPreferences() {
      return { personalMeetingRoom: { enabledAutoLock: true, autoLockMinutes: 5, hostPin: "1234" }, schedulingOptions: { enabledJoinBeforeHost: false }, sites: [{ siteUrl: "example.webex.com", default: true }] };
    },
    async listMeetingSites() {
      return page([{ siteUrl: "example.webex.com", default: true }]);
    },
    async getMeetingCommonSettings() {
      return compliantCommonSettings();
    },
    async listHybridClusters() {
      return page([{ id: "cluster-1", name: "Calendar", orgId: "org-123" }]);
    },
    async listHybridConnectors() {
      return page([{ id: "conn-1", orgId: "org-123", hybridClusterId: "cluster-1", hostname: "cal-1.example.com", type: "calendar", version: "1.0", status: "operational", created: "2026-01-01T00:00:00.000Z", alarms: [] }]);
    },
    async listDevices() {
      return page([{ id: "dev-1", displayName: "Room Kit", workspaceId: "ws-1", software: "RoomOS 11.20", upgradeChannel: "stable", connectionStatus: "connected", managedBy: "CUSTOMER", created: "2025-01-01T00:00:00.000Z" }]);
    },
    async listWorkspaces() {
      return page([{ id: "ws-1", displayName: "Boardroom", type: "meetingRoom", created: "2025-01-01T00:00:00.000Z" }]);
    },
    async listRooms() {
      return page([{ id: "room-1", title: "General", type: "group", classificationId: "class-1", isLocked: true, isPublic: false }]);
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
    async listMeetingSites() {
      return page((await base.listMeetingSites()).items, true);
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

function byId(findings, id) {
  return findings.find((item) => item.id === id);
}

const FINDING_COUNT = 22;
const AUTOMATABLE = [
  "WEBEX-ID-03", "WEBEX-ID-04", "WEBEX-ID-05", "WEBEX-ID-07",
  "WEBEX-COLLAB-04", "WEBEX-COLLAB-05", "WEBEX-COLLAB-06", "WEBEX-COLLAB-07",
  "WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-04", "WEBEX-MTG-06",
];
const MANUAL_ON_COMPLIANT = [
  "WEBEX-ID-01", "WEBEX-ID-02", "WEBEX-ID-06",
  "WEBEX-COLLAB-01", "WEBEX-COLLAB-02", "WEBEX-COLLAB-03", "WEBEX-COLLAB-08",
  "WEBEX-MTG-01", "WEBEX-MTG-05", "WEBEX-MTG-07",
];

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
  assert.deepEqual(
    redactSecrets({ securityOptions: { requireStrongPassword: true, passwordCriteria: { minLength: 8 } }, panelistPassword: "p" }),
    { securityOptions: { requireStrongPassword: true, passwordCriteria: { minLength: 8 } }, panelistPassword: "[REDACTED]" },
  );
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

test("WebexApiClient sends max only where the reference documents it and orgId only where documented", async () => {
  const seen = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push(`${url.pathname}?${url.searchParams.toString()}`);
    if (url.pathname === "/v1/guests/count") return textResponse("112");
    if (url.pathname === "/v1/admin/meeting/config/commonSettings") return jsonResponse(compliantCommonSettings());
    if (url.pathname === "/v1/meetingPreferences/sites") return jsonResponse({ sites: [{ siteUrl: "example.webex.com", default: true }] });
    return jsonResponse({ items: [] });
  };
  const now = () => new Date("2026-09-21T12:00:00.000Z");
  const client = new WebexApiClient(sampleConfig(), { fetchImpl, now });
  await client.listOrganizations();
  await client.listPeople();
  await client.listRoles();
  await client.listLicenses();
  await client.listEvents();
  await client.listAdminAuditEvents("org-123");
  await client.listAdminRecordings();
  await client.listMeetings();
  const sites = await client.listMeetingSites();
  await client.getMeetingCommonSettings(sites.items[0].siteUrl);
  await client.getMeetingCommonSettings();
  await client.listHybridClusters();
  await client.listHybridConnectors();
  await client.listDevices();
  await client.listWorkspaces();
  await client.listRooms();
  await client.listWebhooks();
  const guests = await client.getGuestCount();

  assert.deepEqual(seen, [
    "/v1/organizations?",
    "/v1/people?max=100&orgId=org-123",
    "/v1/roles?",
    "/v1/licenses?orgId=org-123",
    "/v1/events?max=100",
    "/v1/adminAudit/events?max=200&orgId=org-123&from=2026-08-22T12%3A00%3A00.000Z&to=2026-09-21T12%3A00%3A00.000Z",
    "/v1/admin/recordings?max=100",
    "/v1/meetings?max=100",
    "/v1/meetingPreferences/sites?",
    "/v1/admin/meeting/config/commonSettings?siteUrl=example.webex.com",
    "/v1/admin/meeting/config/commonSettings?",
    "/v1/hybrid/clusters?orgId=org-123",
    "/v1/hybrid/connectors?orgId=org-123",
    "/v1/devices?max=100&orgId=org-123",
    "/v1/workspaces?max=100&orgId=org-123",
    "/v1/rooms?max=100",
    "/v1/webhooks?max=100",
    "/v1/guests/count?",
  ]);
  assert.deepEqual(sites.items.map((site) => site.siteUrl), ["example.webex.com"]);
  assert.deepEqual(guests, { count: 112 });
  const jsonGuests = await new WebexApiClient(sampleConfig(), { fetchImpl: async () => jsonResponse({ count: 7 }) }).getGuestCount();
  assert.deepEqual(jsonGuests, { count: 7 });
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

test("WEBEX_DOCS cites the redirect-target reference pages and the repo no longer calls them unfetchable", () => {
  const referencePattern = /^https:\/\/developer\.webex\.com\/(admin|meeting|calling|messaging)\/docs\/api\/v1\/[a-z-]+\/?[a-z-]*$/;
  const guidePattern = /^https:\/\/developer\.webex\.com\/docs\/(api\/basics|integrations|service-apps|bots|api\/guides\/compliance)$/;
  for (const [key, url] of Object.entries(WEBEX_DOCS)) {
    assert.ok(referencePattern.test(url) || guidePattern.test(url), `${key} should cite a category-prefixed reference page or a guide: ${url}`);
  }
  assert.equal(WEBEX_DOCS.meetingCommonSettings, "https://developer.webex.com/meeting/docs/api/v1/site/get-meeting-common-settings-configuration");
  assert.equal(WEBEX_DOCS.guestCount, "https://developer.webex.com/admin/docs/api/v1/guest-management/get-guest-count");
  assert.match(WEBEX_DOCS.authenticationConfig, /identity-organization\/update-organization-authentication-configuration-settings$/);

  for (const relativePath of [
    "cli/extensions/grc-tools/webex.ts",
    "specs/webex-sec-inspector.spec.md",
    "src/content/docs/docs/integrations/webex.md",
  ]) {
    const source = readFileSync(join(REPO_ROOT, relativePath), "utf8");
    assert.doesNotMatch(source, /client-rendered/i, `${relativePath} still claims the reference is client-rendered`);
    assert.doesNotMatch(source, /could not be fetched/i, `${relativePath} still claims the reference could not be fetched`);
    assert.doesNotMatch(source, /\u2014/, `${relativePath} contains an em dash`);
  }
  const guide = readFileSync(join(REPO_ROOT, "src/content/docs/docs/integrations/webex.md"), "utf8");
  assert.match(guide, /admin\/meeting\/config\/commonSettings/);
  assert.match(guide, /guests\/count/);
  assert.doesNotMatch(guide, /createdAt/);
});

test("checkWebexAccess reports readable surfaces and token type for an admin token", async () => {
  const result = await checkWebexAccess(compliantClient());
  assert.equal(result.status, "healthy");
  assert.equal(result.tokenType, "person");
  assert.equal(result.adminCapable, true);
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 20);
  assert.ok(result.surfaces.some((surface) => surface.name === "organization" && surface.status === "readable"));
  assert.ok(result.surfaces.some((surface) => surface.name === "meeting_common_settings" && surface.status === "readable" && surface.endpoint === "/admin/meeting/config/commonSettings"));
  assert.ok(result.surfaces.some((surface) => surface.name === "guest_count" && surface.status === "readable"));
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
  assert.equal(result.surfaces.find((surface) => surface.name === "meeting_common_settings").status, "manual");
  assert.ok(result.notes.some((note) => /Bot tokens cannot read admin surfaces/.test(note)));
  assert.match(result.recommendedNextStep, /meeting:admin_config_read/);
});

test("fixture (a): every endpoint 403 yields manual verdicts naming the cause, never pass", async () => {
  const findings = findingsOf(await allAssessments(forbiddenClient()));
  assert.equal(findings.length, FINDING_COUNT);
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} passed under 403`);
    assert.equal(item.status, "manual", `${item.id} should be manual under 403`);
  }
  assert.match(byId(findings, "WEBEX-ID-03").summary, /403.*scope or admin role/);
  assert.match(byId(findings, "WEBEX-COLLAB-05").summary, /\/webhooks returned 403/);
  assert.match(byId(findings, "WEBEX-MTG-02").summary, /\/admin\/meeting\/config\/commonSettings returned 403/);
  assert.match(byId(findings, "WEBEX-MTG-06").summary, /\/admin\/meeting\/config\/commonSettings returned 403/);
  assert.match(byId(findings, "WEBEX-MTG-03").summary, /\/admin\/meeting\/config\/commonSettings returned 403/);
  assert.match(byId(findings, "WEBEX-ID-07").summary, /\/people returned 403/);
});

test("fixture (b): empty inventories never pass by default", async () => {
  const findings = findingsOf(await allAssessments(emptyClient()));
  assert.equal(findings.length, FINDING_COUNT);
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} passed on empty data`);
  }
  assert.equal(byId(findings, "WEBEX-ID-03").status, "manual");
  assert.equal(byId(findings, "WEBEX-ID-07").status, "manual");
  assert.equal(byId(findings, "WEBEX-COLLAB-04").status, "manual");
  assert.equal(byId(findings, "WEBEX-COLLAB-05").status, "manual");
  assert.equal(byId(findings, "WEBEX-COLLAB-06").status, "manual");
  assert.equal(byId(findings, "WEBEX-COLLAB-07").status, "warn");
  assert.equal(byId(findings, "WEBEX-MTG-04").status, "manual");
  const lobby = byId(findings, "WEBEX-MTG-02");
  assert.equal(lobby.status, "manual");
  assert.match(lobby.summary, /^Manual: .*joinBeforeHost was absent/);
  assert.match(lobby.summary, /site list .* was empty, so only the administrator's preferred site was evaluated/);
  assert.equal(byId(findings, "WEBEX-MTG-06").status, "manual");
  assert.equal(byId(findings, "WEBEX-MTG-03").status, "manual");
});

test("fixture (c): partial inventories flag the partial view instead of passing", async () => {
  const findings = findingsOf(await allAssessments(partialClient()));
  assert.equal(findings.length, FINDING_COUNT);
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} passed on a partial inventory`);
  }
  const compliance = byId(findings, "WEBEX-ID-03");
  assert.equal(compliance.status, "warn");
  assert.match(compliance.summary, /truncated at 5 items/);
  assert.equal(compliance.evidence.people_truncated, true);
  assert.equal(byId(findings, "WEBEX-ID-07").status, "warn");
  const audit = byId(findings, "WEBEX-COLLAB-07");
  assert.equal(audit.status, "manual");
  assert.match(audit.summary, /audit:events_read/);
  for (const id of ["WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-06"]) {
    const item = byId(findings, id);
    assert.equal(item.status, "warn", `${id} should warn when the site list is truncated`);
    assert.match(item.summary, /site list was truncated at 1 sites/);
    assert.equal(item.evidence.site_coverage_complete, false);
  }

  const botFindings = findingsOf(await allAssessments(botClient()));
  for (const item of botFindings) {
    assert.notEqual(item.status, "pass", `${item.id} passed with a bot token`);
  }
  assert.match(byId(botFindings, "WEBEX-ID-05").summary, /bot token cannot read admin surfaces/);
  assert.match(byId(botFindings, "WEBEX-ID-07").summary, /bot token cannot read admin surfaces/);
  assert.match(byId(botFindings, "WEBEX-COLLAB-04").summary, /bot token sees only its own spaces/);
  assert.match(byId(botFindings, "WEBEX-MTG-02").summary, /^Manual: \/admin\/meeting\/config\/commonSettings was not queried because a bot token cannot read admin surfaces/);
  assert.equal(byId(botFindings, "WEBEX-MTG-06").status, "manual");
  assert.equal(byId(botFindings, "WEBEX-MTG-03").status, "manual");
});

test("fixture (d): a compliant organization passes every automatable control, including 9, 10, and 13", async () => {
  const assessments = await allAssessments(compliantClient());
  const findings = findingsOf(assessments);
  assert.equal(findings.length, FINDING_COUNT);
  for (const id of AUTOMATABLE) {
    assert.equal(byId(findings, id)?.status, "pass", `${id} should pass on the compliant fixture`);
  }
  const manual = findings.filter((item) => item.status === "manual").map((item) => item.id);
  assert.deepEqual(manual, MANUAL_ON_COMPLIANT);
  for (const item of findings.filter((entry) => entry.status === "manual")) {
    assert.match(item.summary, /^Manual:/);
    assert.match(item.summary, /developer\.webex\.com|Control Hub/);
  }
  const covered = new Set(findings.flatMap((item) => item.control));
  assert.equal(covered.size, 25);
  assert.ok(findings.every((item) => item.frameworks.fedramp.length > 0));
  assert.equal(byId(findings, "WEBEX-ID-05").evidence.bot_count, 1);
  assert.match(byId(findings, "WEBEX-MTG-01").summary, /SRTP .*folded/);
  assert.deepEqual(byId(findings, "WEBEX-MTG-02").control, [9]);
  assert.deepEqual(byId(findings, "WEBEX-MTG-06").control, [10]);
  assert.deepEqual(byId(findings, "WEBEX-MTG-03").control, [13]);
  assert.deepEqual(byId(findings, "WEBEX-MTG-07").control, [23]);
  assert.deepEqual(byId(findings, "WEBEX-COLLAB-01").control, [4]);
  assert.deepEqual(byId(findings, "WEBEX-ID-07").control, [13]);
  const passingControls = new Set(findings.filter((item) => item.status === "pass").flatMap((item) => item.control));
  for (const control of [3, 9, 10, 13, 14, 15, 16, 19, 20, 24, 25]) {
    assert.ok(passingControls.has(control), `control ${control} should pass on the compliant fixture`);
  }
  for (const assessment of assessments) {
    assert.deepEqual(assessment.errors, []);
  }
});

test("WEBEX-MTG-02 and WEBEX-MTG-06 judge lobby and password defaults per site from commonSettings", async () => {
  const compliant = await assessWebexMeetingHybridSecurity(compliantClient());
  const lobby = byId(compliant.findings, "WEBEX-MTG-02");
  assert.equal(lobby.status, "pass");
  assert.match(lobby.summary, /example\.webex\.com: joinBeforeHost = false, audioBeforeHost = false, unlistAllMeetings = true \(GET \/admin\/meeting\/config\/commonSettings, 1 of 1 sites\)/);
  assert.equal(lobby.evidence.site_coverage_complete, true);
  assert.equal(lobby.evidence.citation, WEBEX_DOCS.meetingCommonSettings);
  assert.deepEqual(lobby.evidence.sites[0], {
    site_url: "example.webex.com",
    status: "pass",
    detail: "joinBeforeHost = false, audioBeforeHost = false, unlistAllMeetings = true",
    join_before_host: false,
    audio_before_host: false,
    unlist_all_meetings: true,
  });
  assert.equal(lobby.evidence.sampled_allow_join_without_lobby, 0);
  assert.equal(lobby.evidence.personal_meeting_room_auto_lock, true);
  const password = byId(compliant.findings, "WEBEX-MTG-06");
  assert.equal(password.status, "pass");
  assert.match(password.summary, /requireStrongPassword = true with passwordCriteria\.minLength = 8/);
  assert.equal(password.evidence.sites[0].min_special, 1);
  assert.equal(compliant.summary.sites_evaluated, 1);

  const failing = await assessWebexMeetingHybridSecurity(compliantClient({
    async getMeetingCommonSettings() {
      return compliantCommonSettings({ joinBeforeHost: true, requireStrongPassword: false });
    },
  }));
  const failingLobby = byId(failing.findings, "WEBEX-MTG-02");
  assert.equal(failingLobby.status, "fail");
  assert.match(failingLobby.summary, /attendees may join before the host \(joinBeforeHost = true, audioBeforeHost = false\)/);
  assert.equal(byId(failing.findings, "WEBEX-MTG-06").status, "fail");
  assert.match(byId(failing.findings, "WEBEX-MTG-06").summary, /requireStrongPassword = false/);

  const weak = await assessWebexMeetingHybridSecurity(compliantClient({
    async getMeetingCommonSettings() {
      return compliantCommonSettings({ unlistAllMeetings: false, passwordCriteria: { minLength: 6, mixedCase: false } });
    },
  }));
  assert.equal(byId(weak.findings, "WEBEX-MTG-02").status, "warn");
  assert.match(byId(weak.findings, "WEBEX-MTG-02").summary, /unlistAllMeetings = false/);
  assert.equal(byId(weak.findings, "WEBEX-MTG-06").status, "warn");
  assert.match(byId(weak.findings, "WEBEX-MTG-06").summary, /minLength = 6 \(threshold 8\)/);

  const missing = await assessWebexMeetingHybridSecurity(compliantClient({
    async getMeetingCommonSettings() {
      return { siteOptions: { allowCustomPersonalRoomURL: true } };
    },
  }));
  assert.equal(byId(missing.findings, "WEBEX-MTG-02").status, "manual");
  assert.match(byId(missing.findings, "WEBEX-MTG-02").summary, /^Manual: .*securityOptions\.joinBeforeHost was absent.* Collect the Control Hub site Common Settings > Security page/);
  assert.equal(byId(missing.findings, "WEBEX-MTG-06").status, "manual");
});

test("site coverage: a denied or unlisted site downgrades a passing commonSettings verdict to warn", async () => {
  const requested = [];
  const twoSites = compliantClient({
    async listMeetingSites() {
      return page([{ siteUrl: "example.webex.com", default: true }, { siteUrl: "second.webex.com", default: false }]);
    },
    async getMeetingCommonSettings(siteUrl) {
      requested.push(siteUrl);
      if (siteUrl === "second.webex.com") throw forbidden("/admin/meeting/config/commonSettings");
      return compliantCommonSettings();
    },
  });
  const result = await assessWebexMeetingHybridSecurity(twoSites);
  assert.deepEqual(requested.sort(), ["example.webex.com", "second.webex.com"]);
  for (const id of ["WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-06"]) {
    const item = byId(result.findings, id);
    assert.equal(item.status, "warn", `${id} should warn when one site is denied`);
    assert.match(item.summary, /1 of 2 sites could not be read \(second\.webex\.com: .*403/);
    assert.deepEqual(item.evidence.denied_sites.map((site) => site.site_url), ["second.webex.com"]);
    assert.equal(item.evidence.site_coverage_complete, false);
  }
  assert.equal(result.summary.sites_evaluated, 1);
  assert.equal(result.summary.sites_denied, 1);

  const noSiteList = await assessWebexMeetingHybridSecurity(compliantClient({
    async listMeetingSites() {
      throw forbidden("/meetingPreferences/sites");
    },
    async getMeetingPreferences() {
      return { personalMeetingRoom: { enabledAutoLock: true } };
    },
  }));
  const lobby = byId(noSiteList.findings, "WEBEX-MTG-02");
  assert.equal(lobby.status, "warn");
  assert.match(lobby.summary, /\(preferred site\): joinBeforeHost = false/);
  assert.match(lobby.summary, /site list \(GET \/meetingPreferences\/sites\) was not readable .*only the administrator's preferred site was evaluated/);

  const allDenied = await assessWebexMeetingHybridSecurity(compliantClient({
    async getMeetingCommonSettings() {
      throw forbidden("/admin/meeting/config/commonSettings");
    },
  }));
  const denied = byId(allDenied.findings, "WEBEX-MTG-06");
  assert.equal(denied.status, "manual");
  assert.match(denied.summary, /^Manual: \/admin\/meeting\/config\/commonSettings returned 403; the token lacks the scope or admin role for meeting common settings\. Collect the Control Hub site Common Settings > Security page \(strong password criteria\)\./);
  assert.ok(allDenied.errors.some((item) => /meeting_common_settings/.test(item)));
});

test("WEBEX-MTG-03 automates guest access from requireLoginBeforeAccess and WEBEX-MTG-07 keeps virtual background manual", async () => {
  const compliant = await assessWebexMeetingHybridSecurity(compliantClient());
  const guest = byId(compliant.findings, "WEBEX-MTG-03");
  assert.equal(guest.status, "pass");
  assert.deepEqual(guest.control, [13]);
  assert.match(guest.summary, /example\.webex\.com: requireLoginBeforeAccess = true/);
  assert.equal(guest.evidence.sites[0].require_login_before_access, true);
  const background = byId(compliant.findings, "WEBEX-MTG-07");
  assert.equal(background.status, "manual");
  assert.deepEqual(background.control, [23]);
  assert.match(background.summary, /^Manual: virtual background enforcement is a Control Hub meeting setting/);
  assert.match(background.summary, /site\/get-meeting-common-settings-configuration/);
  assert.match(background.summary, /session-types/);

  const open = await assessWebexMeetingHybridSecurity(compliantClient({
    async getMeetingCommonSettings() {
      return compliantCommonSettings({ requireLoginBeforeAccess: false });
    },
  }));
  const openGuest = byId(open.findings, "WEBEX-MTG-03");
  assert.equal(openGuest.status, "fail");
  assert.match(openGuest.summary, /requireLoginBeforeAccess = false \(unauthenticated guests can reach the site\)/);
  assert.equal(byId(open.findings, "WEBEX-MTG-02").status, "pass");

  const absent = await assessWebexMeetingHybridSecurity(compliantClient({
    async getMeetingCommonSettings() {
      return compliantCommonSettings({ requireLoginBeforeAccess: undefined });
    },
  }));
  assert.equal(byId(absent.findings, "WEBEX-MTG-03").status, "manual");
  assert.match(byId(absent.findings, "WEBEX-MTG-03").summary, /requireLoginBeforeAccess was absent/);
});

test("WEBEX-ID-07 inventories guests from Person.type = appuser and GET /guests/count; WEBEX-COLLAB-01 covers control 4 only", async () => {
  const identity = await assessWebexIdentity(compliantClient());
  const guests = byId(identity.findings, "WEBEX-ID-07");
  assert.equal(guests.status, "pass");
  assert.deepEqual(guests.control, [13]);
  assert.match(guests.summary, /1 guest accounts \(Person\.type = appuser, documented as a guest user\) were inventoried among 5 people\. GET \/guests\/count reports 1 guest-issuer guests\./);
  assert.deepEqual(guests.evidence.guests, [{ id: "g1", display_name: "Visitor", created: "2026-09-01T00:00:00.000Z" }]);
  assert.equal(guests.evidence.guest_count_people, 1);
  assert.equal(guests.evidence.guest_count_api, 1);
  assert.equal(guests.evidence.guest_count_citation, WEBEX_DOCS.guestCount);
  assert.equal(identity.summary.guests, 1);
  assert.equal(byId(identity.findings, "WEBEX-ID-04").evidence.people_seen, 3, "guests and bots are excluded from the human population");

  const noScope = await assessWebexIdentity(compliantClient({
    async getGuestCount() {
      throw forbidden("/guests/count");
    },
  }));
  const partialGuests = byId(noScope.findings, "WEBEX-ID-07");
  assert.equal(partialGuests.status, "pass", "a denied /guests/count is supplementary and does not block the people-based inventory");
  assert.match(partialGuests.summary, /GET \/guests\/count was not readable \(.*403.*; scope guest-issuer:read\)/);
  assert.equal(partialGuests.evidence.guest_count_api, null);
  assert.match(partialGuests.evidence.guest_count_api_error, /403/);
  assert.ok(noScope.errors.some((item) => /guest_count/.test(item)));

  const collaboration = await assessWebexCollaborationGovernance(compliantClient());
  const external = byId(collaboration.findings, "WEBEX-COLLAB-01");
  assert.deepEqual(external.control, [4]);
  assert.equal(external.status, "manual");
  assert.match(external.summary, /Guest access \(control 13\) is judged from the site common settings in WEBEX-MTG-03 and inventoried in WEBEX-ID-07/);
  assert.doesNotMatch(external.summary, /guest access policy;/);
});

test("WEBEX-ID-02 states that mfaEnabled is documented only on the PATCH authenticationConfig schema", async () => {
  const identity = await assessWebexIdentity(compliantClient());
  const mfa = byId(identity.findings, "WEBEX-ID-02");
  assert.equal(mfa.status, "manual");
  assert.match(mfa.summary, /^Manual: mfaEnabled is documented on \/identity\/organizations\/\{orgId\}\/authenticationConfig only in the PATCH request schema/);
  assert.match(mfa.summary, /no GET is published, and this read-only inspector never issues a PATCH/);
  assert.equal(mfa.evidence.citation, WEBEX_DOCS.authenticationConfig);
  assert.equal(mfa.evidence.admin_count, 1);

  const denied = byId((await assessWebexIdentity(forbiddenClient())).findings, "WEBEX-ID-02");
  assert.equal(denied.status, "manual");
  assert.match(denied.summary, /mfaEnabled is documented .* only in the PATCH request schema/);
});

test("WEBEX-MTG-05 collects upgradeChannel evidence alongside software versions", async () => {
  const result = await assessWebexMeetingHybridSecurity(compliantClient({
    async listDevices() {
      return page([
        { id: "dev-1", displayName: "Room Kit", workspaceId: "ws-1", software: "RoomOS 11.20", upgradeChannel: "stable", connectionStatus: "connected", managedBy: "CUSTOMER" },
        { id: "dev-2", displayName: "Desk", personId: "u3", software: "RoomOS 11.18", upgradeChannel: "beta", connectionStatus: "disconnected", managedBy: "CUSTOMER" },
        { id: "dev-3", displayName: "Legacy", workspaceId: "ws-1", software: "ce9.15", connectionStatus: "connected", managedBy: "CISCO" },
      ]);
    },
  }));
  const devices = byId(result.findings, "WEBEX-MTG-05");
  assert.equal(devices.status, "manual");
  assert.deepEqual(devices.evidence.upgrade_channels, ["stable", "beta"]);
  assert.equal(devices.evidence.devices_without_upgrade_channel, 1);
  assert.deepEqual(devices.evidence.software_versions, ["RoomOS 11.20", "RoomOS 11.18", "ce9.15"]);
  assert.deepEqual(devices.evidence.managed_by, ["CUSTOMER", "CISCO"]);
  assert.match(devices.summary, /upgrade channels stable, beta/);
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
  assert.equal(byId(result.findings, "WEBEX-ID-03").status, "fail");
  assert.equal(byId(result.findings, "WEBEX-ID-04").status, "warn");
  assert.equal(byId(result.findings, "WEBEX-ID-05").status, "pass");
  assert.equal(byId(result.findings, "WEBEX-ID-05").evidence.bot_count, 0);
  assert.equal(byId(result.findings, "WEBEX-ID-07").evidence.guest_count_people, 0);
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
  assert.equal(byId(result.findings, "WEBEX-COLLAB-04").status, "fail");
  assert.equal(byId(result.findings, "WEBEX-COLLAB-05").status, "fail");
  assert.equal(byId(result.findings, "WEBEX-COLLAB-06").status, "warn");
  assert.equal(byId(result.findings, "WEBEX-COLLAB-08").status, "manual");
  assert.match(byId(result.findings, "WEBEX-COLLAB-08").summary, /eDiscovery report is available through Control Hub/);
});

test("assessWebexMeetingHybridSecurity fails non-operational connectors and counts undated connectors by the documented created field", async () => {
  const client = compliantClient({
    async listHybridConnectors() {
      return page([{ id: "conn-1", type: "calendar", status: "impaired" }, { id: "conn-2", type: "calendar", status: "operational", created: "2026-01-01T00:00:00.000Z" }]);
    },
    async listMeetings() {
      return page([{ id: "m-1", unlockedMeetingJoinSecurity: "allowJoin" }]);
    },
  });
  const result = await assessWebexMeetingHybridSecurity(client);
  const hybrid = byId(result.findings, "WEBEX-MTG-04");
  assert.equal(hybrid.status, "fail");
  assert.equal(hybrid.evidence.non_operational.length, 1);
  const lobby = byId(result.findings, "WEBEX-MTG-02");
  assert.equal(lobby.status, "pass");
  assert.equal(lobby.evidence.sampled_allow_join_without_lobby, 1);
  assert.equal(lobby.evidence.sampled_without_password, 1);
  assert.equal(byId(result.findings, "WEBEX-MTG-05").status, "manual");

  const healthy = await assessWebexMeetingHybridSecurity(compliantClient({
    async listHybridConnectors() {
      return page([{ id: "conn-1", type: "calendar", status: "operational", version: "1.0" }]);
    },
  }));
  assert.equal(byId(healthy.findings, "WEBEX-MTG-04").evidence.undated_connectors, 1);
  assert.equal(byId((await assessWebexMeetingHybridSecurity(compliantClient())).findings, "WEBEX-MTG-04").evidence.undated_connectors, 0);
});

test("exportWebexAuditBundle writes the shared layout, redacts secrets, and never overwrites a prior bundle", async () => {
  const base = createTempBase("grclanker-webex-export-");
  const first = await exportWebexAuditBundle(compliantClient(), sampleConfig(), base);
  assert.ok(existsSync(first.outputDir));
  assert.equal(first.zipPath, `${first.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath));
  assert.equal(first.findingCount, FINDING_COUNT);
  assert.equal(first.errorCount, 0);
  assert.ok(!existsSync(join(first.outputDir, "_errors.log")));

  for (const relativePath of [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access.json",
    "core_data/identity/people.json",
    "core_data/identity/guest_count.json",
    "core_data/collaboration-governance/webhooks.json",
    "core_data/meeting-hybrid-security/meeting_preferences.json",
    "core_data/meeting-hybrid-security/meeting_common_settings.json",
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
  const commonSettings = JSON.parse(readFileSync(join(first.outputDir, "core_data/meeting-hybrid-security/meeting_common_settings.json"), "utf8"));
  assert.equal(commonSettings[0].siteUrl, "example.webex.com");
  assert.equal(commonSettings[0].securityOptions.passwordCriteria.minLength, 8);
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
