import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  SLACK_METHODS,
  SLACK_SPEC_CONTROLS,
  SlackApiClient,
  assessSlackAdminAccess,
  assessSlackChannelGovernance,
  assessSlackIdentity,
  assessSlackIntegrations,
  assessSlackMonitoring,
  checkSlackAccess,
  exportSlackAuditBundle,
  resolveSecureOutputPath,
  resolveSlackConfiguration,
} from "../dist/extensions/grc-tools/slack.js";

const NOW = new Date("2026-09-21T00:00:00.000Z");
const EMPTY_ENV = { SLACK_CONFIG_FILE: "" };

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function jsonResponse(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", ...headers } });
}

async function requestParams(input, init = {}) {
  const url = new URL(typeof input === "string" ? input : input.toString());
  const params = new URLSearchParams(url.search);
  if (init.method === "POST" && typeof init.body === "string") {
    for (const [key, value] of new URLSearchParams(init.body)) params.set(key, value);
  }
  return { pathname: url.pathname, params, method: init.method ?? "GET", auth: init.headers?.authorization };
}

function makeClient(handler, config = { token: "xoxp-test", scim_token: "scim-test", org_id: "E1" }) {
  const fetchImpl = async (input, init) => {
    const request = await requestParams(input, init);
    const result = handler(request);
    return result instanceof Response ? result : jsonResponse(result);
  };
  return new SlackApiClient(resolveSlackConfiguration(config, EMPTY_ENV), { fetchImpl, now: () => NOW, sleep: async () => {} });
}

function byId(result, id) {
  const item = result.findings.find((entry) => entry.id === id);
  assert.ok(item, `missing finding ${id}`);
  return item;
}

function statuses(result) {
  return Object.fromEntries(result.findings.map((item) => [item.id, item.status]));
}

const deniedFixture = () => jsonResponse({ ok: false, error: "missing_scope" });

const emptyFixture = ({ pathname }) => {
  const method = pathname.replace(/^\/api\//, "");
  if (pathname === "/api/auth.test") return { ok: true, team: "Acme", team_id: "T1", user: "auditor", user_id: "U0", is_enterprise_install: true };
  if (pathname.startsWith("/scim/v2/ServiceProviderConfig")) return { patch: { supported: true } };
  if (pathname.startsWith("/scim/v2/")) return { totalResults: 0, Resources: [] };
  if (pathname === "/audit/v1/logs") return { entries: [], response_metadata: { next_cursor: "" } };
  if (pathname === "/audit/v1/schemas") return { schemas: [] };
  const lists = {
    "users.list": { members: [] },
    "admin.teams.list": { teams: [] },
    "admin.users.list": { users: [] },
    "admin.apps.approved.list": { approved_apps: [] },
    "admin.apps.restricted.list": { restricted_apps: [] },
    "admin.barriers.list": { barriers: [] },
    "admin.conversations.search": { conversations: [], next_cursor: "", total_count: 0 },
    "admin.emoji.list": { emoji: {} },
    "admin.users.session.getSettings": { session_settings: [], no_settings_applied: [] },
    "admin.teams.admins.list": { admin_ids: [] },
  };
  if (lists[method]) return { ok: true, ...lists[method], response_metadata: { next_cursor: "" } };
  if (method === "discovery.enterprise.info") return { ok: true, enterprise: { id: "E1" } };
  if (method === "admin.analytics.getFile") return { ok: true };
  return { ok: true };
};

const compliantUsers = [
  { id: "W1", name: "alice", deleted: false, is_admin: true, is_owner: false, is_bot: false, is_app_user: false, is_restricted: false, is_ultra_restricted: false, has_2fa: true, profile: { email: "alice@example.com" } },
  { id: "W2", name: "bob", deleted: false, is_admin: false, is_owner: false, is_bot: false, is_app_user: false, is_restricted: false, is_ultra_restricted: false, has_2fa: true, profile: { email: "bob@example.com" } },
  { id: "W3", name: "gone", deleted: true, is_bot: false, is_app_user: false, has_2fa: true, profile: { email: "gone@example.com" } },
];

const compliantFixture = ({ pathname, params }) => {
  const method = pathname.replace(/^\/api\//, "");
  if (pathname === "/api/auth.test") return { ok: true, url: "https://acme.slack.com/", team: "Acme", team_id: "T1", user: "auditor", user_id: "W1", enterprise_id: "E1", is_enterprise_install: true };
  if (pathname === "/scim/v2/ServiceProviderConfig") return { patch: { supported: true } };
  if (pathname === "/scim/v2/Users") {
    return { totalResults: 2, itemsPerPage: 2, startIndex: 1, Resources: [
      { id: "S1", userName: "alice@example.com", active: true, emails: [{ value: "alice@example.com", primary: true }] },
      { id: "S2", userName: "gone@example.com", active: false, emails: [{ value: "gone@example.com", primary: true }] },
    ] };
  }
  if (pathname === "/scim/v2/Groups") return { totalResults: 1, Resources: [{ id: "G1", displayName: "Engineering" }] };
  if (pathname === "/audit/v1/logs") {
    return { entries: [
      { id: "L1", date_create: 1789920000, action: "user_login", actor: { type: "user" }, entity: { type: "user" } },
      { id: "L2", date_create: 1789910000, action: "channel_shared", actor: { type: "user" }, entity: { type: "channel" } },
    ], response_metadata: { next_cursor: "" } };
  }
  if (pathname === "/audit/v1/schemas") return { schemas: [{ type: "user", user: {} }] };
  switch (method) {
    case "users.list":
      return { ok: true, members: compliantUsers, response_metadata: { next_cursor: "" } };
    case "admin.teams.list":
      return { ok: true, teams: [{ id: "T1", name: "Core", discoverability: "invite_only", primary_owner: { user_id: "W1", email: "alice@example.com" }, team_url: "https://acme.slack.com/" }], response_metadata: { next_cursor: "" } };
    case "admin.teams.settings.info":
      return { ok: true, team: { id: "T1", name: "Core", domain: "acme", email_domain: "example.com", icon: {}, enterprise_id: "E1", enterprise_name: "Acme", default_channels: ["C1"] } };
    case "admin.teams.admins.list":
      return { ok: true, admin_ids: ["W1"], response_metadata: { next_cursor: "" } };
    case "admin.users.list":
      return { ok: true, users: [
        { id: "W1", email: "alice@example.com", is_admin: true, is_owner: false, is_primary_owner: true, is_restricted: false, is_ultra_restricted: false, is_bot: false, username: "alice", full_name: "Alice", is_active: true, date_created: 1566922090, deactivated_ts: 0, expiration_ts: 0, workspaces: ["T1"], has_2fa: true, has_sso: true },
        { id: "W2", email: "bob@example.com", is_admin: false, is_owner: false, is_primary_owner: false, is_restricted: false, is_ultra_restricted: false, is_bot: false, username: "bob", full_name: "Bob", is_active: true, date_created: 1566922090, deactivated_ts: 0, expiration_ts: 0, workspaces: ["T1"], has_2fa: true, has_sso: true },
      ], response_metadata: { next_cursor: "" } };
    case "admin.users.session.getSettings":
      assert.equal(params.get("user_ids"), "W1,W2");
      return { ok: true, session_settings: [
        { user_id: "W1", desktop_app_browser_quit: true, duration: 43200 },
        { user_id: "W2", desktop_app_browser_quit: true, duration: 43200 },
      ], no_settings_applied: [] };
    case "admin.apps.approved.list":
      return { ok: true, approved_apps: [{ app: { id: "A1", name: "Marketplace App", is_app_directory_approved: true, is_internal: false, developer_type: "third_party" }, scopes: [{ name: "chat:write", description: "", is_sensitive: false, token_type: "bot" }], date_updated: 1574296707, last_resolved_by: { actor_id: "W1", actor_type: "user" } }], response_metadata: { next_cursor: "" } };
    case "admin.apps.restricted.list":
      return { ok: true, restricted_apps: [{ app: { id: "A2", name: "Blocked App", is_app_directory_approved: true, is_internal: false, developer_type: "third_party" }, scopes: [{ name: "files:write:user", description: "", is_sensitive: true, token_type: "user" }], date_updated: 1574296721, last_resolved_by: { actor_id: "W1", actor_type: "user" } }], response_metadata: { next_cursor: "" } };
    case "admin.barriers.list":
      return { ok: true, barriers: [{ id: "B1", enterprise_id: "E1", primary_usergroup: { id: "S1", name: "Trading" }, barriered_from_usergroups: [{ id: "S2", name: "Research" }], restricted_subjects: ["im", "mpim", "call"], date_update: 1660224825 }], response_metadata: { next_cursor: "" } };
    case "admin.conversations.search":
      if (params.get("search_channel_types") === "external_shared") return { ok: true, conversations: [], next_cursor: "", total_count: 0 };
      return { ok: true, conversations: [
        { id: "C1", name: "general", member_count: 2, created: 1578423973, creator_id: "W1", is_private: false, is_archived: false, is_general: true, is_ext_shared: false, is_org_default: true, is_org_mandatory: false, is_org_shared: true, connected_team_ids: [], pending_connected_team_ids: [], is_pending_ext_shared: false },
        { id: "C2", name: "eng", member_count: 2, created: 1578423973, creator_id: "W1", is_private: false, is_archived: false, is_general: false, is_ext_shared: false, is_org_default: false, is_org_mandatory: false, is_org_shared: false, connected_team_ids: [], pending_connected_team_ids: [], is_pending_ext_shared: false },
      ], next_cursor: "", total_count: 2 };
    case "admin.conversations.getConversationPrefs":
      return params.get("channel_id") === "C1"
        ? { ok: true, prefs: { who_can_post: { type: ["admin"], user: [] }, can_thread: { type: ["ra"], user: [] } } }
        : { ok: true, prefs: { who_can_post: { type: ["ra"], user: [] }, can_thread: { type: ["ra"], user: [] } } };
    case "admin.conversations.getCustomRetention":
      return params.get("channel_id") === "C1" ? { ok: true, is_policy_enabled: true, duration_days: 400 } : { ok: true, is_policy_enabled: false, duration_days: 0 };
    case "admin.emoji.list":
      return { ok: true, emoji: { party: { url: "https://emoji.slack-edge.com/T1/party/1.png", date_created: 1591720632, uploaded_by: "W1" } }, response_metadata: { next_cursor: "" } };
    case "admin.analytics.getFile":
      return { ok: true };
    case "discovery.enterprise.info":
      return { ok: true, enterprise: { id: "E1", name: "Acme" } };
    default:
      throw new Error(`unexpected method ${method}`);
  }
};

const TRUNCATED_LISTS = new Set(["admin.teams.list", "users.list", "admin.users.list", "admin.apps.approved.list", "admin.apps.restricted.list", "admin.barriers.list", "admin.emoji.list", "admin.teams.admins.list"]);

const partialFixture = (request) => {
  const method = request.pathname.replace(/^\/api\//, "");
  if (method === "admin.conversations.search") return jsonResponse({ ok: false, error: "not_allowed_token_type" });
  if (request.pathname === "/audit/v1/schemas") return jsonResponse({ error: "forbidden" }, 403);
  const base = compliantFixture(request);
  if (TRUNCATED_LISTS.has(method)) return { ...base, response_metadata: { next_cursor: "more" } };
  if (request.pathname === "/scim/v2/Users") return { ...base, totalResults: 5 };
  if (request.pathname === "/audit/v1/logs") return { ...base, response_metadata: { next_cursor: "more" } };
  return base;
};

const MANUAL_BY_DESIGN = new Set(["SLACK-ADMIN-04", "SLACK-ADMIN-06", "SLACK-ADMIN-09", "SLACK-APP-05", "SLACK-APP-06", "SLACK-APP-07", "SLACK-CHAN-04", "SLACK-CHAN-05", "SLACK-MON-06"]);

async function runAll(client, options = {}) {
  return [
    await assessSlackIdentity(client, options),
    await assessSlackAdminAccess(client, { ...options, workspaceLimit: options.workspaceLimit }),
    await assessSlackIntegrations(client, options),
    await assessSlackChannelGovernance(client, options),
    await assessSlackMonitoring(client, options),
  ];
}

test("resolveSlackConfiguration reads arguments, environment, bot tokens, and config files", () => {
  const resolved = resolveSlackConfiguration(
    { org_id: " E123 ", timeout_seconds: "12" },
    { SLACK_USER_TOKEN: "xoxp-env", SLACK_SCIM_TOKEN: "scim-env", SLACK_BOT_TOKEN: "xoxb-env", SLACK_CONFIG_FILE: "" },
  );
  assert.equal(resolved.token, "xoxp-env");
  assert.equal(resolved.botToken, "xoxb-env");
  assert.equal(resolved.scimToken, "scim-env");
  assert.equal(resolved.orgId, "E123");
  assert.equal(resolved.timeoutMs, 12_000);
  assert.ok(resolved.sourceChain.includes("environment-token"));
  assert.ok(resolved.sourceChain.includes("environment-bot-token"));

  const botOnly = resolveSlackConfiguration({}, { SLACK_BOT_TOKEN: "xoxb-only", SLACK_CONFIG_FILE: "" });
  assert.equal(botOnly.token, undefined);
  assert.equal(botOnly.botToken, "xoxb-only");

  const base = createTempBase("grclanker-slack-config-");
  const configPath = join(base, "slack.json");
  writeFileSync(configPath, JSON.stringify({ user_token: "xoxp-file", scim_token: "scim-file", org_id: "E9" }));
  const fromFile = resolveSlackConfiguration({}, { SLACK_CONFIG_FILE: configPath });
  assert.equal(fromFile.token, "xoxp-file");
  assert.equal(fromFile.orgId, "E9");
  assert.ok(fromFile.sourceChain.includes("config-file-token"));

  assert.throws(() => resolveSlackConfiguration({}, EMPTY_ENV), /SLACK_USER_TOKEN/);
  assert.throws(() => resolveSlackConfiguration({}, { SLACK_CONFIG_FILE: join(base, "missing.json") }), /does not exist/);
});

test("SlackApiClient uses documented verbs, bearer auth, cursor pagination, and limit maxima", async () => {
  const seen = [];
  const client = makeClient((request) => {
    seen.push(request);
    if (request.pathname === "/api/users.list") {
      return request.params.get("cursor")
        ? { ok: true, members: [{ id: "U2" }], response_metadata: { next_cursor: "" } }
        : { ok: true, members: [{ id: "U1" }], response_metadata: { next_cursor: "next-page" } };
    }
    if (request.pathname === "/api/admin.conversations.search") {
      return request.params.get("cursor")
        ? { ok: true, conversations: [{ id: "C2" }], next_cursor: "", total_count: 2 }
        : { ok: true, conversations: [{ id: "C1" }], next_cursor: "top-level", total_count: 2 };
    }
    throw new Error(`unexpected ${request.pathname}`);
  });

  const users = await client.collectWeb("users.list", ["members"], {}, { pageLimit: 1 });
  assert.deepEqual(users.items.map((user) => user.id), ["U1", "U2"]);
  assert.equal(users.complete, true);
  assert.equal(seen[0].method, "GET");
  assert.equal(seen[0].auth, "Bearer xoxp-test");
  assert.equal(seen[1].params.get("cursor"), "next-page");

  const channels = await client.collectWeb("admin.conversations.search", ["conversations"], {}, { pageLimit: 500 });
  assert.deepEqual(channels.items.map((channel) => channel.id), ["C1", "C2"]);
  assert.equal(channels.total, 2);
  assert.equal(seen[2].method, "POST");
  assert.equal(seen[2].params.get("limit"), "20");
  assert.equal(seen[3].params.get("cursor"), "top-level");

  const capped = await client.collectWeb("users.list", ["members"], {}, { pageLimit: 1, limit: 1 });
  assert.equal(capped.complete, false);
});

test("SlackApiClient treats ok:false and HTTP 403 as errors and honors Retry-After on 429", async () => {
  const okFalse = makeClient(() => ({ ok: false, error: "not_allowed_token_type" }));
  await assert.rejects(okFalse.web("admin.teams.list"), (error) => error.code === "not_allowed_token_type");

  const forbidden = makeClient(() => jsonResponse({ ok: false, error: "invalid_auth" }, 403));
  await assert.rejects(forbidden.web("users.list"), (error) => error.code === "http_forbidden" && error.httpStatus === 403);

  let attempts = 0;
  const waits = [];
  const fetchImpl = async () => {
    attempts += 1;
    return attempts === 1 ? jsonResponse({ ok: false, error: "ratelimited" }, 429, { "retry-after": "3" }) : jsonResponse({ ok: true, team_id: "T1" });
  };
  const limited = new SlackApiClient(resolveSlackConfiguration({ token: "xoxp-test" }, EMPTY_ENV), { fetchImpl, sleep: async (ms) => { waits.push(ms); } });
  const auth = await limited.web("auth.test");
  assert.equal(auth.team_id, "T1");
  assert.deepEqual(waits, [3000]);
});

test("SlackApiClient uses bot tokens only for bot-capable methods", async () => {
  const seen = [];
  const client = makeClient((request) => {
    seen.push(request.auth);
    return { ok: true, members: [], response_metadata: { next_cursor: "" } };
  }, { bot_token: "xoxb-test" });
  await client.web("users.list");
  assert.deepEqual(seen, ["Bearer xoxb-test"]);
  await assert.rejects(client.web("admin.teams.list"), (error) => error.code === "not_allowed_token_type");
  await assert.rejects(client.audit("/logs"), (error) => error.code === "not_allowed_token_type");
});

test("checkSlackAccess reports readable surfaces using documented response keys", async () => {
  const result = await checkSlackAccess(makeClient(compliantFixture));
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 15);
  assert.equal(result.surfaces.find((surface) => surface.name === "approved_apps")?.count, 1);
  assert.deepEqual(result.tokenKinds, ["user"]);
  assert.match(result.recommendedNextStep, /slack_assess_channel_governance/);

  const limited = await checkSlackAccess(makeClient((request) => request.pathname === "/api/auth.test" ? { ok: true, team_id: "T1" } : deniedFixture(), { token: "xoxp-test" }));
  assert.equal(limited.status, "limited");
  assert.equal(limited.surfaces.find((surface) => surface.name === "scim_users")?.status, "not_configured");
});

test("fixture (a): every method denied yields manual findings and never pass", async () => {
  const client = makeClient((request) => request.pathname === "/api/auth.test" ? { ok: true, team_id: "T1" } : deniedFixture());
  const results = await runAll(client);
  const all = results.flatMap((result) => result.findings);
  assert.equal(all.length, 32);
  assert.equal(all.filter((item) => item.status === "pass").length, 0);
  assert.equal(all.filter((item) => item.status === "manual").length, all.length);
  for (const item of all.filter((entry) => !MANUAL_BY_DESIGN.has(entry.id))) {
    assert.match(item.summary, /not readable|not configured|not exposed|No active users|no workspaces/i, `${item.id} should name the cause`);
    assert.match(item.summary, /Manual evidence:/, `${item.id} should name the evidence to collect`);
  }
  assert.match(byId(results[0], "SLACK-ID-01").summary, /users\.list is not readable: .*missing_scope/);
  assert.ok(results.every((result) => result.errors.length > 0));
});

test("fixture (a'): HTTP 403 responses are treated as unreadable, not empty", async () => {
  const client = makeClient((request) => request.pathname === "/api/auth.test" ? { ok: true, team_id: "T1" } : jsonResponse({ ok: false, error: "invalid_auth" }, 403));
  const results = await runAll(client);
  const all = results.flatMap((result) => result.findings);
  assert.equal(all.filter((item) => item.status === "pass").length, 0);
  assert.equal(byId(results[2], "SLACK-APP-01").status, "manual");
  assert.match(byId(results[2], "SLACK-APP-01").summary, /HTTP 403/);
});

test("fixture (b): empty inventories never pass by default", async () => {
  const results = await runAll(makeClient(emptyFixture));
  const all = results.flatMap((result) => result.findings);
  assert.equal(all.filter((item) => item.status === "pass").length, 1, JSON.stringify(statuses({ findings: all })));
  assert.equal(byId(results[3], "SLACK-CHAN-01").status, "pass");
  assert.equal(byId(results[0], "SLACK-ID-05").status, "warn");
  assert.match(byId(results[3], "SLACK-CHAN-01").summary, /emptiness is compliant by intent/);
  assert.equal(byId(results[0], "SLACK-ID-01").status, "warn");
  assert.equal(byId(results[0], "SLACK-ID-02").status, "warn");
  assert.equal(byId(results[0], "SLACK-ID-03").status, "fail");
  assert.equal(byId(results[1], "SLACK-ADMIN-01").status, "manual");
  assert.equal(byId(results[1], "SLACK-ADMIN-02").status, "warn");
  assert.equal(byId(results[1], "SLACK-ADMIN-03").status, "manual");
  assert.equal(byId(results[2], "SLACK-APP-01").status, "warn");
  assert.match(byId(results[2], "SLACK-APP-01").summary, /not treated as compliant/);
  assert.equal(byId(results[2], "SLACK-APP-04").status, "warn");
  assert.equal(byId(results[4], "SLACK-MON-01").status, "fail");
  assert.equal(byId(results[4], "SLACK-MON-04").status, "warn");
});

test("fixture (c): partial inventories and not_allowed_token_type never pass", async () => {
  const results = await runAll(makeClient(partialFixture), { userLimit: 3, workspaceLimit: 1, appLimit: 1 });
  const all = results.flatMap((result) => result.findings);
  assert.equal(all.filter((item) => item.status === "pass").length, 0, JSON.stringify(statuses({ findings: all })));
  assert.match(byId(results[0], "SLACK-ID-01").summary, /partial/);
  assert.notEqual(byId(results[1], "SLACK-ADMIN-01").status, "pass");
  assert.match(byId(results[1], "SLACK-ADMIN-05").summary, /partial/);
  assert.match(byId(results[2], "SLACK-APP-01").summary, /partial view/);
  assert.equal(byId(results[3], "SLACK-CHAN-01").status, "manual");
  assert.match(byId(results[3], "SLACK-CHAN-01").summary, /not_allowed_token_type.*org-level user token/);
  assert.equal(byId(results[4], "SLACK-MON-01").status, "warn");
  assert.match(byId(results[4], "SLACK-MON-01").summary, /truncated/);
  assert.equal(byId(results[4], "SLACK-MON-04").status, "manual");
});

test("fixture (d): a compliant Enterprise Grid org passes every automatable control", async () => {
  const results = await runAll(makeClient(compliantFixture));
  const all = results.flatMap((result) => result.findings);
  const automatable = all.filter((item) => !MANUAL_BY_DESIGN.has(item.id));
  const notPassing = automatable.filter((item) => item.status !== "pass").map((item) => `${item.id}=${item.status}: ${item.summary}`);
  assert.deepEqual(notPassing, []);
  assert.equal(all.filter((item) => MANUAL_BY_DESIGN.has(item.id)).every((item) => item.status === "manual"), true);
  assert.equal(new Set(all.map((item) => item.control)).size, SLACK_SPEC_CONTROLS.length);
  assert.ok(all.every((item) => item.mappings.length > 0));
  assert.ok(results.every((result) => result.errors.length === 0));
});

test("verdict rules: failing evidence, undated entries, and stale audit logs are graded correctly", async () => {
  const failing = makeClient((request) => {
    const method = request.pathname.replace(/^\/api\//, "");
    if (method === "admin.teams.list") return { ok: true, teams: [{ id: "T1", name: "Core", discoverability: "open" }], response_metadata: { next_cursor: "" } };
    if (method === "admin.teams.settings.info") return { ok: true, team: { id: "T1", email_domain: "" } };
    if (method === "admin.teams.admins.list") return { ok: true, admin_ids: ["W1", "W2", "W3", "W4", "W5", "W6"], response_metadata: { next_cursor: "" } };
    if (method === "admin.users.list") return { ok: true, users: [{ id: "W1", is_active: true, is_admin: true, has_sso: false }], response_metadata: { next_cursor: "" } };
    if (method === "admin.users.session.getSettings") return { ok: true, session_settings: [{ user_id: "W1", desktop_app_browser_quit: false, duration: 315569520 }], no_settings_applied: [] };
    if (method === "admin.emoji.list") return { ok: true, emoji: { rogue: { url: "u", date_created: 1591720632, uploaded_by: "W9" } }, response_metadata: { next_cursor: "" } };
    if (request.pathname === "/audit/v1/logs") return { entries: [{ id: "L1", action: "file_downloaded", date_create: 1757548800 }, { id: "L2", action: "user_login" }], response_metadata: { next_cursor: "" } };
    if (request.pathname === "/audit/v1/schemas") return { schemas: [{ type: "user" }] };
    return compliantFixture(request);
  });
  const admin = await assessSlackAdminAccess(failing, { maxWorkspaceAdmins: 5, maxSessionHours: 24 });
  assert.equal(byId(admin, "SLACK-ADMIN-01").status, "fail");
  assert.equal(byId(admin, "SLACK-ADMIN-02").status, "fail");
  assert.equal(byId(admin, "SLACK-ADMIN-03").status, "fail");
  assert.equal(byId(admin, "SLACK-ADMIN-05").status, "fail");
  assert.equal(byId(admin, "SLACK-ADMIN-07").status, "fail");
  assert.equal(byId(admin, "SLACK-ADMIN-08").status, "fail");

  const monitoring = await assessSlackMonitoring(failing, { days: 30 });
  assert.equal(byId(monitoring, "SLACK-MON-02").status, "fail");
  assert.equal(byId(monitoring, "SLACK-MON-02").evidence.undated_entries, 1);
  assert.equal(byId(monitoring, "SLACK-MON-03").status, "pass");
});

test("verdict rules: apps with sensitive scopes, unrestricted default channels, and short retention are flagged", async () => {
  const client = makeClient((request) => {
    const method = request.pathname.replace(/^\/api\//, "");
    if (method === "admin.apps.approved.list") {
      return { ok: true, approved_apps: [{ app: { id: "A1", name: "Internal Bot", is_app_directory_approved: false, is_internal: true, developer_type: "internal" }, scopes: [{ name: "files:read", is_sensitive: true, token_type: "user" }] }], response_metadata: { next_cursor: "" } };
    }
    if (method === "admin.conversations.getConversationPrefs") return { ok: true, prefs: { who_can_post: { type: ["ra"], user: [] } } };
    if (method === "admin.conversations.getCustomRetention") return { ok: true, is_policy_enabled: true, duration_days: 30 };
    return compliantFixture(request);
  });
  const integrations = await assessSlackIntegrations(client);
  assert.equal(byId(integrations, "SLACK-APP-03").status, "warn");
  assert.deepEqual(byId(integrations, "SLACK-APP-03").evidence.custom_apps, ["Internal Bot"]);

  const channels = await assessSlackChannelGovernance(client, { minRetentionDays: 365 });
  assert.equal(byId(channels, "SLACK-CHAN-02").status, "fail");
  assert.equal(byId(channels, "SLACK-CHAN-03").status, "fail");
  assert.equal(byId(channels, "SLACK-CHAN-03").evidence.short_retention_channels.length, 2);
});

test("SLACK_METHODS documents every Web API method the tools call", () => {
  const source = readFileSync(new URL("../extensions/grc-tools/slack.ts", import.meta.url), "utf8");
  const called = new Set([...source.matchAll(/(?:readWeb|readWebList|webSurface|client\.web|client\.collectWeb)\((?:client, )?(?:"[^"]*", )?"([a-zA-Z.]+)"/g)].map((match) => match[1]).filter((name) => name.includes(".")));
  for (const method of called) {
    assert.ok(SLACK_METHODS[method], `${method} is missing from SLACK_METHODS`);
    assert.match(SLACK_METHODS[method].docs, /^https:\/\/(api\.slack\.com|docs\.slack\.dev)\//);
  }
  assert.ok(called.size >= 12);
});

test("resolveSecureOutputPath rejects traversal and symlinked parents", () => {
  const base = createTempBase("grclanker-slack-secure-");
  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, join("..", "..", "etc")), /Refusing to write outside/);
  const outside = createTempBase("grclanker-slack-outside-");
  symlinkSync(outside, join(base, "linked"));
  assert.throws(() => resolveSecureOutputPath(base, join("linked", "bundle")), /symlinked parent/);
  const ok = resolveSecureOutputPath(base, join("nested", "bundle"));
  assert.ok(ok.startsWith(base));
});

test("exportSlackAuditBundle writes the shared layout and never overwrites a prior bundle", async () => {
  const base = createTempBase("grclanker-slack-export-");
  const client = makeClient(compliantFixture);
  const config = resolveSlackConfiguration({ token: "xoxp-test", scim_token: "scim-test", org_id: "E1" }, EMPTY_ENV);

  const first = await exportSlackAuditBundle(client, config, base);
  assert.ok(existsSync(first.outputDir));
  assert.equal(first.zipPath, `${first.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath));
  assert.equal(first.findingCount, 32);
  assert.equal(first.errorCount, 0);
  assert.ok(!existsSync(join(first.outputDir, "_errors.log")));
  for (const file of [
    "README.md",
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access.json",
    "core_data/identity.json",
    "core_data/channel-governance.json",
    "analysis/findings.json",
    "analysis/admin-access.json",
    "reports/monitoring.md",
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
    assert.ok(existsSync(join(first.outputDir, file)), `missing ${file}`);
  }
  const metadata = JSON.parse(readFileSync(join(first.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.target, "E1");
  assert.deepEqual(metadata.token_kinds, ["user"]);
  const raw = readFileSync(join(first.outputDir, "core_data", "access.json"), "utf8");
  assert.ok(!raw.includes("xoxp-test") && !raw.includes("scim-test"));
  assert.match(readFileSync(join(first.outputDir, "compliance", "executive_summary.md"), "utf8"), /Spec controls covered: 25 of 25/);

  const second = await exportSlackAuditBundle(client, config, base);
  assert.equal(second.outputDir, `${first.outputDir}-2`);
  assert.equal(second.zipPath, `${first.outputDir}-2.zip`);
  assert.ok(existsSync(first.zipPath) && existsSync(second.zipPath));
  const third = await exportSlackAuditBundle(client, config, base);
  assert.equal(third.outputDir, `${first.outputDir}-3`);
  assert.equal(readdirSync(base).filter((name) => name.endsWith(".zip")).length, 3);
});

test("exportSlackAuditBundle writes _errors.log when collection partially failed", async () => {
  const base = createTempBase("grclanker-slack-export-errors-");
  const client = makeClient((request) => request.pathname === "/api/admin.barriers.list" ? jsonResponse({ ok: false, error: "missing_scope" }) : compliantFixture(request));
  const config = resolveSlackConfiguration({ token: "xoxp-test", scim_token: "scim-test", org_id: "E1" }, EMPTY_ENV);
  const result = await exportSlackAuditBundle(client, config, base);
  assert.ok(result.errorCount >= 1);
  const log = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(log, /\[integrations\] admin\.barriers\.list: .*missing_scope/);
  mkdirSync(join(base, "unused"));
});
