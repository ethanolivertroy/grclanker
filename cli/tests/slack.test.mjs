import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inflateRawSync } from "node:zlib";

import {
  SLACK_EXTERNAL_SHARING_AUDIT_ACTIONS,
  SLACK_FILE_UPLOAD_VERDICTS,
  SLACK_METHODS,
  SLACK_REDACTION_MARKER,
  SLACK_SECURITY_AUDIT_ACTIONS,
  SLACK_SPEC_CONTROLS,
  SlackApiClient,
  UNKNOWN_ERROR_CODE,
  assessSlackAdminAccess,
  assessSlackChannelGovernance,
  assessSlackIdentity,
  assessSlackIntegrations,
  assessSlackMonitoring,
  checkSlackAccess,
  describeErrorFields,
  exportSlackAuditBundle,
  isSlackPostingRestricted,
  redactErrorText,
  redactSecretText,
  redactSecrets,
  registerSlackTools,
  resolveSecureOutputPath,
  resolveSlackConfiguration,
  vendorErrorCode,
} from "../dist/extensions/grc-tools/slack.js";

const NOW = new Date("2026-09-21T00:00:00.000Z");
const EMPTY_ENV = { SLACK_CONFIG_FILE: "" };

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function jsonResponse(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", ...headers } });
}

function gzipResponse() {
  const gzipMagic = Uint8Array.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);
  return new Response(gzipMagic, { status: 200, headers: { "content-type": "application/gzip" } });
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

function listFilesRecursively(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? listFilesRecursively(path) : [path];
  });
}

/** Minimal ZIP reader (central directory, stored or deflated entries) so the archive is inspected without an unzip dependency. */
function readZipEntries(zipPath) {
  const buffer = readFileSync(zipPath);
  let eocd = buffer.length - 22;
  while (eocd >= 0 && buffer.readUInt32LE(eocd) !== 0x06054b50) eocd -= 1;
  assert.ok(eocd >= 0, "end of central directory record not found");
  const entryCount = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  const entries = [];
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50, "central directory signature");
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");
    assert.equal(buffer.readUInt32LE(localOffset), 0x04034b50, "local header signature");
    const dataStart = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
    const data = buffer.subarray(dataStart, dataStart + compressedSize);
    entries.push({ name, content: method === 8 ? inflateRawSync(data).toString("utf8") : data.toString("utf8") });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
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
  if (method === "admin.analytics.getFile") return gzipResponse();
  if (method === "team.preferences.list") return { ok: true };
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
      { id: "L2", date_create: 1789910000, action: "external_shared_channel_connected", actor: { type: "user" }, entity: { type: "channel" } },
      { id: "L3", date_create: 1789900000, action: "pref.sso_setting_changed", actor: { type: "user" }, entity: { type: "workspace" } },
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
    case "admin.users.session.getSettings": {
      const userIds = (params.get("user_ids") ?? "").split(",").filter(Boolean);
      assert.ok(userIds.length > 0 && userIds.length <= 100, "user_ids must carry 1 to 100 ids");
      return { ok: true, session_settings: userIds.map((userId) => ({ user_id: userId, desktop_app_browser_quit: true, duration: 43200 })), no_settings_applied: [] };
    }
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
      assert.equal(params.get("metadata_only"), "true");
      assert.equal(params.get("type"), "public_channel");
      return gzipResponse();
    case "team.preferences.list":
      return { ok: true, display_real_names: true, disable_file_uploads: "type:owner,type:admin", msg_edit_window_mins: 25, who_can_post_general: "admins" };
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

const MANUAL_BY_DESIGN = new Set(["SLACK-ADMIN-04", "SLACK-ADMIN-06", "SLACK-ADMIN-09", "SLACK-APP-05", "SLACK-APP-07", "SLACK-CHAN-04", "SLACK-CHAN-05", "SLACK-MON-06"]);

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
  assert.equal(byId(results[2], "SLACK-APP-06").status, "manual");
  assert.match(byId(results[2], "SLACK-APP-06").summary, /did not return disable_file_uploads/);
  assert.equal(byId(results[4], "SLACK-MON-01").status, "fail");
  assert.equal(byId(results[4], "SLACK-MON-04").status, "warn");
});

test("fixture (c): partial inventories and not_allowed_token_type never pass", async () => {
  const results = await runAll(makeClient(partialFixture), { userLimit: 3, workspaceLimit: 1, appLimit: 1 });
  const all = results.flatMap((result) => result.findings);
  assert.equal(all.filter((item) => item.status === "pass").length, 0, JSON.stringify(statuses({ findings: all })));
  assert.match(byId(results[0], "SLACK-ID-01").summary, /partial/);
  assert.notEqual(byId(results[1], "SLACK-ADMIN-01").status, "pass");
  assert.equal(byId(results[1], "SLACK-ADMIN-02").status, "warn");
  assert.equal(byId(results[1], "SLACK-ADMIN-03").status, "warn");
  assert.match(byId(results[1], "SLACK-ADMIN-03").summary, /user inventory is partial/);
  assert.equal(byId(results[1], "SLACK-ADMIN-03").evidence.inventory_complete, false);
  assert.match(byId(results[1], "SLACK-ADMIN-05").summary, /partial/);
  assert.equal(byId(results[3], "SLACK-CHAN-02").status, "manual");
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
  assert.equal(automatable.length, 24);
  assert.equal(all.length, 32);
  assert.equal(all.filter((item) => MANUAL_BY_DESIGN.has(item.id)).every((item) => item.status === "manual"), true);
  assert.equal(byId(results[2], "SLACK-APP-06").status, "pass");
  assert.equal(byId(results[4], "SLACK-MON-05").status, "pass");
  assert.equal(byId(results[4], "SLACK-MON-05").evidence.external_event_count, 1);
  assert.deepEqual(byId(results[4], "SLACK-MON-05").evidence.matched_actions, ["external_shared_channel_connected"]);
  assert.deepEqual(byId(results[4], "SLACK-MON-03").evidence.matched_actions, ["user_login", "pref.sso_setting_changed"]);
  assert.equal(byId(results[1], "SLACK-ADMIN-09").evidence.analytics_export_readable, true);
  assert.equal(byId(results[1], "SLACK-ADMIN-09").evidence.analytics_content_type, "application/gzip");
  assert.equal(byId(results[2], "SLACK-APP-05").status, "manual");
  assert.match(byId(results[2], "SLACK-APP-05").summary, /no public reference page/);
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

test("review fix 2: SLACK-APP-06 reads team.preferences.list and maps every documented disable_file_uploads value", async () => {
  const seen = [];
  const withSetting = (value) => makeClient((request) => {
    if (request.pathname === "/api/team.preferences.list") {
      seen.push({ method: request.method, auth: request.auth, params: [...request.params.keys()] });
      return value === undefined ? { ok: true, display_real_names: false } : { ok: true, disable_file_uploads: value };
    }
    return compliantFixture(request);
  });
  const expected = { disallow_all: "pass", "type:owner,type:admin": "pass", "type:regular": "warn", allow_all: "fail" };
  assert.deepEqual(SLACK_FILE_UPLOAD_VERDICTS, expected);
  for (const [value, status] of Object.entries(expected)) {
    const item = byId(await assessSlackIntegrations(withSetting(value)), "SLACK-APP-06");
    assert.equal(item.status, status, `${value} should be ${status}`);
    assert.equal(item.evidence.disable_file_uploads, value);
    assert.match(item.summary, new RegExp(`disable_file_uploads=${value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
  }
  assert.deepEqual(seen[0], { method: "POST", auth: "Bearer xoxp-test", params: [] });
  assert.equal(SLACK_METHODS["team.preferences.list"].verb, "POST");
  assert.deepEqual(SLACK_METHODS["team.preferences.list"].tokens, ["user", "bot"]);
  assert.equal(byId(await assessSlackIntegrations(withSetting("type:guest")), "SLACK-APP-06").status, "warn");
  assert.equal(byId(await assessSlackIntegrations(withSetting(undefined)), "SLACK-APP-06").status, "manual");
  const denied = byId(await assessSlackIntegrations(makeClient((request) => request.pathname === "/api/team.preferences.list" ? { ok: false, error: "missing_scope" } : compliantFixture(request))), "SLACK-APP-06");
  assert.equal(denied.status, "manual");
  assert.match(denied.summary, /team\.preferences\.list is not readable: .*missing_scope/);
  const botOnly = byId(await assessSlackIntegrations(makeClient((request) => request.pathname === "/api/team.preferences.list" ? { ok: true, disable_file_uploads: "disallow_all" } : deniedFixture(), { bot_token: "xoxb-test" })), "SLACK-APP-06");
  assert.equal(botOnly.status, "warn");
  assert.match(botOnly.summary, /admin\.teams\.list is not readable/);
  const multiWorkspace = byId(await assessSlackIntegrations(makeClient((request) => request.pathname === "/api/admin.teams.list"
    ? { ok: true, teams: [{ id: "T1", name: "Core" }, { id: "T2", name: "Labs" }], response_metadata: { next_cursor: "" } }
    : compliantFixture(request))), "SLACK-APP-06");
  assert.equal(multiWorkspace.status, "warn");
  assert.match(multiWorkspace.summary, /org has 2 workspaces and only the token's workspace was read/);
  assert.equal(multiWorkspace.evidence.workspace_id, "T1");
  const partialWorkspaces = byId(await assessSlackIntegrations(makeClient(partialFixture), { workspaceLimit: 1 }), "SLACK-APP-06");
  assert.equal(partialWorkspaces.status, "warn");
  assert.match(partialWorkspaces.summary, /workspace inventory is partial/);
});

test("review fixes 3 and 4: every matched audit action string is a documented Audit Logs action", async () => {
  const documentedSecurityActions = [
    "user_login",
    "user_logout",
    "app_installed",
    "app_approved",
    "app_restricted",
    "role_change_to_admin",
    "pref.sso_setting_changed",
    "pref.two_factor_auth_changed",
    "user_deactivated",
  ];
  const documentedExternalActions = [
    "external_shared_channel_connected",
    "external_shared_channel_reconnected",
    "external_shared_channel_disconnected",
    "external_shared_channel_disconnect_and_archived",
    "external_shared_channel_invite_created",
    "external_shared_channel_invite_accepted",
    "external_shared_channel_invite_approved",
    "external_shared_channel_invite_declined",
    "external_shared_channel_invite_expired",
    "external_shared_channel_invite_revoked",
    "external_shared_channel_invite_auto_revoked",
    "external_shared_channel_access_upgraded",
  ];
  assert.deepEqual([...SLACK_SECURITY_AUDIT_ACTIONS], documentedSecurityActions);
  assert.deepEqual([...SLACK_EXTERNAL_SHARING_AUDIT_ACTIONS], documentedExternalActions);
  const source = readFileSync(new URL("../extensions/grc-tools/slack.ts", import.meta.url), "utf8");
  for (const invented of ["pref_sso_setting_changed", "pref_two_factor_auth_changed", "channel_shared", "channel_unshared", "file_shared_externally", "slack_connect_channel_created", "discovery.enterprise.info", "admin.enterprise.info"]) {
    assert.equal(source.includes(`"${invented}"`), false, `${invented} must not appear in slack.ts`);
  }

  const withActions = (actions) => makeClient((request) => request.pathname === "/audit/v1/logs"
    ? { entries: actions.map((action, index) => ({ id: `L${index}`, date_create: 1789920000 - index, action, actor: { type: "user" }, entity: { type: "channel" } })), response_metadata: { next_cursor: "" } }
    : compliantFixture(request));
  const external = await assessSlackMonitoring(withActions(["external_shared_channel_invite_accepted", "external_shared_channel_disconnected"]), { days: 30 });
  assert.equal(byId(external, "SLACK-MON-05").status, "pass");
  assert.equal(byId(external, "SLACK-MON-05").evidence.external_event_count, 2);
  const invented = await assessSlackMonitoring(withActions(["channel_shared", "pref_sso_setting_changed", "user_login"]), { days: 30 });
  assert.equal(byId(invented, "SLACK-MON-05").status, "warn");
  assert.equal(byId(invented, "SLACK-MON-05").evidence.external_event_count, 0);
  assert.equal(byId(invented, "SLACK-MON-03").evidence.security_event_count, 1);
  assert.deepEqual(byId(invented, "SLACK-MON-03").evidence.matched_actions, ["user_login"]);
  const prefs = await assessSlackMonitoring(withActions(["pref.sso_setting_changed", "pref.two_factor_auth_changed"]), { days: 30 });
  assert.equal(byId(prefs, "SLACK-MON-03").status, "pass");
  assert.equal(byId(prefs, "SLACK-MON-03").evidence.security_event_count, 2);
});

test("review fix 5: admin.analytics.getFile gzip bodies are a successful probe and ok:false JSON is the failure path", async () => {
  let downloaded = false;
  const gzipClient = makeClient((request) => {
    if (request.pathname !== "/api/admin.analytics.getFile") return compliantFixture(request);
    assert.equal(request.method, "GET");
    assert.equal(request.params.get("metadata_only"), "true");
    const stream = new ReadableStream({
      pull(controller) {
        downloaded = true;
        controller.enqueue(Uint8Array.from([0x1f, 0x8b]));
        controller.close();
      },
    }, { highWaterMark: 0 });
    return new Response(stream, { status: 200, headers: { "content-type": "application/gzip" } });
  });
  const admin = await assessSlackAdminAccess(gzipClient);
  assert.equal(byId(admin, "SLACK-ADMIN-09").evidence.analytics_export_readable, true);
  assert.equal(byId(admin, "SLACK-ADMIN-09").evidence.analytics_content_type, "application/gzip");
  assert.match(byId(admin, "SLACK-ADMIN-09").summary, /probe returned application\/gzip/);
  assert.equal(downloaded, false);
  assert.equal(admin.errors.some((entry) => entry.startsWith("admin.analytics.getFile")), false);

  const jsonFailure = makeClient((request) => request.pathname === "/api/admin.analytics.getFile" ? { ok: false, error: "org_level_email_display_disabled" } : compliantFixture(request));
  const failed = byId(await assessSlackAdminAccess(jsonFailure), "SLACK-ADMIN-09");
  assert.equal(failed.evidence.analytics_export_readable, false);
  assert.match(failed.summary, /probe failed: .*org_level_email_display_disabled/);

  const untypedFailure = makeClient((request) => request.pathname === "/api/admin.analytics.getFile" ? new Response(JSON.stringify({ ok: false, error: "not_allowed_token_type" }), { status: 200 }) : compliantFixture(request));
  assert.equal(byId(await assessSlackAdminAccess(untypedFailure), "SLACK-ADMIN-09").evidence.analytics_export_readable, false);

  const forbidden = makeClient((request) => request.pathname === "/api/admin.analytics.getFile" ? jsonResponse({ ok: false, error: "invalid_auth" }, 403) : compliantFixture(request));
  assert.match(byId(await assessSlackAdminAccess(forbidden), "SLACK-ADMIN-09").summary, /HTTP 403/);
});

test("review fix 6: who_can_post accepts the documented singular and plural type spellings", async () => {
  const cases = [
    [["admin"], true],
    [["admins"], true],
    [["owner"], true],
    [["owners"], true],
    [["admin", "owner"], true],
    [["Admins", "Owners"], true],
    ["admin, owner", true],
    [["ra"], false],
    [["admins", "ra"], false],
    [[], undefined],
  ];
  for (const [type, expected] of cases) {
    assert.equal(isSlackPostingRestricted({ who_can_post: { type, user: [] } }), expected, JSON.stringify(type));
  }
  assert.equal(isSlackPostingRestricted({ who_can_post: { type: [], user: ["W1"] } }), true);
  assert.equal(isSlackPostingRestricted({}), undefined);
  for (const type of ["admin", "admins", "owner", "owners"]) {
    const client = makeClient((request) => request.pathname === "/api/admin.conversations.getConversationPrefs"
      ? { ok: true, prefs: { who_can_post: { type: [type], user: [] } } }
      : compliantFixture(request));
    assert.equal(byId(await assessSlackChannelGovernance(client), "SLACK-CHAN-02").status, "pass", type);
  }
});

test("review fix: SLACK-ADMIN-03 never passes on a truncated admin.users.list", async () => {
  const truncatedUsers = (request) => {
    if (request.pathname === "/api/admin.users.list") return { ...compliantFixture(request), response_metadata: { next_cursor: "dXNlcjpVMEc5V0ZYTlo=" } };
    return compliantFixture(request);
  };
  const truncated = byId(await assessSlackAdminAccess(makeClient(truncatedUsers), { maxSessionHours: 24, userLimit: 2 }), "SLACK-ADMIN-03");
  assert.equal(truncated.status, "warn");
  assert.match(truncated.summary, /user inventory is partial \(2 seen of unknown total \(partial view, item limit reached\)\)/);
  assert.equal(truncated.evidence.inventory_complete, false);
  assert.equal(truncated.evidence.active_users_seen, 2);
  assert.equal(truncated.evidence.sampled_users, 2);
  assert.equal(truncated.evidence.sessions_with_settings, 2);

  const capped = byId(await assessSlackAdminAccess(makeClient(truncatedUsers), { maxSessionHours: 24, userLimit: 1 }), "SLACK-ADMIN-03");
  assert.equal(capped.status, "warn");
  assert.equal(capped.evidence.inventory_complete, false);

  const complete = byId(await assessSlackAdminAccess(makeClient(compliantFixture), { maxSessionHours: 24 }), "SLACK-ADMIN-03");
  assert.equal(complete.status, "pass");
  assert.equal(complete.evidence.inventory_complete, true);
  assert.match(complete.summary, /All 2 active users have a session duration at or below 24 hours \(2 seen \(complete\)\)/);

  const overlongTruncated = byId(await assessSlackAdminAccess(makeClient((request) => {
    if (request.pathname === "/api/admin.users.session.getSettings") return { ok: true, session_settings: [{ user_id: "W1", desktop_app_browser_quit: true, duration: 43200 }, { user_id: "W2", desktop_app_browser_quit: true, duration: 172800 }], no_settings_applied: [] };
    return truncatedUsers(request);
  }), { maxSessionHours: 24, userLimit: 2 }), "SLACK-ADMIN-03");
  assert.equal(overlongTruncated.status, "fail");
  assert.equal(overlongTruncated.evidence.inventory_complete, false);
});

test("review follow-up: SLACK-CHAN-02 warns when the channel search is truncated", async () => {
  const truncatedChannels = makeClient((request) => {
    if (request.pathname === "/api/admin.conversations.search" && request.params.get("search_channel_types") !== "external_shared") {
      return { ...compliantFixture(request), next_cursor: "more" };
    }
    return compliantFixture(request);
  });
  const item = byId(await assessSlackChannelGovernance(truncatedChannels, { channelLimit: 2 }), "SLACK-CHAN-02");
  assert.equal(item.status, "warn");
  assert.match(item.summary, /channel search is partial/);
  assert.equal(item.evidence.channels_complete, false);
  const complete = byId(await assessSlackChannelGovernance(makeClient(compliantFixture)), "SLACK-CHAN-02");
  assert.equal(complete.status, "pass");
  assert.equal(complete.evidence.channels_complete, true);
});

const FAKE_SECRETS = {
  userToken: "xoxp-FAKE_SECRET_TOKEN_1",
  botToken: "xoxb-FAKE_SECRET_TOKEN_2",
  scimToken: "FAKE_SCIM_SECRET_1",
  appToken: "xapp-1-FAKE_APP_TOKEN_1",
  refreshToken: "xoxe-1-FAKE_REFRESH_TOKEN_1",
  webhook: "https://hooks.slack.com/services/T1/B1/FAKE_WEBHOOK_URL_1",
  clientSecret: "FAKE_CLIENT_SECRET_1",
  signingSecret: "FAKE_SIGNING_SECRET_1",
  password: "FAKE_PASSWORD_1",
  bareToken: "FAKE_SECRET_TOKEN_3",
};
const FAKE_SECRET_MARKERS = ["FAKE_SECRET_TOKEN", "FAKE_SCIM_SECRET", "FAKE_APP_TOKEN", "FAKE_REFRESH_TOKEN", "FAKE_WEBHOOK_URL", "FAKE_CLIENT_SECRET", "FAKE_SIGNING_SECRET", "FAKE_PASSWORD"];

/** The compliant fixture with a credential planted in every collected object that can carry one. */
const secretLadenFixture = (request) => {
  const method = request.pathname.replace(/^\/api\//, "");
  if (method === "admin.barriers.list") return jsonResponse({ ok: false, error: "invalid_auth", token: FAKE_SECRETS.bareToken, hint: `retry with ${FAKE_SECRETS.userToken}` }, 403);
  const base = compliantFixture(request);
  if (request.pathname === "/api/auth.test") return { ...base, token: FAKE_SECRETS.bareToken, team: `Acme ${FAKE_SECRETS.botToken}`, url: `https://acme.slack.com/?t=${FAKE_SECRETS.userToken}` };
  if (request.pathname === "/scim/v2/Users") return { ...base, Resources: base.Resources.map((item) => ({ ...item, password: FAKE_SECRETS.password, "urn:scim:schemas:extension:slack:1.0": { api_token: FAKE_SECRETS.bareToken } })) };
  if (request.pathname === "/scim/v2/Groups") return { ...base, Resources: base.Resources.map((item) => ({ ...item, displayName: `Engineering ${FAKE_SECRETS.webhook}` })) };
  if (request.pathname === "/audit/v1/logs") {
    return { ...base, entries: base.entries.map((entry) => ({
      ...entry,
      details: { token: FAKE_SECRETS.bareToken, new_value: FAKE_SECRETS.userToken, reason: `rotated ${FAKE_SECRETS.refreshToken}` },
      entity: { type: "app", app: { id: "A9", name: "Rotator", client_secret: FAKE_SECRETS.clientSecret, signing_secret: FAKE_SECRETS.signingSecret, incoming_webhook: { url: FAKE_SECRETS.webhook } } },
      context: { session_id: FAKE_SECRETS.bareToken, ua: `curl Bearer ${FAKE_SECRETS.userToken}` },
    })) };
  }
  if (request.pathname === "/audit/v1/schemas") return { schemas: [{ type: "user", user: {}, example_token: FAKE_SECRETS.bareToken }] };
  switch (method) {
    case "users.list":
      return { ...base, members: base.members.map((member) => ({ ...member, profile: { ...member.profile, api_token: FAKE_SECRETS.bareToken, title: `Owner of ${FAKE_SECRETS.webhook}` } })) };
    case "admin.users.list":
      return { ...base, users: base.users.map((user) => ({ ...user, password: FAKE_SECRETS.password, full_name: `Alice ${FAKE_SECRETS.userToken}` })) };
    case "admin.teams.list":
      return { ...base, teams: base.teams.map((team) => ({ ...team, name: `Core ${FAKE_SECRETS.appToken}`, signing_secret: FAKE_SECRETS.signingSecret })) };
    case "admin.teams.settings.info":
      return { ...base, team: { ...base.team, webhook_url: FAKE_SECRETS.webhook, name: `Core ${FAKE_SECRETS.botToken}`, default_channels: base.team.default_channels } };
    case "admin.teams.admins.list":
      return { ...base, admin_ids: [...base.admin_ids, FAKE_SECRETS.userToken] };
    case "admin.users.session.getSettings":
      return { ...base, session_settings: base.session_settings.map((item) => ({ ...item, session_token: FAKE_SECRETS.bareToken })) };
    case "admin.apps.approved.list":
      return { ...base, approved_apps: base.approved_apps.map((item) => ({ ...item, app: { ...item.app, name: `Marketplace App ${FAKE_SECRETS.webhook}`, client_secret: FAKE_SECRETS.clientSecret, signing_secret: FAKE_SECRETS.signingSecret, incoming_webhook: { url: FAKE_SECRETS.webhook }, app_level_token: FAKE_SECRETS.appToken, refresh_token: FAKE_SECRETS.refreshToken } })) };
    case "admin.apps.restricted.list":
      return { ...base, restricted_apps: base.restricted_apps.map((item) => ({ ...item, app: { ...item.app, name: `Blocked App ${FAKE_SECRETS.userToken}`, oauth_client_secret: FAKE_SECRETS.clientSecret } })) };
    case "admin.conversations.search":
      return { ...base, conversations: base.conversations.map((item) => ({ ...item, name: `${item.name}-${FAKE_SECRETS.botToken}`, purpose: { value: `Posts via ${FAKE_SECRETS.webhook}` } })) };
    case "admin.conversations.getConversationPrefs":
      return { ...base, prefs: { ...base.prefs, webhook: FAKE_SECRETS.webhook } };
    case "admin.conversations.getCustomRetention":
      return { ...base, policy_token: FAKE_SECRETS.bareToken };
    case "admin.emoji.list":
      return { ...base, emoji: { party: { ...base.emoji.party, uploaded_by: `W1 ${FAKE_SECRETS.userToken}`, url: `https://emoji.slack-edge.com/T1/party/1.png?token=${FAKE_SECRETS.bareToken}` } } };
    case "team.preferences.list":
      return { ...base, disable_file_uploads: "type:owner,type:admin", app_level_token: FAKE_SECRETS.appToken, who_can_post_general: `admins ${FAKE_SECRETS.webhook}` };
    default:
      return base;
  }
};

test("rule 9: redaction keeps field names, replaces credential values, and scrubs Slack token shapes", async () => {
  const redacted = redactSecrets({
    token: "abc", token_type: "bot", access_token: "x", client_secret: "y", incoming_webhook: { url: "https://hooks.slack.com/services/A/B/C" }, refresh_token: "r", signing_secret: "s", password: "p",
    nested: { note: "use xoxb-123456789-abcdef or xapp-1-A-123456789 with Bearer abcdefghijklmnop" }, list: ["xoxp-987654321-zyx", "ok"], count: 3, flag: true, empty: null,
  }, ["known-secret-value"]);
  assert.deepEqual(redacted, {
    token: SLACK_REDACTION_MARKER, token_type: "bot", access_token: SLACK_REDACTION_MARKER, client_secret: SLACK_REDACTION_MARKER, incoming_webhook: SLACK_REDACTION_MARKER, refresh_token: SLACK_REDACTION_MARKER, signing_secret: SLACK_REDACTION_MARKER, password: SLACK_REDACTION_MARKER,
    nested: { note: `use ${SLACK_REDACTION_MARKER} or ${SLACK_REDACTION_MARKER} with ${SLACK_REDACTION_MARKER}` }, list: [SLACK_REDACTION_MARKER, "ok"], count: 3, flag: true, empty: null,
  });
  assert.equal(redactSecretText("token known-secret-value and https://hooks.slack.com/services/T/B/X end", ["known-secret-value"]), `token ${SLACK_REDACTION_MARKER} and ${SLACK_REDACTION_MARKER} end`);
  assert.equal(redactSecretText("https://files.slack.com/f.png?token=abc123&size=2&Signature=zzz"), `https://files.slack.com/f.png?token=${SLACK_REDACTION_MARKER}&size=2&Signature=${SLACK_REDACTION_MARKER}`);
  assert.equal(redactSecretText("a-b-c and channel-general stay intact", ["-", "a", "channel"]), "a-b-c and channel-general stay intact");
  assert.equal(redactSecretText("long-secret-value stays scrubbed", ["long-secret-value"]), `${SLACK_REDACTION_MARKER} stays scrubbed`);

  const client = makeClient(secretLadenFixture, { token: FAKE_SECRETS.userToken, bot_token: FAKE_SECRETS.botToken, scim_token: FAKE_SECRETS.scimToken, org_id: "E1" });
  const auth = await client.web("auth.test");
  assert.equal(auth.token, SLACK_REDACTION_MARKER);
  assert.equal(auth.team, `Acme ${SLACK_REDACTION_MARKER}`);
  assert.equal(auth.url, `https://acme.slack.com/?t=${SLACK_REDACTION_MARKER}`);
  const apps = await client.web("admin.apps.approved.list", { limit: 10 });
  assert.equal(apps.approved_apps[0].app.client_secret, SLACK_REDACTION_MARKER);
  assert.equal(apps.approved_apps[0].app.incoming_webhook, SLACK_REDACTION_MARKER);
  assert.equal(apps.approved_apps[0].scopes[0].token_type, "bot");
  await assert.rejects(client.web("admin.barriers.list"), (error) => {
    assert.match(error.message, /HTTP 403/);
    assert.equal(FAKE_SECRET_MARKERS.some((marker) => error.message.includes(marker)), false, error.message);
    return true;
  });
});

test("rule 9: the audit bundle and its zip never contain planted credentials", async () => {
  const base = createTempBase("grclanker-slack-secrets-");
  const client = makeClient(secretLadenFixture, { token: FAKE_SECRETS.userToken, bot_token: FAKE_SECRETS.botToken, scim_token: FAKE_SECRETS.scimToken, org_id: "E1" });
  const config = resolveSlackConfiguration({ token: FAKE_SECRETS.userToken, bot_token: FAKE_SECRETS.botToken, scim_token: FAKE_SECRETS.scimToken, org_id: "E1" }, EMPTY_ENV);
  const bundle = await exportSlackAuditBundle(client, config, base);
  assert.ok(bundle.errorCount > 0, "the planted 403 must be recorded as a collection error");
  const files = listFilesRecursively(bundle.outputDir);
  assert.ok(files.length >= 20);
  assert.ok(files.some((file) => file.endsWith("_errors.log")));
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    for (const marker of FAKE_SECRET_MARKERS) {
      assert.equal(content.includes(marker), false, `${file} leaks ${marker}`);
    }
    for (const secret of Object.values(FAKE_SECRETS)) {
      assert.equal(content.includes(secret), false, `${file} leaks ${secret}`);
    }
  }
  const errorsLog = readFileSync(join(bundle.outputDir, "_errors.log"), "utf8");
  assert.match(errorsLog, /admin\.barriers\.list: Slack Web API admin\.barriers\.list failed \(HTTP 403\) error=invalid_auth$/m);
  assert.doesNotMatch(errorsLog, /token|hint/, "undocumented error body fields are dropped, not echoed");
  const access = JSON.parse(readFileSync(join(bundle.outputDir, "core_data/access.json"), "utf8"));
  assert.equal(JSON.stringify(access).includes("FAKE_"), false);

  const entries = readZipEntries(bundle.zipPath).filter((entry) => !entry.name.endsWith("/"));
  assert.equal(entries.length, files.length);
  for (const entry of entries) {
    for (const marker of FAKE_SECRET_MARKERS) {
      assert.equal(entry.content.includes(marker), false, `zip entry ${entry.name} leaks ${marker}`);
    }
  }
  assert.ok(entries.some((entry) => entry.name.endsWith("_errors.log") && /HTTP 403\) error=invalid_auth$/m.test(entry.content)));
});

test("rule 10: every pagination loop reports truncation on its cap exit and dependent findings do not pass", async () => {
  const withOverride = (override) => makeClient((request) => override(request) ?? compliantFixture(request));
  const method = (request) => request.pathname.replace(/^\/api\//, "");

  const userCap = await assessSlackIdentity(withOverride((request) => method(request) === "users.list" ? { ok: true, members: [...compliantUsers, { ...compliantUsers[1], id: "W4", name: "carol" }], response_metadata: { next_cursor: "" } } : undefined), { userLimit: 2 });
  assert.equal(byId(userCap, "SLACK-ID-01").status, "warn");
  assert.match(byId(userCap, "SLACK-ID-01").summary, /2 seen of unknown total \(partial view, item limit reached\)/);
  assert.equal(byId(userCap, "SLACK-ID-01").evidence.inventory_complete, false);

  const stalledCursor = await assessSlackIdentity(withOverride((request) => method(request) === "users.list" && request.params.get("cursor")
    ? { ok: true, members: [], response_metadata: { next_cursor: "still-more" } }
    : method(request) === "users.list" ? { ...compliantFixture(request), response_metadata: { next_cursor: "page2" } } : undefined));
  assert.equal(byId(stalledCursor, "SLACK-ID-01").status, "warn");
  assert.match(byId(stalledCursor, "SLACK-ID-01").summary, /partial view, cursor returned an empty page/);

  let pageCalls = 0;
  const pageCap = await assessSlackIdentity(withOverride((request) => {
    if (method(request) !== "users.list") return undefined;
    pageCalls += 1;
    return { ok: true, members: [{ ...compliantUsers[0], id: `W${pageCalls}` }], response_metadata: { next_cursor: `page-${pageCalls + 1}` } };
  }), { userLimit: 10_000 });
  assert.equal(pageCalls, 50);
  assert.equal(byId(pageCap, "SLACK-ID-01").status, "warn");
  assert.match(byId(pageCap, "SLACK-ID-01").summary, /50 seen of unknown total \(partial view, page cap of 50 reached\)/);

  const scimNoTotal = await assessSlackIdentity(withOverride((request) => request.pathname === "/scim/v2/Users" ? { Resources: compliantFixture(request).Resources } : undefined));
  assert.notEqual(byId(scimNoTotal, "SLACK-ID-03").status, "pass");
  assert.match(byId(scimNoTotal, "SLACK-ID-03").summary, /total count missing from the response/);
  assert.equal(byId(scimNoTotal, "SLACK-ID-03").evidence.inventory_complete, false);

  const scimCap = await assessSlackIdentity(withOverride((request) => request.pathname === "/scim/v2/Users" ? { ...compliantFixture(request), totalResults: 40 } : undefined), { userLimit: 2 });
  assert.notEqual(byId(scimCap, "SLACK-ID-03").status, "pass");
  assert.match(byId(scimCap, "SLACK-ID-03").summary, /2 seen of 40 \(partial view, item limit reached\)/);

  const scimStalled = await assessSlackIdentity(withOverride((request) => request.pathname === "/scim/v2/Users" && Number(request.params.get("startIndex")) > 1 ? { totalResults: 40, Resources: [] } : request.pathname === "/scim/v2/Users" ? { ...compliantFixture(request), totalResults: 40 } : undefined));
  assert.notEqual(byId(scimStalled, "SLACK-ID-03").status, "pass");
  assert.match(byId(scimStalled, "SLACK-ID-03").summary, /2 seen of 40 \(partial view, cursor returned an empty page\)/);

  const workspaceCap = await assessSlackAdminAccess(withOverride((request) => method(request) === "admin.teams.list"
    ? { ok: true, teams: [...compliantFixture(request).teams, { id: "T2", name: "Labs", discoverability: "invite_only" }], response_metadata: { next_cursor: "" } }
    : method(request) === "admin.teams.settings.info" ? { ok: true, team: { id: request.params.get("team_id"), email_domain: "example.com", default_channels: [] } } : undefined), { workspaceLimit: 1 });
  for (const id of ["SLACK-ADMIN-01", "SLACK-ADMIN-05", "SLACK-ADMIN-07"]) {
    assert.notEqual(byId(workspaceCap, id).status, "pass", id);
    assert.match(byId(workspaceCap, id).summary, /1 seen of unknown total \(partial view, item limit reached\)/, id);
  }

  const orgUserCap = await assessSlackAdminAccess(withOverride((request) => method(request) === "admin.users.list"
    ? { ...compliantFixture(request), users: [...compliantFixture(request).users, { id: "W7", is_active: true, is_admin: false, is_bot: false, has_sso: true }], response_metadata: { next_cursor: "" } }
    : undefined), { userLimit: 2 });
  for (const id of ["SLACK-ADMIN-02", "SLACK-ADMIN-03", "SLACK-ADMIN-08"]) {
    assert.notEqual(byId(orgUserCap, id).status, "pass", id);
  }
  assert.match(byId(orgUserCap, "SLACK-ADMIN-02").summary, /2 seen of unknown total \(partial view, item limit reached\)/);
  assert.equal(byId(orgUserCap, "SLACK-ADMIN-03").evidence.inventory_complete, false);

  let adminPages = 0;
  const adminPageCap = await assessSlackAdminAccess(withOverride((request) => {
    if (method(request) !== "admin.teams.admins.list") return undefined;
    adminPages += 1;
    return { ok: true, admin_ids: [`W${adminPages}`], response_metadata: { next_cursor: "more" } };
  }), { maxWorkspaceAdmins: 500 });
  assert.equal(adminPages, 50);
  assert.equal(byId(adminPageCap, "SLACK-ADMIN-01").status, "warn");
  assert.match(byId(adminPageCap, "SLACK-ADMIN-01").summary, /partial/);
  assert.equal(byId(adminPageCap, "SLACK-ADMIN-01").evidence.inventory_complete, false);

  let emojiPages = 0;
  const emojiPageCap = await assessSlackAdminAccess(withOverride((request) => {
    if (method(request) !== "admin.emoji.list") return undefined;
    emojiPages += 1;
    return { ok: true, emoji: { [`e${emojiPages}`]: { url: "u", date_created: 1591720632, uploaded_by: "W1" } }, response_metadata: { next_cursor: "more" } };
  }));
  assert.equal(emojiPages, 50, "the emoji loop stops at MAX_PAGES_PER_LIST requests");
  assert.equal(byId(emojiPageCap, "SLACK-ADMIN-08").status, "warn");
  assert.match(byId(emojiPageCap, "SLACK-ADMIN-08").summary, /All 50 seen custom emoji were uploaded by admins or owners, but the emoji inventory is partial \(emoji: 50 seen of unknown total \(partial view, page cap of 50 reached\); users: 2 seen \(complete\)\)/);
  assert.equal(byId(emojiPageCap, "SLACK-ADMIN-08").evidence.inventory_complete, false);
  assert.equal(byId(emojiPageCap, "SLACK-ADMIN-08").evidence.emoji_truncation, "page_cap");
  assert.equal(byId(emojiPageCap, "SLACK-ADMIN-08").evidence.emoji_count, 50);

  let emojiStalledPages = 0;
  const emojiStalled = await assessSlackAdminAccess(withOverride((request) => {
    if (method(request) !== "admin.emoji.list") return undefined;
    emojiStalledPages += 1;
    return { ok: true, emoji: {}, response_metadata: { next_cursor: "still-more" } };
  }));
  assert.equal(emojiStalledPages, 1, "an empty page with a cursor outstanding stops the listing on the spot");
  assert.notEqual(byId(emojiStalled, "SLACK-ADMIN-08").status, "pass");
  assert.match(byId(emojiStalled, "SLACK-ADMIN-08").summary, /admin\.emoji\.list was truncated before any custom emoji were seen \(0 seen of unknown total \(partial view, cursor returned an empty page\)\)/);
  assert.doesNotMatch(byId(emojiStalled, "SLACK-ADMIN-08").summary, /returned no custom emoji/);
  assert.equal(byId(emojiStalled, "SLACK-ADMIN-08").evidence.inventory_complete, false);
  assert.equal(byId(emojiStalled, "SLACK-ADMIN-08").evidence.emoji_truncation, "stalled_cursor");

  let emojiLatePages = 0;
  const emojiLateStall = await assessSlackAdminAccess(withOverride((request) => {
    if (method(request) !== "admin.emoji.list") return undefined;
    emojiLatePages += 1;
    return emojiLatePages === 1
      ? { ok: true, emoji: { party: { url: "u", date_created: 1591720632, uploaded_by: "W1" } }, response_metadata: { next_cursor: "page2" } }
      : { ok: true, emoji: {}, response_metadata: { next_cursor: "page3" } };
  }));
  assert.equal(emojiLatePages, 2);
  assert.equal(byId(emojiLateStall, "SLACK-ADMIN-08").status, "warn");
  assert.match(byId(emojiLateStall, "SLACK-ADMIN-08").summary, /emoji: 1 seen of unknown total \(partial view, cursor returned an empty page\)/);

  const emojiUsersPartial = await assessSlackAdminAccess(withOverride((request) => method(request) === "admin.users.list"
    ? { ...compliantFixture(request), response_metadata: { next_cursor: "more" } }
    : undefined), { userLimit: 2 });
  assert.equal(byId(emojiUsersPartial, "SLACK-ADMIN-08").status, "warn");
  assert.match(byId(emojiUsersPartial, "SLACK-ADMIN-08").summary, /checked against an incomplete admin roster \(admin\.users\.list partial \(2 seen of unknown total \(partial view, item limit reached\)\)\)/);
  assert.equal(byId(emojiUsersPartial, "SLACK-ADMIN-08").evidence.non_admin_uploads, null);

  const appCap = await assessSlackIntegrations(withOverride((request) => method(request) === "admin.apps.approved.list"
    ? { ...compliantFixture(request), approved_apps: [...compliantFixture(request).approved_apps, { app: { id: "A3", name: "Second", is_app_directory_approved: true, is_internal: false, developer_type: "third_party" }, scopes: [] }], response_metadata: { next_cursor: "" } }
    : undefined), { appLimit: 1 });
  assert.equal(byId(appCap, "SLACK-APP-01").status, "warn");
  assert.match(byId(appCap, "SLACK-APP-01").summary, /1 seen of unknown total \(partial view, item limit reached\)/);
  assert.equal(byId(appCap, "SLACK-APP-01").evidence.inventory_complete, false);

  const channelCap = await assessSlackChannelGovernance(withOverride((request) => method(request) === "admin.conversations.search" && request.params.get("search_channel_types") !== "external_shared"
    ? { ...compliantFixture(request), total_count: 9 }
    : undefined), { channelLimit: 1 });
  for (const id of ["SLACK-CHAN-02", "SLACK-CHAN-03"]) {
    assert.notEqual(byId(channelCap, id).status, "pass", id);
    assert.match(byId(channelCap, id).summary, /1 seen of 9 \(partial view, item limit reached\)/, id);
  }

  const externalCap = await assessSlackChannelGovernance(withOverride((request) => method(request) === "admin.conversations.search" && request.params.get("search_channel_types") === "external_shared"
    ? { ok: true, conversations: [], next_cursor: "more", total_count: 3 }
    : undefined));
  assert.equal(byId(externalCap, "SLACK-CHAN-01").status, "warn");
  assert.match(byId(externalCap, "SLACK-CHAN-01").summary, /0 seen of 3 \(partial view, cursor returned an empty page\)/);

  const auditCap = await assessSlackMonitoring(withOverride((request) => request.pathname === "/audit/v1/logs" ? { ...compliantFixture(request), response_metadata: { next_cursor: "more" } } : undefined), { auditLimit: 3 });
  for (const id of ["SLACK-MON-01", "SLACK-MON-03", "SLACK-MON-05"]) {
    assert.equal(byId(auditCap, id).status, "warn", id);
  }
  assert.match(byId(auditCap, "SLACK-MON-01").summary, /truncated at audit_limit=3/);
  assert.equal(byId(auditCap, "SLACK-MON-01").evidence.window_complete, false);
});

const methodOf = (request) => request.pathname.replace(/^\/api\//, "");
const webDenied = () => jsonResponse({ ok: false, error: "missing_scope" });
const httpForbidden = () => jsonResponse({ ok: false, error: "not_allowed_token_type" }, 403);

/** Two-workspace profile: T1 (Core) with admin W1 and T2 (Labs) with the workspace-only admin W4; "multi" adds an emoji uploaded by W4. */
const multiWorkspaceFixture = (variant) => (request) => {
  const method = methodOf(request);
  const base = compliantFixture(request);
  switch (method) {
    case "admin.teams.list":
      return { ok: true, teams: [...base.teams, { id: "T2", name: "Labs", discoverability: "invite_only", primary_owner: { user_id: "W4", email: "dana@example.com" }, team_url: "https://labs.slack.com/" }], response_metadata: { next_cursor: "" } };
    case "admin.teams.admins.list":
      return { ok: true, admin_ids: request.params.get("team_id") === "T2" ? ["W4"] : ["W1"], response_metadata: { next_cursor: "" } };
    case "admin.teams.settings.info":
      return request.params.get("team_id") === "T2"
        ? { ok: true, team: { id: "T2", name: "Labs", domain: "labs", email_domain: "example.com", icon: {}, enterprise_id: "E1", enterprise_name: "Acme", default_channels: ["C1"] } }
        : base;
    case "admin.users.list":
      return { ...base, users: [...base.users, { id: "W4", email: "dana@example.com", is_admin: false, is_owner: false, is_primary_owner: false, is_restricted: false, is_ultra_restricted: false, is_bot: false, username: "dana", full_name: "Dana", is_active: true, date_created: 1566922090, deactivated_ts: 0, expiration_ts: 0, workspaces: ["T2"], has_2fa: true, has_sso: true }] };
    case "admin.emoji.list":
      return variant === "multi"
        ? { ok: true, emoji: { ...base.emoji, rocket: { url: "https://emoji.slack-edge.com/T2/rocket/1.png", date_created: 1591720632, uploaded_by: "W4" } }, response_metadata: { next_cursor: "" } }
        : base;
    default:
      return base;
  }
};

const denyOn = (baseFixture, predicate, response = webDenied) => makeClient((request) => (predicate(request) ? response() : baseFixture(request)));

async function assessAll(client) {
  const results = [
    await assessSlackIdentity(client),
    await assessSlackAdminAccess(client),
    await assessSlackIntegrations(client),
    await assessSlackChannelGovernance(client),
    await assessSlackMonitoring(client),
  ];
  return { findings: results.flatMap((result) => result.findings), errors: results.flatMap((result) => result.errors), summaries: results.map((result) => result.summary) };
}

function passingIds(result) {
  return new Set(result.findings.filter((item) => item.status === "pass").map((item) => item.id));
}

test("corollary hit 1: SLACK-APP-06 demotes below pass when auth.test is unreadable", async () => {
  for (const [label, response] of [["ok:false missing_scope", webDenied], ["HTTP 403", httpForbidden]]) {
    const result = await assessSlackIntegrations(denyOn(compliantFixture, (request) => request.pathname === "/api/auth.test", response));
    const finding = byId(result, "SLACK-APP-06");
    assert.equal(finding.status, "warn", label);
    assert.match(finding.summary, /disable_file_uploads=type:owner,type:admin: uploads are restricted to owners and admins in the token's workspace \(id unknown\); auth\.test was not readable \(.*\), so the workspace the preference applies to could not be identified/, label);
    assert.doesNotMatch(finding.summary, /workspace unknown/, label);
    assert.equal(finding.evidence.workspace_id, null, label);
    assert.match(finding.evidence.workspace_id_status, /^unreadable: auth\.test /, label);
    assert.ok(result.errors.some((item) => item.startsWith("auth.test: ")), `${label}: errors array names auth.test`);
  }
  const readable = byId(await assessSlackIntegrations(makeClient(compliantFixture)), "SLACK-APP-06");
  assert.equal(readable.status, "pass");
  assert.equal(readable.evidence.workspace_id, "T1");
  assert.equal(readable.evidence.workspace_id_status, "read from auth.test team_id");
});

test("corollary hit 2: SLACK-ADMIN-08 never passes or fails on an incomplete workspace admin roster", async () => {
  const adminsList = (request) => methodOf(request) === "admin.teams.admins.list";
  const adminsListForT2 = (request) => adminsList(request) && request.params.get("team_id") === "T2";

  const cleanBaseline = await assessSlackAdminAccess(makeClient(multiWorkspaceFixture("multi-clean")));
  assert.equal(byId(cleanBaseline, "SLACK-ADMIN-08").status, "pass");
  assert.equal(byId(cleanBaseline, "SLACK-ADMIN-01").status, "pass");
  const uploadBaseline = byId(await assessSlackAdminAccess(makeClient(multiWorkspaceFixture("multi"))), "SLACK-ADMIN-08");
  assert.equal(uploadBaseline.status, "pass", "W4 is in the readable T2 admin roster, so the rocket upload is an admin upload");
  assert.deepEqual(uploadBaseline.evidence.non_admin_uploads, []);
  assert.equal(uploadBaseline.evidence.roster_complete, true);

  for (const [label, response] of [["ok:false missing_scope", webDenied], ["HTTP 403", httpForbidden]]) {
    const everyWorkspace = byId(await assessSlackAdminAccess(denyOn(compliantFixture, adminsList, response)), "SLACK-ADMIN-08");
    assert.equal(everyWorkspace.status, "manual", label);
    assert.match(everyWorkspace.summary, /^admin\.teams\.admins\.list unreadable for T1 \(Core\): .+, so the 1 custom emoji uploaders could not be compared with a workspace admin roster/, label);
    assert.equal(everyWorkspace.evidence.non_admin_uploads, null, label);
    assert.match(everyWorkspace.evidence.non_admin_uploads_status, /^unknown: admin\.teams\.admins\.list unreadable for T1/, label);
    assert.equal(everyWorkspace.evidence.unreadable_workspaces.length, 1, label);
    assert.match(everyWorkspace.evidence.unreadable_workspaces[0], /^T1: /, label);
    assert.equal(everyWorkspace.evidence.roster_complete, false, label);

    const oneWorkspace = await assessSlackAdminAccess(denyOn(multiWorkspaceFixture("multi-clean"), adminsListForT2, response));
    const clean = byId(oneWorkspace, "SLACK-ADMIN-08");
    assert.equal(clean.status, "warn", label);
    assert.match(clean.summary, /checked against an incomplete admin roster \(admin\.teams\.admins\.list unreadable for T2 \(Labs\): .+\); 0 uploads are by users outside the readable roster/, label);
    assert.equal(clean.evidence.non_admin_uploads, null, label);
    assert.match(clean.evidence.non_admin_uploads_status, /^unknown: admin roster incomplete \(admin\.teams\.admins\.list unreadable for T2 \(Labs\)/, label);
    assert.deepEqual(clean.evidence.unreadable_workspaces.map((item) => item.split(":")[0]), ["T2"], label);
    assert.equal(clean.evidence.roster_complete, false, label);
    const adminInventory = byId(oneWorkspace, "SLACK-ADMIN-01");
    assert.equal(adminInventory.status, "warn", label);
    assert.match(adminInventory.summary, /admin\.teams\.admins\.list unreadable for T2 \(Labs\): /, label);
    const deniedCount = adminInventory.evidence.admin_counts.find((item) => item.id === "T2");
    assert.equal(deniedCount.count, null, label);
    assert.equal(deniedCount.complete, false, label);
    assert.match(deniedCount.status, /^unreadable: admin\.teams\.admins\.list /, label);
    assert.equal(adminInventory.evidence.admin_counts.find((item) => item.id === "T1").count, 1, label);

    const falseFail = byId(await assessSlackAdminAccess(denyOn(multiWorkspaceFixture("multi"), adminsListForT2, response)), "SLACK-ADMIN-08");
    assert.equal(falseFail.status, "warn", `${label}: W4's upload is not classified as non-admin while T2's roster is unreadable`);
    assert.match(falseFail.summary, /admin\.teams\.admins\.list unreadable for T2 \(Labs\)/, label);
    assert.match(falseFail.summary, /1 uploads are by users outside the readable roster and were not classified as non-admin/, label);
    assert.equal(falseFail.evidence.non_admin_uploads, null, label);
    assert.equal(falseFail.evidence.uploads_outside_readable_roster, 1, label);
  }
});

test("corollary wording: partial denials name the endpoint and the workspace or channel id", async () => {
  const settingsForT2 = byId(await assessSlackAdminAccess(denyOn(multiWorkspaceFixture("multi-clean"), (request) => methodOf(request) === "admin.teams.settings.info" && request.params.get("team_id") === "T2")), "SLACK-ADMIN-07");
  assert.equal(settingsForT2.status, "warn");
  assert.match(settingsForT2.summary, /admin\.teams\.settings\.info unreadable or lacking team\.email_domain for T2: /);
  assert.deepEqual(settingsForT2.evidence.unreadable_workspaces.map((item) => item.split(":")[0]), ["T2"]);

  const usersDenied = byId(await assessSlackAdminAccess(denyOn(compliantFixture, (request) => methodOf(request) === "admin.users.list")), "SLACK-ADMIN-08");
  assert.notEqual(usersDenied.status, "pass");
  assert.match(usersDenied.summary, /admin\.users\.list unreadable \(.+\)/);
  assert.equal(usersDenied.evidence.non_admin_uploads, null);

  const prefsFor = (channelId) => (request) => methodOf(request) === "admin.conversations.getConversationPrefs" && (channelId === undefined || request.params.get("channel_id") === channelId);
  const generalDenied = byId(await assessSlackChannelGovernance(denyOn(compliantFixture, prefsFor("C1"))), "SLACK-CHAN-02");
  assert.equal(generalDenied.status, "manual");
  assert.match(generalDenied.summary, /^admin\.conversations\.getConversationPrefs is not readable for the announcement channel C1 \(#general\): /);
  assert.doesNotMatch(generalDenied.summary, /No general, org default/);
  assert.deepEqual(generalDenied.evidence.announcement_channels.map((item) => [item.id, item.restricted]), [["C1", null]]);
  assert.match(generalDenied.evidence.announcement_channels[0].status, /^unreadable: admin\.conversations\.getConversationPrefs /);

  const engDenied = byId(await assessSlackChannelGovernance(denyOn(compliantFixture, prefsFor("C2"))), "SLACK-CHAN-02");
  assert.equal(engDenied.status, "warn");
  assert.match(engDenied.summary, /Restricted posting is set on every readable general or org default channel \(1\/1 readable\), but 0 lacked a who_can_post value and admin\.conversations\.getConversationPrefs unreadable for C2 \(#eng\): /);
  assert.deepEqual(engDenied.evidence.unreadable_channel_details.map((item) => item.split(":")[0]), ["C2"]);

  const allPrefsDenied = byId(await assessSlackChannelGovernance(denyOn(compliantFixture, prefsFor(undefined))), "SLACK-CHAN-02");
  assert.equal(allPrefsDenied.status, "manual");
  assert.match(allPrefsDenied.summary, /getConversationPrefs is not readable for the announcement channel C1 \(#general\)/);
  assert.equal(allPrefsDenied.evidence.restricted_channels_seen, null);

  const retentionFor = (channelId) => (request) => methodOf(request) === "admin.conversations.getCustomRetention" && (channelId === undefined || request.params.get("channel_id") === channelId);
  const retentionEng = byId(await assessSlackChannelGovernance(denyOn(compliantFixture, retentionFor("C2"))), "SLACK-CHAN-03");
  assert.equal(retentionEng.status, "warn");
  assert.match(retentionEng.summary, /No readable channel overrides retention below 365 days, but admin\.conversations\.getCustomRetention unreadable for C2 \(#eng\): .+ \(channels: 2 seen \(complete\)\)\.$/);
  assert.deepEqual(retentionEng.evidence.unreadable_channel_details.map((item) => item.split(":")[0]), ["C2"]);

  const retentionAll = byId(await assessSlackChannelGovernance(denyOn(compliantFixture, retentionFor(undefined))), "SLACK-CHAN-03");
  assert.equal(retentionAll.status, "manual");
  assert.match(retentionAll.summary, /^admin\.conversations\.getCustomRetention unreadable for C1 \(#general\): .+; C2 \(#eng\): /);
  assert.equal(retentionAll.evidence.short_retention_channels, null);
  assert.match(retentionAll.evidence.short_retention_status, /^unknown: admin\.conversations\.getCustomRetention unreadable for C1/);
});

const UNAVAILABLE_STATUS = /^(unreadable|not collected|unknown)\b/;
const COLLECTED_STATUS = /^(complete|partial)\b/;
const ENDPOINT_MENTION = /\b(admin\.[A-Za-z.]+[A-Za-z]|users\.list|auth\.test|team\.preferences\.list|SCIM \/[A-Za-z]+|Audit Logs \/[a-z]+)/g;

function endpointPath(mention) {
  if (mention.startsWith("SCIM /")) return `/scim/v2/${mention.slice("SCIM /".length)}`;
  if (mention.startsWith("Audit Logs /")) return `/audit/v1/${mention.slice("Audit Logs /".length)}`;
  return `/api/${mention}`;
}

/** No count or list renders 0, [], or "unknown" beside a status that says the data was unreadable, not collected, or unknown. */
function assertNoFabricatedValues(value, label, path = "") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoFabricatedValues(item, label, `${path}[${index}]`));
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

/** A status that says complete or partial may only name endpoints that were actually requested. */
function assertStatusesMatchRequests(value, requested, label, path = "") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertStatusesMatchRequests(item, requested, label, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === "string" && (key.endsWith("_status") || key === "status") && COLLECTED_STATUS.test(entry)) {
      for (const mention of entry.match(ENDPOINT_MENTION) ?? []) {
        assert.ok(requested.has(endpointPath(mention)), `${label}: ${path}.${key} says "${entry}" but ${mention} was never requested`);
      }
    }
    assertStatusesMatchRequests(entry, requested, label, `${path}.${key}`);
  }
}

function recordingClient(fixture) {
  const requested = new Set();
  const client = makeClient((request) => {
    requested.add(request.pathname);
    return fixture(request);
  });
  return { client, requested };
}

test("corollary follow-up: a read skipped because its input inventory failed renders null with a not-collected status", async () => {
  const usersDenied = recordingClient((request) => (methodOf(request) === "admin.users.list" ? webDenied() : compliantFixture(request)));
  const admin = await assessSlackAdminAccess(usersDenied.client);
  assert.equal(admin.summary.sessions_sampled, null);
  assert.match(admin.summary.sessions_status, /^not collected: admin\.users\.list was unreadable \(.*missing_scope\), so admin\.users\.session\.getSettings was not called$/);
  assert.doesNotMatch(admin.summary.sessions_status, /complete/);
  assert.ok(!usersDenied.requested.has("/api/admin.users.session.getSettings"), "the session read is never issued without a user inventory");
  assert.equal(byId(admin, "SLACK-ADMIN-03").status, "manual");

  const teamsDenied = await assessSlackAdminAccess(denyOn(compliantFixture, (request) => methodOf(request) === "admin.teams.list"));
  assert.equal(teamsDenied.summary.workspace_admins_seen, null);
  assert.match(teamsDenied.summary.workspace_admins_status, /^not collected: admin\.teams\.list was unreadable \(.*missing_scope\), so admin\.teams\.admins\.list was not called$/);
  assert.equal(byId(teamsDenied, "SLACK-ADMIN-08").evidence.unreadable_workspaces, null);
  assert.equal(byId(teamsDenied, "SLACK-ADMIN-08").evidence.workspace_admin_lists_status, teamsDenied.summary.workspace_admins_status);

  const skipped = await assessSlackIdentity(makeClient(compliantFixture), { skipScim: true });
  assert.equal(skipped.summary.scim_users, null);
  assert.equal(skipped.summary.scim_users_status, "not collected: SCIM checks were skipped by request, so SCIM /Users was not called");
  const configDenied = await assessSlackIdentity(denyOn(compliantFixture, (request) => request.pathname === "/scim/v2/ServiceProviderConfig", httpForbidden));
  assert.equal(configDenied.summary.scim_users, null);
  assert.match(configDenied.summary.scim_users_status, /^not collected: SCIM \/ServiceProviderConfig was unreadable \(.+\), so SCIM \/Users was not called$/);

  const slackUsersDenied = byId(await assessSlackIdentity(denyOn(compliantFixture, (request) => methodOf(request) === "users.list")), "SLACK-ID-04");
  assert.equal(slackUsersDenied.status, "manual");
  assert.equal(slackUsersDenied.evidence.mismatched_users, null);
  assert.match(slackUsersDenied.evidence.mismatched_users_status, /^not collected: users\.list was unreadable \(.*missing_scope\), so SCIM-active users were not compared with Slack deactivations$/);

  const channelsDenied = await assessSlackChannelGovernance(denyOn(compliantFixture, (request) => methodOf(request) === "admin.conversations.search" && request.params.get("search_channel_types") === "exclude_archived"));
  assert.equal(channelsDenied.summary.restricted_posting_channels, null);
  assert.match(channelsDenied.summary.posting_prefs_status, /^not collected: admin\.conversations\.search was unreadable \(.*missing_scope\), so admin\.conversations\.getConversationPrefs was not called$/);
  assert.equal(channelsDenied.summary.short_retention_channels, null);
  assert.match(channelsDenied.summary.retention_status, /^not collected: admin\.conversations\.search was unreadable \(.*missing_scope\), so admin\.conversations\.getCustomRetention was not called$/);

  const empty = await assessSlackAdminAccess(makeClient(emptyFixture));
  assert.equal(empty.summary.sessions_sampled, null);
  assert.equal(empty.summary.sessions_status, "not collected: admin.users.list returned no active users, so admin.users.session.getSettings was not called");
  assert.equal(empty.summary.workspace_admins_seen, null);
  assert.equal(empty.summary.workspace_admins_status, "not collected: admin.teams.list returned no workspaces, so admin.teams.admins.list was not called");
  const emptyChannels = await assessSlackChannelGovernance(makeClient(emptyFixture));
  assert.equal(emptyChannels.summary.restricted_posting_channels, null);
  assert.equal(emptyChannels.summary.posting_prefs_status, "not collected: admin.conversations.search returned no active channels, so admin.conversations.getConversationPrefs was not called");

  const compliant = await assessSlackAdminAccess(makeClient(compliantFixture));
  assert.equal(compliant.summary.sessions_sampled, 2);
  assert.equal(compliant.summary.sessions_status, "complete: admin.users.session.getSettings sampled 2 of 2 seen active users");
  assert.equal(compliant.summary.workspace_admins_seen, 1);
  assert.equal(compliant.summary.workspace_admins_status, "complete: admin.teams.admins.list readable for 1 of 1 workspaces");
  const sampled = await assessSlackAdminAccess(makeClient(compliantFixture), { sessionSample: 1 });
  assert.equal(sampled.summary.sessions_sampled, 1);
  assert.equal(sampled.summary.sessions_status, "partial: admin.users.session.getSettings sampled 1 of 2 seen active users");
});

/** Mirrors the reviewer's per-inventory sweep: exactly the dependent findings leave pass and every other baseline pass stays. */
test("corollary sweep: denying one inventory demotes exactly its dependent findings", async () => {
  const single = compliantFixture;
  const multiClean = multiWorkspaceFixture("multi-clean");
  const multi = multiWorkspaceFixture("multi");
  const web = (name) => (request) => methodOf(request) === name;
  const forTeam = (name, teamId) => (request) => methodOf(request) === name && request.params.get("team_id") === teamId;
  const forChannel = (name, channelId) => (request) => methodOf(request) === name && request.params.get("channel_id") === channelId;
  const rows = [
    ["auth.test", single, web("auth.test"), webDenied, ["SLACK-APP-06"]],
    ["users.list", single, web("users.list"), webDenied, ["SLACK-ID-01", "SLACK-ID-02", "SLACK-ID-04", "SLACK-ID-05"]],
    ["SCIM /ServiceProviderConfig (403)", single, (request) => request.pathname === "/scim/v2/ServiceProviderConfig", httpForbidden, ["SLACK-ID-03", "SLACK-ID-04"]],
    ["SCIM /Users (403)", single, (request) => request.pathname === "/scim/v2/Users", httpForbidden, ["SLACK-ID-03", "SLACK-ID-04"]],
    ["admin.teams.list", single, web("admin.teams.list"), webDenied, ["SLACK-ADMIN-01", "SLACK-ADMIN-05", "SLACK-ADMIN-07", "SLACK-ADMIN-08", "SLACK-APP-06"]],
    ["admin.teams.admins.list (every workspace)", single, web("admin.teams.admins.list"), webDenied, ["SLACK-ADMIN-01", "SLACK-ADMIN-08"]],
    ["admin.teams.admins.list for T2 only (multi-clean)", multiClean, forTeam("admin.teams.admins.list", "T2"), webDenied, ["SLACK-ADMIN-01", "SLACK-ADMIN-08"]],
    ["admin.teams.admins.list for T2 only (multi, W4 uploaded an emoji)", multi, forTeam("admin.teams.admins.list", "T2"), webDenied, ["SLACK-ADMIN-01", "SLACK-ADMIN-08"]],
    ["admin.teams.settings.info (every workspace)", single, web("admin.teams.settings.info"), webDenied, ["SLACK-ADMIN-07"]],
    ["admin.teams.settings.info for T2 only", multiClean, forTeam("admin.teams.settings.info", "T2"), webDenied, ["SLACK-ADMIN-07"]],
    ["admin.users.list", single, web("admin.users.list"), webDenied, ["SLACK-ADMIN-02", "SLACK-ADMIN-03", "SLACK-ADMIN-08"]],
    ["admin.users.session.getSettings", single, web("admin.users.session.getSettings"), webDenied, ["SLACK-ADMIN-03"]],
    ["admin.emoji.list", single, web("admin.emoji.list"), webDenied, ["SLACK-ADMIN-08"]],
    ["admin.analytics.getFile", single, web("admin.analytics.getFile"), webDenied, []],
    ["admin.apps.approved.list", single, web("admin.apps.approved.list"), webDenied, ["SLACK-APP-01", "SLACK-APP-03"]],
    ["admin.apps.restricted.list", single, web("admin.apps.restricted.list"), webDenied, ["SLACK-APP-02"]],
    ["admin.barriers.list", single, web("admin.barriers.list"), webDenied, ["SLACK-APP-04"]],
    ["team.preferences.list", single, web("team.preferences.list"), webDenied, ["SLACK-APP-06"]],
    ["admin.conversations.search (both calls)", single, web("admin.conversations.search"), webDenied, ["SLACK-CHAN-01", "SLACK-CHAN-02", "SLACK-CHAN-03"]],
    ["admin.conversations.search external_shared only", single, (request) => web("admin.conversations.search")(request) && request.params.get("search_channel_types") === "external_shared", webDenied, ["SLACK-CHAN-01"]],
    ["admin.conversations.search exclude_archived only", single, (request) => web("admin.conversations.search")(request) && request.params.get("search_channel_types") === "exclude_archived", webDenied, ["SLACK-CHAN-02", "SLACK-CHAN-03"]],
    ["admin.conversations.getConversationPrefs (every channel)", single, web("admin.conversations.getConversationPrefs"), webDenied, ["SLACK-CHAN-02"]],
    ["getConversationPrefs for C1 (#general) only", single, forChannel("admin.conversations.getConversationPrefs", "C1"), webDenied, ["SLACK-CHAN-02"]],
    ["getConversationPrefs for C2 only", single, forChannel("admin.conversations.getConversationPrefs", "C2"), webDenied, ["SLACK-CHAN-02"]],
    ["admin.conversations.getCustomRetention (every channel)", single, web("admin.conversations.getCustomRetention"), webDenied, ["SLACK-CHAN-03"]],
    ["getCustomRetention for C2 only", single, forChannel("admin.conversations.getCustomRetention", "C2"), webDenied, ["SLACK-CHAN-03"]],
    ["Audit Logs /logs (403)", single, (request) => request.pathname === "/audit/v1/logs", httpForbidden, ["SLACK-MON-01", "SLACK-MON-02", "SLACK-MON-03", "SLACK-MON-05"]],
    ["Audit Logs /schemas (403)", single, (request) => request.pathname === "/audit/v1/schemas", httpForbidden, ["SLACK-MON-04"]],
  ];

  const baselines = new Map();
  for (const fixture of [single, multiClean, multi]) {
    const recorder = recordingClient(fixture);
    const baseline = await assessAll(recorder.client);
    assert.deepEqual(baseline.errors, [], "baseline collects without errors");
    assertNoFabricatedValues(baseline.summaries, "baseline summaries");
    assertNoFabricatedValues(baseline.findings.map((item) => item.evidence ?? null), "baseline evidence");
    assertStatusesMatchRequests(baseline.summaries, recorder.requested, "baseline summaries");
    baselines.set(fixture, passingIds(baseline));
  }
  assert.equal(baselines.get(single).size, 24, "single-workspace baseline passes every automatable finding");
  assert.equal(baselines.get(multiClean).size, 23, "the two-workspace baseline downgrades SLACK-APP-06 to warn because team.preferences.list reads one workspace");

  const table = [];
  for (const [label, fixture, predicate, response, expected] of rows) {
    const baseline = baselines.get(fixture);
    for (const id of expected) assert.ok(baseline.has(id), `${label}: ${id} passes at baseline`);
    const recorder = recordingClient((request) => (predicate(request) ? response() : fixture(request)));
    const denied = await assessAll(recorder.client);
    const statusById = Object.fromEntries(denied.findings.map((item) => [item.id, item.status]));
    assertNoFabricatedValues(denied.summaries, `${label}: summaries`);
    assertNoFabricatedValues(denied.findings.map((item) => item.evidence ?? null), `${label}: evidence`);
    assertStatusesMatchRequests(denied.summaries, recorder.requested, `${label}: summaries`);
    assertStatusesMatchRequests(denied.findings.map((item) => item.evidence ?? null), recorder.requested, `${label}: evidence`);
    const demoted = [...baseline].filter((id) => statusById[id] !== "pass").sort();
    assert.deepEqual(demoted, [...expected].sort(), `${label}: exactly the dependent findings leave pass`);
    for (const id of demoted) {
      const finding = denied.findings.find((item) => item.id === id);
      assert.ok(finding.evidence === undefined || !Object.values(finding.evidence).some((value) => value === "unknown"), `${label}: ${id} carries no "unknown" placeholder`);
    }
    if (expected.length > 0) assert.ok(denied.errors.length > 0, `${label}: the denial is disclosed in the errors array`);
    table.push({ label, demoted: demoted.map((id) => `${id}=${statusById[id]}`) });
  }
  const falseFailRow = table.find((row) => row.label.startsWith("admin.teams.admins.list for T2 only (multi,"));
  assert.ok(falseFailRow.demoted.includes("SLACK-ADMIN-08=warn"), "an upload by the denied workspace's admin reads as warn, never fail");
});

test("corollary bundle check: findings.json never carries SLACK-ADMIN-08 as pass when admin.teams.admins.list is denied", async () => {
  const base = createTempBase("grclanker-slack-corollary-");
  const client = denyOn(compliantFixture, (request) => methodOf(request) === "admin.teams.admins.list");
  const config = resolveSlackConfiguration({ token: "xoxp-test", scim_token: "scim-test", org_id: "E1" }, EMPTY_ENV);
  const bundle = await exportSlackAuditBundle(client, config, base);
  assert.ok(bundle.errorCount > 0);
  const errorsLog = readFileSync(join(bundle.outputDir, "_errors.log"), "utf8");
  assert.match(errorsLog, /\[admin-access\] admin\.teams\.admins\.list T1: /);
  const findings = JSON.parse(readFileSync(join(bundle.outputDir, "analysis/findings.json"), "utf8"));
  const emoji = findings.find((item) => item.id === "SLACK-ADMIN-08");
  assert.equal(emoji.status, "manual");
  assert.match(emoji.summary, /admin\.teams\.admins\.list unreadable for T1 \(Core\)/);
  assert.equal(emoji.evidence.non_admin_uploads, null);
  assert.notEqual(findings.find((item) => item.id === "SLACK-ADMIN-01").status, "pass");
  const adminAccess = JSON.parse(readFileSync(join(bundle.outputDir, "core_data/admin-access.json"), "utf8"));
  assert.equal(adminAccess.summary.workspace_admins_seen, null);
  assert.match(adminAccess.summary.workspace_admins_status, /^unreadable: admin\.teams\.admins\.list unreadable for T1 \(Core\): /);
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

test("redactErrorText scrubs embedded URLs, bearer headers, session cookies and ids, API keys, and HTML error pages", () => {
  const cases = [
    ["redirect to https://example.invalid/cb?access_token=CANARY-URLTOKEN-1&state=x failed", /\?access_token=\[REDACTED\]&state=x/],
    ["Authorization: Bearer CANARY-BEARER-1", /^Authorization: \[REDACTED\]$/],
    ["Authorization: Basic Q0FOQVJZLUJBU0lDLTE=", /^Authorization: \[REDACTED\]$/],
    ["Cookie: d=CANARY-SESSION-1; b=CANARY-SESSION-2", /^Cookie: \[REDACTED\]$/],
    ["Set-Cookie: sid=CANARY-SESSION-3; Path=/; HttpOnly", /^Set-Cookie: \[REDACTED\]$/],
    ["session_id=CANARY-SESSION-4", /^session_id=\[REDACTED\]$/],
    ['"sessionId": "CANARY-SESSION-5"', /^"sessionId": "\[REDACTED\]"$/],
    ["X-Api-Key: CANARY-APIKEY-1", /^X-Api-Key: \[REDACTED\]$/],
    ['{"api_key":"CANARY-APIKEY-2","error":"invalid_auth"}', /^\{"api_key":"\[REDACTED\]","error":"invalid_auth"\}$/],
    ["client_secret=CANARY-CLIENTSECRET-1&grant_type=refresh", /^client_secret=\[REDACTED\]&grant_type=refresh$/],
    ["<html><body><h1>502 Bad Gateway</h1><pre>Authorization: Bearer CANARY-BEARER-2; Cookie: d=CANARY-SESSION-6; X-Api-Key: CANARY-APIKEY-3</pre></body></html>", /<pre>Authorization: \[REDACTED\]; Cookie: \[REDACTED\]<\/pre>/],
  ];
  for (const [input, expected] of cases) {
    const output = redactErrorText(input);
    assert.doesNotMatch(output, /CANARY-/, input);
    assert.match(output, expected, input);
  }
  assert.equal(redactErrorText("token FAKE_SECRET_TOKEN_9 leaked", ["FAKE_SECRET_TOKEN_9"]), "token [REDACTED] leaked");
  for (const benign of [
    "Session idle timeout: 30 minutes",
    "token: user, rotating (xoxe.) format",
    "All 2 active users have a session duration at or below 24 hours",
    "api_key_count: 3",
    "Slack Web API users.list failed: missing_scope",
    "complete: admin.users.session.getSettings sampled 2 of 2 seen active users",
    "Cookies are not read by this tool",
  ]) {
    assert.equal(redactErrorText(benign), benign);
  }
});

test("non-JSON response bodies are described, never quoted, and every error string is scrubbed at creation", async () => {
  const page = "<html><body><h1>502 Bad Gateway</h1><pre>Cookie: d=CANARY-SESSION-7; X-Api-Key: CANARY-APIKEY-4</pre></body></html>";
  const html = (status) => new Response(page, { status, headers: { "content-type": "text/html; charset=utf-8" } });
  const gateway = makeClient(() => html(502));
  await assert.rejects(gateway.web("users.list"), (error) => {
    assert.equal(error.name, "SlackApiError");
    assert.equal(error.message, `Slack Web API users.list failed (HTTP 502) non-JSON text/html body (${page.length} characters) withheld`);
    assert.equal(error.code, "http_502");
    return true;
  });
  const okHtml = makeClient(() => html(200));
  await assert.rejects(okHtml.web("users.list"), (error) => {
    assert.equal(error.message, `Slack Web API users.list failed (HTTP 200) non-JSON text/html body (${page.length} characters) withheld`);
    assert.equal(error.code, "non_json_body");
    return true;
  });
  await assert.rejects(okHtml.scim("/Users"), /Slack SCIM \/Users failed \(HTTP 200\) non-JSON text\/html body/);
  await assert.rejects(okHtml.audit("/logs"), /Slack Audit Logs \/logs failed \(HTTP 200\) non-JSON text\/html body/);
  await assert.rejects(gateway.probeAnalyticsExport(), /admin\.analytics\.getFile failed \(HTTP 502\) non-JSON text\/html body/);
  const untyped = makeClient(() => new Response(new TextEncoder().encode("upstream request timeout"), { status: 504 }));
  await assert.rejects(untyped.web("users.list"), /failed \(HTTP 504\) non-JSON unknown content type body \(24 characters\) withheld$/);

  const tokenised = "https://example.invalid/cb?access_token=CANARY-URLTOKEN-2&state=x";
  const jsonForbidden = makeClient(() => jsonResponse({ ok: false, error: `invalid_auth: see ${tokenised}`, response_metadata: { messages: [`redirect ${tokenised}`] } }, 403));
  await assert.rejects(jsonForbidden.web("users.list"), (error) => {
    assert.doesNotMatch(error.message, /CANARY-|redirect/);
    assert.equal(error.message, "Slack Web API users.list failed (HTTP 403) error=UnknownError", "a free-text error value is not a documented code and response_metadata.messages is never rendered");
    return true;
  });
  const okFalse = makeClient(() => ({ ok: false, error: `invalid_auth: see ${tokenised}` }));
  await assert.rejects(okFalse.web("users.list"), (error) => {
    assert.equal(error.message, "Slack Web API users.list failed: UnknownError");
    assert.equal(error.code, "UnknownError");
    return true;
  });
  const scimDetail = makeClient(() => jsonResponse({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], detail: `forbidden, see ${tokenised}`, status: "403" }, 403));
  await assert.rejects(scimDetail.scim("/Users"), (error) => {
    assert.doesNotMatch(error.message, /CANARY-/);
    assert.equal(error.message, "Slack SCIM /Users failed (HTTP 403) status=403 detail=forbidden, see https://example.invalid/cb?access_token=[REDACTED]&state=x");
    return true;
  });

  const base = createTempBase("grclanker-slack-config-error-");
  const configPath = join(base, "slack.json");
  writeFileSync(configPath, '{ "token": "xoxp-CANARY-CONFIG-1", ');
  const parseFailure = /^Unable to parse Slack config file .*slack\.json: the file is not valid JSON \(parser detail withheld because it can quote the file\)$/;
  const readWording = /Unable to read|EISDIR|EACCES|Unexpected token|JSON\.parse/;
  assert.throws(() => resolveSlackConfiguration({}, { SLACK_CONFIG_FILE: configPath }), (error) => {
    assert.doesNotMatch(error.message, /CANARY-/);
    assert.match(error.message, parseFailure);
    assert.doesNotMatch(error.message, readWording, "a parse failure never carries the read wording or a parser excerpt");
    return true;
  });

  const directoryPath = join(base, "config-as-directory.json");
  mkdirSync(directoryPath);
  assert.throws(() => readFileSync(directoryPath, "utf8"), /EISDIR: illegal operation on a directory/, "positive control: the fs wording the loader must not echo");
  const readFailure = /^Unable to read Slack config file .*config-as-directory\.json \(EISDIR\)$/;
  assert.throws(() => resolveSlackConfiguration({}, { SLACK_CONFIG_FILE: directoryPath }), (error) => {
    assert.match(error.message, readFailure);
    assert.doesNotMatch(error.message, /illegal operation|Unable to parse/);
    return true;
  });

  const tools = new Map();
  registerSlackTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  const checkAccess = tools.get("slack_check_access");
  const previous = process.env.SLACK_CONFIG_FILE;
  try {
    process.env.SLACK_CONFIG_FILE = directoryPath;
    const unreadable = await checkAccess.execute("call-1", checkAccess.prepareArguments({}));
    assert.equal(unreadable.isError, true);
    assert.match(unreadable.content[0].text, /^Check Slack audit access failed: Unable to read Slack config file .*config-as-directory\.json \(EISDIR\)$/);
    assert.doesNotMatch(unreadable.content[0].text, /illegal operation|Unable to parse/);
    process.env.SLACK_CONFIG_FILE = configPath;
    const malformed = await checkAccess.execute("call-2", checkAccess.prepareArguments({}));
    assert.equal(malformed.isError, true);
    assert.match(malformed.content[0].text, /^Check Slack audit access failed: Unable to parse Slack config file .*slack\.json: the file is not valid JSON \(parser detail withheld because it can quote the file\)$/);
    assert.doesNotMatch(malformed.content[0].text, /CANARY-|Unable to read|EISDIR/);
  } finally {
    if (previous === undefined) delete process.env.SLACK_CONFIG_FILE;
    else process.env.SLACK_CONFIG_FILE = previous;
  }
});

/** Every surface the collectors call, the same list as the reviewer's canary sweep: 16 Web API methods, 3 SCIM paths, 2 Audit Logs paths. */
const ERROR_SURFACES = [
  ...Object.keys(SLACK_METHODS).map((name) => ({ label: `web:${name}`, family: "web", predicate: (request) => methodOf(request) === name })),
  ...["/ServiceProviderConfig", "/Users", "/Groups"].map((path) => ({ label: `scim:${path}`, family: "scim", predicate: (request) => request.pathname === `/scim/v2${path}` })),
  ...["/logs", "/schemas"].map((path) => ({ label: `audit:${path}`, family: "audit", predicate: (request) => request.pathname === `/audit/v1${path}` })),
];

const canaryUrl = (slug) => `https://example.invalid/callback?access_token=CANARY-URLTOKEN-${slug}&state=x`;

/** A: 502 HTML gateway page carrying bearer, session, and API key canaries inside the first 200 characters. */
const htmlGatewayError = (slug) => () => new Response(
  `<html><body><h1>502 Bad Gateway</h1><pre>Authorization: Bearer CANARY-BEARER-${slug}; Cookie: d=CANARY-SESSION-${slug}; X-Api-Key: CANARY-APIKEY-${slug}</pre></body></html>`,
  { status: 502, headers: { "content-type": "text/html; charset=utf-8" } },
);

/** B: 403 JSON error whose error, response_metadata.messages, or SCIM detail embeds a tokenised URL. */
const tokenisedJsonError = (slug, family) => () => {
  if (family === "scim") return jsonResponse({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], detail: `forbidden, see ${canaryUrl(slug)}`, status: "403" }, 403);
  if (family === "audit") return jsonResponse({ ok: false, error: `forbidden, see ${canaryUrl(slug)}` }, 403);
  return jsonResponse({ ok: false, error: `invalid_auth: see ${canaryUrl(slug)}`, response_metadata: { messages: [`[ERROR] redirect ${canaryUrl(slug)}`] } }, 403);
};

/** C: the Web API's normal error mode, HTTP 200 ok:false with the tokenised URL (SCIM and Audit: 401 JSON). */
const tokenisedOkFalse = (slug, family) => () => {
  if (family === "web") return jsonResponse({ ok: false, error: `invalid_auth: see ${canaryUrl(slug)}`, response_metadata: { messages: [`[ERROR] redirect ${canaryUrl(slug)}`] } }, 200);
  if (family === "scim") return jsonResponse({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], detail: `unauthorized, see ${canaryUrl(slug)}`, status: "401" }, 401);
  return jsonResponse({ ok: false, error: `unauthorized, see ${canaryUrl(slug)}` }, 401);
};

function assertNoCanary(value, label) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  const hit = text.match(/CANARY-[A-Z]+-[a-z0-9.-]+/);
  assert.equal(hit, null, `${label} leaks ${hit?.[0]}`);
}

test("rule 9 error bodies: a failing surface's HTML page or tokenised JSON error never reaches a finding, summary, errors array, bundle file, zip entry, or the thrown export error", async () => {
  assert.equal(ERROR_SURFACES.length, 21, "the surface list matches the reviewer's sweep");
  const config = resolveSlackConfiguration({ token: "xoxp-test", scim_token: "scim-test", org_id: "E1" }, EMPTY_ENV);
  const tokenisedDisclosure = (family) => (family === "scim" ? /detail=(?:forbidden|unauthorized), see https:\/\/example\.invalid\/callback\?access_token=\[REDACTED\]&state=x/ : /failed(?: \(HTTP \d{3}\) error=|: )UnknownError/);
  const shapes = [
    ["A:502-html", (slug) => htmlGatewayError(slug), () => /non-JSON text\/html body \(\d+ characters\) withheld/],
    ["B:403-json-url", (slug, family) => tokenisedJsonError(slug, family), tokenisedDisclosure],
    ["C:ok-false-url", (slug, family) => tokenisedOkFalse(slug, family), tokenisedDisclosure],
  ];
  const table = [];
  for (const surface of ERROR_SURFACES) {
    for (const [shape, build, disclosure] of shapes) {
      const slug = `${surface.label}-${shape}`.toLowerCase().replace(/[^a-z0-9.]+/g, "-");
      const run = `${surface.label} ${shape}`;
      const response = build(slug, surface.family);
      const client = makeClient((request) => (surface.predicate(request) ? response() : compliantFixture(request)));
      const collected = [];

      let accessThrew = false;
      try {
        collected.push(JSON.stringify(await checkSlackAccess(client)));
      } catch (error) {
        accessThrew = true;
        collected.push(error.message);
      }
      const all = await assessAll(client);
      collected.push(JSON.stringify(all.findings), JSON.stringify(all.summaries), JSON.stringify(all.errors));

      const base = createTempBase("grclanker-slack-error-canary-");
      let files = 0;
      let entries = 0;
      let exportThrew = false;
      try {
        const bundle = await exportSlackAuditBundle(client, config, base);
        if (surface.label === "scim:/Groups") {
          assert.match(readFileSync(join(bundle.outputDir, "core_data/access.json"), "utf8"), disclosure(surface.family), `${run}: only the access check reads /Groups, so its surface entry carries the failure`);
        } else {
          assert.ok(bundle.errorCount > 0, `${run}: the failure is recorded as a collection error`);
        }
        const paths = listFilesRecursively(bundle.outputDir);
        files = paths.length;
        for (const file of paths) assertNoCanary(readFileSync(file, "utf8"), `${run}: ${file.slice(bundle.outputDir.length + 1)}`);
        const zipEntries = readZipEntries(bundle.zipPath).filter((entry) => !entry.name.endsWith("/"));
        entries = zipEntries.length;
        assert.equal(entries, files, `${run}: every bundle file is in the zip`);
        for (const entry of zipEntries) assertNoCanary(entry.content, `${run}: zip ${entry.name}`);
        if (existsSync(join(bundle.outputDir, "_errors.log"))) collected.push(readFileSync(join(bundle.outputDir, "_errors.log"), "utf8"));
      } catch (error) {
        if (error instanceof assert.AssertionError) throw error;
        exportThrew = true;
        collected.push(error.message);
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
      assert.equal(exportThrew, surface.label === "web:auth.test", `${run}: only an unreadable auth.test aborts the export`);
      assert.equal(accessThrew, surface.label === "web:auth.test", `${run}: only an unreadable auth.test aborts the access check`);

      const everything = collected.join("\n");
      assertNoCanary(everything, `${run}: in-memory findings, summaries, errors, access surfaces, thrown errors, and _errors.log`);
      assert.match(everything, disclosure(surface.family), `${run}: the failure is disclosed with the validated shape`);
      if (shape === "A:502-html") assert.match(everything, /HTTP 502/, `${run}: the HTTP status is disclosed`);
      table.push({ surface: surface.label, shape, files, entries, exportThrew });
    }
  }
  assert.equal(table.length, 63);
  assert.equal(table.filter((row) => !row.exportThrew && row.files >= 20).length, 60, "every export other than the auth.test runs wrote a full bundle");
});

/** 68 mixed-case alphanumerics with no token prefix, so no shape pattern in redactErrorText can catch it: only code validation can. */
const TOKEN_CANARY = "CANARYSL7f3a9C1d2E4b6A8c0D1e2F3a4B5c6D7e8F9a0B1c2D3e4F5a6B7c8D9e0Fqz";
const SCIM_TYPE_CANARY = "CANSL+Qz8Wx7Vy6Ut5Sr4/Pq3On2Ml1Kj0Ih==";
const TOOL_ARGS = { token: "xoxp-test", scim_token: "scim-test", org_id: "E1" };

async function withStubbedFetch(handler, run) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const request = await requestParams(input, init);
    const result = handler(request);
    return result instanceof Response ? result : jsonResponse(result);
  };
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test("vendor codes: a token-shaped Web API error code renders UnknownError everywhere and SCIM errors render only documented fields", async () => {
  assert.equal(TOKEN_CANARY.length, 68);
  assert.equal(redactErrorText(TOKEN_CANARY), TOKEN_CANARY, "positive control: the scrub alone does not catch an unprefixed token");
  const canaryBody = { ok: false, error: TOKEN_CANARY };
  assert.ok(JSON.stringify(canaryBody).includes(TOKEN_CANARY), "positive control: the raw body carries the canary");
  assert.equal(vendorErrorCode(TOKEN_CANARY), UNKNOWN_ERROR_CODE);
  assert.equal(vendorErrorCode("not_allowed_token_type"), "not_allowed_token_type");
  assert.equal(vendorErrorCode("missing_scope"), "missing_scope");
  for (const rejected of ["Missing_Scope", "a".repeat(65), "", "1abc", "invalid auth", "xoxp-abc123456"]) assert.equal(vendorErrorCode(rejected), UNKNOWN_ERROR_CODE, rejected);
  assert.equal(describeErrorFields({ ok: false, error: "missing_scope", needed: "admin.users:read", provided: "identify,users:read" }, "web"), "error=missing_scope needed=admin.users:read provided=identify,users:read");
  assert.equal(describeErrorFields({ ok: false, error: "missing_scope", needed: TOKEN_CANARY, provided: `identify,${TOKEN_CANARY}`, warning: `missing_charset,${TOKEN_CANARY}`, response_metadata: { messages: [TOKEN_CANARY] } }, "web"), "error=missing_scope needed=UnknownError provided=identify,UnknownError warning=missing_charset,UnknownError");
  assert.equal(describeErrorFields({ ok: false }, "web"), "JSON body without documented error fields withheld");
  assert.equal(describeErrorFields({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "403", scimType: SCIM_TYPE_CANARY, code: TOKEN_CANARY, detail: "denied" }, "scim"), "status=403 detail=denied");
  assert.equal(describeErrorFields({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: 403, scimType: "invalidFilter", detail: "Not authorized to view this resource" }, "scim"), "status=403 scimType=invalidFilter detail=Not authorized to view this resource");
  assert.equal(describeErrorFields({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "401", scimType: "urn:ietf:params:scim:api:messages:2.0:invalidToken", detail: `see https://example.invalid/cb?access_token=${TOKEN_CANARY}` }, "scim"), "status=401 scimType=urn:ietf:params:scim:api:messages:2.0:invalidToken detail=see https://example.invalid/cb?access_token=[REDACTED]");
  assert.equal(describeErrorFields({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: TOKEN_CANARY, scimType: TOKEN_CANARY, detail: 7 }, "scim"), "JSON body without documented error fields withheld");

  const documented = makeClient(() => ({ ok: false, error: "missing_scope", needed: "admin.users:read" }));
  await assert.rejects(documented.web("users.list"), (error) => {
    assert.equal(error.message, "Slack Web API users.list failed: missing_scope");
    assert.equal(error.code, "missing_scope");
    return true;
  });
  await assert.rejects(makeClient(() => jsonResponse({ ok: false, error: "not_allowed_token_type" }, 403)).web("users.list"), (error) => {
    assert.equal(error.message, "Slack Web API users.list failed (HTTP 403) error=not_allowed_token_type");
    assert.equal(error.code, "http_forbidden");
    return true;
  });
  await assert.rejects(makeClient(() => canaryBody).web("users.list"), (error) => {
    assert.equal(error.message, "Slack Web API users.list failed: UnknownError");
    assert.equal(error.code, "UnknownError");
    return true;
  });
  await assert.rejects(makeClient(() => jsonResponse(canaryBody, 403)).web("users.list"), (error) => {
    assert.equal(error.message, "Slack Web API users.list failed (HTTP 403) error=UnknownError");
    return true;
  });

  const scimCanary = { schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "403", scimType: SCIM_TYPE_CANARY, code: TOKEN_CANARY, detail: "denied" };
  await assert.rejects(makeClient(() => jsonResponse(scimCanary, 403)).scim("/Users"), (error) => {
    assert.equal(error.message, "Slack SCIM /Users failed (HTTP 403) status=403 detail=denied");
    return true;
  });
  await assert.rejects(makeClient(() => jsonResponse({ ...scimCanary, scimType: "invalidFilter" }, 403)).scim("/Users"), (error) => {
    assert.equal(error.message, "Slack SCIM /Users failed (HTTP 403) status=403 scimType=invalidFilter detail=denied");
    return true;
  });

  const config = resolveSlackConfiguration(TOOL_ARGS, EMPTY_ENV);
  const leaks = (text) => text.includes(TOKEN_CANARY) || text.includes(SCIM_TYPE_CANARY) || text.includes("CANSL+") || text.includes("CANARYSL");
  const walk = async (label, fixture, expectThrow) => {
    const client = makeClient(fixture);
    const collected = [];
    let threw = false;
    try {
      collected.push(JSON.stringify(await checkSlackAccess(client)));
    } catch (error) {
      threw = true;
      collected.push(error.message);
    }
    assert.equal(threw, expectThrow, `${label}: access check throw`);
    const all = await assessAll(client);
    collected.push(JSON.stringify(all.findings), JSON.stringify(all.summaries), JSON.stringify(all.errors));
    const base = createTempBase("grclanker-slack-vendor-code-");
    try {
      const bundle = await exportSlackAuditBundle(client, config, base);
      for (const file of listFilesRecursively(bundle.outputDir)) {
        const content = readFileSync(file, "utf8");
        assert.equal(leaks(content), false, `${label}: ${file.slice(bundle.outputDir.length + 1)} leaks a canary`);
        collected.push(content);
      }
      for (const entry of readZipEntries(bundle.zipPath)) assert.equal(leaks(entry.content), false, `${label}: zip ${entry.name} leaks a canary`);
    } catch (error) {
      if (error instanceof assert.AssertionError) throw error;
      collected.push(error.message);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
    const everything = collected.join("\n");
    assert.equal(leaks(everything), false, `${label}: in-memory findings, summaries, errors, access surfaces, thrown errors, or bundle files leak a canary`);
    return everything;
  };

  for (const method of Object.keys(SLACK_METHODS)) {
    const everything = await walk(`web:${method}`, (request) => (methodOf(request) === method ? canaryBody : compliantFixture(request)), method === "auth.test");
    assert.match(everything, new RegExp(`Slack Web API ${method.replace(/\./g, "\\.")} failed: UnknownError`), `web:${method}: the placeholder code is disclosed`);
  }
  const everyMethod = await walk("every web method except auth.test", (request) => (request.pathname.startsWith("/api/") && methodOf(request) !== "auth.test" ? canaryBody : compliantFixture(request)), false);
  assert.match(everyMethod, /"error":"Slack Web API admin\.teams\.list failed: UnknownError"/);
  const scimWalk = await walk("scim 403 with scimType and code canaries", (request) => (request.pathname.startsWith("/scim/v2/") ? jsonResponse(scimCanary, 403) : compliantFixture(request)), false);
  assert.match(scimWalk, /Slack SCIM \/ServiceProviderConfig failed \(HTTP 403\) status=403 detail=denied/);
  assert.doesNotMatch(scimWalk, /scimType=/);

  const tools = new Map();
  registerSlackTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  const checkAccess = tools.get("slack_check_access");
  const identity = tools.get("slack_assess_identity");
  const previous = process.env.SLACK_CONFIG_FILE;
  process.env.SLACK_CONFIG_FILE = "";
  try {
    const denied = await withStubbedFetch(() => canaryBody, () => checkAccess.execute("call-1", checkAccess.prepareArguments({ ...TOOL_ARGS })));
    assert.equal(denied.isError, true);
    assert.equal(denied.content[0].text, "Check Slack audit access failed: Slack Web API auth.test failed: UnknownError");
    const partial = await withStubbedFetch((request) => (request.pathname.startsWith("/api/") && methodOf(request) !== "auth.test" ? canaryBody : compliantFixture(request)), () => checkAccess.execute("call-2", checkAccess.prepareArguments({ ...TOOL_ARGS })));
    assert.equal(partial.isError, undefined);
    const surfaces = partial.details.surfaces.filter((surface) => surface.error);
    assert.ok(surfaces.length > 0);
    for (const surface of surfaces) assert.match(surface.error, /failed: UnknownError$/, JSON.stringify(surface));
    assert.equal(leaks(JSON.stringify(partial)), false);
    const scimTool = await withStubbedFetch((request) => (request.pathname.startsWith("/scim/v2/") ? jsonResponse(scimCanary, 403) : compliantFixture(request)), () => identity.execute("call-3", identity.prepareArguments({ ...TOOL_ARGS })));
    assert.equal(leaks(JSON.stringify(scimTool)), false);
    assert.match(JSON.stringify(scimTool), /status=403 detail=denied/);
  } finally {
    if (previous === undefined) delete process.env.SLACK_CONFIG_FILE;
    else process.env.SLACK_CONFIG_FILE = previous;
  }
});

const SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
/** Gateway text a proxy adds beside Slack's own fields; the canary has no prefix, so only the branch choice keeps it out. */
const GATEWAY_DETAIL = `upstream gateway rejected the request; trace ${TOKEN_CANARY}`;

/** Runs the access check, every assessment, and an export bundle against the fixture and returns every rendered string. */
async function collectEverything(fixture, config) {
  const client = makeClient(fixture);
  const collected = [];
  let accessThrew = false;
  try {
    collected.push(JSON.stringify(await checkSlackAccess(client)));
  } catch (error) {
    accessThrew = true;
    collected.push(error.message);
  }
  const all = await assessAll(client);
  collected.push(JSON.stringify(all.findings), JSON.stringify(all.summaries), JSON.stringify(all.errors));
  const base = createTempBase("grclanker-slack-api-family-");
  let exportThrew = false;
  try {
    const bundle = await exportSlackAuditBundle(client, config, base);
    for (const file of listFilesRecursively(bundle.outputDir)) collected.push(readFileSync(file, "utf8"));
    for (const entry of readZipEntries(bundle.zipPath)) collected.push(entry.content);
  } catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    exportThrew = true;
    collected.push(error.message);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
  return { everything: collected.join("\n"), accessThrew, exportThrew };
}

test("API family: a Web API or Audit Logs error body carrying a gateway detail field renders its validated code, never the SCIM shape, and a SCIM body needs the RFC 7644 error schema", async () => {
  const webBody = { ok: false, error: "invalid_auth", detail: GATEWAY_DETAIL };
  const auditBody = { ok: false, error: "invalid_authentication", detail: GATEWAY_DETAIL, status: "401", scimType: "invalidFilter" };
  const scimBody = { schemas: [SCIM_ERROR_SCHEMA], status: "403", scimType: "invalidFilter", detail: "denied" };
  // Positive controls: the bodies carry the field the old discriminator keyed on, and the scrub alone does not catch the canary.
  assert.ok("detail" in webBody && "detail" in auditBody, "control: the Web API and Audit Logs bodies carry detail");
  assert.equal(redactErrorText(GATEWAY_DETAIL).includes(TOKEN_CANARY), true, "control: the scrub alone keeps the canary");
  const leaks = (text) => text.includes(TOKEN_CANARY) || text.includes("CANARYSL") || text.includes("upstream gateway");

  // The renderer reads the fields documented for the API that was called; detail, status, and scimType in a Web API or Audit Logs body are dropped.
  assert.equal(describeErrorFields(webBody, "web"), "error=invalid_auth");
  assert.equal(describeErrorFields(auditBody, "audit"), "error=invalid_authentication");
  assert.equal(describeErrorFields({ ok: false, error: "invalid_auth", needed: "admin.users:read", schemas: [SCIM_ERROR_SCHEMA], detail: GATEWAY_DETAIL }, "web"), "error=invalid_auth needed=admin.users:read", "a SCIM-shaped body returned by the Web API still renders only the Web API fields");
  assert.equal(describeErrorFields({ ok: false, detail: GATEWAY_DETAIL }, "web"), "JSON body without documented error fields withheld");
  assert.equal(describeErrorFields({ ok: false, detail: GATEWAY_DETAIL }, "audit"), "JSON body without documented error fields withheld");
  // A SCIM error is rendered only when the body carries the SCIM 2.0 error schema; the Web API fields of a SCIM body are never read.
  assert.equal(describeErrorFields(scimBody, "scim"), "status=403 scimType=invalidFilter detail=denied");
  assert.equal(describeErrorFields({ ...scimBody, error: TOKEN_CANARY, needed: TOKEN_CANARY }, "scim"), "status=403 scimType=invalidFilter detail=denied");
  assert.equal(describeErrorFields({ status: "403", scimType: "invalidFilter", detail: GATEWAY_DETAIL }, "scim"), "JSON body without documented error fields withheld", "a SCIM body without the schema discriminator is withheld");
  assert.equal(describeErrorFields({ schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], detail: GATEWAY_DETAIL }, "scim"), "JSON body without documented error fields withheld", "another schema is not the error discriminator");
  assert.equal(describeErrorFields({ ok: false, error: "invalid_auth", detail: GATEWAY_DETAIL }, "scim"), "JSON body without documented error fields withheld", "a Web API body answered on the SCIM path renders nothing");
  assert.throws(() => describeErrorFields(webBody, "rtm"), /Unhandled Slack API family rtm/);

  // Through the client: the thrown message carries the validated code and the HTTP status, and never the gateway text.
  await assert.rejects(makeClient(() => jsonResponse(webBody, 401)).web("users.list"), (error) => {
    assert.equal(error.message, "Slack Web API users.list failed (HTTP 401) error=invalid_auth");
    assert.equal(error.code, "http_forbidden");
    return true;
  });
  await assert.rejects(makeClient(() => jsonResponse(webBody, 502)).probeAnalyticsExport(), (error) => {
    assert.equal(error.message, "Slack Web API admin.analytics.getFile failed (HTTP 502) error=invalid_auth");
    return true;
  });
  await assert.rejects(makeClient(() => jsonResponse(auditBody, 401)).audit("/logs"), (error) => {
    assert.equal(error.message, "Slack Audit Logs /logs failed (HTTP 401) error=invalid_authentication");
    return true;
  });
  await assert.rejects(makeClient(() => jsonResponse(scimBody, 403)).scim("/Users"), (error) => {
    assert.equal(error.message, "Slack SCIM /Users failed (HTTP 403) status=403 scimType=invalidFilter detail=denied");
    return true;
  });
  await assert.rejects(makeClient(() => jsonResponse({ error: "forbidden", detail: GATEWAY_DETAIL }, 403)).scim("/Users"), (error) => {
    assert.equal(error.message, "Slack SCIM /Users failed (HTTP 403) JSON body without documented error fields withheld");
    return true;
  });

  // Through the collectors, the bundle, and the zip: every Web API surface, then auth.test alone, then the Audit Logs surfaces.
  const config = resolveSlackConfiguration(TOOL_ARGS, EMPTY_ENV);
  const everyMethod = await collectEverything((request) => (request.pathname.startsWith("/api/") && methodOf(request) !== "auth.test" ? jsonResponse(webBody, 401) : compliantFixture(request)), config);
  assert.equal(everyMethod.accessThrew, false);
  assert.equal(everyMethod.exportThrew, false);
  assert.equal(leaks(everyMethod.everything), false, "the gateway text reached a finding, a summary, an errors array, an access surface, a bundle file, or the zip");
  assert.match(everyMethod.everything, /Slack Web API admin\.teams\.list failed \(HTTP 401\) error=invalid_auth/);
  assert.match(everyMethod.everything, /Slack Web API users\.list failed \(HTTP 401\) error=invalid_auth/);
  assert.doesNotMatch(everyMethod.everything, /detail=|scimType=|status=401/);
  const authTest = await collectEverything((request) => (methodOf(request) === "auth.test" ? jsonResponse(webBody, 401) : compliantFixture(request)), config);
  assert.equal(authTest.accessThrew, true);
  assert.equal(authTest.exportThrew, true);
  assert.equal(leaks(authTest.everything), false);
  assert.match(authTest.everything, /Slack Web API auth\.test failed \(HTTP 401\) error=invalid_auth/);
  const auditLogs = await collectEverything((request) => (request.pathname.startsWith("/audit/v1/") ? jsonResponse(auditBody, 401) : compliantFixture(request)), config);
  assert.equal(auditLogs.accessThrew, false);
  assert.equal(auditLogs.exportThrew, false);
  assert.equal(leaks(auditLogs.everything), false);
  assert.match(auditLogs.everything, /Slack Audit Logs \/logs failed \(HTTP 401\) error=invalid_authentication/);
  assert.match(auditLogs.everything, /Slack Audit Logs \/schemas failed \(HTTP 401\) error=invalid_authentication/);
  assert.doesNotMatch(auditLogs.everything, /detail=|scimType=/);
  const scim = await collectEverything((request) => (request.pathname.startsWith("/scim/v2/") ? jsonResponse(scimBody, 403) : compliantFixture(request)), config);
  assert.equal(leaks(scim.everything), false);
  assert.match(scim.everything, /Slack SCIM \/ServiceProviderConfig failed \(HTTP 403\) status=403 scimType=invalidFilter detail=denied/);

  // Through the registered tools with a stubbed global fetch.
  const tools = new Map();
  registerSlackTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  const checkAccess = tools.get("slack_check_access");
  const monitoring = tools.get("slack_assess_monitoring");
  const previous = process.env.SLACK_CONFIG_FILE;
  process.env.SLACK_CONFIG_FILE = "";
  try {
    const denied = await withStubbedFetch(() => jsonResponse(webBody, 401), () => checkAccess.execute("call-1", checkAccess.prepareArguments({ ...TOOL_ARGS })));
    assert.equal(denied.isError, true);
    assert.equal(denied.content[0].text, "Check Slack audit access failed: Slack Web API auth.test failed (HTTP 401) error=invalid_auth");
    const partial = await withStubbedFetch((request) => (request.pathname.startsWith("/api/") && methodOf(request) !== "auth.test" ? jsonResponse(webBody, 401) : compliantFixture(request)), () => checkAccess.execute("call-2", checkAccess.prepareArguments({ ...TOOL_ARGS })));
    assert.equal(partial.isError, undefined);
    const surfaces = partial.details.surfaces.filter((surface) => surface.error);
    assert.ok(surfaces.length > 0);
    for (const surface of surfaces) assert.match(surface.error, /failed \(HTTP 401\) error=invalid_auth$/, JSON.stringify(surface));
    assert.equal(leaks(JSON.stringify(partial)), false);
    const auditTool = await withStubbedFetch((request) => (request.pathname.startsWith("/audit/v1/") ? jsonResponse(auditBody, 401) : compliantFixture(request)), () => monitoring.execute("call-3", monitoring.prepareArguments({ ...TOOL_ARGS })));
    assert.equal(leaks(JSON.stringify(auditTool)), false);
    assert.match(JSON.stringify(auditTool), /Slack Audit Logs \/logs failed \(HTTP 401\) error=invalid_authentication/);
  } finally {
    if (previous === undefined) delete process.env.SLACK_CONFIG_FILE;
    else process.env.SLACK_CONFIG_FILE = previous;
  }
});
